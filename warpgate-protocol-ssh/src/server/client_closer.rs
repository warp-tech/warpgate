use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::FutureExt;
use futures::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

/// Ends a client connection from outside russh.
///
/// russh cannot send anything while its loop is parked in a write that the
/// client never drains. Closing wakes that write: reads return end of
/// stream and writes fail with `BrokenPipe`. russh then ends the session
/// and drops the socket
#[derive(Default)]
pub struct ClientCloser {
    cancel: CancellationToken,
}

impl ClientCloser {
    /// Wraps the stream russh runs on. [`ClientCloser::close`] ends it
    pub fn guard<S>(&self, stream: S) -> CancellableStream<S> {
        CancellableStream::new(stream, self.cancel.clone())
    }

    /// Idempotent
    pub fn close(&self) {
        self.cancel.cancel();
    }
}

/// A stream that ends once its token is cancelled, even while a read or a
/// write is parked on the inner stream
pub struct CancellableStream<S> {
    inner: S,
    // A future holds one waker. Each direction has its own so that a read
    // and a write parked in different tasks are both woken
    read_cancelled: BoxFuture<'static, ()>,
    write_cancelled: BoxFuture<'static, ()>,
}

impl<S> CancellableStream<S> {
    fn new(inner: S, cancel: CancellationToken) -> Self {
        Self {
            inner,
            read_cancelled: cancel.clone().cancelled_owned().boxed(),
            write_cancelled: cancel.cancelled_owned().boxed(),
        }
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "connection closed by Warpgate")
}

impl<S: AsyncRead + Unpin> AsyncRead for CancellableStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_cancelled.poll_unpin(cx).is_ready() {
            // End of stream
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CancellableStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_cancelled.poll_unpin(cx).is_ready() {
            return Poll::Ready(Err(closed()));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_cancelled.poll_unpin(cx).is_ready() {
            return Poll::Ready(Err(closed()));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    /// A cancelled stream still shuts the inner stream down and fails if
    /// that would block. `Ok` always means the shutdown happened
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let cancelled = self.write_cancelled.poll_unpin(cx).is_ready();
        match Pin::new(&mut self.inner).poll_shutdown(cx) {
            Poll::Pending if cancelled => Poll::Ready(Err(closed())),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::ClientCloser;

    async fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (server, client)
    }

    /// Session teardown depends on this to cut a client that never reads
    #[tokio::test]
    async fn close_releases_parked_write() {
        let (server, _client) = connected_pair().await;
        let closer = ClientCloser::default();
        let mut server = closer.guard(server);

        let writer = tokio::spawn(async move {
            let chunk = vec![0u8; 65536];
            loop {
                if let Err(e) = server.write_all(&chunk).await {
                    return e;
                }
            }
        });
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!writer.is_finished(), "write never parked");

        closer.close();
        let error = tokio::time::timeout(Duration::from_secs(2), writer)
            .await
            .expect("write still parked after close")
            .unwrap();
        assert_eq!(error.kind(), ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn shutdown_after_close_sends_fin() {
        let (server, mut client) = connected_pair().await;
        let closer = ClientCloser::default();
        let mut server = closer.guard(server);

        closer.close();
        server.shutdown().await.unwrap();
        assert_eq!(client.read(&mut [0u8; 1]).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn close_releases_parked_read() {
        let (server, _client) = connected_pair().await;
        let closer = ClientCloser::default();
        let mut server = closer.guard(server);

        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            server.read(&mut buf).await
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!reader.is_finished(), "read never parked");

        closer.close();
        let read = tokio::time::timeout(Duration::from_secs(2), reader)
            .await
            .expect("read still parked after close")
            .unwrap();
        assert_eq!(read.unwrap(), 0);
    }
}
