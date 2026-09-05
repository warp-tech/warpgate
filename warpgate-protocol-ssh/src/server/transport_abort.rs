//! Closing the client transport when nothing politer can reach the client.
//!
//! Everything Warpgate's teardown says to a client goes through russh's
//! bounded message queue, which russh drains only while it has no data
//! pending. A client that has stopped reading blocks all of it, and russh's
//! own loop parks in a socket write to that client, so no timer inside it is
//! ever armed.
//!
//! The connection is then only reachable from underneath. Warpgate owns the
//! stream before handing it to `russh::server::run_stream`, so it can fail
//! the write out from under russh. `shutdown(2)` on the descriptor would do
//! the same, but `unsafe_code` is denied workspace-wide.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use futures::task::AtomicWaker;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
struct AbortState {
    aborted: AtomicBool,
    /// One per direction. russh drives both halves from a single task today,
    /// but a waker that only covers the direction polled most recently would
    /// be a silent trap for whoever changes that.
    read_waker: AtomicWaker,
    write_waker: AtomicWaker,
}

impl AbortState {
    fn aborted(&self) -> bool {
        self.aborted.load(Ordering::Acquire)
    }
}

fn aborted_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "connection closed by Warpgate",
    )
}

/// Ends the connection [`AbortableStream`] wraps, from outside the task using
/// it. Cheap to clone and safe to call more than once.
#[derive(Clone)]
pub struct TransportAbort(Arc<AbortState>);

impl TransportAbort {
    /// Fails every future read and write on the stream, and wakes whichever
    /// one is parked right now so it finds out immediately rather than
    /// whenever the client next moves.
    pub fn abort(&self) {
        self.0.aborted.store(true, Ordering::Release);
        self.0.read_waker.wake();
        self.0.write_waker.wake();
    }

    #[cfg(test)]
    fn is_aborted(&self) -> bool {
        self.0.aborted()
    }
}

/// A stream that can be made to fail from elsewhere.
pub struct AbortableStream<S> {
    inner: S,
    state: Arc<AbortState>,
}

impl<S> AbortableStream<S> {
    pub fn new(inner: S) -> (Self, TransportAbort) {
        let state = Arc::new(AbortState::default());
        (
            Self {
                inner,
                state: Arc::clone(&state),
            },
            TransportAbort(state),
        )
    }

    /// Registers first, then checks. The other order would drop an abort that
    /// landed between the two, leaving the caller parked on a stream nobody
    /// will wake again.
    fn stopped(&self, waker: &AtomicWaker, cx: &Context<'_>) -> bool {
        waker.register(cx.waker());
        self.state.aborted()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for AbortableStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.stopped(&self.state.read_waker, cx) {
            return Poll::Ready(Err(aborted_error()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for AbortableStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.stopped(&self.state.write_waker, cx) {
            return Poll::Ready(Err(aborted_error()));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if self.stopped(&self.state.write_waker, cx) {
            return Poll::Ready(Err(aborted_error()));
        }
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    /// Forwarded rather than defaulted: answering `false` here would quietly
    /// turn russh's vectored writes into one syscall per buffer.
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.stopped(&self.state.write_waker, cx) {
            return Poll::Ready(Err(aborted_error()));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    /// An aborted shutdown reports success. The caller's intent -- stop using
    /// this stream -- has already been met, and returning an error here only
    /// turns an orderly unwind into a logged failure.
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.state.aborted() {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::{AbortableStream, TransportAbort};

    #[tokio::test]
    async fn a_write_parked_on_a_full_peer_is_released_by_an_abort() {
        // A duplex with a small buffer and nobody reading is the same shape as
        // the case this exists for: a socket whose peer has stopped reading.
        let (near, _far) = duplex(64);
        let (mut stream, abort) = AbortableStream::new(near);

        let writer = tokio::spawn(async move {
            // Larger than the buffer, so this cannot complete on its own.
            stream.write_all(&[0u8; 4096]).await
        });

        // Asserted first: without it a writer that had already failed for some
        // other reason would make the rest of this test prove nothing.
        assert!(!abort.is_aborted());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), async {})
                .await
                .is_ok()
        );

        abort.abort();

        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), writer)
            .await
            .map(|joined| joined.map(|result| result.map_err(|e| e.kind())));
        assert_eq!(
            outcome.map(|r| r.ok()),
            Ok(Some(Err(ErrorKind::ConnectionAborted))),
            "the parked write was not released by the abort"
        );
    }

    #[tokio::test]
    async fn an_abort_stops_reads_too() {
        let (near, mut far) = duplex(64);
        let (mut stream, abort) = AbortableStream::new(near);
        far.write_all(b"hello").await.ok();

        let mut buf = [0u8; 5];
        assert_eq!(stream.read_exact(&mut buf).await.ok(), Some(5));

        abort.abort();
        let after = stream.read(&mut buf).await;
        assert_eq!(
            after.map_err(|e| e.kind()).err(),
            Some(ErrorKind::ConnectionAborted),
            "reads kept working after the transport was closed"
        );
    }

    #[tokio::test]
    async fn an_untouched_stream_behaves_normally() {
        // The other direction: without this, aborting everything always would
        // pass the two tests above.
        let (near, mut far) = duplex(64);
        let (mut stream, _abort) = AbortableStream::new(near);

        stream.write_all(b"ping").await.ok();
        let mut buf = [0u8; 4];
        assert_eq!(far.read_exact(&mut buf).await.ok(), Some(4));
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn aborting_twice_is_harmless() {
        let (near, _far) = duplex(64);
        let (_stream, abort) = AbortableStream::new(near);
        abort.abort();
        let second: TransportAbort = abort.clone();
        second.abort();
        assert!(abort.is_aborted());
    }
}
