use futures::task::{Context, Poll};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::pin::Pin;
use std::process::Command;
use tokio;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// A type to implement either a TCP socket, or proxying through an external command.
pub enum Stream {
    #[allow(missing_docs)]
    Child(std::process::Child),
    #[allow(missing_docs)]
    Tcp(TcpStream),
}

impl Stream {
    /// Connect a direct TCP stream (as opposed to a proxied one).
    pub async fn tcp_connect(addr: &SocketAddr) -> Result<Stream, tokio::io::Error> {
        TcpStream::connect(addr).await.map(Stream::Tcp)
    }
    /// Connect through a proxy command.
    pub fn proxy_connect(cmd: &str, args: &[&str]) -> Result<Stream, std::io::Error> {
        Ok(Stream::Child(Command::new(cmd).args(args).spawn()?))
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<Result<(), tokio::io::Error>> {
        match *self {
            Stream::Child(ref mut c) => {
                let n = c.stdout.as_mut().unwrap().read(buf.initialize_unfilled())?;
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Stream::Tcp(ref mut t) => AsyncRead::poll_read(Pin::new(t), cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, tokio::io::Error>> {
        match *self {
            Stream::Child(ref mut c) => Poll::Ready(c.stdin.as_mut().unwrap().write(buf)),
            Stream::Tcp(ref mut t) => AsyncWrite::poll_write(Pin::new(t), cx, buf),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<(), tokio::io::Error>> {
        match *self {
            Stream::Child(_) => Poll::Ready(Ok(())),
            Stream::Tcp(ref mut t) => AsyncWrite::poll_flush(Pin::new(t), cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<(), tokio::io::Error>> {
        match *self {
            Stream::Child(_) => Poll::Ready(Ok(())),
            Stream::Tcp(ref mut t) => AsyncWrite::poll_shutdown(Pin::new(t), cx),
        }
    }
}
