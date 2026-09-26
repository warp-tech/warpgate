use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(thiserror::Error, Debug)]
pub enum MaybeTlsStreamError {
    #[error("stream is already upgraded")]
    AlreadyUpgraded,
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
}

/// A TLS client stream produced by upgrading `S`.
pub type ClientTlsStream<S> = tokio_rustls::client::TlsStream<PrefixedStream<S>>;
/// A TLS server stream produced by upgrading `S`.
pub type ServerTlsStream<S> = tokio_rustls::server::TlsStream<PrefixedStream<S>>;

/// Replays a buffer and then continues with the underlying stream.
///
/// Protocols with a midstream TLS upgrade can read a chunk off the socket
/// that already contains the start of the TLS handshake (e.g. a MySQL
/// client may send its ClientHello right behind the SSLRequest packet).
/// `MaybeTlsStream::upgrade` feeds those leftover bytes back into the TLS
/// layer through this wrapper (#1421).
pub struct PrefixedStream<S> {
    prefix: Bytes,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub const fn new(inner: S, prefix: Bytes) -> Self {
        Self { prefix, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        let this = self.get_mut();
        if !this.prefix.is_empty() {
            let n = this.prefix.len().min(buf.remaining());
            buf.put_slice(&this.prefix.split_to(n));
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub trait UpgradableStream<T>
where
    Self: Sized,
    T: AsyncRead + AsyncWrite + Unpin,
{
    type UpgradeConfig;
    /// Upgrade to TLS; `leftover` is data already read off the stream that
    /// belongs to the TLS handshake.
    fn upgrade(
        self,
        config: Self::UpgradeConfig,
        leftover: Bytes,
    ) -> impl Future<Output = Result<T, MaybeTlsStreamError>> + Send;
}

pub enum MaybeTlsStream<S, TS>
where
    S: AsyncRead + AsyncWrite + Unpin + UpgradableStream<TS>,
    TS: AsyncRead + AsyncWrite + Unpin,
{
    Tls(TS),
    Raw(S),
    Upgrading,
}

impl<S, TS> MaybeTlsStream<S, TS>
where
    S: AsyncRead + AsyncWrite + Unpin + UpgradableStream<TS>,
    TS: AsyncRead + AsyncWrite + Unpin,
{
    pub const fn new(stream: S) -> Self {
        Self::Raw(stream)
    }
}

impl<S, TS> MaybeTlsStream<S, TS>
where
    S: AsyncRead + AsyncWrite + Unpin + UpgradableStream<TS>,
    TS: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn upgrade(
        mut self,
        tls_config: S::UpgradeConfig,
        leftover: Bytes,
    ) -> Result<Self, MaybeTlsStreamError> {
        if let Self::Raw(stream) = std::mem::replace(&mut self, Self::Upgrading) {
            let stream = stream.upgrade(tls_config, leftover).await?;
            Ok(Self::Tls(stream))
        } else {
            Err(MaybeTlsStreamError::AlreadyUpgraded)
        }
    }
}

impl<S, TS> AsyncRead for MaybeTlsStream<S, TS>
where
    S: AsyncRead + AsyncWrite + Unpin + UpgradableStream<TS>,
    TS: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        match self.get_mut() {
            Self::Tls(tls) => Pin::new(tls).poll_read(cx, buf),
            Self::Raw(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Upgrading => unreachable!(),
        }
    }
}

impl<S, TS> AsyncWrite for MaybeTlsStream<S, TS>
where
    S: AsyncRead + AsyncWrite + Unpin + UpgradableStream<TS>,
    TS: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tls(tls) => Pin::new(tls).poll_write(cx, buf),
            Self::Raw(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Upgrading => unreachable!(),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tls(tls) => Pin::new(tls).poll_flush(cx),
            Self::Raw(stream) => Pin::new(stream).poll_flush(cx),
            Self::Upgrading => unreachable!(),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tls(tls) => Pin::new(tls).poll_shutdown(cx),
            Self::Raw(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Upgrading => unreachable!(),
        }
    }
}

impl<S> UpgradableStream<tokio_rustls::client::TlsStream<PrefixedStream<S>>> for S
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    type UpgradeConfig = (ServerName<'static>, Arc<ClientConfig>);

    async fn upgrade(
        self,
        config: Self::UpgradeConfig,
        leftover: Bytes,
    ) -> Result<tokio_rustls::client::TlsStream<PrefixedStream<S>>, MaybeTlsStreamError> {
        let (domain, tls_config) = config;
        let connector = tokio_rustls::TlsConnector::from(tls_config);
        Ok(connector
            .connect(domain, PrefixedStream::new(self, leftover))
            .await?)
    }
}

impl<S> UpgradableStream<tokio_rustls::server::TlsStream<PrefixedStream<S>>> for S
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    type UpgradeConfig = Arc<ServerConfig>;

    async fn upgrade(
        self,
        tls_config: Self::UpgradeConfig,
        leftover: Bytes,
    ) -> Result<tokio_rustls::server::TlsStream<PrefixedStream<S>>, MaybeTlsStreamError> {
        let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
        Ok(acceptor.accept(PrefixedStream::new(self, leftover)).await?)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn prefixed_stream_replays_prefix_before_inner_data() {
        let (mut near, far) = tokio::io::duplex(64);
        near.write_all(b" world").await.unwrap();

        let mut stream = PrefixedStream::new(far, Bytes::from_static(b"hello"));

        let mut buf = [0u8; 11];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello world");
    }

    #[tokio::test]
    async fn prefixed_stream_serves_prefix_across_small_reads() {
        let (_near, far) = tokio::io::duplex(64);
        let mut stream = PrefixedStream::new(far, Bytes::from_static(b"abcd"));

        let mut buf = [0u8; 3];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"abc");
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"d");
    }

    #[tokio::test]
    async fn prefixed_stream_writes_pass_through() {
        let (mut near, far) = tokio::io::duplex(64);
        let mut stream = PrefixedStream::new(far, Bytes::from_static(b"unused"));

        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = [0u8; 4];
        near.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }
}
