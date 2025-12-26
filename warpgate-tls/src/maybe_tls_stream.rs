use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

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

pub trait UpgradableStream<T>
where
    Self: Sized,
    T: AsyncRead + AsyncWrite + Unpin,
{
    type UpgradeConfig;
    fn upgrade(
        self,
        config: Self::UpgradeConfig,
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
    pub fn new(stream: S) -> Self {
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
    ) -> Result<Self, MaybeTlsStreamError> {
        if let Self::Raw(stream) = std::mem::replace(&mut self, Self::Upgrading) {
            let stream = stream.upgrade(tls_config).await?;
            Ok(MaybeTlsStream::Tls(stream))
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
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Tls(tls) => Pin::new(tls).poll_read(cx, buf),
            MaybeTlsStream::Raw(stream) => Pin::new(stream).poll_read(cx, buf),
            _ => unreachable!(),
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
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Tls(tls) => Pin::new(tls).poll_write(cx, buf),
            MaybeTlsStream::Raw(stream) => Pin::new(stream).poll_write(cx, buf),
            _ => unreachable!(),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Tls(tls) => Pin::new(tls).poll_flush(cx),
            MaybeTlsStream::Raw(stream) => Pin::new(stream).poll_flush(cx),
            _ => unreachable!(),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Tls(tls) => Pin::new(tls).poll_shutdown(cx),
            MaybeTlsStream::Raw(stream) => Pin::new(stream).poll_shutdown(cx),
            _ => unreachable!(),
        }
    }
}

impl<S> UpgradableStream<tokio_rustls::client::TlsStream<S>> for S
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    type UpgradeConfig = (ServerName<'static>, Arc<ClientConfig>);

    async fn upgrade(
        self,
        config: Self::UpgradeConfig,
    ) -> Result<tokio_rustls::client::TlsStream<S>, MaybeTlsStreamError> {
        let (domain, tls_config) = config;
        let connector = tokio_rustls::TlsConnector::from(tls_config);
        Ok(connector.connect(domain, self).await?)
    }
}

impl<S> UpgradableStream<tokio_rustls::server::TlsStream<S>> for S
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    type UpgradeConfig = Arc<ServerConfig>;

    async fn upgrade(
        self,
        tls_config: Self::UpgradeConfig,
    ) -> Result<tokio_rustls::server::TlsStream<S>, MaybeTlsStreamError> {
        let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
        Ok(acceptor.accept(self).await?)
    }
}
