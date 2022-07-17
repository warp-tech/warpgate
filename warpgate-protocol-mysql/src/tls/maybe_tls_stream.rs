use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

use async_trait::async_trait;
use rustls::{ClientConfig, ServerConfig, ServerName};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::*;

#[derive(thiserror::Error, Debug)]
pub enum MaybeTlsStreamError {
    #[error("already upgraded")]
    AlreadyUpgraded,
    #[error("I/O")]
    Io(#[from] std::io::Error),
}

#[async_trait]
pub trait UpgradableStream<T>
where
    Self: Sized,
    T: AsyncRead + AsyncWrite + Unpin,
{
    type UpgradeConfig;
    async fn upgrade(self, config: Self::UpgradeConfig) -> Result<T, MaybeTlsStreamError>;
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

#[async_trait]
impl<S> UpgradableStream<tokio_rustls::client::TlsStream<S>> for S
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    type UpgradeConfig = (ServerName, Arc<ClientConfig>);

    async fn upgrade(
        mut self,
        config: Self::UpgradeConfig,
    ) -> Result<tokio_rustls::client::TlsStream<S>, MaybeTlsStreamError> {
        let (domain, tls_config) = config;
        let connector = tokio_rustls::TlsConnector::from(tls_config);
        Ok(connector.connect(domain, self).await?)
    }
}

#[async_trait]
impl<S> UpgradableStream<tokio_rustls::server::TlsStream<S>> for S
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    type UpgradeConfig = Arc<ServerConfig>;

    async fn upgrade(
        mut self,
        tls_config: Self::UpgradeConfig,
    ) -> Result<tokio_rustls::server::TlsStream<S>, MaybeTlsStreamError> {
        let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
        Ok(acceptor.accept(self).await?)
    }
}
