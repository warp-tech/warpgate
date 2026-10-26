use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use poem::http::uri::Scheme;
use poem::listener::Acceptor;
use poem::web::RemoteAddr;
use poem::{Addr, Endpoint, Middleware, Request};
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use rustls::server::ClientHello;
use tokio::time::timeout;
use tokio_rustls::LazyConfigAcceptor;
use tokio_rustls::server::TlsStream;
use warpgate_common::helpers::concurrent_acceptor::ConcurrentAcceptor;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Accepts TLS connections with a dynamic per-connection rustls config and a per-connection
/// mTLS verifier procedure
///
/// It lets `verify` smuggle connection-specific data (e.g. mTLS peer cert) through the peer's RemoteAddr
/// since this is the only thing that is readable in a poem request handler
pub fn extracting_mtls_acceptor<A, S, V, Fut>(
    inner: A,
    config_for: S,
    verify: V,
) -> ConcurrentAcceptor<TlsStream<A::Io>>
where
    A: Acceptor + 'static,
    S: Fn(&ClientHello<'_>) -> Arc<ServerConfig> + Send + Sync + 'static,
    V: Fn(Option<CertificateDer<'static>>, RemoteAddr) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = anyhow::Result<RemoteAddr>> + Send + 'static,
{
    let config_for = Arc::new(config_for);
    let verify = Arc::new(verify);
    ConcurrentAcceptor::new(inner, move |(stream, local_addr, remote_addr, _)| {
        let config_for = config_for.clone();
        let verify = verify.clone();
        async move {
            let tls_stream = timeout(HANDSHAKE_TIMEOUT, async {
                let start = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream)
                    .await
                    .context("reading TLS ClientHello")?;
                let config = config_for(&start.client_hello());
                start
                    .into_stream(config)
                    .await
                    .context("TLS handshake failed")
            })
            .await
            .context("TLS handshake timed out")??;

            let client_certificate = tls_stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .map(|cert| cert.clone().into_owned());

            let remote_addr = verify(client_certificate, remote_addr).await?;
            Ok((tls_stream, local_addr, remote_addr, Scheme::HTTPS))
        }
    })
}

pub fn annotate_remote_addr(
    remote_addr: &RemoteAddr,
    scheme: &'static str,
    payload: &str,
) -> RemoteAddr {
    let addr = match &remote_addr.0 {
        Addr::SocketAddr(addr) => addr.to_string(),
        other => other.to_string(),
    };
    RemoteAddr(Addr::Custom(scheme, format!("{addr}|{payload}").into()))
}

pub fn remote_addr_annotation<'a>(remote_addr: &'a RemoteAddr, scheme: &str) -> Option<&'a str> {
    match &remote_addr.0 {
        Addr::Custom(found, value) if *found == scheme => {
            value.split_once('|').map(|(_, payload)| payload)
        }
        _ => None,
    }
}

/// Middleware that extracts and parses RemoteAddr annotations
pub struct RemoteAddrExtension<F> {
    parse: Arc<F>,
}

impl<F> RemoteAddrExtension<F> {
    pub fn new(parse: F) -> Self {
        Self {
            parse: Arc::new(parse),
        }
    }
}

impl<E, F, T> Middleware<E> for RemoteAddrExtension<F>
where
    E: Endpoint,
    F: Fn(&RemoteAddr) -> Option<T> + Send + Sync + 'static,
    T: Clone + Send + Sync + 'static,
{
    type Output = RemoteAddrExtensionEndpoint<E, F>;

    fn transform(&self, ep: E) -> Self::Output {
        RemoteAddrExtensionEndpoint {
            inner: ep,
            parse: self.parse.clone(),
        }
    }
}

pub struct RemoteAddrExtensionEndpoint<E, F> {
    inner: E,
    parse: Arc<F>,
}

impl<E, F, T> Endpoint for RemoteAddrExtensionEndpoint<E, F>
where
    E: Endpoint,
    F: Fn(&RemoteAddr) -> Option<T> + Send + Sync + 'static,
    T: Clone + Send + Sync + 'static,
{
    type Output = E::Output;

    async fn call(&self, mut req: Request) -> poem::Result<Self::Output> {
        if let Some(value) = (self.parse)(req.remote_addr()) {
            req.extensions_mut().insert(value);
        }
        self.inner.call(req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn annotation_round_trip() {
        let plain = RemoteAddr(Addr::SocketAddr("127.0.0.1:4000".parse().unwrap()));
        let annotated = annotate_remote_addr(&plain, "thing", "key:value");
        assert_eq!(
            remote_addr_annotation(&annotated, "thing"),
            Some("key:value")
        );
        assert_eq!(remote_addr_annotation(&annotated, "other"), None);
        assert_eq!(remote_addr_annotation(&plain, "thing"), None);
        // The address survives for raw_remote_ip
        assert!(matches!(
            &annotated.0,
            Addr::Custom("thing", value) if value.starts_with("127.0.0.1:4000|")
        ));
    }
}
