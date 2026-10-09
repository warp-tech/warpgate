use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use futures::FutureExt;
use futures::future::BoxFuture;
use poem::listener::Listener;
use poem::{EndpointExt, Route, Server};
use rustls::ServerConfig;
use tracing::info;
use warpgate_common::helpers::proxy_protocol::MaybeProxyProtocolAcceptor;
use warpgate_common::{ListenEndpoint, TargetKubernetesOptions};
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_core::Services;
use warpgate_tls::{
    PossessionOnlyClientCertVerifier, SingleCertResolver, TlsCertificateAndPrivateKey,
};

use crate::correlator::RequestCorrelator;
use crate::server::client_certs::{certificate_capturing_acceptor, client_certificate_extension};
use crate::server::handlers::handle_api_request;

pub mod auth;
mod client_certs;
mod handlers;

use warpgate_common_http::errors::render_errors;

/// Cached client reuse time limit, itself limited by the credential lifetime (e.g. EKS token)
const UPSTREAM_CLIENT_MAX_AGE: Duration = Duration::from_mins(5);

/// Key = target ID
type UpstreamClientCache =
    warpgate_common_cache::Cache<uuid::Uuid, TargetKubernetesOptions, reqwest::Client>;

pub async fn bind_server(
    services: Services,
    address: ListenEndpoint,
    proxy_protocol: bool,
    tls: Vec<TlsCertificateAndPrivateKey>,
) -> Result<BoxFuture<'static, Result<()>>> {
    let correlator = RequestCorrelator::new(&services);
    let upstream_clients = UpstreamClientCache::new(UPSTREAM_CLIENT_MAX_AGE);

    let app = Route::new()
        .at("/", handle_api_request)
        .at("/*path", handle_api_request)
        .with(poem::middleware::Cors::new())
        .with(client_certificate_extension())
        .data(UnauthenticatedRequestContext::new(services.clone()).await)
        .data(correlator)
        .data(upstream_clients)
        .around(render_errors);

    info!(?address, "Kubernetes protocol listening");

    let certificate_and_key = tls
        .into_iter()
        .next()
        .context("Kubernetes requires a TLS certificate and key")?;

    // Create TLS configuration with client certificate verification. The
    // verifier shares this provider so it validates handshake signatures with
    // the same algorithms the server negotiates.
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let tls_config = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow::anyhow!("Failed to configure TLS protocol versions: {e}"))?
        .with_client_cert_verifier(Arc::new(PossessionOnlyClientCertVerifier::optional(
            provider,
        )))
        .with_cert_resolver(Arc::new(SingleCertResolver::new(
            certificate_and_key.clone(),
        )));

    let tcp_acceptor = address.poem_listener()?.into_acceptor().await?;
    let tcp_acceptor = MaybeProxyProtocolAcceptor::new(tcp_acceptor, proxy_protocol);
    let cert_capturing_acceptor = certificate_capturing_acceptor(tcp_acceptor, tls_config);

    Ok(async move {
        Server::new_with_acceptor(cert_capturing_acceptor)
            .run(app)
            .await
            .context("Kubernetes server error")?;
        Ok(())
    }
    .boxed())
}
