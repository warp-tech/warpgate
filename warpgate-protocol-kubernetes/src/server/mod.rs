use std::sync::Arc;

use anyhow::{Context, Result};
use poem::listener::Listener;
use poem::{EndpointExt, Route, Server};
use rustls::ServerConfig;
use tracing::info;
use warpgate_common::ListenEndpoint;
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_core::Services;
use warpgate_tls::{SingleCertResolver, TlsCertificateAndPrivateKey};

use crate::correlator::RequestCorrelator;
use crate::server::client_certs::{AcceptAnyClientCert, CertificateCapturingAcceptor};
use crate::server::handlers::handle_api_request;

mod auth;
mod client_certs;
mod handlers;

use client_certs::CertificateExtractorMiddleware;

pub async fn run_server(
    services: Services,
    address: ListenEndpoint,
    tls: Vec<TlsCertificateAndPrivateKey>,
) -> Result<()> {
    let correlator = RequestCorrelator::new(&services);

    let app = Route::new()
        .at("/:target_name/*path", handle_api_request)
        .with(poem::middleware::Cors::new())
        .with(CertificateExtractorMiddleware)
        .data(UnauthenticatedRequestContext::new(services.clone()).await)
        .data(correlator);

    info!(?address, "Kubernetes protocol listening");

    let certificate_and_key = tls
        .into_iter()
        .next()
        .context("Kubernetes requires a TLS certificate and key")?;

    // Create TLS configuration with client certificate verification
    let tls_config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| anyhow::anyhow!("Failed to configure TLS protocol versions: {e}"))?
    .with_client_cert_verifier(Arc::new(AcceptAnyClientCert))
    .with_cert_resolver(Arc::new(SingleCertResolver::new(
        certificate_and_key.clone(),
    )));

    let tcp_acceptor = address.poem_listener()?.into_acceptor().await?;
    let cert_capturing_acceptor = CertificateCapturingAcceptor::new(tcp_acceptor, tls_config);

    Server::new_with_acceptor(cert_capturing_acceptor)
        .run(app)
        .await
        .context("Kubernetes server error")?;

    Ok(())
}
