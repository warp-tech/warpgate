use std::sync::Arc;

use anyhow::{Context, Result};
use poem::listener::Listener;
use poem::{EndpointExt, Route, Server};
use rustls::ServerConfig;
use tracing::*;
use warpgate_common::ListenEndpoint;
use warpgate_core::Services;
use warpgate_tls::{
    SingleCertResolver, TlsCertificateAndPrivateKey, TlsCertificateBundle, TlsPrivateKey,
};

use crate::correlator::RequestCorrelator;
use crate::server::client_certs::{AcceptAnyClientCert, CertificateCapturingAcceptor};
use crate::server::handlers::handle_api_request;

mod auth;
mod client_certs;
mod handlers;

use client_certs::CertificateExtractorMiddleware;

pub async fn run_server(services: Services, address: ListenEndpoint) -> Result<()> {
    let state = services.state.clone();
    let auth_state_store = services.auth_state_store.clone();
    let recordings = services.recordings.clone();

    let correlator = RequestCorrelator::new(&services);

    let app = Route::new()
        .at("/:target_name/*path", handle_api_request)
        .with(poem::middleware::Cors::new())
        .with(CertificateExtractorMiddleware)
        .data(state)
        .data(auth_state_store)
        .data(recordings)
        .data(services.clone())
        .data(correlator);

    info!(?address, "Kubernetes protocol listening");

    let certificate_and_key = {
        let config = services.config.lock().await;
        let certificate_path = services
            .global_params
            .paths_relative_to()
            .join(&config.store.kubernetes.certificate);
        let key_path = services
            .global_params
            .paths_relative_to()
            .join(&config.store.kubernetes.key);

        TlsCertificateAndPrivateKey {
            certificate: TlsCertificateBundle::from_file(&certificate_path)
                .await
                .with_context(|| {
                    format!(
                        "reading TLS certificate from '{}'",
                        certificate_path.display()
                    )
                })?,
            private_key: TlsPrivateKey::from_file(&key_path).await.with_context(|| {
                format!("reading TLS private key from '{}'", key_path.display())
            })?,
        }
    };

    // Create TLS configuration with client certificate verification
    let tls_config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| anyhow::anyhow!("Failed to configure TLS protocol versions: {}", e))?
    .with_client_cert_verifier(Arc::new(AcceptAnyClientCert))
    .with_cert_resolver(Arc::new(SingleCertResolver::new(
        certificate_and_key.clone(),
    )));

    let tcp_acceptor = address.poem_listener().await?.into_acceptor().await?;
    let cert_capturing_acceptor = CertificateCapturingAcceptor::new(tcp_acceptor, tls_config);

    Server::new_with_acceptor(cert_capturing_acceptor)
        .run(app)
        .await
        .context("Kubernetes server error")?;

    Ok(())
}
