#![feature(type_alias_impl_trait, try_blocks)]
mod client;
mod common;
mod error;
mod session;
mod session_handle;
mod stream;

use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use client::{ConnectionOptions, PostgresClient};
use rustls::server::NoClientAuth;
use rustls::ServerConfig;
use session::PostgresSession;
use session_handle::PostgresSessionHandle;
use tokio::net::TcpListener;
use tracing::*;
use warpgate_common::{
    ResolveServerCert, Target, TargetOptions, TlsCertificateAndPrivateKey, TlsCertificateBundle,
    TlsPrivateKey,
};
use warpgate_core::{ProtocolServer, Services, SessionStateInit, TargetTestError};

pub struct PostgresProtocolServer {
    services: Services,
}

impl PostgresProtocolServer {
    pub async fn new(services: &Services) -> Result<Self> {
        Ok(PostgresProtocolServer {
            services: services.clone(),
        })
    }
}

#[async_trait]
impl ProtocolServer for PostgresProtocolServer {
    async fn run(self, address: SocketAddr) -> Result<()> {
        let certificate_and_key = {
            let config = self.services.config.lock().await;
            let certificate_path = config
                .paths_relative_to
                .join(&config.store.mysql.certificate);
            let key_path = config.paths_relative_to.join(&config.store.mysql.key);

            TlsCertificateAndPrivateKey {
                certificate: TlsCertificateBundle::from_file(&certificate_path)
                    .await
                    .with_context(|| {
                        format!("reading SSL private key from '{}'", key_path.display())
                    })?,
                private_key: TlsPrivateKey::from_file(&key_path).await.with_context(|| {
                    format!(
                        "reading SSL certificate from '{}'",
                        certificate_path.display()
                    )
                })?,
            }
        };

        let tls_config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_client_cert_verifier(Arc::new(NoClientAuth))
                .with_cert_resolver(Arc::new(ResolveServerCert(Arc::new(
                    certificate_and_key.into(),
                ))));

        info!(?address, "Listening");
        let listener = TcpListener::bind(address).await?;
        loop {
            let (stream, remote_address) = listener.accept().await?;
            let tls_config = tls_config.clone();
            let services = self.services.clone();
            tokio::spawn(async move {
                let (session_handle, mut abort_rx) = PostgresSessionHandle::new();

                let server_handle = services
                    .state
                    .lock()
                    .await
                    .register_session(
                        &crate::common::PROTOCOL_NAME,
                        SessionStateInit {
                            remote_address: Some(remote_address),
                            handle: Box::new(session_handle),
                        },
                    )
                    .await?;

                let session = PostgresSession::new(
                    server_handle,
                    services,
                    stream,
                    tls_config,
                    remote_address,
                )
                .await;

                let span = session.make_logging_span();
                tokio::select! {
                    result = session.run().instrument(span) => match result {
                        Ok(_) => info!("Session ended"),
                        Err(e) => error!(error=%e, "Session failed"),
                    },
                    _ = abort_rx.recv() => {
                        warn!("Session aborted by admin");
                    },
                }

                Ok::<(), anyhow::Error>(())
            });
        }
    }

    async fn test_target(&self, target: Target) -> Result<(), TargetTestError> {
        let TargetOptions::Postgres(options) = target.options else {
            return Err(TargetTestError::Misconfigured(
                "Not a PostgreSQL target".to_owned(),
            ));
        };
        let mut conn_options = ConnectionOptions::default();
        conn_options
            .parameters
            .insert("database".into(), "postgres".into());
        PostgresClient::connect(&options, conn_options)
            .await
            .map_err(|e| TargetTestError::ConnectionError(format!("{e}")))?;
        Ok(())
    }
}

impl Debug for PostgresProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PostgresProtocolServer")
    }
}
