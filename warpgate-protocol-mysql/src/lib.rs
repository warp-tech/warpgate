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
use client::{ConnectionOptions, MySqlClient};
use rustls::server::NoClientAuth;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tracing::*;
use warpgate_common::{
    ResolveServerCert, Target, TargetOptions, TlsCertificateAndPrivateKey, TlsCertificateBundle,
    TlsPrivateKey,
};
use warpgate_core::{ProtocolServer, Services, SessionStateInit, TargetTestError};

use crate::session::MySqlSession;
use crate::session_handle::MySqlSessionHandle;

pub struct MySQLProtocolServer {
    services: Services,
}

impl MySQLProtocolServer {
    pub async fn new(services: &Services) -> Result<Self> {
        Ok(MySQLProtocolServer {
            services: services.clone(),
        })
    }
}

#[async_trait]
impl ProtocolServer for MySQLProtocolServer {
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

        let tls_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(NoClientAuth::new())
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
                let (session_handle, mut abort_rx) = MySqlSessionHandle::new();

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

                let session =
                    MySqlSession::new(server_handle, services, stream, tls_config, remote_address)
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
        let TargetOptions::MySql(options) = target.options else {
            return Err(TargetTestError::Misconfigured(
                "Not a MySQL target".to_owned(),
            ));
        };
        MySqlClient::connect(&options, ConnectionOptions::default())
            .await
            .map_err(|e| TargetTestError::ConnectionError(format!("{e}")))?;
        Ok(())
    }
}

impl Debug for MySQLProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MySQLProtocolServer")
    }
}
