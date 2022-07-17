#![feature(type_alias_impl_trait, let_else, try_blocks)]
mod client;
mod common;
mod error;
mod session;
mod session_handle;
mod stream;
mod tls;
use std::fmt::Debug;
use std::net::SocketAddr;

use anyhow::{Context, Result};
use async_trait::async_trait;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tracing::*;
use warpgate_common::{ProtocolServer, Services, SessionStateInit, Target, TargetTestError};

use crate::session::MySqlSession;
use crate::session_handle::MySqlSessionHandle;
use crate::tls::FromCertificateAndKey;

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
        let (certificate, key) = {
            let config = self.services.config.lock().await;
            let certificate_path = config
                .paths_relative_to
                .join(&config.store.mysql.certificate);
            let key_path = config.paths_relative_to.join(&config.store.mysql.key);

            (
                std::fs::read(&certificate_path).with_context(|| {
                    format!(
                        "reading SSL certificate from '{}'",
                        certificate_path.display()
                    )
                })?,
                std::fs::read(&key_path).with_context(|| {
                    format!("reading SSL private key from '{}'", key_path.display())
                })?,
            )
        };

        let tls_config = ServerConfig::try_from_certificate_and_key(certificate, key)?;

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

                let session = MySqlSession::new(server_handle, services, stream, tls_config).await;
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

    async fn test_target(self, _target: Target) -> Result<(), TargetTestError> {
        Ok(())
    }
}

impl Debug for MySQLProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MySQLProtocolServer")
    }
}
