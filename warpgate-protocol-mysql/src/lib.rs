#![feature(type_alias_impl_trait, let_else, try_blocks)]
mod client;
mod common;
mod error;
mod session;
mod stream;
mod tls;
use std::fmt::Debug;
use std::net::SocketAddr;

use anyhow::{Context, Result};
use async_trait::async_trait;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tracing::*;
use warpgate_common::{ProtocolServer, Services, Target, TargetTestError};

use crate::session::MySqlSession;
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
            let (stream, addr) = listener.accept().await?;
            let tls_config = tls_config.clone();
            tokio::spawn(async move {
                match MySqlSession::new(stream, tls_config).run().await {
                    Ok(_) => info!(?addr, "Session finished"),
                    Err(e) => error!(?addr, error=%e, "Session failed"),
                }
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
