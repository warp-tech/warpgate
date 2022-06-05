#![feature(type_alias_impl_trait, let_else, try_blocks)]
mod api;
use anyhow::{Context, Result};
use async_trait::async_trait;
use poem::listener::{Listener, RustlsCertificate, RustlsConfig, TcpListener};
use poem::{Route, Server};
use std::fmt::Debug;
use std::net::SocketAddr;
use tracing::*;
use warpgate_common::{ProtocolServer, Services, Target, TargetTestError};

#[derive(Clone)]
pub struct HTTPProtocolServer {
    services: Services,
}

impl HTTPProtocolServer {
    pub async fn new(services: &Services) -> Result<Self> {
        Ok(HTTPProtocolServer {
            services: services.clone(),
        })
    }
}

#[async_trait]
impl ProtocolServer for HTTPProtocolServer {
    async fn run(self, address: SocketAddr) -> Result<()> {
        let app = Route::new().nest_no_strip("/", api::test_endpoint);

        let (certificate, key) = {
            let config = self.services.config.lock().await;
            let certificate_path = config
                .paths_relative_to
                .join(&config.store.web_admin.certificate);
            let key_path = config.paths_relative_to.join(&config.store.web_admin.key);

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

        info!(?address, "Listening");
        Server::new(TcpListener::bind(address).rustls(
            RustlsConfig::new().fallback(RustlsCertificate::new().cert(certificate).key(key)),
        ))
        .run(app)
        .await
        .context("Failed to start admin server")
    }

    async fn test_target(self, target: Target) -> Result<(), TargetTestError> {
        Ok(())
    }
}

impl Debug for HTTPProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SSHProtocolServer")
    }
}
