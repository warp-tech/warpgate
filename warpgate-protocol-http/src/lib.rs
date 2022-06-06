#![feature(type_alias_impl_trait, let_else, try_blocks)]
mod api;
mod proxy;
use anyhow::{Context, Result};
use async_trait::async_trait;
use poem::endpoint::{EmbeddedFileEndpoint, EmbeddedFilesEndpoint};
use poem::listener::{Listener, RustlsCertificate, RustlsConfig, TcpListener};
use poem::session::{CookieConfig, MemoryStorage, ServerSession};
use poem::{EndpointExt, Route, Server};
use warpgate_admin::AdminServer;
use std::fmt::Debug;
use std::net::SocketAddr;
use tracing::*;
use warpgate_common::{ProtocolServer, Services, Target, TargetTestError};
use warpgate_web::Assets;

pub struct HTTPProtocolServer {
    services: Services,
    admin_server: AdminServer,
}

impl HTTPProtocolServer {
    pub async fn new(services: &Services) -> Result<Self> {
        Ok(HTTPProtocolServer {
            services: services.clone(),
            admin_server: AdminServer::new(services).await?,
        })
    }
}

#[derive(Clone)]
pub struct AdminServerAddress(pub SocketAddr);

#[async_trait]
impl ProtocolServer for HTTPProtocolServer {
    async fn run(self, address: SocketAddr) -> Result<()> {
        let app = Route::new()
            .nest(
                "/@warpgate",
                Route::new()
                    .nest_no_strip("/assets", EmbeddedFilesEndpoint::<Assets>::new())
                    .at("/", EmbeddedFileEndpoint::<Assets>::new("index.html")),
            )
            .nest_no_strip("/", api::catchall_endpoint)
            .with(ServerSession::new(
                CookieConfig::default().secure(false).name("warpgate-http-session"),
                MemoryStorage::default(),
            ))
            .data(self.services.clone())
            .data(AdminServerAddress(self.admin_server.local_addr().clone()))
            .data(self.admin_server.secret().clone());

        let (certificate, key) = {
            let config = self.services.config.lock().await;
            let certificate_path = config
                .paths_relative_to
                .join(&config.store.http.certificate);
            let key_path = config.paths_relative_to.join(&config.store.http.key);

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
        let server_future = Server::new(TcpListener::bind(address).rustls(
            RustlsConfig::new().fallback(RustlsCertificate::new().cert(certificate).key(key)),
        ))
        .run(app);

        tokio::select! {
            _ = server_future => Ok(()),
            _ = self.admin_server.run() => Ok(()),
        }
    }

    async fn test_target(self, _target: Target) -> Result<(), TargetTestError> {
        Ok(())
    }
}

impl Debug for HTTPProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SSHProtocolServer")
    }
}
