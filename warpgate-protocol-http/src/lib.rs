#![feature(type_alias_impl_trait, let_else, try_blocks)]
mod api;
mod proxy;
use anyhow::{Context, Result};
use async_trait::async_trait;
use poem::endpoint::{EmbeddedFileEndpoint, EmbeddedFilesEndpoint};
use poem::listener::{Listener, RustlsCertificate, RustlsConfig, TcpListener};
use poem::middleware::SetHeader;
use poem::session::{CookieConfig, MemoryStorage, ServerSession};
use poem::{EndpointExt, Route, Server};
use std::fmt::Debug;
use std::net::SocketAddr;
use tracing::*;
use warpgate_admin::admin_api_app;
use warpgate_common::{ProtocolServer, Services, Target, TargetTestError};
use warpgate_web::Assets;

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
        let admin_api_app = admin_api_app(&self.services);
        let app = Route::new()
            .nest(
                "/@warpgate",
                Route::new()
                    .nest_no_strip("/api", admin_api_app)
                    .nest_no_strip("/assets", EmbeddedFilesEndpoint::<Assets>::new())
                    .at(
                        "/admin",
                        EmbeddedFileEndpoint::<Assets>::new("src/admin/index.html"),
                    )
                    .at(
                        "",
                        EmbeddedFileEndpoint::<Assets>::new("src/gateway/index.html"),
                    ),
            )
            .nest_no_strip("/", api::catchall_endpoint)
            .with(
                SetHeader::new()
                    .overriding(http::header::STRICT_TRANSPORT_SECURITY, "max-age=31536000"),
            )
            .with(ServerSession::new(
                CookieConfig::default()
                    .secure(false)
                    .name("warpgate-http-session"),
                MemoryStorage::default(),
            ))
            .data(self.services.clone());

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
        Server::new(TcpListener::bind(address).rustls(
            RustlsConfig::new().fallback(RustlsCertificate::new().cert(certificate).key(key)),
        ))
        .run(app)
        .await?;

        Ok(())
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
