#![feature(type_alias_impl_trait, let_else, try_blocks)]
mod api;
mod catchall;
mod common;
mod proxy;
mod session;
mod session_handle;
use anyhow::{Context, Result};
use async_trait::async_trait;
use common::page_admin_auth;
use poem::endpoint::{EmbeddedFileEndpoint, EmbeddedFilesEndpoint};
use poem::listener::{Listener, RustlsCertificate, RustlsConfig, TcpListener};
use poem::middleware::SetHeader;
use poem::session::{CookieConfig, MemoryStorage, ServerSession};
use poem::{EndpointExt, IntoEndpoint, Route, Server};
use poem_openapi::OpenApiService;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::*;
use warpgate_admin::admin_api_app;
use warpgate_common::{ProtocolServer, Services, Target, TargetTestError};
use warpgate_web::Assets;

use crate::common::{endpoint_admin_auth, endpoint_auth, page_auth};
use crate::session::SessionMiddleware;

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
        let admin_api_app = admin_api_app(&self.services).into_endpoint();
        let api_service = OpenApiService::new(
            crate::api::get(),
            "Warpgate HTTP proxy",
            env!("CARGO_PKG_VERSION"),
        )
        .server("/@warpgate/api");
        let ui = api_service.swagger_ui();
        let spec = api_service.spec_endpoint();

        let session_middleware = Arc::new(Mutex::new(SessionMiddleware::new()));

        let app = Route::new()
            .nest(
                "/@warpgate",
                Route::new()
                    .nest("/api/swagger", ui)
                    .nest("/api", api_service)
                    .nest("/api/openapi.json", spec)
                    .nest_no_strip("/assets", EmbeddedFilesEndpoint::<Assets>::new())
                    .nest(
                        "/admin/api",
                        endpoint_auth(endpoint_admin_auth(admin_api_app)),
                    )
                    .at(
                        "/admin",
                        page_auth(page_admin_auth(EmbeddedFileEndpoint::<Assets>::new(
                            "src/admin/index.html",
                        ))),
                    )
                    .at(
                        "",
                        EmbeddedFileEndpoint::<Assets>::new("src/gateway/index.html"),
                    ),
            )
            .nest_no_strip("/", page_auth(catchall::catchall_endpoint))
            .before({
                let sm = session_middleware.clone();
                move |r| {
                    let sm = sm.clone();
                    async move {
                        let mut sm = sm.lock().await;
                        sm.process_request(r).await
                    }
                }
            })
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
            .data(self.services.clone())
            .data(session_middleware);

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
