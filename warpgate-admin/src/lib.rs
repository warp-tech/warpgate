#![feature(decl_macro, proc_macro_hygiene, let_else)]
mod api;
mod helpers;
use anyhow::{Context, Result};
use poem::endpoint::{EmbeddedFileEndpoint, EmbeddedFilesEndpoint};
use poem::http::StatusCode;
use poem::listener::{Acceptor, Listener, TcpListener};
use poem::middleware::SetHeader;
use poem::session::{CookieConfig, MemoryStorage, ServerSession};
use poem::{Endpoint, EndpointExt, IntoEndpoint, Route, Server};
use poem_openapi::OpenApiService;
use std::net::SocketAddr;
use std::pin::Pin;
use tracing::*;
use warpgate_common::{Secret, Services};
use warpgate_web::Assets;

#[derive(Clone)]
pub struct AdminServerSecret(pub Secret<String>);

pub struct AdminServer {
    server: Pin<Box<dyn core::future::Future<Output = Result<(), std::io::Error>> + Send>>,
    address: SocketAddr,
    secret: AdminServerSecret,
}

pub static SECRET_HEADER_NAME: &str = "x-warpgate-admin-secret";

fn admin_app(services: &Services, secret: AdminServerSecret) -> impl IntoEndpoint {
    let api_service = OpenApiService::new(
        (
            crate::api::sessions_list::Api,
            crate::api::sessions_detail::Api,
            crate::api::recordings_detail::Api,
            crate::api::users_list::Api,
            crate::api::targets_list::Api,
            crate::api::tickets_list::Api,
            crate::api::tickets_detail::Api,
            crate::api::known_hosts_list::Api,
            crate::api::known_hosts_detail::Api,
            crate::api::info::Api,
            crate::api::auth::Api,
            crate::api::ssh_keys::Api,
            crate::api::logs::Api,
        ),
        "Warpgate",
        env!("CARGO_PKG_VERSION"),
    )
    .server("/api");

    let ui = api_service.swagger_ui();
    let spec = api_service.spec_endpoint();
    let db = services.db.clone();
    let config = services.config.clone();
    let config_provider = services.config_provider.clone();
    let recordings = services.recordings.clone();
    let state = services.state.clone();

    Route::new()
        .nest("/api/swagger", ui)
        .nest("/api", api_service)
        .nest("/api/openapi.json", spec)
        .nest_no_strip("/assets", EmbeddedFilesEndpoint::<Assets>::new())
        .at("/", EmbeddedFileEndpoint::<Assets>::new("index.html"))
        .at(
            "/api/recordings/:id/cast",
            crate::api::recordings_detail::api_get_recording_cast,
        )
        .at(
            "/api/recordings/:id/stream",
            crate::api::recordings_detail::api_get_recording_stream,
        )
        .at(
            "/api/recordings/:id/tcpdump",
            crate::api::recordings_detail::api_get_recording_tcpdump,
        )
        .with(ServerSession::new(
            CookieConfig::default().secure(false),
            MemoryStorage::default(),
        ))
        .with(SetHeader::new().overriding("Strict-Transport-Security", "max-age=31536000"))
        .data(db)
        .data(config_provider)
        .data(state)
        .data(recordings)
        .data(config.clone())
        .data(secret.clone())
        .around(move |ep, req| {
            let secret = secret.clone();
            async move {
                let v = req.headers().get(SECRET_HEADER_NAME);
                if !v.map(|v| v == secret.0.expose_secret()).unwrap_or(false) {
                    return Err(poem::Error::from_string(
                        "Unauthorized",
                        StatusCode::UNAUTHORIZED,
                    ));
                }
                ep.call(req).await
            }
        })
}

impl AdminServer {
    pub async fn new(services: &Services) -> Result<Self> {
        let secret = AdminServerSecret(Secret::random());

        let app = admin_app(&services, secret.clone());

        let listener = TcpListener::bind("127.0.0.1:0");
        let acceptor = listener.into_acceptor().await?;
        let addresses = acceptor.local_addr();
        let address = addresses.first().context("No local listener address")?;

        Ok(AdminServer {
            server: Box::pin(Server::new_with_acceptor(acceptor).run(app)),
            address: address.0.as_socket_addr().unwrap().clone(),
            secret,
        })
    }

    pub fn local_addr(&self) -> &SocketAddr {
        &self.address
    }

    pub fn secret(&self) -> &AdminServerSecret {
        &self.secret
    }

    pub async fn run(self) -> std::io::Result<()> {
        info!(address=?self.address, "Admin server listening on");
        self.server.await
    }
}
