#![feature(decl_macro, proc_macro_hygiene, let_else)]
mod api;
mod embed;
mod helpers;
use crate::embed::{EmbeddedFileEndpoint, EmbeddedFilesEndpoint};
use anyhow::{Context, Result};
use poem::listener::TcpListener;
use poem::middleware::AddData;
use poem::session::{CookieConfig, MemoryStorage, ServerSession};
use poem::{EndpointExt, Route, Server};
use poem_openapi::OpenApiService;
use rust_embed::RustEmbed;
use std::net::SocketAddr;
use tracing::*;
use warpgate_common::Services;

#[derive(RustEmbed)]
#[folder = "../warpgate-admin/app/dist"]
pub struct Assets;

pub struct AdminServer {
    services: Services,
}

impl AdminServer {
    pub fn new(services: &Services) -> Self {
        AdminServer {
            services: services.clone(),
        }
    }

    pub async fn run(self, address: SocketAddr) -> Result<()> {
        let state = self.services.state.clone();
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
            ),
            "Warpgate",
            env!("CARGO_PKG_VERSION"),
        )
        .server("/api");
        let ui = api_service.swagger_ui();
        let spec = api_service.spec_endpoint();
        let db = self.services.db.clone();
        let config_provider = self.services.config_provider.clone();
        let recordings = self.services.recordings.clone();

        let app = Route::new()
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
                "/api/recordings/:id/tcpdump",
                crate::api::recordings_detail::api_get_recording_tcpdump,
            )
            .with(ServerSession::new(
                CookieConfig::default().secure(false),
                MemoryStorage::default(),
            ))
            .with(AddData::new(db))
            .with(AddData::new(config_provider))
            .with(AddData::new(state))
            .with(AddData::new(recordings));

        info!(?address, "Listening");
        Server::new(TcpListener::bind(address))
            .run(app)
            .await
            .context("Failed to start admin server")
    }
}
