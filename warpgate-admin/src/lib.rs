#![feature(decl_macro, proc_macro_hygiene, let_else)]
use anyhow::Result;
use poem::endpoint::{StaticFileEndpoint, StaticFilesEndpoint};
use poem::listener::TcpListener;
use poem::middleware::AddData;
use poem::{EndpointExt, Route, Server};
use poem_openapi::OpenApiService;
use std::net::SocketAddr;
use warpgate_common::Services;
mod api;
mod helpers;

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
            ),
            "Warpgate",
            env!("CARGO_PKG_VERSION"),
        )
        .server("/api");
        let ui = api_service.swagger_ui();
        let spec = api_service.spec_endpoint();
        let db = self.services.db.clone();
        let app = Route::new()
            .nest("/api/swagger", ui)
            .nest("/api", api_service)
            .nest("/api/openapi.json", spec)
            .nest(
                "/assets",
                StaticFilesEndpoint::new("./warpgate-admin/frontend/dist/assets"),
            )
            .at(
                "/",
                StaticFileEndpoint::new("./warpgate-admin/frontend/dist/index.html"),
            )
            .at(
                "/api/recordings/:id/cast",
                crate::api::recordings_detail::api_get_recording_cast,
            )
            .with(AddData::new(db))
            .with(AddData::new(state))
            .with(AddData::new(self.services.config_provider.clone()));
        Server::new(TcpListener::bind(address)).run(app).await?;
        Ok(())
    }
}
