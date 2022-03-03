#![feature(decl_macro, proc_macro_hygiene, let_else)]
use anyhow::Result;
use poem::endpoint::{StaticFileEndpoint, StaticFilesEndpoint};
use poem::listener::TcpListener;
use poem::middleware::AddData;
use poem::EndpointExt;
use poem::{Route, Server};
use poem_openapi::OpenApiService;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use warpgate_common::State;
mod api;
mod helpers;

pub struct AdminServer {
    state: Arc<Mutex<State>>,
}

impl AdminServer {
    pub fn new(state: Arc<Mutex<State>>) -> Self {
        AdminServer { state }
    }

    pub async fn run(self, address: SocketAddr) -> Result<()> {
        let state = self.state.clone();
        let api_service = OpenApiService::new(
            (
                crate::api::sessions_all::Api,
                crate::api::sessions_detail::Api,
                crate::api::recordings_detail::Api,
            ),
            "Hello World",
            env!("CARGO_PKG_VERSION"),
        )
        .server("/api");
        let ui = api_service.swagger_ui();
        let spec = api_service.spec_endpoint();
        let db = state.lock().await.db.clone();
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
            .at("/api/recordings/:id/cast", crate::api::recordings_detail::api_get_recording_cast)
            .with(AddData::new(db))
            .with(AddData::new(state));
        Server::new(TcpListener::bind(address)).run(app).await?;
        Ok(())
    }
}
