#![feature(decl_macro, proc_macro_hygiene, let_else)]
mod api;
mod helpers;
use poem::{EndpointExt, IntoEndpoint, Route};
use poem_openapi::OpenApiService;
use warpgate_common::Services;

pub fn admin_api_app(services: &Services) -> impl IntoEndpoint {
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
        .data(db)
        .data(config_provider)
        .data(state)
        .data(recordings)
        .data(config.clone())
}
