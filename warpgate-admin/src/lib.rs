pub mod api;
use poem::{IntoEndpoint, Route};
use poem_openapi::OpenApiService;
use warpgate_common::version::warpgate_version;

pub fn admin_api_app() -> impl IntoEndpoint {
    let api_service =
        OpenApiService::new(crate::api::get(), "Warpgate admin API", warpgate_version())
            .server("/@warpgate/admin/api");

    let ui = api_service.stoplight_elements();
    let spec = api_service.spec_endpoint();

    Route::new()
        .nest("", api_service)
        .nest("/playground", ui)
        .nest("/openapi.json", spec)
        .at(
            "/recordings/:id/cast",
            crate::api::recordings_detail::api_get_recording_cast,
        )
        .at(
            "/recordings/:id/stream",
            crate::api::recordings_detail::api_get_recording_stream,
        )
        .at(
            "/recordings/:id/tcpdump",
            crate::api::recordings_detail::api_get_recording_tcpdump,
        )
        .at(
            "/sessions/changes",
            crate::api::sessions_list::api_get_sessions_changes_stream,
        )
}
