pub mod api;
use poem::http::header::CONTENT_SECURITY_POLICY;
use poem::middleware::SetHeader;
use poem::{EndpointExt, IntoEndpoint, Route};
use poem_openapi::OpenApiService;
use warpgate_common::version::warpgate_version;
use warpgate_common_http::WARPGATE_PLAYGROUND_CSP;

pub fn admin_api_app() -> impl IntoEndpoint {
    let api_service =
        OpenApiService::new(crate::api::get(), "Warpgate admin API", warpgate_version())
            .server("/@warpgate/admin/api");

    // Stoplight Elements loads its assets from unpkg.com; the gateway's strict
    // default CSP would otherwise blank the playground.
    let ui = api_service
        .stoplight_elements()
        .with(SetHeader::new().overriding(CONTENT_SECURITY_POLICY, WARPGATE_PLAYGROUND_CSP));
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
