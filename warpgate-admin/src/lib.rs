pub mod api;
use poem::http::header::CONTENT_SECURITY_POLICY;
use poem::middleware::SetHeader;
use poem::{EndpointExt, IntoEndpoint, Route};
use poem_openapi::OpenApiService;
use warpgate_cluster::approvals::RESOLVE_APPROVAL_ROUTE;
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
            "/recordings/:id/stream",
            crate::api::recordings_detail::api_get_recording_stream,
        )
        .at(
            "/recordings/:id/tcpdump",
            crate::api::recordings_detail::api_get_recording_tcpdump,
        )
        .at(
            "/recordings/:id/data",
            crate::api::recordings_detail::api_get_recording_data,
        )
        .at(
            "/recordings/:id/index",
            crate::api::recordings_detail::api_get_recording_index,
        )
        .at(
            "/sessions/changes",
            crate::api::sessions_list::api_get_sessions_changes_stream,
        )
        .at(
            "/session-approvals/changes",
            crate::api::session_approvals::api_get_session_approvals_stream,
        )
        .at(
            RESOLVE_APPROVAL_ROUTE,
            crate::api::session_approvals::api_resolve_session_approval,
        )
}
