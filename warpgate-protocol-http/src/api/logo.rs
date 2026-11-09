use poem::http::{StatusCode, header};
use poem::web::{Data, Query};
use poem::{Response, handler};
use serde::Deserialize;
use warpgate_common::WarpgateError;
use warpgate_common_http::auth::UnauthenticatedRequestContext;

#[derive(Deserialize)]
pub struct LogoQuery {
    v: Option<String>,
}

#[handler]
pub async fn api_get_logo(
    ctx: Data<&UnauthenticatedRequestContext>,
    Query(query): Query<LogoQuery>,
) -> Result<Response, WarpgateError> {
    let parameters = ctx.parameters().await?;
    let Some(image) = parameters.logo_image() else {
        return Ok(StatusCode::NOT_FOUND.into());
    };
    let cache_control = if query.v == parameters.logo_etag() {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    Ok(Response::builder()
        .content_type(image.content_type)
        .header(header::CACHE_CONTROL, cache_control)
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        // A sandboxed document can't run scripts, so an SVG logo opened directly
        // rather than as an <img> can't act within the Warpgate origin.
        .header(header::CONTENT_SECURITY_POLICY, "sandbox")
        .body(image.bytes))
}
