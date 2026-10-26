use bytes::Bytes;
use poem::http::StatusCode;
use poem::web::Data;
use poem::{Request, handler};
use time::OffsetDateTime;
use tracing::warn;
use warpgate_common::WarpgateError;
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_core::slack::{handle_interaction, slack_config, verify_signature};

/// Slack interactivity endpoint (approval buttons). Authenticated by the
/// request signature rather than a Warpgate session.
#[handler]
pub async fn api_slack_interactions(
    ctx: Data<&UnauthenticatedRequestContext>,
    req: &Request,
    body: Bytes,
) -> Result<StatusCode, WarpgateError> {
    let services = ctx.services();
    let Some(config) = slack_config(services).await else {
        return Ok(StatusCode::NOT_FOUND);
    };

    let header = |name: &str| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
    };
    if !verify_signature(
        config.signing_secret.expose_secret(),
        header("x-slack-request-timestamp"),
        &body,
        header("x-slack-signature"),
        OffsetDateTime::now_utc(),
    ) {
        warn!("Rejected a Slack interaction with an invalid signature");
        return Ok(StatusCode::UNAUTHORIZED);
    }

    let Some(payload) = url::form_urlencoded::parse(&body)
        .find(|(key, _)| key == "payload")
        .map(|(_, value)| value)
    else {
        return Ok(StatusCode::BAD_REQUEST);
    };

    handle_interaction(services, config, &payload);
    Ok(StatusCode::OK)
}
