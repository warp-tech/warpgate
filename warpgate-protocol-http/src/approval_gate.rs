//! Administrator-approval gate for the HTTP proxy.
//!
//! HTTP answers each request on its own instead of holding a connection, so it
//! observes the gate through `Services::poll_admin_approval` rather than parking
//! on it. A held session gets an interstitial that refreshes itself until an
//! administrator decides; the status code carries the same meaning to a client
//! that never renders the body.

use http::StatusCode;
use poem::web::Html;
use poem::{IntoResponse, Request, Response};
use warpgate_common::Target;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::approvals::{AdminApprovalContext, PolledGate};

use crate::session_handle::warpgate_server_handle_for_request;

/// How often the interstitial re-checks. Short enough to feel immediate, long
/// enough not to hammer the gateway while a session waits.
const RETRY_AFTER_SECONDS: u32 = 3;

/// Whether the request may proceed to the target. `Some(response)` is what to
/// send back instead.
pub async fn check_admin_approval(
    req: &Request,
    ctx: &AuthenticatedRequestContext,
    target: &Target,
) -> poem::Result<Option<Response>> {
    let services = ctx.services();

    // A decision needs a session to attribute the request row to and a user to
    // name in it. Without either there is nothing to approve, so a gated target
    // is simply unreachable on this path rather than silently open.
    let handle = warpgate_server_handle_for_request(req).await.ok();
    let (Some(handle), Some(username)) = (handle, ctx.auth.username().cloned()) else {
        return Ok(target.require_approval.then(|| denied_response(target)));
    };

    let session_id = handle.lock().await.id();
    let user_info = AuthStateUserInfo {
        id: ctx.auth.user_id(),
        username,
    };

    let gate = services
        .poll_admin_approval_for_http(
            target.clone(),
            user_info,
            crate::common::PROTOCOL_NAME,
            AdminApprovalContext {
                session_id: &session_id,
                remote_ip: req.remote_addr().as_socket_addr().map(|a| a.ip()),
                // The credentials that authenticated the session aren't carried
                // on the request, so an HTTP session neither contributes nor
                // consumes a remembered approval.
                credentials: None,
            },
        )
        .await?;

    Ok(match gate {
        PolledGate::Approved(_) => None,
        PolledGate::Pending => Some(gate_response(
            target,
            "Waiting for approval",
            "An administrator has been asked to approve this session. This page will \
             continue automatically once they do.",
            true,
        )),
        PolledGate::Denied => Some(denied_response(target)),
    })
}

fn denied_response(target: &Target) -> Response {
    gate_response(
        target,
        "Session not approved",
        "An administrator did not approve this session.",
        false,
    )
}

/// A branded standalone page. The status code is the machine-readable signal —
/// 202 with `Retry-After` while pending, 403 once denied — so a client that
/// never renders the body still knows what happened.
fn gate_response(target: &Target, heading: &str, message: &str, pending: bool) -> Response {
    let refresh = if pending {
        format!(r#"<meta http-equiv="refresh" content="{RETRY_AFTER_SECONDS}">"#)
    } else {
        String::new()
    };
    let heading = html_escape::encode_text(heading);
    let message = html_escape::encode_text(message);
    let target_name = html_escape::encode_text(&target.name);
    let page = format!(
        r#"<!DOCTYPE html>
        {refresh}
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol";
            }}

            img {{
                width: 100px;
            }}

            main {{
                width: 400px;
                margin: 200px auto;
            }}
        </style>
        <main>
            <img src="/@warpgate/assets/brand.svg" />
            <h1>{heading}</h1>
            <p>{message}</p>
            <p><small>{target_name}</small></p>
        </main>
        "#
    );

    if pending {
        Html(page)
            .with_status(StatusCode::ACCEPTED)
            .with_header(http::header::RETRY_AFTER, RETRY_AFTER_SECONDS)
            .into_response()
    } else {
        Html(page)
            .with_status(StatusCode::FORBIDDEN)
            .into_response()
    }
}
