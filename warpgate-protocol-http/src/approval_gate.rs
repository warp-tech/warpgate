//! Administrator-approval gate for the HTTP proxy.
//!
//! HTTP answers each request on its own instead of holding a connection, so it
//! observes the gate through `Services::poll_admin_approval` rather than parking
//! on it. A held session gets an interstitial that refreshes itself until an
//! administrator decides; a client that asked for something other than a
//! document gets the same meaning as a status code it can branch on.

use http::StatusCode;
use poem::web::Html;
use poem::{IntoResponse, Request, Response};
use warpgate_common::Target;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::approvals::{AdminApprovalRequest, AdminApprovalStatus};

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
        return Ok(if services.target_requires_approval(&target.name).await? {
            Some(denied_response(req, target))
        } else {
            None
        });
    };

    let session_id = handle.lock().await.id();
    let user_info = AuthStateUserInfo {
        id: ctx.auth.user_id(),
        username,
    };

    let status = services
        .poll_admin_approval(AdminApprovalRequest {
            session_id: &session_id,
            user_info: &user_info,
            protocol: crate::PROTOCOL_NAME,
            target_name: &target.name,
            remote_ip: req.remote_addr().as_socket_addr().map(|a| a.ip()),
            // The credentials that authenticated the session aren't carried on
            // the request, so an HTTP session neither contributes nor consumes
            // a remembered approval.
            credentials: None,
        })
        .await?;

    Ok(match status {
        AdminApprovalStatus::Approved => None,
        AdminApprovalStatus::Pending => Some(pending_response(req, target)),
        AdminApprovalStatus::Denied => Some(denied_response(req, target)),
    })
}

fn pending_response(req: &Request, target: &Target) -> Response {
    // 202, not 403: the request hasn't been refused, it hasn't been decided.
    // `Retry-After` carries that to clients that never render the body.
    body(
        req,
        target,
        "Waiting for approval",
        "An administrator has been asked to approve this session. This page will continue \
         automatically once they do.",
        Some(RETRY_AFTER_SECONDS),
    )
    .with_status(StatusCode::ACCEPTED)
    .with_header(http::header::RETRY_AFTER, RETRY_AFTER_SECONDS)
    .into_response()
}

fn denied_response(req: &Request, target: &Target) -> Response {
    body(
        req,
        target,
        "Session not approved",
        "An administrator did not approve this session.",
        None,
    )
    .with_status(StatusCode::FORBIDDEN)
    .into_response()
}

/// An HTML document for a browser, the bare message for anything else — an XHR
/// or CLI client gets something it can read without parsing markup.
fn body(
    req: &Request,
    target: &Target,
    heading: &str,
    message: &str,
    refresh_after: Option<u32>,
) -> Response {
    let wants_html = req
        .headers()
        .get(http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|accept| accept.contains("text/html"));

    if wants_html {
        Html(page(target, heading, message, refresh_after)).into_response()
    } else {
        message.to_string().into_response()
    }
}

fn page(target: &Target, heading: &str, message: &str, refresh_after: Option<u32>) -> String {
    let refresh = refresh_after.map_or_else(String::new, |seconds| {
        format!(r#"<meta http-equiv="refresh" content="{seconds}">"#)
    });
    let heading = html_escape::encode_text(heading);
    let message = html_escape::encode_text(message);
    let target = html_escape::encode_text(&target.name);
    format!(
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
            <p><small>{target}</small></p>
        </main>
        "#
    )
}
