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
use warpgate_common::auth::RememberedBy;
use warpgate_common::{Target, TargetHTTPOptions, TargetOptions};
use warpgate_common_http::logging::get_client_ip_addr;
use warpgate_common_http::{
    AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization,
};
use warpgate_core::TargetAuthorization;
use warpgate_core::approvals::{AdminApprovalContext, PolledGate, TicketStake};

use crate::session_handle::warpgate_server_handle_for_request;

/// How often the interstitial re-checks. Short enough to feel immediate, long
/// enough not to hammer the gateway while a session waits.
const RETRY_AFTER_SECONDS: u32 = 3;

/// A resolved, authorized HTTP target that has *not* been through the
/// administrator gate. [`check_admin_approval`] is the only thing that can
/// take it apart, so a request path that resolves a target has no way to
/// proxy to it without passing the gate.
pub struct UngatedTarget {
    authorization: TargetAuthorization,
}

impl UngatedTarget {
    /// Wraps an authorization whose target is an HTTP one; `None` for a target
    /// of another protocol. Carrying the authorization itself — rather than
    /// pieces cloned out of it — is what lets the gate hand the proxy a proof
    /// instead of reassembling one from unproven parts.
    pub fn new_http(authorization: TargetAuthorization) -> Option<Self> {
        matches!(authorization.target().options, TargetOptions::Http(_))
            .then_some(Self { authorization })
    }

    /// Read access for the bookkeeping that happens before the gate (naming
    /// the session's target). The pieces the proxy dials with are taken from
    /// the proof the gate hands back, not from here.
    pub fn target(&self) -> &Target {
        self.authorization.target()
    }
}

/// Splits an HTTP target into the pieces the proxy dials with.
///
/// The `Err` arm is unreachable for a target that came in through
/// [`UngatedTarget::new_http`], but stays a response rather than a panic.
fn http_parts(target: Target) -> Result<(Target, TargetHTTPOptions), Response> {
    let TargetOptions::Http(ref options) = target.options else {
        return Err(
            "Invalid target type"
                .with_status(StatusCode::INTERNAL_SERVER_ERROR)
                .into_response(),
        );
    };
    let options = options.clone();
    Ok((target, options))
}

/// The target the request may proxy to, or the response to send back instead.
pub async fn check_admin_approval(
    req: &Request,
    ctx: &AuthenticatedRequestContext,
    ungated: UngatedTarget,
) -> poem::Result<Result<(Target, TargetHTTPOptions), Response>> {
    let UngatedTarget { authorization } = ungated;
    let services = ctx.services();
    let target_name = authorization.target().name.clone();

    // A decision needs a session to attribute the request row to. Without one
    // there is nothing to approve, so a gated target is simply unreachable on
    // this path rather than silently open.
    let Ok(handle) = warpgate_server_handle_for_request(req).await else {
        return Ok(if authorization.target().require_approval {
            Err(denied_response(&target_name))
        } else {
            http_parts(authorization.target().clone())
        });
    };
    let session_id = handle.lock().await.id();

    // A ticket whose consumption was deferred — the session was established
    // for a gated target — is spent by the approval itself, through the
    // request row.
    let ticket = match &ctx.auth {
        RequestAuthorization::Session(SessionAuthorization::Ticket {
            unconsumed_ticket_id: Some(ticket_id),
            ..
        }) => TicketStake::ConsumedOnApproval(*ticket_id),
        _ => TicketStake::None,
    };

    let gate = services
        .poll_admin_approval(
            authorization,
            AdminApprovalContext {
                session_id,
                remote_ip: get_client_ip_addr(req, services).await,
                // The credentials that authenticated the session aren't carried
                // on the request, so an HTTP session neither contributes nor
                // consumes a remembered approval.
                credentials: RememberedBy::Nothing,
                ticket,
            },
        )
        .await?;

    Ok(match gate {
        // The pieces the proxy dials with come out of the proof, so what it
        // dials is definitionally what the gate approved.
        PolledGate::Approved(approved) => http_parts(approved.into_parts().1),
        PolledGate::Pending => Err(gate_response(
            &target_name,
            "Waiting for approval",
            "An administrator has been asked to approve this session. This page will \
             continue automatically once they do.",
            true,
        )),
        PolledGate::Denied => Err(denied_response(&target_name)),
    })
}

fn denied_response(target_name: &str) -> Response {
    gate_response(
        target_name,
        "Session not approved",
        "An administrator did not approve this session.",
        false,
    )
}

/// A branded standalone page. The status code is the machine-readable signal —
/// 202 with `Retry-After` while pending, 403 once denied — so a client that
/// never renders the body still knows what happened.
fn gate_response(target_name: &str, heading: &str, message: &str, pending: bool) -> Response {
    let refresh = if pending {
        format!(r#"<meta http-equiv="refresh" content="{RETRY_AFTER_SECONDS}">"#)
    } else {
        String::new()
    };
    let heading = html_escape::encode_text(heading);
    let message = html_escape::encode_text(message);
    let target_name = html_escape::encode_text(target_name);
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
