//! Administrator-approval gate for the HTTP proxy.
//!
//! HTTP answers each request on its own instead of holding a connection, so it
//! observes the gate through `Services::poll_admin_approval` rather than parking
//! on it. A held session gets an interstitial that refreshes itself until an
//! administrator decides; the status code carries the same meaning to a client
//! that never renders the body.

use std::sync::Arc;

use http::StatusCode;
use poem::web::Html;
use poem::{IntoResponse, Request, Response};
use tokio::sync::Mutex;
use warpgate_common::auth::RememberedBy;
use warpgate_common::{TargetHTTPOptions, TargetSessionId};
use warpgate_common_http::logging::get_client_ip_addr;
use warpgate_common_http::{
    AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization,
};
use warpgate_core::approvals::{AdminApprovalContext, PolledGate, TicketStake};
use warpgate_core::{ApprovedTarget, TargetAuthorization, WarpgateServerHandle};

/// How often the interstitial re-checks. Short enough to feel immediate, long
/// enough not to hammer the gateway while a session waits.
const RETRY_AFTER_SECONDS: u32 = 3;

/// Takes an authorization the session's target-session start handed back as
/// needing approval, polls the gate, and either registers the admitted target
/// session or produces the response to send instead.
pub async fn resolve_admin_approval(
    req: &Request,
    ctx: &AuthenticatedRequestContext,
    handle: &Arc<Mutex<WarpgateServerHandle>>,
    authorization: TargetAuthorization<TargetHTTPOptions>,
) -> poem::Result<Result<(TargetSessionId, ApprovedTarget<TargetHTTPOptions>), Response>> {
    let services = ctx.services();
    let target_name = authorization.target().name.clone();
    let session_id = handle.lock().await.user_session_id();

    // A ticket whose spend was deferred — the session was established for a
    // gated target — is spent by the approval itself, through the request row.
    let ticket = match &ctx.auth {
        RequestAuthorization::Session(SessionAuthorization::Ticket {
            ticket_id: Some(ticket_id),
            ticket_spend_deferred: true,
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
        PolledGate::Approved(approved) => {
            let target_session_id = handle
                .lock()
                .await
                .register_approved_target_session(&approved)
                .await?;
            Ok((target_session_id, approved))
        }
        PolledGate::Pending => Err(gate_response(
            &target_name,
            "Waiting for approval",
            "An administrator has been asked to approve this session. This page will \
             continue automatically once they do.",
            true,
        )),
        // Saying "an administrator has been asked" here would be untrue: this
        // session is already holding one question, and only asks about this
        // target once that one is answered.
        PolledGate::Queued => Err(gate_response(
            &target_name,
            "Waiting for an earlier request",
            "Another connection in this session is already waiting for an \
             administrator. This one will be submitted once that is decided, and \
             this page will continue automatically.",
            true,
        )),
        PolledGate::Denied => Err(gate_response(
            &target_name,
            "Session not approved",
            "An administrator did not approve this session.",
            false,
        )),
    })
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
