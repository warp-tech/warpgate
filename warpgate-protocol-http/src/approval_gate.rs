//! Administrator-approval gate for the HTTP proxy.
//!
//! HTTP answers each request on its own instead of holding a connection, so it
//! observes the gate through `Services::poll_admin_approval` rather than parking
//! on it. A held session gets an interstitial that refreshes itself until an
//! administrator decides; the status code carries the same meaning to a client
//! that never renders the body.

use std::sync::Arc;

use http::StatusCode;
use poem::{IntoResponse, Request, Response};
use tokio::sync::Mutex;
use warpgate_common::TargetHTTPOptions;
use warpgate_common::auth::RememberApprovalBy;
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_common_http::logging::get_client_ip_addr;
use warpgate_core::approvals::{AdminApprovalContext, PolledGate};
use warpgate_core::{AdmittedTarget, TargetAuthorization, WarpgateServerHandle};

use crate::internal_page::internal_page;

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
) -> poem::Result<Result<AdmittedTarget<TargetHTTPOptions>, Response>> {
    let services = ctx.services();
    let target_name = authorization.target().name.clone();
    let session_id = handle.lock().await.user_session_id();

    let gate = services
        .poll_admin_approval(
            authorization,
            AdminApprovalContext {
                session_id,
                remote_ip: get_client_ip_addr(req, services).await,
                // The credentials that authenticated the session aren't carried
                // on the request, so an HTTP session neither contributes nor
                // consumes a remembered approval.
                credentials: RememberApprovalBy::Nothing,
            },
        )
        .await?;

    Ok(match gate {
        PolledGate::Approved(approved) => Ok(handle
            .lock()
            .await
            .register_approved_target_session(approved)
            .await?),
        PolledGate::Pending => Err(gate_response(
            &target_name,
            "Waiting for approval",
            "An administrator has been asked to approve this session. This page will \
             continue automatically once they do.",
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
    let page = internal_page(
        heading,
        message,
        Some(target_name),
        pending.then_some(RETRY_AFTER_SECONDS),
    );

    if pending {
        page.with_status(StatusCode::ACCEPTED)
            .with_header(http::header::RETRY_AFTER, RETRY_AFTER_SECONDS)
            .into_response()
    } else {
        page.with_status(StatusCode::FORBIDDEN).into_response()
    }
}
