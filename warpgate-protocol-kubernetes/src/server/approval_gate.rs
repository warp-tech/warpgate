//! Administrator-approval gate for the Kubernetes proxy.
//!
//! `kubectl` is an API client, not a browser, so a held session gets a
//! Kubernetes `Status` object rather than a page — that is what the client
//! knows how to render, and it puts the reason in front of the user instead of
//! an opaque transport error.

use poem::http::StatusCode;
use poem::{IntoResponse, Request, Response};
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{SessionId, Target, WarpgateError};
use warpgate_core::Services;
use warpgate_core::approvals::{AdminApprovalRequest, AdminApprovalStatus};

/// Whether the request may proceed to the cluster. `Some(response)` is what to
/// send back instead.
pub async fn check_admin_approval(
    req: &Request,
    services: &Services,
    session_id: SessionId,
    user_info: &AuthStateUserInfo,
    target: &Target,
) -> Result<Option<Response>, WarpgateError> {
    let status = services
        .poll_admin_approval(AdminApprovalRequest {
            session_id: &session_id,
            user_info,
            protocol: crate::PROTOCOL_NAME,
            target_name: &target.name,
            remote_ip: req.remote_addr().as_socket_addr().map(|a| a.ip()),
            // Client certificates and tokens are re-presented per request rather
            // than settled into an auth state, so a Kubernetes session neither
            // contributes nor consumes a remembered approval.
            credentials: None,
        })
        .await?;

    Ok(match status {
        AdminApprovalStatus::Approved => None,
        // 503 rather than 403: the request hasn't been refused, it hasn't been
        // decided, and retrying is the right thing for the client to do.
        AdminApprovalStatus::Pending => Some(status_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            &format!(
                "Warpgate: session for target \"{}\" is waiting for administrator approval; \
                 retry shortly",
                target.name
            ),
        )),
        AdminApprovalStatus::Denied => Some(status_response(
            StatusCode::FORBIDDEN,
            "Forbidden",
            &format!(
                "Warpgate: an administrator did not approve this session for target \"{}\"",
                target.name
            ),
        )),
    })
}

/// A `v1.Status` failure, the shape every Kubernetes client already parses.
fn status_response(code: StatusCode, reason: &str, message: &str) -> Response {
    let body = serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "metadata": {},
        "status": "Failure",
        "message": message,
        "reason": reason,
        "code": code.as_u16(),
    });

    poem::web::Json(body).with_status(code).into_response()
}
