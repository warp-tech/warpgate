//! Administrator-approval gate for the Kubernetes proxy.
//!
//! `kubectl` is an API client, not a browser, so a held session gets a
//! Kubernetes `Status` object rather than a page — that is what the client
//! knows how to render, and it puts the reason in front of the user instead of
//! an opaque transport error.

use poem::http::StatusCode;
use poem::{IntoResponse, Request, Response};
use warpgate_common::{SessionId, WarpgateError};
use warpgate_core::approvals::{AdminApprovalContext, PolledGate};
use warpgate_core::{ApprovedTarget, Services, TargetAuthorization};

/// The proof needed to reach the cluster, or the response to send back instead.
pub async fn check_admin_approval(
    req: &Request,
    services: &Services,
    session_id: SessionId,
    authorization: TargetAuthorization,
) -> Result<Result<ApprovedTarget, Response>, WarpgateError> {
    let target_name = authorization.target().name.clone();
    let gate = services
        .poll_admin_approval(
            authorization,
            AdminApprovalContext {
                session_id: &session_id,
                remote_ip: req.remote_addr().as_socket_addr().map(|a| a.ip()),
                // Client certificates and tokens are re-presented per request rather
                // than settled into an auth state, so a Kubernetes session neither
                // contributes nor consumes a remembered approval.
                credentials: None,
            },
        )
        .await?;

    Ok(match gate {
        PolledGate::Approved(approved) => Ok(approved),
        // 503 rather than 403: the request hasn't been refused, it hasn't been
        // decided, and retrying is the right thing for the client to do.
        PolledGate::Pending => Err(status_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &format!(
                "Warpgate: session for target \"{target_name}\" is waiting for administrator \
                 approval; retry shortly"
            ),
        )),
        PolledGate::Denied => Err(status_response(
            StatusCode::FORBIDDEN,
            &format!(
                "Warpgate: an administrator did not approve this session for target \
                 \"{target_name}\""
            ),
        )),
    })
}

/// A `v1.Status` failure, the shape every Kubernetes client already parses.
///
/// Kubernetes spells `reason` in CamelCase, which is the HTTP status name with
/// its spaces removed.
fn status_response(code: StatusCode, message: &str) -> Response {
    let reason = code.canonical_reason().unwrap_or_default().replace(' ', "");
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
