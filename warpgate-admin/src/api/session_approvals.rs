use futures::{SinkExt, StreamExt};
use poem::web::Data;
use poem::web::websocket::{Message, WebSocket};
use poem::{IntoResponse, handler};
use poem_openapi::param::{Path, Query};
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use time::OffsetDateTime;
use tokio::sync::broadcast;
use uuid::Uuid;
use warpgate_common::auth::ApprovalKind;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::approvals::{ApprovalDecision, ApprovalScope};
use warpgate_db_entities::SessionApprovalRequest;

use super::AdminContext;
use crate::api::common::require_admin_permission;
use crate::approvals::{
    ApprovalResolution, Approver, find_pending_approval, resolve_pending_approval,
};

pub struct Api;

/// A session held pending administrator (JIT) approval.
#[derive(Object)]
struct SessionApprovalItem {
    id: String,
    protocol: String,
    address: Option<String>,
    username: String,
    target: String,
    started: OffsetDateTime,
    /// When administrator-approval caching is enabled, the caching window in
    /// seconds; `None` when caching is disabled.
    caching_grace_seconds: Option<i64>,
}

#[derive(ApiResponse)]
enum ListResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<SessionApprovalItem>>),
}

#[derive(ApiResponse)]
enum ActionResponse {
    #[oai(status = 200)]
    Ok,
    #[oai(status = 404)]
    NotFound,
}

/// Resolves a pending approval from whichever node the admin is talking to.
///
/// The decision is recorded on the request row and read back by the node
/// running the held session, so this is served wherever it lands.
///
/// `target` is the target the admin's screen showed for this session. The
/// request may have been reopened for a different target since the list was
/// rendered — that is a question the admin never saw, so the stale click gets
/// a not-found rather than resolving it.
async fn resolve(
    ctx: &AuthenticatedRequestContext,
    session_id: Uuid,
    target: &str,
    decision: ApprovalDecision,
) -> poem::Result<ActionResponse> {
    let Some(pending) = find_pending_approval(ctx, session_id, ApprovalKind::Admin).await? else {
        return Ok(ActionResponse::NotFound);
    };
    if pending.target != target {
        return Ok(ActionResponse::NotFound);
    }

    match resolve_pending_approval(ctx, Approver::Administrator, pending, decision).await? {
        ApprovalResolution::Resolved => Ok(ActionResponse::Ok),
        ApprovalResolution::NotFound => Ok(ActionResponse::NotFound),
    }
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/session-approvals",
        method = "get",
        operation_id = "get_session_approvals"
    )]
    async fn api_list(&self, admin: AdminContext) -> poem::Result<ListResponse> {
        admin.require(AdminPermission::ApproveSessions)?;
        let services = admin.services();

        // Any node can serve the list: requests are first-class rows in the
        // shared database. A row that already carries a decision is on its way
        // out — the owning node has yet to pick it up — so it is not offered
        // for another one.
        let requests = SessionApprovalRequest::Entity::find()
            .filter(
                SessionApprovalRequest::Column::Kind
                    .eq(SessionApprovalRequest::ApprovalRequestKind::Admin),
            )
            .filter(
                SessionApprovalRequest::Column::Status
                    .eq(SessionApprovalRequest::ApprovalRequestStatus::Pending),
            )
            .order_by_asc(SessionApprovalRequest::Column::Started)
            .all(&services.db)
            .await
            .map_err(WarpgateError::from)?;

        let caching_grace_seconds = services
            .admin_approval_grace_period()
            .await?
            .and_then(|d| i64::try_from(d.as_secs()).ok());

        Ok(ListResponse::Ok(Json(
            requests
                .into_iter()
                .map(|r| SessionApprovalItem {
                    id: r.session_id.to_string(),
                    protocol: r.protocol,
                    address: r.remote_address,
                    username: r.username,
                    target: r.target,
                    started: r.started,
                    caching_grace_seconds,
                })
                .collect(),
        )))
    }

    #[oai(
        path = "/session-approvals/:id/approve",
        method = "post",
        operation_id = "approve_session"
    )]
    async fn api_approve(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        scope: Query<ApprovalScope>,
        /// The target shown for this session in the approvals list.
        target: Query<String>,
    ) -> poem::Result<ActionResponse> {
        admin.require(AdminPermission::ApproveSessions)?;
        resolve(&admin, id.0, &target.0, ApprovalDecision::Approved(scope.0)).await
    }

    #[oai(
        path = "/session-approvals/:id/reject",
        method = "post",
        operation_id = "reject_session"
    )]
    async fn api_reject(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        /// The target shown for this session in the approvals list.
        target: Query<String>,
    ) -> poem::Result<ActionResponse> {
        admin.require(AdminPermission::ApproveSessions)?;
        resolve(&admin, id.0, &target.0, ApprovalDecision::Rejected).await
    }
}

#[handler]
pub async fn api_get_session_approvals_stream(
    ctx: Data<&AuthenticatedRequestContext>,
    ws: WebSocket,
) -> Result<impl IntoResponse, WarpgateError> {
    require_admin_permission(&ctx, Some(AdminPermission::ApproveSessions)).await?;

    let mut rx = ctx.services().subscribe_admin_approval_request();

    Ok(ws
        .on_upgrade(|socket| async move {
            let (mut sink, _) = socket.split();
            loop {
                match rx.recv().await {
                    Ok(_) => sink.send(Message::Text("".into())).await?,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            Ok::<(), anyhow::Error>(())
        })
        .into_response())
}
