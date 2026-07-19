use futures::{SinkExt, StreamExt};
use poem::http::StatusCode;
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
use warpgate_cluster::approvals::{acting_approver, find_pending_approval, resolve_locally};
use warpgate_cluster::proxy::{FromProxiedStatus, local_or_forward, unexpected_proxied_status};
use warpgate_common::auth::ApprovalKind;
use warpgate_common::helpers::username::username_eq_ci;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::approvals::{ApprovalDecision, ApprovalScope};
use warpgate_db_entities::SessionApprovalRequest;

use super::AnySecurityScheme;
use crate::api::common::{
    has_admin_permission, require_admin_permission, require_cluster_or_admin_permission,
};

pub struct Api;

/// Approving your own held session defeats the four-eyes property the gate
/// exists for, so it is refused — unless the approver could edit targets, since
/// that lets them clear `require_approval` and walk through anyway.
async fn require_not_self_approval(
    ctx: &AuthenticatedRequestContext,
    held_username: &str,
) -> Result<(), WarpgateError> {
    let Some(approver) = ctx.auth.actor().username() else {
        // Not a user (admin API token) — there is no "own session" to speak of.
        return Ok(());
    };

    if !username_eq_ci(held_username, approver)
        || has_admin_permission(ctx, Some(AdminPermission::TargetsEdit)).await?
    {
        return Ok(());
    }

    Err(WarpgateError::NoAdminPermission(
        AdminPermission::TargetsEdit,
    ))
}

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

impl FromProxiedStatus for ActionResponse {
    fn from_proxied_status(status: StatusCode) -> poem::Result<Self> {
        match status {
            StatusCode::OK => Ok(Self::Ok),
            StatusCode::NOT_FOUND => Ok(Self::NotFound),
            status => Err(unexpected_proxied_status(status)),
        }
    }
}

/// Resolves a pending approval from whichever node the admin is talking to.
///
/// Only the node running the held session can deliver a decision, so a request
/// that lands elsewhere is forwarded there and re-enters this same handler
/// under a cluster token — which is why the permission gate accepts one.
async fn resolve(
    ctx: &AuthenticatedRequestContext,
    req: &poem::Request,
    session_id: Uuid,
    decision: ApprovalDecision,
) -> poem::Result<ActionResponse> {
    let actor = acting_approver(ctx);
    let Some(pending) = find_pending_approval(ctx, session_id, ApprovalKind::Admin).await? else {
        return Ok(ActionResponse::NotFound);
    };

    // Checked here rather than at the endpoint so it can't be reached around,
    // and so it reuses the row the lookup above already read. Only approvals:
    // rejecting your own session grants nothing.
    if matches!(decision, ApprovalDecision::Approved(_)) {
        require_not_self_approval(ctx, &pending.username).await?;
    }

    local_or_forward(ctx, req, pending.owner, || async {
        Ok(
            if resolve_locally(ctx, session_id, ApprovalKind::Admin, decision, &actor).await? {
                ActionResponse::Ok
            } else {
                ActionResponse::NotFound
            },
        )
    })
    .await
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/session-approvals",
        method = "get",
        operation_id = "get_session_approvals"
    )]
    async fn api_list(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        _sec_scheme: AnySecurityScheme,
    ) -> poem::Result<ListResponse> {
        require_admin_permission(&ctx, Some(AdminPermission::ApproveSessions)).await?;
        let services = ctx.services();

        // Any node can serve the list: requests are first-class rows in the
        // shared database (every row is pending by definition).
        let requests = SessionApprovalRequest::Entity::find()
            .filter(
                SessionApprovalRequest::Column::Kind
                    .eq(SessionApprovalRequest::ApprovalRequestKind::Admin),
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
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        scope: Query<ApprovalScope>,
        req: &poem::Request,
        _sec_scheme: AnySecurityScheme,
    ) -> poem::Result<ActionResponse> {
        require_cluster_or_admin_permission(&ctx, AdminPermission::ApproveSessions).await?;
        resolve(&ctx, req, id.0, ApprovalDecision::Approved(scope.0)).await
    }

    #[oai(
        path = "/session-approvals/:id/reject",
        method = "post",
        operation_id = "reject_session"
    )]
    async fn api_reject(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        req: &poem::Request,
        _sec_scheme: AnySecurityScheme,
    ) -> poem::Result<ActionResponse> {
        require_cluster_or_admin_permission(&ctx, AdminPermission::ApproveSessions).await?;
        resolve(&ctx, req, id.0, ApprovalDecision::Rejected).await
    }
}

#[handler]
pub async fn api_get_session_approvals_stream(
    ctx: Data<&AuthenticatedRequestContext>,
    ws: WebSocket,
) -> Result<impl IntoResponse, WarpgateError> {
    require_admin_permission(&ctx, Some(AdminPermission::ApproveSessions)).await?;

    let mut rx = ctx
        .services()
        .auth_state_store
        .lock()
        .await
        .subscribe_admin_approval_request();

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
