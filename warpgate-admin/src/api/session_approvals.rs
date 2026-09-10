use futures::{SinkExt, StreamExt};
use poem::web::Data;
use poem::web::websocket::{Message, WebSocket};
use poem::{IntoResponse, handler};
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use time::OffsetDateTime;
use tokio::sync::broadcast;
use warpgate_common::auth::ApprovalKind;
use warpgate_common::{AdminPermission, UserSessionId, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::approvals::{ApprovalDecision, ApprovalScope};
use warpgate_db_entities::{Parameters, SessionApprovalRequest};

use super::AdminContext;
use crate::api::common::require_admin_permission;
use crate::approvals::{Approver, find_pending_approval, resolve_pending_approval};

pub struct Api;

#[derive(Object)]
struct SessionApprovalItem {
    id: String,
    protocol: String,
    address: Option<String>,
    username: String,
    target: String,
    started: OffsetDateTime,
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

#[derive(Object)]
struct ApproveSessionRequest {
    scope: ApprovalScope,
    target: String,
}

#[derive(Object)]
struct RejectSessionRequest {
    target: String,
}

async fn resolve_inner(
    ctx: &AuthenticatedRequestContext,
    session_id: UserSessionId,
    target: &str, // target seen by the approval to ensure no TOCTOU
    decision: ApprovalDecision,
) -> poem::Result<ActionResponse> {
    let Some(pending) = find_pending_approval(ctx, session_id, ApprovalKind::Admin, target).await?
    else {
        return Ok(ActionResponse::NotFound);
    };

    if resolve_pending_approval(ctx, Approver::Administrator, pending, decision).await? {
        Ok(ActionResponse::Ok)
    } else {
        Ok(ActionResponse::NotFound)
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

        use SessionApprovalRequest as SAR;

        let requests = SAR::Entity::find()
            .filter(SAR::Column::Kind.eq(ApprovalKind::Admin))
            .filter(SAR::Column::Status.eq(SAR::ApprovalRequestStatus::Pending))
            .order_by_asc(SAR::Column::Started)
            .all(&admin.services().db)
            .await
            .map_err(WarpgateError::from)?;

        let caching_grace_seconds = Parameters::Entity::get(&admin.services().db)
            .await
            .map_err(WarpgateError::from)?
            .admin_approval_grace_period_seconds;

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
        Path(id): Path<UserSessionId>,
        body: Json<ApproveSessionRequest>,
    ) -> poem::Result<ActionResponse> {
        admin.require(AdminPermission::ApproveSessions)?;
        resolve_inner(
            &admin,
            id,
            &body.target,
            ApprovalDecision::Approved(body.scope),
        )
        .await
    }

    #[oai(
        path = "/session-approvals/:id/reject",
        method = "post",
        operation_id = "reject_session"
    )]
    async fn api_reject(
        &self,
        admin: AdminContext,
        Path(id): Path<UserSessionId>,
        body: Json<RejectSessionRequest>,
    ) -> poem::Result<ActionResponse> {
        admin.require(AdminPermission::ApproveSessions)?;
        resolve_inner(&admin, id, &body.target, ApprovalDecision::Rejected).await
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
