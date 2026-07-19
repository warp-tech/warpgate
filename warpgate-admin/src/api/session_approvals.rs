use futures::{SinkExt, StreamExt};
use poem::http::StatusCode;
use poem::web::Data;
use poem::web::websocket::{Message, WebSocket};
use poem::{IntoResponse, Response, handler};
use poem_openapi::param::{Path, Query};
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Enum, Object, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use time::OffsetDateTime;
use tokio::sync::broadcast;
use uuid::Uuid;
use warpgate_common::auth::ApprovalKind;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_common_http::approvals::{ResolveApprovalRpc, acting_approver, resolve_approval};
use warpgate_common_http::{AuthenticatedRequestContext, RequestAuthorization};
use warpgate_core::approvals::{ApprovalDecision, ApprovalScope};
use warpgate_db_entities::SessionApprovalRequest;

use super::AnySecurityScheme;
use crate::api::common::require_admin_permission;

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
    identification_string: String,
    /// When administrator-approval caching is enabled, the caching window in
    /// seconds; `None` when caching is disabled.
    caching_grace_seconds: Option<i64>,
}

/// How an administrator approval should be remembered for bypass.
#[derive(Enum, Clone, Copy)]
enum SessionApprovalScope {
    Once,
    Target,
    AllTargets,
}

impl From<SessionApprovalScope> for ApprovalScope {
    fn from(scope: SessionApprovalScope) -> Self {
        match scope {
            SessionApprovalScope::Once => Self::Once,
            SessionApprovalScope::Target => Self::Target,
            SessionApprovalScope::AllTargets => Self::AllTargets,
        }
    }
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
        require_admin_permission(&ctx, Some(AdminPermission::SessionsView)).await?;
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
                    id: r.id.to_string(),
                    protocol: r.protocol,
                    address: r.remote_address,
                    username: r.username,
                    target: r.target,
                    started: r.started,
                    identification_string: r.identification_string,
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
        scope: Query<SessionApprovalScope>,
        _sec_scheme: AnySecurityScheme,
    ) -> poem::Result<ActionResponse> {
        require_admin_permission(&ctx, Some(AdminPermission::SessionsTerminate)).await?;
        let resolved = resolve_approval(
            &ctx,
            id.0,
            ApprovalKind::Admin,
            ApprovalDecision::Approved(scope.0.into()),
            &acting_approver(&ctx),
        )
        .await?;
        Ok(if resolved {
            ActionResponse::Ok
        } else {
            ActionResponse::NotFound
        })
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
        _sec_scheme: AnySecurityScheme,
    ) -> poem::Result<ActionResponse> {
        require_admin_permission(&ctx, Some(AdminPermission::SessionsTerminate)).await?;
        let resolved = resolve_approval(
            &ctx,
            id.0,
            ApprovalKind::Admin,
            ApprovalDecision::Rejected,
            &acting_approver(&ctx),
        )
        .await?;
        Ok(if resolved {
            ActionResponse::Ok
        } else {
            ActionResponse::NotFound
        })
    }
}

/// The owner side of a cross-node resolution: applies the decision carried in
/// the body to the locally-owned auth state. Cluster-token authenticated only —
/// admins go through the public approve/reject endpoints on any node instead.
#[handler]
pub async fn api_resolve_session_approval(
    ctx: Data<&AuthenticatedRequestContext>,
    id: poem::web::Path<Uuid>,
    body: poem::web::Json<ResolveApprovalRpc>,
) -> poem::Result<Response> {
    if !matches!(ctx.auth, RequestAuthorization::ClusterToken) {
        return Err(poem::Error::from_status(StatusCode::UNAUTHORIZED));
    }
    let applied = ctx
        .services()
        .apply_approval_resolution(id.0, body.kind, body.decision, &body.actor)
        .await
        .map_err(poem::error::InternalServerError)?;
    Ok(Response::builder()
        .status(if applied {
            StatusCode::OK
        } else {
            StatusCode::NOT_FOUND
        })
        .finish())
}

#[handler]
pub async fn api_get_session_approvals_stream(
    ctx: Data<&AuthenticatedRequestContext>,
    ws: WebSocket,
) -> Result<impl IntoResponse, WarpgateError> {
    require_admin_permission(&ctx, Some(AdminPermission::SessionsView)).await?;

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
