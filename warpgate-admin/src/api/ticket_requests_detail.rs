use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use uuid::Uuid;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::ticket_requests::{
    TicketRequestDetails, approve_ticket_request, deny_ticket_request,
    resolve_ticket_request_names,
};

use super::AnySecurityScheme;
use crate::api::common::require_admin_permission;

const fn admin_user_id(ctx: &AuthenticatedRequestContext) -> Option<Uuid> {
    let id = ctx.auth.user_id();
    if id.is_nil() { None } else { Some(id) }
}

pub struct Api;

/// Projects a single resolved request, so the response carries the same shape
/// as the list endpoint.
async fn resolve_one(
    db: &sea_orm::DatabaseConnection,
    request: warpgate_db_entities::TicketRequest::Model,
) -> Result<TicketRequestDetails, WarpgateError> {
    resolve_ticket_request_names(db, vec![request])
        .await?
        .pop()
        .ok_or_else(|| WarpgateError::from(anyhow::anyhow!("request vanished while resolving")))
}

#[derive(Object)]
struct DenyTicketRequestBody {
    reason: Option<String>,
}

#[derive(ApiResponse)]
enum ApproveTicketRequestResponse {
    #[oai(status = 200)]
    Ok(Json<TicketRequestDetails>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DenyTicketRequestResponse {
    #[oai(status = 200)]
    Ok(Json<TicketRequestDetails>),
    #[oai(status = 404)]
    NotFound,
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/ticket-requests/:id/approve",
        method = "post",
        operation_id = "approve_ticket_request"
    )]
    async fn api_approve_ticket_request(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<ApproveTicketRequestResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::TicketRequestsManage)).await?;

        let uid = admin_user_id(&ctx);
        let db = &ctx.services().db;
        match approve_ticket_request(db, id.0, uid).await? {
            Some(request) => Ok(ApproveTicketRequestResponse::Ok(Json(
                resolve_one(db, request).await?,
            ))),
            None => Ok(ApproveTicketRequestResponse::NotFound),
        }
    }

    #[oai(
        path = "/ticket-requests/:id/deny",
        method = "post",
        operation_id = "deny_ticket_request"
    )]
    async fn api_deny_ticket_request(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        body: Json<DenyTicketRequestBody>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DenyTicketRequestResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::TicketRequestsManage)).await?;

        let uid = admin_user_id(&ctx);
        let db = &ctx.services().db;
        match deny_ticket_request(db, id.0, uid, body.reason.clone()).await? {
            Some(request) => Ok(DenyTicketRequestResponse::Ok(Json(
                resolve_one(db, request).await?,
            ))),
            None => Ok(DenyTicketRequestResponse::NotFound),
        }
    }
}
