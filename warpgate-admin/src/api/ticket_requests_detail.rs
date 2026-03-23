use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use uuid::Uuid;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::ticket_requests::{approve_ticket_request, deny_ticket_request};
use warpgate_db_entities::TicketRequest;

use super::AnySecurityScheme;
use crate::api::common::require_admin_permission;

fn admin_username(ctx: &AuthenticatedRequestContext) -> String {
    ctx.auth
        .username()
        .cloned()
        .unwrap_or_else(|| "admin-token".to_string())
}

pub struct Api;

#[derive(Object)]
struct DenyTicketRequestBody {
    reason: Option<String>,
}

#[derive(ApiResponse)]
enum ApproveTicketRequestResponse {
    #[oai(status = 200)]
    Ok(Json<TicketRequest::Model>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DenyTicketRequestResponse {
    #[oai(status = 200)]
    Ok(Json<TicketRequest::Model>),
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

        match approve_ticket_request(&ctx.services.db, id.0, &admin_username(&ctx)).await? {
            Some(request) => Ok(ApproveTicketRequestResponse::Ok(Json(request))),
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

        match deny_ticket_request(&ctx.services.db, id.0, &admin_username(&ctx), body.reason.clone())
            .await?
        {
            Some(request) => Ok(DenyTicketRequestResponse::Ok(Json(request))),
            None => Ok(DenyTicketRequestResponse::NotFound),
        }
    }
}
