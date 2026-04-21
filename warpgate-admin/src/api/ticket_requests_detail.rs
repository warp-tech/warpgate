use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use uuid::Uuid;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::ticket_requests::{approve_ticket_request, deny_ticket_request};
use warpgate_db_entities::{TicketRequest, User};

use super::AnySecurityScheme;
use crate::api::common::require_admin_permission;

async fn admin_user_id(ctx: &AuthenticatedRequestContext) -> Result<Uuid, WarpgateError> {
    let Some(username) = ctx.auth.username() else {
        return Err(WarpgateError::NoAdminAccess);
    };
    let db = ctx.services.db.lock().await;
    let Some(user) = User::Entity::find()
        .filter(User::Column::Username.eq(username))
        .one(&*db)
        .await?
    else {
        return Err(WarpgateError::NoAdminAccess);
    };
    Ok(user.id)
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

        let uid = admin_user_id(&ctx).await?;
        match approve_ticket_request(&ctx.services.db, id.0, uid).await? {
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

        let uid = admin_user_id(&ctx).await?;
        match deny_ticket_request(&ctx.services.db, id.0, uid, body.reason.clone())
            .await?
        {
            Some(request) => Ok(DenyTicketRequestResponse::Ok(Json(request))),
            None => Ok(DenyTicketRequestResponse::NotFound),
        }
    }
}
