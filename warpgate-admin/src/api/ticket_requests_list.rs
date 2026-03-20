use poem::web::Data;
use poem_openapi::param::Query;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use warpgate_common::WarpgateError;
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::ticket_requests::list_ticket_requests;
use warpgate_db_entities::TicketRequest;
use warpgate_db_entities::TicketRequest::TicketRequestStatus;

use super::AnySecurityScheme;
use crate::api::common::require_admin_permission;

pub struct Api;

#[derive(ApiResponse)]
enum GetTicketRequestsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<TicketRequest::Model>>),
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/ticket-requests",
        method = "get",
        operation_id = "get_ticket_requests"
    )]
    async fn api_get_all_ticket_requests(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        status: Query<Option<TicketRequestStatus>>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetTicketRequestsResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;

        let requests = list_ticket_requests(&ctx.services.db, status.0).await?;
        Ok(GetTicketRequestsResponse::Ok(Json(requests)))
    }
}
