use poem_openapi::param::Query;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_core::ticket_requests::list_ticket_requests;
use warpgate_db_entities::TicketRequest::TicketRequestStatus;

use super::AdminContext;
use crate::api::ticket_request_details::{
    TicketRequestDetails, batch_resolve_ticket_request_names,
};

pub struct Api;

#[derive(ApiResponse)]
enum GetTicketRequestsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<TicketRequestDetails>>),
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
        admin: AdminContext,
        status: Query<Option<TicketRequestStatus>>,
    ) -> Result<GetTicketRequestsResponse, WarpgateError> {
        admin.require(AdminPermission::TicketRequestsManage)?;

        let requests = list_ticket_requests(&admin.services().db, status.0).await?;
        let requests = batch_resolve_ticket_request_names(&admin.services().db, requests).await?;
        Ok(GetTicketRequestsResponse::Ok(Json(requests)))
    }
}
