use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, ModelTrait, QueryFilter, QueryOrder};
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_common_http::auth::AuthenticatedRequestContext;
use warpgate_common_http::SessionAuthorization;
use warpgate_core::ticket_requests::{
    create_ticket_request, CreateTicketRequestParams, TicketRequestResult,
};
use warpgate_db_entities::{Ticket, TicketRequest};

use super::common::get_user;
use crate::common::endpoint_auth;

fn is_ticket_session(ctx: &AuthenticatedRequestContext) -> bool {
    matches!(
        &ctx.auth,
        warpgate_common_http::RequestAuthorization::Session(SessionAuthorization::Ticket { .. })
    )
}

pub struct Api;

#[derive(Object)]
struct CreateTicketRequestBody {
    target_name: String,
    duration_seconds: Option<i64>,
    uses: Option<i16>,
    description: Option<String>,
}

#[derive(Object)]
struct TicketRequestResponse {
    request: TicketRequest::Model,
    secret: Option<String>,
}

impl From<TicketRequestResult> for TicketRequestResponse {
    fn from(result: TicketRequestResult) -> Self {
        Self {
            request: result.request,
            secret: result.secret.map(|s| s.expose_secret().to_string()),
        }
    }
}

#[derive(ApiResponse)]
enum CreateTicketRequestResponse {
    #[oai(status = 201)]
    Created(Json<TicketRequestResponse>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 401)]
    Unauthorized,
    #[oai(status = 403)]
    Forbidden(Json<String>),
}

#[derive(ApiResponse)]
enum GetTicketRequestsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<TicketRequest::Model>>),
    #[oai(status = 401)]
    Unauthorized,
}

#[derive(ApiResponse)]
enum GetTicketRequestResponse {
    #[oai(status = 200)]
    Ok(Json<TicketRequestResponse>),
    #[oai(status = 401)]
    Unauthorized,
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum GetMyTicketsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<Ticket::Model>>),
    #[oai(status = 401)]
    Unauthorized,
}

#[derive(ApiResponse)]
enum DeleteMyTicketResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 401)]
    Unauthorized,
    #[oai(status = 404)]
    NotFound,
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/ticket-requests",
        method = "post",
        operation_id = "create_ticket_request",
        transform = "endpoint_auth"
    )]
    async fn api_create_ticket_request(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        body: Json<CreateTicketRequestBody>,
    ) -> Result<CreateTicketRequestResponse, WarpgateError> {
        if is_ticket_session(&ctx) {
            return Ok(CreateTicketRequestResponse::Forbidden(Json(
                "Ticket-authenticated sessions cannot request new tickets".into(),
            )));
        }

        let db = ctx.services.db.lock().await;
        let Some(user_model) = get_user(&ctx.auth, &db).await? else {
            return Ok(CreateTicketRequestResponse::Unauthorized);
        };
        drop(db);

        let target_name = body.target_name.trim().to_string();
        if target_name.is_empty() {
            return Ok(CreateTicketRequestResponse::BadRequest(Json(
                "target_name is required".into(),
            )));
        }

        let result = create_ticket_request(
            &ctx.services.db,
            &ctx.services.config_provider,
            CreateTicketRequestParams {
                user_id: user_model.id,
                username: user_model.username.clone(),
                target_name,
                duration_seconds: body.duration_seconds,
                uses: body.uses,
                description: body.description.clone().unwrap_or_default(),
            },
        )
        .await;

        match result {
            Ok(result) => Ok(CreateTicketRequestResponse::Created(Json(result.into()))),
            Err(e) => Ok(CreateTicketRequestResponse::BadRequest(Json(
                e.to_string(),
            ))),
        }
    }

    #[oai(
        path = "/ticket-requests",
        method = "get",
        operation_id = "get_my_ticket_requests",
        transform = "endpoint_auth"
    )]
    async fn api_get_my_ticket_requests(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
    ) -> Result<GetTicketRequestsResponse, WarpgateError> {
        if is_ticket_session(&ctx) {
            return Ok(GetTicketRequestsResponse::Unauthorized);
        }
        let db = ctx.services.db.lock().await;
        let Some(user_model) = get_user(&ctx.auth, &db).await? else {
            return Ok(GetTicketRequestsResponse::Unauthorized);
        };

        let requests = TicketRequest::Entity::find()
            .filter(TicketRequest::Column::UserId.eq(user_model.id))
            .order_by_desc(TicketRequest::Column::Created)
            .all(&*db)
            .await?;

        Ok(GetTicketRequestsResponse::Ok(Json(requests)))
    }

    #[oai(
        path = "/ticket-requests/:id",
        method = "get",
        operation_id = "get_my_ticket_request",
        transform = "endpoint_auth"
    )]
    async fn api_get_my_ticket_request(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
    ) -> Result<GetTicketRequestResponse, WarpgateError> {
        if is_ticket_session(&ctx) {
            return Ok(GetTicketRequestResponse::Unauthorized);
        }
        let db = ctx.services.db.lock().await;
        let Some(user_model) = get_user(&ctx.auth, &db).await? else {
            return Ok(GetTicketRequestResponse::Unauthorized);
        };

        let Some(request) = TicketRequest::Entity::find_by_id(id.0)
            .filter(TicketRequest::Column::UserId.eq(user_model.id))
            .one(&*db)
            .await?
        else {
            return Ok(GetTicketRequestResponse::NotFound);
        };

        Ok(GetTicketRequestResponse::Ok(Json(TicketRequestResponse {
            request,
            secret: None,
        })))
    }

    #[oai(
        path = "/my-tickets",
        method = "get",
        operation_id = "get_my_tickets",
        transform = "endpoint_auth"
    )]
    async fn api_get_my_tickets(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
    ) -> Result<GetMyTicketsResponse, WarpgateError> {
        if is_ticket_session(&ctx) {
            return Ok(GetMyTicketsResponse::Unauthorized);
        }
        let db = ctx.services.db.lock().await;
        let Some(user_model) = get_user(&ctx.auth, &db).await? else {
            return Ok(GetMyTicketsResponse::Unauthorized);
        };

        let tickets = Ticket::Entity::find()
            .filter(Ticket::Column::Username.eq(&user_model.username))
            .filter(Ticket::Column::SelfService.eq(true))
            .order_by_desc(Ticket::Column::Created)
            .all(&*db)
            .await?;

        Ok(GetMyTicketsResponse::Ok(Json(tickets)))
    }

    #[oai(
        path = "/my-tickets/:id",
        method = "delete",
        operation_id = "delete_my_ticket",
        transform = "endpoint_auth"
    )]
    async fn api_delete_my_ticket(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
    ) -> Result<DeleteMyTicketResponse, WarpgateError> {
        if is_ticket_session(&ctx) {
            return Ok(DeleteMyTicketResponse::Unauthorized);
        }
        let db = ctx.services.db.lock().await;
        let Some(user_model) = get_user(&ctx.auth, &db).await? else {
            return Ok(DeleteMyTicketResponse::Unauthorized);
        };

        let Some(ticket) = Ticket::Entity::find_by_id(id.0)
            .filter(Ticket::Column::Username.eq(&user_model.username))
            .filter(Ticket::Column::SelfService.eq(true))
            .one(&*db)
            .await?
        else {
            return Ok(DeleteMyTicketResponse::NotFound);
        };

        ticket.delete(&*db).await?;
        Ok(DeleteMyTicketResponse::Deleted)
    }
}
