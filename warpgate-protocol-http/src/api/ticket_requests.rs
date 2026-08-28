use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, ModelTrait, QueryFilter, QueryOrder};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::{Secret, Target as TargetConfig, WarpgateError};
use warpgate_common_http::SessionAuthorization;
use warpgate_common_http::auth::AuthenticatedRequestContext;
use warpgate_core::ticket_requests::{
    ActivateTicketRequestError, CreateTicketRequestError, CreateTicketRequestParams,
    activate_ticket_request, create_ticket_request, delete_ticket,
};
use warpgate_db_entities::{Target, Ticket, TicketRequest};

use super::common::get_user;
use crate::api::auth_scheme::AuthedSession;

const fn is_ticket_session(ctx: &AuthenticatedRequestContext) -> bool {
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
    description: Option<String>,
}

#[derive(Object)]
struct ActivatedTicketModel {
    request: TicketRequest::Model,
    target: ActivatedTicketTargetInfo,
    secret: Option<String>,
}

/// Just the slim view of fields that the UI needs to show connection instructions
/// since the user might not have full role based access to the target
#[derive(Object)]
struct ActivatedTicketTargetInfo {
    pub name: String,
    pub kind: Target::TargetKind,
    pub external_host: Option<String>,
    pub default_database_name: Option<String>,
}

impl TryFrom<Target::Model> for ActivatedTicketTargetInfo {
    type Error = WarpgateError;

    fn try_from(model: Target::Model) -> Result<Self, Self::Error> {
        let target = TargetConfig::try_from(model)?;
        Ok(Self {
            name: target.name,
            kind: (&target.options).into(),
            external_host: target.options.external_host().map(ToString::to_string),
            default_database_name: target
                .options
                .default_database_name()
                .map(ToString::to_string),
        })
    }
}

#[derive(Object)]
struct TicketRequestResponse {
    request: TicketRequest::Model,
}

#[derive(Object)]
struct TicketRequestModel {
    pub id: Uuid,
    pub user_id: Uuid,
    pub target_id: Uuid,
    pub target_name: String,
    pub requested_duration_seconds: Option<i64>,
    pub description: String,
    pub status: warpgate_db_entities::TicketRequest::TicketRequestStatus,
    pub resolved_by_user_id: Option<Uuid>,
    pub ticket_id: Option<Uuid>,
    pub created: OffsetDateTime,
    pub resolved_at: Option<OffsetDateTime>,
    pub deny_reason: Option<String>,
}

#[derive(Object)]
struct MyTicketModel {
    pub id: Uuid,
    pub target_name: String,
    pub description: String,
    pub uses_left: Option<i16>,
    pub expiry: Option<OffsetDateTime>,
    pub created: OffsetDateTime,
}

#[derive(Object)]
struct CreatedRequest {
    pub request: TicketRequest::Model,
    pub target: ActivatedTicketTargetInfo,
    pub auto_approved_ticket_secret: Option<Secret<String>>,
}

#[derive(ApiResponse)]
enum CreateTicketRequestResponse {
    #[oai(status = 201)]
    Created(Json<CreatedRequest>),
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
    Ok(Json<Vec<TicketRequestModel>>),
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
    Ok(Json<Vec<MyTicketModel>>),
    #[oai(status = 401)]
    Unauthorized,
}

#[derive(ApiResponse)]
enum ActivateTicketRequestResponse {
    #[oai(status = 200)]
    Ok(Json<ActivatedTicketModel>),
    #[oai(status = 401)]
    Unauthorized,
    #[oai(status = 404)]
    NotFound,
    #[oai(status = 409)]
    AlreadyActivated(Json<String>),
    #[oai(status = 410)]
    TargetGone(Json<String>),
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
        operation_id = "create_ticket_request"
    )]
    async fn api_create_ticket_request(
        &self,
        ctx: AuthedSession,
        body: Json<CreateTicketRequestBody>,
    ) -> Result<CreateTicketRequestResponse, WarpgateError> {
        if is_ticket_session(&ctx) {
            return Ok(CreateTicketRequestResponse::Forbidden(Json(
                "Ticket-authenticated sessions cannot request new tickets".into(),
            )));
        }

        let db = &ctx.services().db;
        let Some(full) = ctx.auth.as_full_user() else {
            return Ok(CreateTicketRequestResponse::Unauthorized);
        };
        let Some(user_model) = get_user(&full, db).await? else {
            return Ok(CreateTicketRequestResponse::Unauthorized);
        };

        let target_name = body.target_name.trim().to_string();
        if target_name.is_empty() {
            return Ok(CreateTicketRequestResponse::BadRequest(Json(
                "target_name is required".into(),
            )));
        }

        let result = create_ticket_request(
            &ctx.services().db,
            &ctx.services().config_provider,
            CreateTicketRequestParams {
                user_id: user_model.id,
                username: user_model.username.clone(),
                target_name,
                duration_seconds: body.duration_seconds,
                description: body.description.clone().unwrap_or_default(),
            },
        )
        .await;

        match result {
            Ok(result) => Ok(CreateTicketRequestResponse::Created(Json(CreatedRequest {
                request: result.request,
                target: result.target.try_into()?,
                auto_approved_ticket_secret: result.auto_approved_secret,
            }))),
            Err(CreateTicketRequestError::InvalidInput(msg)) => {
                Ok(CreateTicketRequestResponse::BadRequest(Json(msg)))
            }
            Err(CreateTicketRequestError::Internal(e)) => Err(e),
        }
    }

    #[oai(
        path = "/ticket-requests",
        method = "get",
        operation_id = "get_my_ticket_requests"
    )]
    async fn api_get_my_ticket_requests(
        &self,
        ctx: AuthedSession,
    ) -> Result<GetTicketRequestsResponse, WarpgateError> {
        if is_ticket_session(&ctx) {
            return Ok(GetTicketRequestsResponse::Unauthorized);
        }
        let db = &ctx.services().db;
        let Some(full) = ctx.auth.as_full_user() else {
            return Ok(GetTicketRequestsResponse::Unauthorized);
        };
        let Some(user_model) = get_user(&full, db).await? else {
            return Ok(GetTicketRequestsResponse::Unauthorized);
        };

        let requests = TicketRequest::Entity::find()
            .filter(TicketRequest::Column::UserId.eq(user_model.id))
            .order_by_desc(TicketRequest::Column::Created)
            .all(db)
            .await?;

        let mut views = Vec::with_capacity(requests.len());
        for req in requests {
            let target_name = req
                .find_related(Target::Entity)
                .one(db)
                .await?
                .map(|t| t.name)
                .unwrap_or_default();
            views.push(TicketRequestModel {
                id: req.id,
                user_id: req.user_id,
                target_id: req.target_id,
                target_name,
                requested_duration_seconds: req.requested_duration_seconds,
                description: req.description,
                status: req.status,
                resolved_by_user_id: req.resolved_by_user_id,
                ticket_id: req.ticket_id,
                created: req.created,
                resolved_at: req.resolved_at,
                deny_reason: req.deny_reason,
            });
        }

        Ok(GetTicketRequestsResponse::Ok(Json(views)))
    }

    #[oai(
        path = "/ticket-requests/:id",
        method = "get",
        operation_id = "get_my_ticket_request"
    )]
    async fn api_get_my_ticket_request(
        &self,
        ctx: AuthedSession,
        id: Path<Uuid>,
    ) -> Result<GetTicketRequestResponse, WarpgateError> {
        if is_ticket_session(&ctx) {
            return Ok(GetTicketRequestResponse::Unauthorized);
        }
        let db = &ctx.services().db;
        let Some(full) = ctx.auth.as_full_user() else {
            return Ok(GetTicketRequestResponse::Unauthorized);
        };
        let Some(user_model) = get_user(&full, db).await? else {
            return Ok(GetTicketRequestResponse::Unauthorized);
        };

        let Some(request) = TicketRequest::Entity::find_by_id(id.0)
            .filter(TicketRequest::Column::UserId.eq(user_model.id))
            .one(db)
            .await?
        else {
            return Ok(GetTicketRequestResponse::NotFound);
        };

        Ok(GetTicketRequestResponse::Ok(Json(TicketRequestResponse {
            request,
        })))
    }

    #[oai(
        path = "/ticket-requests/:id/activate",
        method = "post",
        operation_id = "activate_ticket_request"
    )]
    async fn api_activate_ticket_request(
        &self,
        ctx: AuthedSession,
        id: Path<Uuid>,
    ) -> Result<ActivateTicketRequestResponse, WarpgateError> {
        if is_ticket_session(&ctx) {
            return Ok(ActivateTicketRequestResponse::Unauthorized);
        }
        let db = &ctx.services().db;
        let Some(full) = ctx.auth.as_full_user() else {
            return Ok(ActivateTicketRequestResponse::Unauthorized);
        };
        let Some(user_model) = get_user(&full, db).await? else {
            return Ok(ActivateTicketRequestResponse::Unauthorized);
        };

        match activate_ticket_request(&ctx.services().db, id.0, user_model.id).await {
            Ok(activated) => Ok(ActivateTicketRequestResponse::Ok(Json(
                ActivatedTicketModel {
                    request: activated.request,
                    target: activated.target.try_into()?,
                    secret: Some(activated.secret.expose_secret().clone()),
                },
            ))),
            Err(ActivateTicketRequestError::NotFound) => {
                Ok(ActivateTicketRequestResponse::NotFound)
            }
            Err(ActivateTicketRequestError::AlreadyActivated) => {
                Ok(ActivateTicketRequestResponse::AlreadyActivated(Json(
                    "This ticket has already been activated".into(),
                )))
            }
            Err(ActivateTicketRequestError::TargetGone) => {
                Ok(ActivateTicketRequestResponse::TargetGone(Json(
                    "The target no longer exists".into(),
                )))
            }
            Err(ActivateTicketRequestError::Internal(e)) => Err(e),
        }
    }

    #[oai(path = "/my-tickets", method = "get", operation_id = "get_my_tickets")]
    async fn api_get_my_tickets(
        &self,
        ctx: AuthedSession,
    ) -> Result<GetMyTicketsResponse, WarpgateError> {
        if is_ticket_session(&ctx) {
            return Ok(GetMyTicketsResponse::Unauthorized);
        }
        let db = &ctx.services().db;
        let Some(full) = ctx.auth.as_full_user() else {
            return Ok(GetMyTicketsResponse::Unauthorized);
        };
        let Some(user_model) = get_user(&full, db).await? else {
            return Ok(GetMyTicketsResponse::Unauthorized);
        };

        // Only show self-service tickets — admin-created tickets are not visible to the user
        let tickets = Ticket::Entity::find()
            .filter(Ticket::Column::UserId.eq(user_model.id))
            .filter(Ticket::Column::SelfService.eq(true))
            .order_by_desc(Ticket::Column::Created)
            .all(db)
            .await?;

        let mut result = Vec::with_capacity(tickets.len());
        for ticket in tickets {
            let target_name = ticket
                .find_related(Target::Entity)
                .one(db)
                .await?
                .map(|t| t.name)
                .unwrap_or_default();
            result.push(MyTicketModel {
                id: ticket.id,
                target_name,
                description: ticket.description,
                uses_left: ticket.uses_left,
                expiry: ticket.expiry,
                created: ticket.created,
            });
        }

        Ok(GetMyTicketsResponse::Ok(Json(result)))
    }

    #[oai(
        path = "/my-tickets/:id",
        method = "delete",
        operation_id = "delete_my_ticket"
    )]
    async fn api_delete_my_ticket(
        &self,
        ctx: AuthedSession,
        id: Path<Uuid>,
    ) -> Result<DeleteMyTicketResponse, WarpgateError> {
        if is_ticket_session(&ctx) {
            return Ok(DeleteMyTicketResponse::Unauthorized);
        }
        let db = &ctx.services().db;
        let Some(full) = ctx.auth.as_full_user() else {
            return Ok(DeleteMyTicketResponse::Unauthorized);
        };
        let Some(user_model) = get_user(&full, db).await? else {
            return Ok(DeleteMyTicketResponse::Unauthorized);
        };

        // Users can only delete their own self-service tickets, not admin-issued ones
        let Some(ticket) = Ticket::Entity::find_by_id(id.0)
            .filter(Ticket::Column::UserId.eq(user_model.id))
            .filter(Ticket::Column::SelfService.eq(true))
            .one(db)
            .await?
        else {
            return Ok(DeleteMyTicketResponse::NotFound);
        };

        delete_ticket(db, ticket.id).await?;
        Ok(DeleteMyTicketResponse::Deleted)
    }
}
