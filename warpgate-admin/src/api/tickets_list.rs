use anyhow::Context;
use chrono::{DateTime, Utc};
use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter};
use serde::Serialize;
use uuid::Uuid;
use warpgate_common::helpers::hash::generate_ticket_secret;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_db_entities::{Target, Ticket, User};

use super::AnySecurityScheme;
use crate::api::common::require_admin_permission;

pub struct Api;

#[derive(Serialize, Object)]
#[oai(rename = "Ticket")]
pub struct TicketModel {
    pub id: Uuid,
    pub user_id: Uuid,
    pub username: String,
    pub description: String,
    pub target_id: Uuid,
    pub target_name: String,
    pub uses_left: Option<i16>,
    pub expiry: Option<DateTime<Utc>>,
    pub created: DateTime<Utc>,
    pub self_service: bool,
}

impl TicketModel {
    async fn from_entity(
        ticket: Ticket::Model,
        db: &sea_orm::DatabaseConnection,
    ) -> Result<Self, WarpgateError> {
        let user = ticket
            .find_related(User::Entity)
            .one(db)
            .await?
            .ok_or_else(|| WarpgateError::InconsistentState)?;
        let target = ticket
            .find_related(Target::Entity)
            .one(db)
            .await?
            .ok_or_else(|| WarpgateError::InconsistentState)?;

        Ok(Self {
            id: ticket.id,
            user_id: ticket.user_id,
            username: user.username,
            description: ticket.description,
            target_id: ticket.target_id,
            target_name: target.name,
            uses_left: ticket.uses_left,
            expiry: ticket.expiry,
            created: ticket.created,
            self_service: ticket.self_service,
        })
    }
}

#[derive(ApiResponse)]
enum GetTicketsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<TicketModel>>),
}

#[derive(Object)]
struct CreateTicketRequest {
    username: Option<String>,
    user_id: Option<Uuid>,
    target_id: Option<Uuid>,
    target_name: Option<String>,
    expiry: Option<DateTime<Utc>>,
    number_of_uses: Option<i16>,
    description: Option<String>,
}

#[derive(Object)]
struct TicketAndSecret {
    ticket: TicketModel,
    secret: String,
}

#[derive(ApiResponse)]
enum CreateTicketResponse {
    #[oai(status = 201)]
    Created(Json<TicketAndSecret>),

    #[oai(status = 400)]
    BadRequest(Json<String>),

    #[oai(status = 404)]
    NotFound,
}

#[OpenApi]
impl Api {
    #[oai(path = "/tickets", method = "get", operation_id = "get_tickets")]
    async fn api_get_all_tickets(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetTicketsResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;

        let db = ctx.services.db.lock().await;
        let tickets = Ticket::Entity::find().all(&*db).await?;
        let tickets = futures::future::join_all(
            tickets
                .into_iter()
                .map(|ticket| TicketModel::from_entity(ticket, &db)),
        )
        .await
        .into_iter()
        .collect::<Result<_, _>>()?;
        Ok(GetTicketsResponse::Ok(Json(tickets)))
    }

    #[oai(path = "/tickets", method = "post", operation_id = "create_ticket")]
    async fn api_create_ticket(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        body: Json<CreateTicketRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<CreateTicketResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::TicketsCreate)).await?;

        let db = ctx.services.db.lock().await;

        let Some(user) = (if let Some(user_id) = body.user_id {
            User::Entity::find_by_id(user_id).one(&*db).await?
        } else if let Some(username) = &body.username {
            User::Entity::find()
                .filter(User::Column::Username.eq(username.clone()))
                .one(&*db)
                .await?
        } else {
            return Ok(CreateTicketResponse::BadRequest(Json(
                "user_id or username is required".into(),
            )));
        }) else {
            return Ok(CreateTicketResponse::NotFound);
        };

        let Some(target) = (if let Some(target_id) = body.target_id {
            Target::Entity::find_by_id(target_id).one(&*db).await?
        } else if let Some(target_name) = &body.target_name {
            Target::Entity::find()
                .filter(Target::Column::Name.eq(target_name.clone()))
                .one(&*db)
                .await?
        } else {
            return Ok(CreateTicketResponse::BadRequest(Json(
                "target_id or target_name is required".into(),
            )));
        }) else {
            return Ok(CreateTicketResponse::NotFound);
        };

        let secret = generate_ticket_secret();
        let values = Ticket::ActiveModel {
            id: Set(Uuid::new_v4()),
            secret: Set(secret.expose_secret().to_string()),
            user_id: Set(user.id),
            target_id: Set(target.id),
            created: Set(chrono::Utc::now()),
            expiry: Set(body.expiry),
            uses_left: Set(body.number_of_uses),
            description: Set(body.description.clone().unwrap_or_default()),
            self_service: Set(false),
        };

        let ticket = values.insert(&*db).await.context("Error saving ticket")?;

        Ok(CreateTicketResponse::Created(Json(TicketAndSecret {
            secret: secret.expose_secret().to_string(),
            ticket: TicketModel::from_entity(ticket, &db).await?,
        })))
    }
}
