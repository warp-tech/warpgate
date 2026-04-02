use anyhow::Context;
use chrono::{DateTime, Utc};
use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, EntityTrait};
use uuid::Uuid;
use warpgate_common::helpers::hash::generate_ticket_secret;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::logging::{format_related_ids, AuditEvent};
use warpgate_db_entities::Ticket;

use super::AnySecurityScheme;
use crate::api::common::require_admin_permission;

pub struct Api;

#[derive(ApiResponse)]
enum GetTicketsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<Ticket::Model>>),
}

#[derive(Object)]
struct CreateTicketRequest {
    username: String,
    target_name: String,
    expiry: Option<DateTime<Utc>>,
    number_of_uses: Option<i16>,
    description: Option<String>,
}

#[derive(Object)]
struct TicketAndSecret {
    ticket: Ticket::Model,
    secret: String,
}

#[derive(ApiResponse)]
enum CreateTicketResponse {
    #[oai(status = 201)]
    Created(Json<TicketAndSecret>),

    #[oai(status = 400)]
    BadRequest(Json<String>),
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

        use warpgate_db_entities::Ticket;

        let db = ctx.services.db.lock().await;
        let tickets = Ticket::Entity::find().all(&*db).await?;
        Ok(GetTicketsResponse::Ok(Json(tickets)))
    }

    #[oai(path = "/tickets", method = "post", operation_id = "create_ticket")]
    async fn api_create_ticket(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        body: Json<CreateTicketRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> poem::Result<CreateTicketResponse> {
        require_admin_permission(&ctx, Some(AdminPermission::TicketsCreate)).await?;

        use warpgate_db_entities::Ticket;

        if body.username.is_empty() {
            return Ok(CreateTicketResponse::BadRequest(Json("username".into())));
        }
        if body.target_name.is_empty() {
            return Ok(CreateTicketResponse::BadRequest(Json("target_name".into())));
        }

        let db = ctx.services.db.lock().await;
        let secret = generate_ticket_secret();
        let values = Ticket::ActiveModel {
            id: Set(Uuid::new_v4()),
            secret: Set(secret.expose_secret().to_string()),
            username: Set(body.username.clone()),
            target: Set(body.target_name.clone()),
            created: Set(chrono::Utc::now()),
            expiry: Set(body.expiry),
            uses_left: Set(body.number_of_uses),
            description: Set(body.description.clone().unwrap_or_default()),
        };

        let ticket = values.insert(&*db).await.context("Error saving ticket")?;

        AuditEvent::TicketCreated {
            ticket_id: ticket.id,
            username: ticket.username.clone(),
            target: ticket.target.clone(),
            related_users: format_related_ids(&[ticket.id, ctx.auth.user_id()]),
        }
        .emit();

        Ok(CreateTicketResponse::Created(Json(TicketAndSecret {
            secret: secret.expose_secret().to_string(),
            ticket,
        })))
    }
}
