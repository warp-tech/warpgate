use crate::helpers::ApiResult;
use anyhow::Context;
use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::hash::generate_ticket_secret;
use warpgate_db_entities::Ticket;

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
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
    ) -> ApiResult<GetTicketsResponse> {
        use warpgate_db_entities::Ticket;

        let db = db.lock().await;
        let tickets = Ticket::Entity::find()
            .all(&*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        let tickets = tickets
            .into_iter()
            .map(Into::into)
            .collect::<Vec<Ticket::Model>>();
        Ok(GetTicketsResponse::Ok(Json(tickets)))
    }

    #[oai(path = "/tickets", method = "post", operation_id = "create_ticket")]
    async fn api_create_ticket(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        body: Json<CreateTicketRequest>,
    ) -> ApiResult<CreateTicketResponse> {
        use warpgate_db_entities::Ticket;

        if body.username.is_empty() {
            return Ok(CreateTicketResponse::BadRequest(Json("username".into())));
        }
        if body.target_name.is_empty() {
            return Ok(CreateTicketResponse::BadRequest(Json("target_name".into())));
        }

        let db = db.lock().await;
        let secret = generate_ticket_secret();
        let values = Ticket::ActiveModel {
            id: Set(Uuid::new_v4()),
            secret: Set(secret.expose_secret().to_string()),
            username: Set(body.username.clone()),
            target: Set(body.target_name.clone()),
            created: Set(chrono::Utc::now()),
            ..Default::default()
        };

        let ticket = values.insert(&*db).await.context("Error saving ticket")?;

        Ok(CreateTicketResponse::Created(Json(TicketAndSecret {
            secret: secret.expose_secret().to_string(),
            ticket,
        })))
    }
}
