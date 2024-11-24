use std::sync::Arc;

use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{DatabaseConnection, EntityTrait, ModelTrait};
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::WarpgateError;

use super::TokenSecurityScheme;

pub struct Api;

#[derive(ApiResponse)]
enum DeleteTicketResponse {
    #[oai(status = 204)]
    Deleted,

    #[oai(status = 404)]
    NotFound,
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/tickets/:id",
        method = "delete",
        operation_id = "delete_ticket"
    )]
    async fn api_delete_ticket(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _auth: TokenSecurityScheme,
    ) ->Result<DeleteTicketResponse,WarpgateError> {
        use warpgate_db_entities::Ticket;
        let db = db.lock().await;

        let ticket = Ticket::Entity::find_by_id(id.0)
            .one(&*db)
            .await
            ?;

        match ticket {
            Some(ticket) => {
                ticket
                    .delete(&*db)
                    .await
                    ?;
                Ok(DeleteTicketResponse::Deleted)
            }
            None => Ok(DeleteTicketResponse::NotFound),
        }
    }
}
