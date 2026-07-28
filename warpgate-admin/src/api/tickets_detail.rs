use poem_openapi::param::Path;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{EntityTrait, ModelTrait};
use uuid::Uuid;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_core::logging::AuditEvent;
use warpgate_db_entities::{Target, User};

use super::AdminContext;

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
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<DeleteTicketResponse, WarpgateError> {
        use warpgate_db_entities::Ticket;

        admin.require(AdminPermission::TicketsDelete)?;

        let db = &admin.services().db;

        let Some(ticket) = Ticket::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(DeleteTicketResponse::NotFound);
        };

        let user = User::Entity::find_by_id(ticket.user_id).one(db).await?;

        let target = Target::Entity::find_by_id(ticket.target_id).one(db).await?;

        if let (Some(user), Some(target)) = (user, target) {
            AuditEvent::TicketDeleted {
                ticket_id: ticket.id,
                user_id: user.id,
                username: user.username,
                target: target.name,
                actor_user_id: admin.auth.user_id(),
            }
            .emit();
        }

        ticket.delete(db).await?;
        Ok(DeleteTicketResponse::Deleted)
    }
}
