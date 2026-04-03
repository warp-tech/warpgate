use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, ModelTrait, QueryFilter};
use uuid::Uuid;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::logging::AuditEvent;
use warpgate_db_entities::User;

use super::AnySecurityScheme;
use crate::api::common::require_admin_permission;

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
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteTicketResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::TicketsDelete)).await?;

        use warpgate_db_entities::Ticket;
        let db = ctx.services.db.lock().await;

        let Some(ticket) = Ticket::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(DeleteTicketResponse::NotFound);
        };

        let user = User::Entity::find()
            .filter(User::Column::Username.eq(&ticket.username))
            .one(&*db)
            .await?;

        // TODO: link tickets to users via IDs
        if let Some(user) = user {
            AuditEvent::TicketDeleted {
                ticket_id: ticket.id,
                user_id: user.id,
                username: ticket.username.clone(),
                target: ticket.target.clone(),
                actor_user_id: ctx.auth.user_id(),
            }
            .emit();
        }

        ticket.delete(&*db).await?;
        Ok(DeleteTicketResponse::Deleted)
    }
}
