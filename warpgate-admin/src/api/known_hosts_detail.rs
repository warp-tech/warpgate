use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{DatabaseConnection, EntityTrait, ModelTrait};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
pub struct Api;

#[derive(ApiResponse)]
enum DeleteSSHKnownHostResponse {
    #[oai(status = 204)]
    Deleted,

    #[oai(status = 404)]
    NotFound,
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/ssh/known-hosts/:id",
        method = "delete",
        operation_id = "delete_ssh_known_host"
    )]
    async fn api_ssh_delete_known_host(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
    ) -> poem::Result<DeleteSSHKnownHostResponse> {
        use warpgate_db_entities::KnownHost;
        let db = db.lock().await;

        let known_host = KnownHost::Entity::find_by_id(id.0)
            .one(&*db)
            .await
            .map_err(poem::error::InternalServerError)?;

        match known_host {
            Some(known_host) => {
                known_host
                    .delete(&*db)
                    .await
                    .map_err(poem::error::InternalServerError)?;
                Ok(DeleteSSHKnownHostResponse::Deleted)
            }
            None => Ok(DeleteSSHKnownHostResponse::NotFound),
        }
    }
}
