use poem_openapi::param::Path;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{EntityTrait, ModelTrait};
use uuid::Uuid;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_db_entities::KnownHost;

use super::AdminContext;
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
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<DeleteSSHKnownHostResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;

        let db = &admin.services().db;

        let known_host = KnownHost::Entity::find_by_id(id.0).one(db).await?;

        match known_host {
            Some(known_host) => {
                known_host.delete(db).await?;
                Ok(DeleteSSHKnownHostResponse::Deleted)
            }
            None => Ok(DeleteSSHKnownHostResponse::NotFound),
        }
    }
}
