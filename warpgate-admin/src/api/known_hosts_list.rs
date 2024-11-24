use std::sync::Arc;

use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{DatabaseConnection, EntityTrait};
use tokio::sync::Mutex;
use warpgate_db_entities::KnownHost;

use super::TokenSecurityScheme;

pub struct Api;

#[derive(ApiResponse)]
enum GetSSHKnownHostsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<KnownHost::Model>>),
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/ssh/known-hosts",
        method = "get",
        operation_id = "get_ssh_known_hosts"
    )]
    async fn api_ssh_get_all_known_hosts(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        _auth: TokenSecurityScheme,
    ) -> poem::Result<GetSSHKnownHostsResponse> {
        use warpgate_db_entities::KnownHost;

        let db = db.lock().await;
        let hosts = KnownHost::Entity::find()
            .all(&*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        Ok(GetSSHKnownHostsResponse::Ok(Json(hosts)))
    }
}
