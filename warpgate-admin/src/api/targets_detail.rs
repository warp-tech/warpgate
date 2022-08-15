use std::sync::Arc;

use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{DatabaseConnection, EntityTrait};
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::Target as TargetConfig;
use warpgate_db_entities::Target;

pub struct Api;

#[derive(ApiResponse)]
enum GetTargetResponse {
    #[oai(status = 200)]
    Ok(Json<TargetConfig>),
    #[oai(status = 404)]
    NotFound,
}

#[OpenApi]
impl Api {
    #[oai(path = "/target/:id", method = "get", operation_id = "get_target")]
    async fn api_get_target(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
    ) -> poem::Result<GetTargetResponse> {
        let db = db.lock().await;

        let target = Target::Entity::find_by_id(id.0)
            .one(&*db)
            .await
            .map_err(poem::error::InternalServerError)?;

        Ok(match target {
            Some(target) => GetTargetResponse::Ok(Json(
                target
                    .try_into()
                    .map_err(poem::error::InternalServerError)?,
            )),
            None => GetTargetResponse::NotFound,
        })
    }
}
