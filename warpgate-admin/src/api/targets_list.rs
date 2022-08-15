use std::sync::Arc;

use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi, Object};
use sea_orm::{ActiveModelTrait, DatabaseConnection, Set};
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::{Target, TargetOptions, WarpgateError};
use warpgate_core::ConfigProvider;

pub struct Api;

#[derive(ApiResponse)]
enum GetTargetsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<Target>>),
}

#[derive(Object)]
struct CreateTargetRequest {
    name: String,
    options: TargetOptions,
}

#[derive(ApiResponse)]
enum CreateTargetResponse {
    #[oai(status = 201)]
    Created(Json<Target>),

    #[oai(status = 400)]
    BadRequest(Json<String>),
}

#[OpenApi]
impl Api {
    #[oai(path = "/targets", method = "get", operation_id = "get_targets")]
    async fn api_get_all_targets(
        &self,
        config_provider: Data<&Arc<Mutex<dyn ConfigProvider + Send>>>,
    ) -> poem::Result<GetTargetsResponse> {
        let mut targets = config_provider.lock().await.list_targets().await?;
        targets.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(GetTargetsResponse::Ok(Json(targets)))
    }

    #[oai(path = "/targets", method = "post", operation_id = "create_target")]
    async fn api_create_target(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        body: Json<CreateTargetRequest>,
    ) -> poem::Result<CreateTargetResponse> {
        use warpgate_db_entities::Target;

        if body.name.is_empty() {
            return Ok(CreateTargetResponse::BadRequest(Json("name".into())));
        }

        let db = db.lock().await;

        let values = Target::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(body.name.clone()),
            kind: Set((&body.options).into()),
            options: Set(serde_json::to_value(body.options.clone()).map_err(WarpgateError::from)?),
        };

        let target = values.insert(&*db).await.map_err(WarpgateError::from)?;

        Ok(CreateTargetResponse::Created(Json(
            target.try_into().map_err(WarpgateError::from)?,
        )))
    }
}
