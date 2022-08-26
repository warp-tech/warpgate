use std::sync::Arc;

use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, ModelTrait, Set};
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::{Target as TargetConfig, TargetOptions, WarpgateError};
use warpgate_core::ConfigProvider;
use warpgate_db_entities::Target;

#[derive(Object)]
struct TargetDataRequest {
    name: String,
    options: TargetOptions,
}

#[derive(ApiResponse)]
enum GetTargetsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<TargetConfig>>),
}
#[derive(ApiResponse)]
enum CreateTargetResponse {
    #[oai(status = 201)]
    Created(Json<TargetConfig>),

    #[oai(status = 400)]
    BadRequest(Json<String>),
}

pub struct ListApi;

#[OpenApi]
impl ListApi {
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
        body: Json<TargetDataRequest>,
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

#[derive(ApiResponse)]
enum GetTargetResponse {
    #[oai(status = 200)]
    Ok(Json<TargetConfig>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum UpdateTargetResponse {
    #[oai(status = 200)]
    Ok(Json<TargetConfig>),
    #[oai(status = 400)]
    BadRequest,
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteTargetResponse {
    #[oai(status = 204)]
    Deleted,

    #[oai(status = 404)]
    NotFound,
}

pub struct DetailApi;

#[OpenApi]
impl DetailApi {
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

    #[oai(path = "/target/:id", method = "put", operation_id = "update_target")]
    async fn api_update_target(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        body: Json<TargetDataRequest>,
        id: Path<Uuid>,
    ) -> poem::Result<UpdateTargetResponse> {
        let db = db.lock().await;

        let Some(target) = Target::Entity::find_by_id(id.0)
            .one(&*db)
            .await
            .map_err(poem::error::InternalServerError)? else {
            return Ok(UpdateTargetResponse::NotFound);
        };

        if target.kind != (&body.options).into() {
            return Ok(UpdateTargetResponse::BadRequest);
        }

        let mut model: Target::ActiveModel = target.into();
        model.name = Set(body.name.clone());
        model.options =
            Set(serde_json::to_value(body.options.clone()).map_err(WarpgateError::from)?);
        let target = model
            .update(&*db)
            .await
            .map_err(poem::error::InternalServerError)?;

        Ok(UpdateTargetResponse::Ok(Json(
            target.try_into().map_err(WarpgateError::from)?,
        )))
    }

    #[oai(
        path = "/target/:id",
        method = "delete",
        operation_id = "delete_target"
    )]
    async fn api_delete_target(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
    ) -> poem::Result<DeleteTargetResponse> {
        let db = db.lock().await;

        let Some(target) = Target::Entity::find_by_id(id.0)
            .one(&*db)
            .await
            .map_err(poem::error::InternalServerError)? else {
                return Ok(DeleteTargetResponse::NotFound);
            };

        target
            .delete(&*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        Ok(DeleteTargetResponse::Deleted)
    }
}
