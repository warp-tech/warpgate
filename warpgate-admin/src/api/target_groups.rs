use std::sync::Arc;

use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, ModelTrait, QueryFilter,
    QueryOrder, Set,
};
use sea_orm::prelude::Expr;
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_db_entities::TargetGroup;

use super::AnySecurityScheme;

#[derive(Object)]
struct TargetGroupDataRequest {
    name: String,
    description: Option<String>,
    color: Option<String>,
}

#[derive(ApiResponse)]
enum GetTargetGroupsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<TargetGroup::Model>>),
}

#[derive(ApiResponse)]
enum CreateTargetGroupResponse {
    #[oai(status = 201)]
    Created(Json<TargetGroup::Model>),

    #[oai(status = 409)]
    Conflict(Json<String>),

    #[oai(status = 400)]
    BadRequest(Json<String>),
}

pub struct ListApi;

#[OpenApi]
impl ListApi {
    #[oai(path = "/target-groups", method = "get", operation_id = "list_target_groups")]
    async fn api_list_target_groups(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetTargetGroupsResponse, WarpgateError> {
        let db = db.lock().await;
        let groups = TargetGroup::Entity::find()
            .order_by_asc(TargetGroup::Column::Name)
            .all(&*db)
            .await?;

        Ok(GetTargetGroupsResponse::Ok(Json(groups)))
    }

    #[oai(path = "/target-groups", method = "post", operation_id = "create_target_group")]
    async fn api_create_target_group(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        body: Json<TargetGroupDataRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<CreateTargetGroupResponse, WarpgateError> {
        if body.name.is_empty() {
            return Ok(CreateTargetGroupResponse::BadRequest(Json("name".into())));
        }

        let db = db.lock().await;
        let existing = TargetGroup::Entity::find()
            .filter(TargetGroup::Column::Name.eq(body.name.clone()))
            .one(&*db)
            .await?;
        if existing.is_some() {
            return Ok(CreateTargetGroupResponse::Conflict(Json(
                "Name already exists".into(),
            )));
        }

        let values = TargetGroup::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(body.name.clone()),
            description: Set(body.description.clone().unwrap_or_default()),
            color: Set(body.color.clone()),
        };

        let group = values.insert(&*db).await.map_err(WarpgateError::from)?;

        Ok(CreateTargetGroupResponse::Created(Json(group)))
    }
}

#[derive(ApiResponse)]
enum GetTargetGroupResponse {
    #[oai(status = 200)]
    Ok(Json<TargetGroup::Model>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum UpdateTargetGroupResponse {
    #[oai(status = 200)]
    Ok(Json<TargetGroup::Model>),
    #[oai(status = 400)]
    BadRequest,
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteTargetGroupResponse {
    #[oai(status = 204)]
    Deleted,


    #[oai(status = 404)]
    NotFound,
}

pub struct DetailApi;

#[OpenApi]
impl DetailApi {
    #[oai(path = "/target-groups/:id", method = "get", operation_id = "get_target_group")]
    async fn api_get_target_group(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetTargetGroupResponse, WarpgateError> {
        let db = db.lock().await;
        let group = TargetGroup::Entity::find_by_id(id.0)
            .one(&*db)
            .await?;

        match group {
            Some(group) => Ok(GetTargetGroupResponse::Ok(Json(group))),
            None => Ok(GetTargetGroupResponse::NotFound),
        }
    }

    #[oai(path = "/target-groups/:id", method = "put", operation_id = "update_target_group")]
    async fn api_update_target_group(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        body: Json<TargetGroupDataRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UpdateTargetGroupResponse, WarpgateError> {
        if body.name.is_empty() {
            return Ok(UpdateTargetGroupResponse::BadRequest);
        }

        let db = db.lock().await;
        let group = TargetGroup::Entity::find_by_id(id.0)
            .one(&*db)
            .await?;

        match group {
            Some(group) => {
                // Check if name is already taken by another group
                let existing = TargetGroup::Entity::find()
                    .filter(TargetGroup::Column::Name.eq(body.name.clone()))
                    .filter(TargetGroup::Column::Id.ne(id.0))
                    .one(&*db)
                    .await?;
                if existing.is_some() {
                    return Ok(UpdateTargetGroupResponse::BadRequest);
                }

                let mut group: TargetGroup::ActiveModel = group.into();
                group.name = Set(body.name.clone());
                group.description = Set(body.description.clone().unwrap_or_default());
                group.color = Set(body.color.clone());

                let group = group.update(&*db).await.map_err(WarpgateError::from)?;
                Ok(UpdateTargetGroupResponse::Ok(Json(group)))
            }
            None => Ok(UpdateTargetGroupResponse::NotFound),
        }
    }

    #[oai(path = "/target-groups/:id", method = "delete", operation_id = "delete_target_group")]
    async fn api_delete_target_group(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteTargetGroupResponse, WarpgateError> {
        let db = db.lock().await;
        let group = TargetGroup::Entity::find_by_id(id.0)
            .one(&*db)
            .await?;

        match group {
            Some(group) => {
                // First, unassign all targets from this group by setting their group_id to NULL
                use warpgate_db_entities::Target;
                Target::Entity::update_many()
                    .col_expr(Target::Column::GroupId, Expr::value(Option::<Uuid>::None))
                    .filter(Target::Column::GroupId.eq(id.0))
                    .exec(&*db)
                    .await?;

                // Then delete the group
                group.delete(&*db).await.map_err(WarpgateError::from)?;
                Ok(DeleteTargetGroupResponse::Deleted)
            }
            None => Ok(DeleteTargetGroupResponse::NotFound),
        }
    }
}
