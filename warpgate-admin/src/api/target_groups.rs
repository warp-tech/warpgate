use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::prelude::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter, QueryOrder, Set,
};
use uuid::Uuid;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_db_entities::TargetGroup;
use warpgate_db_entities::TargetGroup::BootstrapThemeColor;

use super::AdminContext;
use crate::api::common::is_unique_violation;

#[derive(Object)]
struct TargetGroupDataRequest {
    name: String,
    description: Option<String>,
    color: Option<BootstrapThemeColor>,
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
    #[oai(
        path = "/target-groups",
        method = "get",
        operation_id = "list_target_groups"
    )]
    async fn api_list_target_groups(
        &self,
        admin: AdminContext,
    ) -> Result<GetTargetGroupsResponse, WarpgateError> {
        let db = &admin.services().db;
        let groups = TargetGroup::Entity::find()
            .order_by_asc(TargetGroup::Column::Name)
            .all(db)
            .await?;

        Ok(GetTargetGroupsResponse::Ok(Json(groups)))
    }

    #[oai(
        path = "/target-groups",
        method = "post",
        operation_id = "create_target_group"
    )]
    async fn api_create_target_group(
        &self,
        admin: AdminContext,
        body: Json<TargetGroupDataRequest>,
    ) -> Result<CreateTargetGroupResponse, WarpgateError> {
        admin.require(AdminPermission::TargetsCreate)?;

        if body.name.is_empty() {
            return Ok(CreateTargetGroupResponse::BadRequest(Json("name".into())));
        }

        let db = &admin.services().db;
        let values = TargetGroup::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(body.name.clone()),
            description: Set(body.description.clone().unwrap_or_default()),
            color: Set(body.color.clone()),
        };

        let group = match values.insert(db).await {
            Ok(group) => group,
            Err(err) if is_unique_violation(&err) => {
                return Ok(CreateTargetGroupResponse::Conflict(Json(
                    "Name already exists".into(),
                )));
            }
            Err(err) => return Err(WarpgateError::from(err)),
        };

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
    #[oai(status = 409)]
    Conflict(Json<String>),
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
    #[oai(
        path = "/target-groups/:id",
        method = "get",
        operation_id = "get_target_group"
    )]
    async fn api_get_target_group(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<GetTargetGroupResponse, WarpgateError> {
        let db = &admin.services().db;
        let group = TargetGroup::Entity::find_by_id(id.0).one(db).await?;

        match group {
            Some(group) => Ok(GetTargetGroupResponse::Ok(Json(group))),
            None => Ok(GetTargetGroupResponse::NotFound),
        }
    }

    #[oai(
        path = "/target-groups/:id",
        method = "put",
        operation_id = "update_target_group"
    )]
    async fn api_update_target_group(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        body: Json<TargetGroupDataRequest>,
    ) -> Result<UpdateTargetGroupResponse, WarpgateError> {
        admin.require(AdminPermission::TargetsEdit)?;

        if body.name.is_empty() {
            return Ok(UpdateTargetGroupResponse::BadRequest);
        }

        let db = &admin.services().db;
        let group = TargetGroup::Entity::find_by_id(id.0).one(db).await?;

        let Some(group) = group else {
            return Ok(UpdateTargetGroupResponse::NotFound);
        };

        let mut group: TargetGroup::ActiveModel = group.into();
        group.name = Set(body.name.clone());
        group.description = Set(body.description.clone().unwrap_or_default());
        group.color = Set(body.color.clone());

        let group = match group.update(db).await {
            Ok(group) => group,
            Err(err) if is_unique_violation(&err) => {
                return Ok(UpdateTargetGroupResponse::Conflict(Json(
                    "Name already exists".into(),
                )));
            }
            Err(err) => return Err(WarpgateError::from(err)),
        };
        Ok(UpdateTargetGroupResponse::Ok(Json(group)))
    }

    #[oai(
        path = "/target-groups/:id",
        method = "delete",
        operation_id = "delete_target_group"
    )]
    async fn api_delete_target_group(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<DeleteTargetGroupResponse, WarpgateError> {
        use warpgate_db_entities::Target;

        admin.require(AdminPermission::TargetsDelete)?;

        let db = &admin.services().db;
        let group = TargetGroup::Entity::find_by_id(id.0).one(db).await?;

        let Some(group) = group else {
            return Ok(DeleteTargetGroupResponse::NotFound);
        };

        // First, unassign all targets from this group by setting their group_id to NULL
        Target::Entity::update_many()
            .col_expr(Target::Column::GroupId, Expr::value(Option::<Uuid>::None))
            .filter(Target::Column::GroupId.eq(id.0))
            .exec(db)
            .await?;

        // Then delete the group
        group.delete(db).await?;
        Ok(DeleteTargetGroupResponse::Deleted)
    }
}
