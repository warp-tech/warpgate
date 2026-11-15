use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{EntityTrait, QueryOrder};
use tracing::warn;
use uuid::Uuid;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_common_http::errors::invalid_field;
use warpgate_core::resources::ResourceError;
use warpgate_core::resources::target_groups::{self as store, TargetGroupDataRequest};
use warpgate_db_entities::TargetGroup;

use super::AdminContext;

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

        match store::create(&admin.services().db, &body).await {
            Ok(group) => Ok(CreateTargetGroupResponse::Created(Json(group))),
            Err(ResourceError::EmptyName) => Ok(CreateTargetGroupResponse::BadRequest(
                invalid_field("name", "target group name is empty"),
            )),
            Err(ResourceError::NameTaken) => Ok(CreateTargetGroupResponse::Conflict(Json(
                "Name already exists".into(),
            ))),
            Err(err) => Err(err.into()),
        }
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

        match store::update(&admin.services().db, id.0, &body).await {
            Ok(group) => Ok(UpdateTargetGroupResponse::Ok(Json(group))),
            Err(ResourceError::EmptyName) => {
                warn!("Rejecting request: target group name is empty");
                Ok(UpdateTargetGroupResponse::BadRequest)
            }
            Err(ResourceError::NameTaken) => Ok(UpdateTargetGroupResponse::Conflict(Json(
                "Name already exists".into(),
            ))),
            Err(ResourceError::NotFound) => Ok(UpdateTargetGroupResponse::NotFound),
            Err(err) => Err(err.into()),
        }
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
        admin.require(AdminPermission::TargetsDelete)?;

        match store::delete(&admin.services().db, id.0).await {
            Ok(()) => Ok(DeleteTargetGroupResponse::Deleted),
            Err(ResourceError::NotFound) => Ok(DeleteTargetGroupResponse::NotFound),
            Err(err) => Err(err.into()),
        }
    }
}
