use poem_openapi::param::{Path, Query};
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{EntityTrait, ModelTrait, QueryFilter, QueryOrder};
use tracing::warn;
use uuid::Uuid;
use warpgate_common::{
    AdminPermission, Role as RoleConfig, Target as TargetConfig, User as UserConfig, WarpgateError,
};
use warpgate_common_http::errors::invalid_field;
use warpgate_core::resources::ResourceError;
use warpgate_core::resources::roles::{self as store, RoleDataRequest};
use warpgate_db_entities::{Role, Target, User};

use super::AdminContext;
use super::targets::maybe_redacted_target;
use crate::api::common::case_insensitive_search;

#[derive(ApiResponse)]
enum GetRolesResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<RoleConfig>>),
}
#[derive(ApiResponse)]
enum CreateRoleResponse {
    #[oai(status = 201)]
    Created(Json<RoleConfig>),

    #[oai(status = 409)]
    Conflict(Json<String>),

    #[oai(status = 400)]
    BadRequest(Json<String>),
}

pub struct ListApi;

#[OpenApi]
impl ListApi {
    #[oai(path = "/roles", method = "get", operation_id = "get_roles")]
    async fn api_get_all_roles(
        &self,
        admin: AdminContext,
        search: Query<Option<String>>,
    ) -> Result<GetRolesResponse, WarpgateError> {
        // listing roles is allowed for any administrator
        let db = &admin.services().db;

        let mut roles = Role::Entity::find().order_by_asc(Role::Column::Name);

        if let Some(ref search) = *search {
            roles = roles.filter(case_insensitive_search(search, [Role::Column::Name]));
        }

        let roles = roles.all(db).await?;

        Ok(GetRolesResponse::Ok(Json(
            roles.into_iter().map(Into::into).collect(),
        )))
    }

    #[oai(path = "/roles", method = "post", operation_id = "create_role")]
    async fn api_create_role(
        &self,
        admin: AdminContext,
        body: Json<RoleDataRequest>,
    ) -> Result<CreateRoleResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesCreate)?;

        match store::create(&admin.services().db, &body).await {
            Ok(role) => Ok(CreateRoleResponse::Created(Json(role.into()))),
            Err(ResourceError::EmptyName) => Ok(CreateRoleResponse::BadRequest(invalid_field(
                "name",
                "role name is empty",
            ))),
            Err(ResourceError::NameTaken) => Ok(CreateRoleResponse::Conflict(Json(
                "Name already exists".into(),
            ))),
            Err(err) => Err(err.into()),
        }
    }
}

#[derive(ApiResponse)]
enum GetRoleResponse {
    #[oai(status = 200)]
    Ok(Json<RoleConfig>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum UpdateRoleResponse {
    #[oai(status = 200)]
    Ok(Json<RoleConfig>),
    #[oai(status = 400)]
    BadRequest,
    #[oai(status = 409)]
    Conflict(Json<String>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteRoleResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum GetRoleTargetsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<TargetConfig>>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum GetRoleUsersResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<UserConfig>>),
    #[oai(status = 404)]
    NotFound,
}

pub struct DetailApi;

#[OpenApi]
impl DetailApi {
    #[oai(path = "/role/:id", method = "get", operation_id = "get_role")]
    async fn api_get_role(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<GetRoleResponse, WarpgateError> {
        let db = &admin.services().db;

        let role = Role::Entity::find_by_id(id.0).one(db).await?;

        Ok(match role {
            Some(role) => GetRoleResponse::Ok(Json(role.into())),
            None => GetRoleResponse::NotFound,
        })
    }

    #[oai(path = "/role/:id", method = "put", operation_id = "update_role")]
    async fn api_update_role(
        &self,
        admin: AdminContext,
        body: Json<RoleDataRequest>,
        id: Path<Uuid>,
    ) -> Result<UpdateRoleResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesEdit)?;

        match store::update(&admin.services().db, id.0, &body).await {
            Ok(role) => Ok(UpdateRoleResponse::Ok(Json(role.into()))),
            Err(ResourceError::EmptyName) => {
                warn!("Rejecting request: role name is empty");
                Ok(UpdateRoleResponse::BadRequest)
            }
            Err(ResourceError::NameTaken) => Ok(UpdateRoleResponse::Conflict(Json(
                "Name already exists".into(),
            ))),
            Err(ResourceError::NotFound) => Ok(UpdateRoleResponse::NotFound),
            Err(err) => Err(err.into()),
        }
    }

    #[oai(path = "/role/:id", method = "delete", operation_id = "delete_role")]
    async fn api_delete_role(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<DeleteRoleResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesDelete)?;

        match store::delete(&admin.services().db, id.0).await {
            Ok(()) => Ok(DeleteRoleResponse::Deleted),
            Err(ResourceError::NotFound) => Ok(DeleteRoleResponse::NotFound),
            Err(err) => Err(err.into()),
        }
    }

    #[oai(
        path = "/role/:id/targets",
        method = "get",
        operation_id = "get_role_targets"
    )]
    async fn api_get_role_targets(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<GetRoleTargetsResponse, WarpgateError> {
        let db = &admin.services().db;

        let Some(role) = Role::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(GetRoleTargetsResponse::NotFound);
        };

        let targets = role.find_related(Target::Entity).all(db).await?;

        Ok(GetRoleTargetsResponse::Ok(Json(
            targets
                .into_iter()
                .map(|t| maybe_redacted_target(&admin, t))
                .collect::<Result<Vec<_>, _>>()?,
        )))
    }

    #[oai(
        path = "/role/:id/users",
        method = "get",
        operation_id = "get_role_users"
    )]
    async fn api_get_role_users(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<GetRoleUsersResponse, WarpgateError> {
        let db = &admin.services().db;

        let Some(role) = Role::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(GetRoleUsersResponse::NotFound);
        };

        let users = role.find_related(User::Entity).all(db).await?;

        Ok(GetRoleUsersResponse::Ok(Json(
            users
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, WarpgateError>>()?,
        )))
    }
}
