use poem::web::Data;
use poem_openapi::param::{Path, Query};
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter, QueryOrder, Set,
};
use uuid::Uuid;
use warpgate_common::{
    AdminPermission, Role as RoleConfig, Target as TargetConfig, User as UserConfig, WarpgateError,
};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_db_entities::{Role, Target, User};

use super::AnySecurityScheme;
use crate::api::common::require_admin_permission;

#[derive(Object)]
struct RoleDataRequest {
    name: String,
    description: Option<String>,
}

#[derive(ApiResponse)]
enum GetRolesResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<RoleConfig>>),
}
#[derive(ApiResponse)]
enum CreateRoleResponse {
    #[oai(status = 201)]
    Created(Json<RoleConfig>),

    #[oai(status = 400)]
    BadRequest(Json<String>),
}

pub struct ListApi;

#[OpenApi]
impl ListApi {
    #[oai(path = "/roles", method = "get", operation_id = "get_roles")]
    async fn api_get_all_roles(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        search: Query<Option<String>>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetRolesResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;

        // listing roles is allowed for any administrator
        let db = ctx.services.db.lock().await;

        let mut roles = Role::Entity::find().order_by_asc(Role::Column::Name);

        if let Some(ref search) = *search {
            let search = format!("%{search}%");
            roles = roles.filter(Role::Column::Name.like(search));
        }

        let roles = roles.all(&*db).await?;

        Ok(GetRolesResponse::Ok(Json(
            roles.into_iter().map(Into::into).collect(),
        )))
    }

    #[oai(path = "/roles", method = "post", operation_id = "create_role")]
    async fn api_create_role(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        body: Json<RoleDataRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<CreateRoleResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::AccessRolesCreate)).await?;

        use warpgate_db_entities::Role;

        if body.name.is_empty() {
            return Ok(CreateRoleResponse::BadRequest(Json("name".into())));
        }

        let db = ctx.services.db.lock().await;

        let values = Role::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(body.name.clone()),
            description: Set(body.description.clone().unwrap_or_default()),
        };

        let role = values.insert(&*db).await.map_err(WarpgateError::from)?;

        Ok(CreateRoleResponse::Created(Json(role.into())))
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
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetRoleResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;

        let db = ctx.services.db.lock().await;

        let role = Role::Entity::find_by_id(id.0).one(&*db).await?;

        Ok(match role {
            Some(role) => GetRoleResponse::Ok(Json(role.into())),
            None => GetRoleResponse::NotFound,
        })
    }

    #[oai(path = "/role/:id", method = "put", operation_id = "update_role")]
    async fn api_update_role(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        body: Json<RoleDataRequest>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UpdateRoleResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::AccessRolesEdit)).await?;

        let db = ctx.services.db.lock().await;

        let Some(role) = Role::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(UpdateRoleResponse::NotFound);
        };

        let mut model: Role::ActiveModel = role.into();
        model.name = Set(body.name.clone());
        model.description = Set(body.description.clone().unwrap_or_default());
        let role = model.update(&*db).await?;

        Ok(UpdateRoleResponse::Ok(Json(role.into())))
    }

    #[oai(path = "/role/:id", method = "delete", operation_id = "delete_role")]
    async fn api_delete_role(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteRoleResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::AccessRolesDelete)).await?;

        let db = ctx.services.db.lock().await;

        let Some(role) = Role::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(DeleteRoleResponse::NotFound);
        };

        role.delete(&*db).await?;
        Ok(DeleteRoleResponse::Deleted)
    }

    #[oai(
        path = "/role/:id/targets",
        method = "get",
        operation_id = "get_role_targets"
    )]
    async fn api_get_role_targets(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetRoleTargetsResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;

        let db = ctx.services.db.lock().await;

        let Some(role) = Role::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(GetRoleTargetsResponse::NotFound);
        };

        let targets = role.find_related(Target::Entity).all(&*db).await?;

        Ok(GetRoleTargetsResponse::Ok(Json(
            targets
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, serde_json::Error>>()?,
        )))
    }

    #[oai(
        path = "/role/:id/users",
        method = "get",
        operation_id = "get_role_users"
    )]
    async fn api_get_role_users(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetRoleUsersResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;

        let db = ctx.services.db.lock().await;

        let Some(role) = Role::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(GetRoleUsersResponse::NotFound);
        };

        let users = role.find_related(User::Entity).all(&*db).await?;

        Ok(GetRoleUsersResponse::Ok(Json(
            users
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, WarpgateError>>()?,
        )))
    }
}
