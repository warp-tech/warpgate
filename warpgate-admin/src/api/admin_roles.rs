use poem::web::Data;
use poem_openapi::param::{Path, Query};
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter, QueryOrder, Set,
};
use uuid::Uuid;
use warpgate_common::{AdminPermission, AdminRole as AdminRoleConfig, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::consts::BUILTIN_ADMIN_ROLE_NAME;
use warpgate_db_entities::{AdminRole, User};

use super::AnySecurityScheme;
use crate::api::common::require_admin_permission;

#[derive(Object)]
struct AdminRoleDataRequest {
    name: String,
    description: Option<String>,

    targets_create: bool,
    targets_edit: bool,
    targets_delete: bool,

    users_create: bool,
    users_edit: bool,
    users_delete: bool,

    access_roles_create: bool,
    access_roles_edit: bool,
    access_roles_delete: bool,
    access_roles_assign: bool,

    sessions_view: bool,
    sessions_terminate: bool,

    recordings_view: bool,

    tickets_create: bool,
    tickets_delete: bool,

    config_edit: bool,

    admin_roles_manage: bool,

    ticket_requests_manage: bool,
}

#[derive(ApiResponse)]
enum GetAdminRolesResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<AdminRoleConfig>>),
}

#[derive(ApiResponse)]
enum CreateAdminRoleResponse {
    #[oai(status = 201)]
    Created(Json<AdminRoleConfig>),
}

#[derive(ApiResponse)]
enum GetAdminRoleResponse {
    #[oai(status = 200)]
    Ok(Json<AdminRoleConfig>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum UpdateAdminRoleResponse {
    #[oai(status = 200)]
    Ok(Json<AdminRoleConfig>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteAdminRoleResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 403)]
    Forbidden,
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum GetAdminRoleUsersResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<warpgate_common::User>>),
    #[oai(status = 404)]
    NotFound,
}

pub struct ListApi;

#[OpenApi]
impl ListApi {
    #[oai(
        path = "/admin-roles",
        method = "get",
        operation_id = "get_admin_roles"
    )]
    async fn api_get_all_admin_roles(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        search: Query<Option<String>>,
        _sec: AnySecurityScheme,
    ) -> Result<GetAdminRolesResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;

        let db = ctx.services().db.lock().await;
        let mut roles = AdminRole::Entity::find().order_by_asc(AdminRole::Column::Name);

        if let Some(ref search) = *search {
            let search = format!("%{search}%");
            roles = roles.filter(AdminRole::Column::Name.like(search));
        }

        let roles = roles.all(&*db).await?;
        Ok(GetAdminRolesResponse::Ok(Json(
            roles.into_iter().map(Into::into).collect(),
        )))
    }

    #[oai(
        path = "/admin-roles",
        method = "post",
        operation_id = "create_admin_role"
    )]
    async fn api_create_admin_role(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        body: Json<AdminRoleDataRequest>,
        _sec: AnySecurityScheme,
    ) -> Result<CreateAdminRoleResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::AdminRolesManage)).await?;

        let db = ctx.services().db.lock().await;
        let values = AdminRole::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(body.name.clone()),
            description: Set(body.description.clone().unwrap_or_default()),
            targets_create: Set(body.targets_create),
            targets_edit: Set(body.targets_edit),
            targets_delete: Set(body.targets_delete),
            users_create: Set(body.users_create),
            users_edit: Set(body.users_edit),
            users_delete: Set(body.users_delete),
            access_roles_create: Set(body.access_roles_create),
            access_roles_edit: Set(body.access_roles_edit),
            access_roles_delete: Set(body.access_roles_delete),
            access_roles_assign: Set(body.access_roles_assign),
            sessions_view: Set(body.sessions_view),
            sessions_terminate: Set(body.sessions_terminate),
            recordings_view: Set(body.recordings_view),
            tickets_create: Set(body.tickets_create),
            tickets_delete: Set(body.tickets_delete),
            config_edit: Set(body.config_edit),
            admin_roles_manage: Set(body.admin_roles_manage),
            ticket_requests_manage: Set(body.ticket_requests_manage),
        };

        let role = values.insert(&*db).await?;
        let role_config: AdminRoleConfig = role.into();
        Ok(CreateAdminRoleResponse::Created(Json(role_config)))
    }
}

pub struct DetailApi;

#[OpenApi]
impl DetailApi {
    #[oai(
        path = "/admin-roles/:id",
        method = "get",
        operation_id = "get_admin_role"
    )]
    async fn api_get_admin_role(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        _sec: AnySecurityScheme,
    ) -> Result<GetAdminRoleResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;

        let db = ctx.services().db.lock().await;
        let role = AdminRole::Entity::find_by_id(id.0).one(&*db).await?;
        Ok(match role {
            Some(r) => GetAdminRoleResponse::Ok(Json(r.into())),
            None => GetAdminRoleResponse::NotFound,
        })
    }

    #[oai(
        path = "/admin-roles/:id",
        method = "put",
        operation_id = "update_admin_role"
    )]
    async fn api_update_admin_role(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        body: Json<AdminRoleDataRequest>,
        id: Path<Uuid>,
        _sec: AnySecurityScheme,
    ) -> Result<UpdateAdminRoleResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::AdminRolesManage)).await?;

        let db = ctx.services().db.lock().await;
        let Some(role) = AdminRole::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(UpdateAdminRoleResponse::NotFound);
        };

        let mut model: AdminRole::ActiveModel = role.into();
        model.name = Set(body.name.clone());
        model.description = Set(body.description.clone().unwrap_or_default());
        model.targets_create = Set(body.targets_create);
        model.targets_edit = Set(body.targets_edit);
        model.targets_delete = Set(body.targets_delete);
        model.users_create = Set(body.users_create);
        model.users_edit = Set(body.users_edit);
        model.users_delete = Set(body.users_delete);
        model.access_roles_create = Set(body.access_roles_create);
        model.access_roles_edit = Set(body.access_roles_edit);
        model.access_roles_delete = Set(body.access_roles_delete);
        model.access_roles_assign = Set(body.access_roles_assign);
        model.sessions_view = Set(body.sessions_view);
        model.sessions_terminate = Set(body.sessions_terminate);
        model.recordings_view = Set(body.recordings_view);
        model.tickets_create = Set(body.tickets_create);
        model.tickets_delete = Set(body.tickets_delete);
        model.config_edit = Set(body.config_edit);
        model.admin_roles_manage = Set(body.admin_roles_manage);
        model.ticket_requests_manage = Set(body.ticket_requests_manage);
        let role = model.update(&*db).await?;
        Ok(UpdateAdminRoleResponse::Ok(Json(role.into())))
    }

    #[oai(
        path = "/admin-roles/:id",
        method = "delete",
        operation_id = "delete_admin_role"
    )]
    async fn api_delete_admin_role(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        _sec: AnySecurityScheme,
    ) -> Result<DeleteAdminRoleResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::AdminRolesManage)).await?;

        let db = ctx.services().db.lock().await;
        let Some(role) = AdminRole::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(DeleteAdminRoleResponse::NotFound);
        };

        // don't allow deleting builtin admin role
        if role.name == BUILTIN_ADMIN_ROLE_NAME {
            return Ok(DeleteAdminRoleResponse::Forbidden);
        }

        role.delete(&*db).await?;
        Ok(DeleteAdminRoleResponse::Deleted)
    }

    #[oai(
        path = "/admin-roles/:id/users",
        method = "get",
        operation_id = "get_admin_role_users"
    )]
    async fn api_get_admin_role_users(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        _sec: AnySecurityScheme,
    ) -> Result<GetAdminRoleUsersResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;

        let db = ctx.services().db.lock().await;
        let Some((_, users)) = AdminRole::Entity::find_by_id(id.0)
            .find_with_related(User::Entity)
            .all(&*db)
            .await
            .map(|x| x.into_iter().next())
            .map_err(WarpgateError::from)?
        else {
            return Ok(GetAdminRoleUsersResponse::NotFound);
        };
        let users: Vec<warpgate_common::User> = users
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(GetAdminRoleUsersResponse::Ok(Json(users)))
    }
}
