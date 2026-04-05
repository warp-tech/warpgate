use poem::web::Data;
use poem_openapi::param::{Path, Query};
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter, QueryOrder, Set,
};
use tracing::warn;
use uuid::Uuid;
use warpgate_common::{
    AdminPermission, AdminRole as AdminRoleConfig, Role as RoleConfig, User as UserConfig,
    UserRequireCredentialsPolicy, WarpgateError,
};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::logging::{format_related_ids, AuditEvent};
use warpgate_db_entities::{AdminRole, Role, User, UserAdminRoleAssignment, UserRoleAssignment};

use super::AnySecurityScheme;
use crate::api::common::require_admin_permission;

#[derive(Object)]
struct CreateUserRequest {
    username: String,
    description: Option<String>,
}

#[derive(Object)]
struct UserDataRequest {
    username: String,
    credential_policy: Option<UserRequireCredentialsPolicy>,
    description: Option<String>,
    rate_limit_bytes_per_second: Option<u32>,
}

#[derive(ApiResponse)]
enum GetUsersResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<UserConfig>>),
}
#[derive(ApiResponse)]
enum CreateUserResponse {
    #[oai(status = 201)]
    Created(Json<UserConfig>),

    #[oai(status = 400)]
    BadRequest(Json<String>),
}

pub struct ListApi;

#[OpenApi]
impl ListApi {
    #[oai(path = "/users", method = "get", operation_id = "get_users")]
    async fn api_get_all_users(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        search: Query<Option<String>>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetUsersResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;

        let db = ctx.services.db.lock().await;

        let mut users = User::Entity::find().order_by_asc(User::Column::Username);

        if let Some(ref search) = *search {
            let search = format!("%{search}%");
            users = users.filter(User::Column::Username.like(search));
        }

        let users = users.all(&*db).await.map_err(WarpgateError::from)?;

        let users: Vec<UserConfig> = users
            .into_iter()
            .map(UserConfig::try_from)
            .collect::<Result<Vec<UserConfig>, _>>()?;

        Ok(GetUsersResponse::Ok(Json(users)))
    }

    #[oai(path = "/users", method = "post", operation_id = "create_user")]
    async fn api_create_user(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        body: Json<CreateUserRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<CreateUserResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::UsersCreate)).await?;

        if body.username.is_empty() {
            return Ok(CreateUserResponse::BadRequest(Json("name".into())));
        }

        let db = ctx.services.db.lock().await;

        let values = User::ActiveModel {
            id: Set(Uuid::new_v4()),
            username: Set(body.username.clone()),
            credential_policy: Set(
                serde_json::to_value(UserRequireCredentialsPolicy::default())
                    .map_err(WarpgateError::from)?,
            ),
            description: Set(body.description.clone().unwrap_or_default()),
            rate_limit_bytes_per_second: Set(None),
            ldap_server_id: Set(None),
            ldap_object_uuid: Set(None),
        };

        let user = values.insert(&*db).await.map_err(WarpgateError::from)?;

        AuditEvent::UserCreated {
            user_id: user.id,
            username: user.username.clone(),
            actor_user_id: ctx.auth.user_id(),
        }
        .emit();

        Ok(CreateUserResponse::Created(Json(user.try_into()?)))
    }
}

#[derive(ApiResponse)]
#[allow(clippy::large_enum_variant)]
enum GetUserResponse {
    #[oai(status = 200)]
    Ok(Json<UserConfig>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
#[allow(clippy::large_enum_variant)]
enum UpdateUserResponse {
    #[oai(status = 200)]
    Ok(Json<UserConfig>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteUserResponse {
    #[oai(status = 204)]
    Deleted,

    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum UnlinkUserFromLdapResponse {
    #[oai(status = 200)]
    Ok(Json<UserConfig>),

    #[oai(status = 404)]
    NotFound,

    #[oai(status = 400)]
    BadRequest(Json<String>),
}

#[derive(ApiResponse)]
enum AutoLinkUserToLdapResponse {
    #[oai(status = 200)]
    Ok(Json<UserConfig>),

    #[oai(status = 404)]
    NotFound,

    #[oai(status = 400)]
    BadRequest(Json<String>),
}

pub struct DetailApi;

#[OpenApi]
impl DetailApi {
    #[oai(path = "/users/:id", method = "get", operation_id = "get_user")]
    async fn api_get_user(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetUserResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;

        let db = ctx.services.db.lock().await;

        let Some(user) = User::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(GetUserResponse::NotFound);
        };

        Ok(GetUserResponse::Ok(Json(user.try_into()?)))
    }

    #[oai(path = "/users/:id", method = "put", operation_id = "update_user")]
    async fn api_update_user(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        body: Json<UserDataRequest>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UpdateUserResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::UsersEdit)).await?;

        let db = ctx.services.db.lock().await;

        let Some(user) = User::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(UpdateUserResponse::NotFound);
        };

        let mut model: User::ActiveModel = user.into();
        model.username = Set(body.username.clone());
        model.description = Set(body.description.clone().unwrap_or_default());
        model.credential_policy =
            Set(serde_json::to_value(body.credential_policy.clone())
                .map_err(WarpgateError::from)?);
        model.rate_limit_bytes_per_second = Set(body.rate_limit_bytes_per_second.map(i64::from));
        let user = model.update(&*db).await?;

        drop(db);

        ctx.services
            .rate_limiter_registry
            .lock()
            .await
            .apply_new_rate_limits(&*ctx.services.state.lock().await)
            .await?;

        Ok(UpdateUserResponse::Ok(Json(user.try_into()?)))
    }

    #[oai(path = "/users/:id", method = "delete", operation_id = "delete_user")]
    async fn api_delete_user(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteUserResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::UsersDelete)).await?;

        let db = ctx.services.db.lock().await;

        let Some(user) = User::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(DeleteUserResponse::NotFound);
        };

        UserRoleAssignment::Entity::delete_many()
            .filter(UserRoleAssignment::Column::UserId.eq(user.id))
            .exec(&*db)
            .await?;

        UserAdminRoleAssignment::Entity::delete_many()
            .filter(UserAdminRoleAssignment::Column::UserId.eq(user.id))
            .exec(&*db)
            .await?;

        AuditEvent::UserDeleted {
            user_id: user.id,
            username: user.username.clone(),
            actor_user_id: ctx.auth.user_id(),
        }
        .emit();

        user.delete(&*db).await?;

        Ok(DeleteUserResponse::Deleted)
    }

    #[oai(
        path = "/users/:id/ldap-link/unlink",
        method = "post",
        operation_id = "unlink_user_from_ldap"
    )]
    async fn api_unlink_user_from_ldap(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UnlinkUserFromLdapResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::UsersEdit)).await?;

        let db = ctx.services.db.lock().await;

        let Some(user) = User::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(UnlinkUserFromLdapResponse::NotFound);
        };

        if user.ldap_server_id.is_none() {
            return Ok(UnlinkUserFromLdapResponse::BadRequest(Json(
                "User is not linked to LDAP".to_string(),
            )));
        }

        let mut model: User::ActiveModel = user.into();
        model.ldap_server_id = Set(None);
        model.ldap_object_uuid = Set(None);
        let user = model.update(&*db).await?;

        Ok(UnlinkUserFromLdapResponse::Ok(Json(user.try_into()?)))
    }

    #[oai(
        path = "/users/:id/ldap-link/auto-link",
        method = "post",
        operation_id = "auto_link_user_to_ldap"
    )]
    async fn api_auto_link_user_to_ldap(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<AutoLinkUserToLdapResponse, WarpgateError> {
        use warpgate_db_entities::LdapServer;

        require_admin_permission(&ctx, Some(AdminPermission::UsersEdit)).await?;

        let db = ctx.services.db.lock().await;

        let Some(user) = User::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(AutoLinkUserToLdapResponse::NotFound);
        };

        if user.ldap_server_id.is_some() {
            return Ok(AutoLinkUserToLdapResponse::BadRequest(Json(
                "User is already linked to LDAP".to_string(),
            )));
        }

        // Get all enabled LDAP servers
        let ldap_servers: Vec<LdapServer::Model> = LdapServer::Entity::find()
            .filter(LdapServer::Column::Enabled.eq(true))
            .all(&*db)
            .await?;

        if ldap_servers.is_empty() {
            return Ok(AutoLinkUserToLdapResponse::BadRequest(Json(
                "No enabled LDAP servers configured".to_string(),
            )));
        }

        // Try to find user in LDAP servers using username as email
        let username = &user.username;
        let mut ldap_server_id = None;
        let mut ldap_object_uuid = None;

        for ldap_server in ldap_servers {
            let ldap_config = warpgate_ldap::LdapConfig::try_from(&ldap_server)?;

            match warpgate_ldap::find_user_by_username(&ldap_config, username).await {
                Ok(Some(ldap_user)) => {
                    ldap_server_id = Some(ldap_server.id);
                    ldap_object_uuid = Some(ldap_user.object_uuid);
                    break;
                }
                Ok(None) => (),
                Err(e) => {
                    warn!("Error searching for LDAP user in {}: {e}", ldap_server.name);
                }
            }
        }

        if ldap_server_id.is_none() {
            return Ok(AutoLinkUserToLdapResponse::BadRequest(Json(format!(
                "No LDAP user found with username: {username}",
            ))));
        }

        let mut model: User::ActiveModel = user.into();
        model.ldap_server_id = Set(ldap_server_id);
        model.ldap_object_uuid = Set(ldap_object_uuid);
        let user = model.update(&*db).await?;

        Ok(AutoLinkUserToLdapResponse::Ok(Json(user.try_into()?)))
    }
}

#[derive(ApiResponse)]
enum GetUserRolesResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<RoleConfig>>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum AddUserRoleResponse {
    #[oai(status = 201)]
    Created,
    #[oai(status = 409)]
    AlreadyExists,
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteUserRoleResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum GetUserAdminRolesResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<AdminRoleConfig>>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum AddUserAdminRoleResponse {
    #[oai(status = 201)]
    Created,
    #[oai(status = 409)]
    AlreadyExists,
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteUserAdminRoleResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
}

pub struct RolesApi;

#[OpenApi]
impl RolesApi {
    #[oai(
        path = "/users/:id/roles",
        method = "get",
        operation_id = "get_user_roles"
    )]
    async fn api_get_user_roles(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetUserRolesResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;

        let db = ctx.services.db.lock().await;

        let Some((_, roles)) = User::Entity::find_by_id(*id)
            .find_with_related(Role::Entity)
            .all(&*db)
            .await
            .map(|x| x.into_iter().next())
            .map_err(WarpgateError::from)?
        else {
            return Ok(GetUserRolesResponse::NotFound);
        };

        Ok(GetUserRolesResponse::Ok(Json(
            roles.into_iter().map(Into::into).collect(),
        )))
    }

    #[oai(
        path = "/users/:id/roles/:role_id",
        method = "post",
        operation_id = "add_user_role"
    )]
    async fn api_add_user_role(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<AddUserRoleResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::AccessRolesAssign)).await?;

        let db = ctx.services.db.lock().await;

        let Some(grantee) = User::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(AddUserRoleResponse::NotFound);
        };

        let Some(role) = Role::Entity::find_by_id(role_id.0).one(&*db).await? else {
            return Ok(AddUserRoleResponse::NotFound);
        };

        if !UserRoleAssignment::Entity::find()
            .filter(UserRoleAssignment::Column::UserId.eq(id.0))
            .filter(UserRoleAssignment::Column::RoleId.eq(role_id.0))
            .all(&*db)
            .await
            .map_err(WarpgateError::from)?
            .is_empty()
        {
            return Ok(AddUserRoleResponse::AlreadyExists);
        }

        let values = UserRoleAssignment::ActiveModel {
            user_id: Set(id.0),
            role_id: Set(role_id.0),
            ..Default::default()
        };

        values.insert(&*db).await.map_err(WarpgateError::from)?;

        AuditEvent::AccessRoleGranted {
            grantee_id: grantee.id,
            grantee_username: grantee.username.clone(),
            role_id: role.id,
            role_name: role.name.clone(),
            actor_user_id: ctx.auth.user_id(),
            related_access_roles: format_related_ids(&[role.id]),
        }
        .emit();

        Ok(AddUserRoleResponse::Created)
    }

    #[oai(
        path = "/users/:id/roles/:role_id",
        method = "delete",
        operation_id = "delete_user_role"
    )]
    async fn api_delete_user_role(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteUserRoleResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::AccessRolesAssign)).await?;

        let db = ctx.services.db.lock().await;

        let Some(grantee) = User::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(DeleteUserRoleResponse::NotFound);
        };

        let Some(role) = Role::Entity::find_by_id(role_id.0).one(&*db).await? else {
            return Ok(DeleteUserRoleResponse::NotFound);
        };

        let Some(model) = UserRoleAssignment::Entity::find()
            .filter(UserRoleAssignment::Column::UserId.eq(id.0))
            .filter(UserRoleAssignment::Column::RoleId.eq(role_id.0))
            .one(&*db)
            .await
            .map_err(WarpgateError::from)?
        else {
            return Ok(DeleteUserRoleResponse::NotFound);
        };

        model.delete(&*db).await.map_err(WarpgateError::from)?;

        AuditEvent::AccessRoleRevoked {
            grantee_id: grantee.id,
            grantee_username: grantee.username.clone(),
            role_id: role.id,
            role_name: role.name.clone(),
            actor_user_id: ctx.auth.user_id(),
            related_access_roles: format_related_ids(&[role.id]),
        }
        .emit();

        Ok(DeleteUserRoleResponse::Deleted)
    }

    #[oai(
        path = "/users/:id/admin-roles",
        method = "get",
        operation_id = "get_user_admin_roles"
    )]
    async fn api_get_user_admin_roles(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetUserAdminRolesResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;

        let db = ctx.services.db.lock().await;

        let Some((_, roles)) = User::Entity::find_by_id(*id)
            .find_with_related(AdminRole::Entity)
            .all(&*db)
            .await
            .map(|x| x.into_iter().next())
            .map_err(WarpgateError::from)?
        else {
            return Ok(GetUserAdminRolesResponse::NotFound);
        };

        Ok(GetUserAdminRolesResponse::Ok(Json(
            roles.into_iter().map(Into::into).collect(),
        )))
    }

    #[oai(
        path = "/users/:id/admin-roles/:role_id",
        method = "post",
        operation_id = "add_user_admin_role"
    )]
    async fn api_add_user_admin_role(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<AddUserAdminRoleResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::AdminRolesManage)).await?;

        let db = ctx.services.db.lock().await;

        let Some(grantee) = User::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(AddUserAdminRoleResponse::NotFound);
        };

        let Some(role) = AdminRole::Entity::find_by_id(role_id.0).one(&*db).await? else {
            return Ok(AddUserAdminRoleResponse::NotFound);
        };

        if !warpgate_db_entities::UserAdminRoleAssignment::Entity::find()
            .filter(warpgate_db_entities::UserAdminRoleAssignment::Column::UserId.eq(id.0))
            .filter(
                warpgate_db_entities::UserAdminRoleAssignment::Column::AdminRoleId.eq(role_id.0),
            )
            .all(&*db)
            .await
            .map_err(WarpgateError::from)?
            .is_empty()
        {
            return Ok(AddUserAdminRoleResponse::AlreadyExists);
        }

        let values = warpgate_db_entities::UserAdminRoleAssignment::ActiveModel {
            user_id: Set(id.0),
            admin_role_id: Set(role_id.0),
            ..Default::default()
        };

        values.insert(&*db).await.map_err(WarpgateError::from)?;

        AuditEvent::AdminRoleGranted {
            grantee_id: grantee.id,
            grantee_username: grantee.username.clone(),
            admin_role_id: role.id,
            admin_role_name: role.name.clone(),
            actor_user_id: ctx.auth.user_id(),
            related_admin_roles: format_related_ids(&[role.id]),
        }
        .emit();

        Ok(AddUserAdminRoleResponse::Created)
    }

    #[oai(
        path = "/users/:id/admin-roles/:role_id",
        method = "delete",
        operation_id = "delete_user_admin_role"
    )]
    async fn api_delete_user_admin_role(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteUserAdminRoleResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::AdminRolesManage)).await?;

        let db = ctx.services.db.lock().await;

        let Some(grantee) = User::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(DeleteUserAdminRoleResponse::NotFound);
        };

        let Some(role) = AdminRole::Entity::find_by_id(role_id.0).one(&*db).await? else {
            return Ok(DeleteUserAdminRoleResponse::NotFound);
        };

        let Some(model) = warpgate_db_entities::UserAdminRoleAssignment::Entity::find()
            .filter(warpgate_db_entities::UserAdminRoleAssignment::Column::UserId.eq(id.0))
            .filter(
                warpgate_db_entities::UserAdminRoleAssignment::Column::AdminRoleId.eq(role_id.0),
            )
            .one(&*db)
            .await
            .map_err(WarpgateError::from)?
        else {
            return Ok(DeleteUserAdminRoleResponse::NotFound);
        };

        model.delete(&*db).await.map_err(WarpgateError::from)?;

        AuditEvent::AdminRoleRevoked {
            grantee_id: grantee.id,
            grantee_username: grantee.username.clone(),
            admin_role_id: role.id,
            admin_role_name: role.name.clone(),
            actor_user_id: ctx.auth.user_id(),
            related_admin_roles: format_related_ids(&[role.id]),
        }
        .emit();

        Ok(DeleteUserAdminRoleResponse::Deleted)
    }
}
