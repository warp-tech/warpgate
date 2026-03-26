use chrono::{DateTime, Utc};
use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter, QueryOrder, Set};
use serde::{Deserialize, Serialize};
use tracing::warn;
use uuid::Uuid;
use warpgate_common::{
    AdminPermission, AdminRole as AdminRoleConfig, User as UserConfig,
    UserRequireCredentialsPolicy, WarpgateError,
};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_db_entities::{AdminRole, Role, User, UserRoleAssignment};

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
        search: poem_openapi::param::Query<Option<String>>,
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
        model.rate_limit_bytes_per_second = Set(body.rate_limit_bytes_per_second.map(|x| x as i64));
        let user = model.update(&*db).await?;

        drop(db);

        ctx.services
            .rate_limiter_registry
            .lock()
            .await
            .apply_new_rate_limits(&mut *ctx.services.state.lock().await)
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
        require_admin_permission(&ctx, Some(AdminPermission::UsersEdit)).await?;

        use warpgate_db_entities::LdapServer;

        let db = ctx.services.db.lock().await;

        let Some(user) = User::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(AutoLinkUserToLdapResponse::NotFound);
        };

        if user.ldap_server_id.is_some() {
            return Ok(AutoLinkUserToLdapResponse::BadRequest(Json(
                "User is already linked to LDAP".to_string(),
            )));
        }

        let ldap_servers: Vec<LdapServer::Model> = LdapServer::Entity::find()
            .filter(LdapServer::Column::Enabled.eq(true))
            .all(&*db)
            .await?;

        if ldap_servers.is_empty() {
            return Ok(AutoLinkUserToLdapResponse::BadRequest(Json(
                "No enabled LDAP servers configured".to_string(),
            )));
        }

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
                Ok(None) => continue,
                Err(e) => {
                    warn!("Error searching for LDAP user in {}: {e}", ldap_server.name);
                    continue;
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

// ========== User Role Assignment DTOs ==========

/// Response containing user role assignment with expiry info.
#[derive(Object, Serialize, Deserialize, Clone, Debug)]
struct UserRoleAssignmentResponse {
    /// Role ID
    id: Uuid,
    /// Role name
    name: String,
    /// Role description
    description: String,
    /// When the role was granted
    granted_at: DateTime<Utc>,
    /// ID of the user who granted this role
    granted_by: Option<Uuid>,
    /// Username of the user who granted this role
    granted_by_username: Option<String>,
    /// When this role assignment expires (null = permanent)
    expires_at: Option<DateTime<Utc>>,
    /// Whether this assignment has expired
    is_expired: bool,
    /// Whether this assignment is currently active (not expired, not revoked)
    is_active: bool,
}

/// Request to add a user role with optional expiry
#[derive(Object, Serialize, Deserialize, Clone, Debug)]
struct AddUserRoleRequest {
    #[oai(default)]
    expires_at: Option<DateTime<Utc>>,
}

/// Request to update user role expiry
#[derive(Object, Serialize, Deserialize, Clone, Debug)]
struct UpdateUserRoleExpiryRequest {
    /// The new expiry timestamp, or null to remove expiry (make permanent)
    expires_at: Option<DateTime<Utc>>,
}

#[derive(ApiResponse)]
enum GetUserRolesResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<UserRoleAssignmentResponse>>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum GetUserRoleResponse {
    #[oai(status = 200)]
    Ok(Json<UserRoleAssignmentResponse>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum AddUserRoleResponse {
    #[oai(status = 201)]
    Created(Json<UserRoleAssignmentResponse>),
    #[oai(status = 409)]
    AlreadyExists,
}

#[derive(ApiResponse)]
enum DeleteUserRoleResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum UpdateUserRoleExpiryResponse {
    #[oai(status = 200)]
    Ok(Json<UserRoleAssignmentResponse>),
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
}

#[derive(ApiResponse)]
enum DeleteUserAdminRoleResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
}

pub struct RolesApi;

/// Helper function to check if a user-role assignment is expired
fn is_assignment_expired(assignment: &UserRoleAssignment::Model) -> bool {
    if let Some(expires_at) = assignment.expires_at {
        expires_at <= Utc::now()
    } else {
        false
    }
}

/// Helper function to check if a user-role assignment is active
fn is_assignment_active(assignment: &UserRoleAssignment::Model) -> bool {
    assignment.revoked_at.is_none() && !is_assignment_expired(assignment)
}

/// Helper to build UserRoleAssignmentResponse from assignment and role
async fn build_assignment_response(
    db: &sea_orm::DatabaseConnection,
    assignment: &UserRoleAssignment::Model,
    role: &Role::Model,
) -> Result<UserRoleAssignmentResponse, WarpgateError> {
    let granted_by_username = if let Some(granter_id) = assignment.granted_by {
        User::Entity::find_by_id(granter_id)
            .one(db)
            .await?
            .map(|u| u.username)
    } else {
        None
    };

    Ok(UserRoleAssignmentResponse {
        id: role.id,
        name: role.name.clone(),
        description: role.description.clone(),
        granted_at: assignment.granted_at.unwrap_or_else(Utc::now),
        granted_by: assignment.granted_by,
        granted_by_username,
        expires_at: assignment.expires_at,
        is_expired: is_assignment_expired(assignment),
        is_active: is_assignment_active(assignment),
    })
}

#[OpenApi]
impl RolesApi {
    /// Get all role assignments for a user with expiry information
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

        let Some(_user) = User::Entity::find_by_id(*id).one(&*db).await? else {
            return Ok(GetUserRolesResponse::NotFound);
        };

        let assignments = UserRoleAssignment::Entity::find()
            .filter(UserRoleAssignment::Column::UserId.eq(*id))
            .all(&*db)
            .await?;

        let mut results = Vec::new();
        for assignment in assignments {
            let Some(role) = Role::Entity::find_by_id(assignment.role_id)
                .one(&*db)
                .await?
            else {
                continue;
            };
            results.push(build_assignment_response(&db, &assignment, &role).await?);
        }

        Ok(GetUserRolesResponse::Ok(Json(results)))
    }

    /// Get a single user role assignment with details
    #[oai(
        path = "/users/:id/roles/:role_id",
        method = "get",
        operation_id = "get_user_role"
    )]
    async fn api_get_user_role(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetUserRoleResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;
        let db = ctx.services.db.lock().await;

        let Some(assignment) = UserRoleAssignment::Entity::find()
            .filter(UserRoleAssignment::Column::UserId.eq(id.0))
            .filter(UserRoleAssignment::Column::RoleId.eq(role_id.0))
            .one(&*db)
            .await?
        else {
            return Ok(GetUserRoleResponse::NotFound);
        };

        let Some(role) = Role::Entity::find_by_id(role_id.0).one(&*db).await? else {
            return Ok(GetUserRoleResponse::NotFound);
        };

        Ok(GetUserRoleResponse::Ok(Json(
            build_assignment_response(&db, &assignment, &role).await?,
        )))
    }

    /// Add a role to a user with optional expiry
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
        body: Json<Option<AddUserRoleRequest>>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<AddUserRoleResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::AccessRolesAssign)).await?;

        let db = ctx.services.db.lock().await;
        let expires_at = body.0.and_then(|b| b.expires_at);

        let Some(_user) = User::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(AddUserRoleResponse::AlreadyExists);
        };

        let Some(role) = Role::Entity::find_by_id(role_id.0).one(&*db).await? else {
            return Ok(AddUserRoleResponse::AlreadyExists);
        };

        let now = Utc::now();

        let existing = UserRoleAssignment::Entity::find()
            .filter(UserRoleAssignment::Column::UserId.eq(id.0))
            .filter(UserRoleAssignment::Column::RoleId.eq(role_id.0))
            .one(&*db)
            .await?;

        let assignment = if let Some(existing) = existing {
            if is_assignment_active(&existing) {
                return Ok(AddUserRoleResponse::AlreadyExists);
            }
            // Re-activate a revoked/expired assignment
            let mut model: UserRoleAssignment::ActiveModel = existing.into();
            model.granted_at = Set(Some(now));
            model.granted_by = Set(None);
            model.expires_at = Set(expires_at);
            model.revoked_at = Set(None);
            model.revoked_by = Set(None);
            model.update(&*db).await?
        } else {
            let values = UserRoleAssignment::ActiveModel {
                user_id: Set(id.0),
                role_id: Set(role_id.0),
                granted_at: Set(Some(now)),
                granted_by: Set(None),
                expires_at: Set(expires_at),
                revoked_at: Set(None),
                revoked_by: Set(None),
                ..Default::default()
            };
            values.insert(&*db).await?
        };

        Ok(AddUserRoleResponse::Created(Json(
            build_assignment_response(&db, &assignment, &role).await?,
        )))
    }

    /// Remove a role from a user (soft delete - sets revoked_at)
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

        let Some(assignment) = UserRoleAssignment::Entity::find()
            .filter(UserRoleAssignment::Column::UserId.eq(id.0))
            .filter(UserRoleAssignment::Column::RoleId.eq(role_id.0))
            .one(&*db)
            .await?
        else {
            return Ok(DeleteUserRoleResponse::NotFound);
        };

        // Soft delete - set revoked_at
        let now = Utc::now();
        let mut model: UserRoleAssignment::ActiveModel = assignment.into();
        model.revoked_at = Set(Some(now));
        model.revoked_by = Set(None);
        model.update(&*db).await?;

        Ok(DeleteUserRoleResponse::Deleted)
    }

    /// Update expiry for a user role assignment
    #[oai(
        path = "/users/:id/roles/:role_id/expiry",
        method = "put",
        operation_id = "update_user_role_expiry"
    )]
    async fn api_update_user_role_expiry(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        body: Json<UpdateUserRoleExpiryRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UpdateUserRoleExpiryResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;
        let db = ctx.services.db.lock().await;

        let Some(role) = Role::Entity::find_by_id(role_id.0).one(&*db).await? else {
            return Ok(UpdateUserRoleExpiryResponse::NotFound);
        };

        let Some(assignment) = UserRoleAssignment::Entity::find()
            .filter(UserRoleAssignment::Column::UserId.eq(id.0))
            .filter(UserRoleAssignment::Column::RoleId.eq(role_id.0))
            .one(&*db)
            .await?
        else {
            return Ok(UpdateUserRoleExpiryResponse::NotFound);
        };

        let mut model: UserRoleAssignment::ActiveModel = assignment.into();
        model.expires_at = Set(body.expires_at);
        // If renewing an expired role, clear revoked_at
        model.revoked_at = Set(None);
        model.revoked_by = Set(None);
        let updated = model.update(&*db).await?;

        Ok(UpdateUserRoleExpiryResponse::Ok(Json(
            build_assignment_response(&db, &updated, &role).await?,
        )))
    }

    /// Remove expiry from a user role assignment (make permanent)
    #[oai(
        path = "/users/:id/roles/:role_id/expiry",
        method = "delete",
        operation_id = "remove_user_role_expiry"
    )]
    async fn api_remove_user_role_expiry(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UpdateUserRoleExpiryResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;
        let db = ctx.services.db.lock().await;

        let Some(role) = Role::Entity::find_by_id(role_id.0).one(&*db).await? else {
            return Ok(UpdateUserRoleExpiryResponse::NotFound);
        };

        let Some(assignment) = UserRoleAssignment::Entity::find()
            .filter(UserRoleAssignment::Column::UserId.eq(id.0))
            .filter(UserRoleAssignment::Column::RoleId.eq(role_id.0))
            .one(&*db)
            .await?
        else {
            return Ok(UpdateUserRoleExpiryResponse::NotFound);
        };

        let mut model: UserRoleAssignment::ActiveModel = assignment.into();
        model.expires_at = Set(None);
        model.revoked_at = Set(None);
        model.revoked_by = Set(None);
        let updated = model.update(&*db).await?;

        Ok(UpdateUserRoleExpiryResponse::Ok(Json(
            build_assignment_response(&db, &updated, &role).await?,
        )))
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
            roles.into_iter().map(|x| x.into()).collect(),
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

        let Some(_user) = User::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(DeleteUserAdminRoleResponse::NotFound);
        };

        let Some(_role) = AdminRole::Entity::find_by_id(role_id.0).one(&*db).await? else {
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
        Ok(DeleteUserAdminRoleResponse::Deleted)
    }
}
