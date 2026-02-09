use std::sync::Arc;

use chrono::{DateTime, Utc};
use poem::web::Data;
use poem_openapi::param::{Path, Query};
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, ModelTrait, QueryFilter,
    QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::warn;
use uuid::Uuid;
use warpgate_common::api::RequestAuthorization;
use warpgate_common::{User as UserConfig, UserRequireCredentialsPolicy, WarpgateError};
use warpgate_core::Services;
use warpgate_db_entities::{Role, User, UserRoleAssignment, UserRoleHistory};

use super::AnySecurityScheme;
use crate::api::pagination::{PaginatedResponse, PaginationParams};

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
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        search: Query<Option<String>>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetUsersResponse, WarpgateError> {
        let db = db.lock().await;

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
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        body: Json<CreateUserRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<CreateUserResponse, WarpgateError> {
        if body.username.is_empty() {
            return Ok(CreateUserResponse::BadRequest(Json("name".into())));
        }

        let db = db.lock().await;

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
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetUserResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(user) = User::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(GetUserResponse::NotFound);
        };

        Ok(GetUserResponse::Ok(Json(user.try_into()?)))
    }

    #[oai(path = "/users/:id", method = "put", operation_id = "update_user")]
    async fn api_update_user(
        &self,
        services: Data<&Services>,
        body: Json<UserDataRequest>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UpdateUserResponse, WarpgateError> {
        let db = services.db.lock().await;

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

        services
            .rate_limiter_registry
            .lock()
            .await
            .apply_new_rate_limits(&mut *services.state.lock().await)
            .await?;

        Ok(UpdateUserResponse::Ok(Json(user.try_into()?)))
    }

    #[oai(path = "/users/:id", method = "delete", operation_id = "delete_user")]
    async fn api_delete_user(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteUserResponse, WarpgateError> {
        let db = db.lock().await;

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
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UnlinkUserFromLdapResponse, WarpgateError> {
        let db = db.lock().await;

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
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<AutoLinkUserToLdapResponse, WarpgateError> {
        use warpgate_db_entities::LdapServer;

        let db = db.lock().await;

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
/// Extends the upstream `Role` response shape (`id`, `name`, `description`)
/// with assignment-specific fields for expiry and audit tracking.
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

/// History entry details stored in the details JSON column
#[derive(Object, Serialize, Deserialize, Clone, Debug)]
struct UserRoleHistoryDetails {
    role_id: Uuid,
    role_name: String,
    user_id: Uuid,
    user_username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    old_expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    new_expires_at: Option<DateTime<Utc>>,
    actor_id: Option<Uuid>,
    actor_username: Option<String>,
}

/// Response entry for user role history
#[derive(Object, Serialize, Deserialize, Clone, Debug)]
struct UserRoleHistoryEntry {
    id: Uuid,
    user_id: Uuid,
    role_id: Uuid,
    action: String,
    occurred_at: DateTime<Utc>,
    actor_id: Option<Uuid>,
    actor_username: Option<String>,
    details: UserRoleHistoryDetails,
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
enum GetUserRoleHistoryResponse {
    #[oai(status = 200)]
    Ok(Json<PaginatedResponse<UserRoleHistoryEntry>>),
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

/// Helper to get the actor ID from request authorization
async fn get_actor_id(
    db: &DatabaseConnection,
    auth: &RequestAuthorization,
) -> Result<Option<Uuid>, WarpgateError> {
    match auth {
        RequestAuthorization::Session(s) => {
            let username = s.username();
            let user = User::Entity::find()
                .filter(User::Column::Username.eq(username))
                .one(db)
                .await?;
            Ok(user.map(|u| u.id))
        }
        RequestAuthorization::UserToken { username } => {
            let user = User::Entity::find()
                .filter(User::Column::Username.eq(username))
                .one(db)
                .await?;
            Ok(user.map(|u| u.id))
        }
        RequestAuthorization::AdminToken => Ok(None),
    }
}

/// Helper function to check if a user-role assignment is active
fn is_assignment_active(assignment: &UserRoleAssignment::Model) -> bool {
    assignment.revoked_at.is_none() && !is_assignment_expired(assignment)
}

/// Helper function to create a history entry
async fn create_history_entry(
    db: &DatabaseConnection,
    user_id: Uuid,
    role_id: Uuid,
    action: &str,
    actor_id: Option<Uuid>,
    details: UserRoleHistoryDetails,
) -> Result<(), WarpgateError> {
    let history = UserRoleHistory::ActiveModel {
        id: Set(Uuid::new_v4()),
        user_id: Set(user_id),
        role_id: Set(role_id),
        action: Set(action.to_string()),
        occurred_at: Set(Utc::now()),
        actor_id: Set(actor_id),
        details: Set(serde_json::to_value(details).map_err(WarpgateError::from)?),
    };
    history.insert(db).await?;
    Ok(())
}

/// Helper to build UserRoleAssignmentResponse from assignment and role
async fn build_assignment_response(
    db: &DatabaseConnection,
    assignment: &UserRoleAssignment::Model,
    role: &Role::Model,
) -> Result<UserRoleAssignmentResponse, WarpgateError> {
    // Lookup granted_by username if present
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
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetUserRolesResponse, WarpgateError> {
        let db = db.lock().await;

        // Check user exists
        let Some(_user) = User::Entity::find_by_id(*id).one(&*db).await? else {
            return Ok(GetUserRolesResponse::NotFound);
        };

        // Get all assignments for this user
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
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetUserRoleResponse, WarpgateError> {
        let db = db.lock().await;

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
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        body: Json<AddUserRoleRequest>,
        auth: Data<&RequestAuthorization>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<AddUserRoleResponse, WarpgateError> {
        let db = db.lock().await;
        let actor_id = get_actor_id(&*db, auth.0).await?;
        let expires_at = body.expires_at;

        // Check if assignment already exists (including revoked ones)
        let existing = UserRoleAssignment::Entity::find()
            .filter(UserRoleAssignment::Column::UserId.eq(id.0))
            .filter(UserRoleAssignment::Column::RoleId.eq(role_id.0))
            .one(&*db)
            .await?;

        if existing.is_some() {
            return Ok(AddUserRoleResponse::AlreadyExists);
        }

        // Get user and role for validation and history
        let Some(user) = User::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(AddUserRoleResponse::AlreadyExists); // Or return NotFound if preferred
        };

        let Some(role) = Role::Entity::find_by_id(role_id.0).one(&*db).await? else {
            return Ok(AddUserRoleResponse::AlreadyExists);
        };

        let now = Utc::now();

        // Create the assignment
        let values = UserRoleAssignment::ActiveModel {
            user_id: Set(id.0),
            role_id: Set(role_id.0),
            granted_at: Set(Some(now)), // Option for SQLite compat, but always set
            granted_by: Set(actor_id),
            expires_at: Set(expires_at),
            revoked_at: Set(None),
            revoked_by: Set(None),
            ..Default::default()
        };

        let assignment = values.insert(&*db).await?;

        // Create history entry
        let details = UserRoleHistoryDetails {
            role_id: role_id.0,
            role_name: role.name.clone(),
            user_id: id.0,
            user_username: user.username.clone(),
            expires_at,
            old_expires_at: None,
            new_expires_at: None,
            actor_id,
            actor_username: auth.0.username().cloned(),
        };

        create_history_entry(&*db, id.0, role_id.0, "granted", actor_id, details).await?;

        Ok(AddUserRoleResponse::Created(Json(
            build_assignment_response(&*db, &assignment, &role).await?,
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
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        auth: Data<&RequestAuthorization>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteUserRoleResponse, WarpgateError> {
        let db = db.lock().await;
        let actor_id = get_actor_id(&*db, auth.0).await?;

        let Some(user) = User::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(DeleteUserRoleResponse::NotFound);
        };

        let Some(role) = Role::Entity::find_by_id(role_id.0).one(&*db).await? else {
            return Ok(DeleteUserRoleResponse::NotFound);
        };

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
        let mut model: UserRoleAssignment::ActiveModel = assignment.clone().into();
        model.revoked_at = Set(Some(now));
        model.revoked_by = Set(actor_id);
        model.update(&*db).await?;

        // Create history entry
        let details = UserRoleHistoryDetails {
            role_id: role_id.0,
            role_name: role.name.clone(),
            user_id: id.0,
            user_username: user.username.clone(),
            expires_at: assignment.expires_at,
            old_expires_at: None,
            new_expires_at: None,
            actor_id,
            actor_username: auth.0.username().cloned(),
        };

        create_history_entry(&*db, id.0, role_id.0, "revoked", actor_id, details).await?;

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
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        body: Json<UpdateUserRoleExpiryRequest>,
        auth: Data<&RequestAuthorization>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UpdateUserRoleExpiryResponse, WarpgateError> {
        let db = db.lock().await;
        let actor_id = get_actor_id(&*db, auth.0).await?;

        let Some(user) = User::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(UpdateUserRoleExpiryResponse::NotFound);
        };

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

        let old_expires_at = assignment.expires_at;

        // Update expiry
        let mut model: UserRoleAssignment::ActiveModel = assignment.into();
        model.expires_at = Set(body.expires_at);
        // If we are renewing an expired role, clear revoked_at
        model.revoked_at = Set(None);
        model.revoked_by = Set(None);
        let updated = model.update(&*db).await?;

        // Create history entry
        let details = UserRoleHistoryDetails {
            role_id: role_id.0,
            role_name: role.name.clone(),
            user_id: id.0,
            user_username: user.username.clone(),
            expires_at: body.expires_at,
            old_expires_at,
            new_expires_at: body.expires_at,
            actor_id,
            actor_username: auth.0.username().cloned(),
        };

        create_history_entry(&*db, id.0, role_id.0, "expiry_changed", actor_id, details).await?;

        Ok(UpdateUserRoleExpiryResponse::Ok(Json(
            build_assignment_response(&*db, &updated, &role).await?,
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
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        auth: Data<&RequestAuthorization>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UpdateUserRoleExpiryResponse, WarpgateError> {
        let db = db.lock().await;
        let actor_id = get_actor_id(&*db, auth.0).await?;

        let Some(user) = User::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(UpdateUserRoleExpiryResponse::NotFound);
        };

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

        let old_expires_at = assignment.expires_at;

        // Remove expiry
        let mut model: UserRoleAssignment::ActiveModel = assignment.into();
        model.expires_at = Set(None);
        model.revoked_at = Set(None);
        model.revoked_by = Set(None);
        let updated = model.update(&*db).await?;

        // Create history entry
        let details = UserRoleHistoryDetails {
            role_id: role_id.0,
            role_name: role.name.clone(),
            user_id: id.0,
            user_username: user.username.clone(),
            expires_at: None,
            old_expires_at,
            new_expires_at: None,
            actor_id,
            actor_username: auth.0.username().cloned(),
        };

        create_history_entry(&*db, id.0, role_id.0, "expiry_removed", actor_id, details).await?;

        Ok(UpdateUserRoleExpiryResponse::Ok(Json(
            build_assignment_response(&*db, &updated, &role).await?,
        )))
    }

    /// Get history for a specific user role assignment
    #[oai(
        path = "/users/:id/roles/:role_id/history",
        method = "get",
        operation_id = "get_user_role_history"
    )]
    async fn api_get_user_role_history(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        offset: Query<Option<u64>>,
        limit: Query<Option<u64>>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetUserRoleHistoryResponse, WarpgateError> {
        let db = db.lock().await;

        // Check user and role exist
        if User::Entity::find_by_id(id.0).one(&*db).await?.is_none() {
            return Ok(GetUserRoleHistoryResponse::NotFound);
        }

        if Role::Entity::find_by_id(role_id.0)
            .one(&*db)
            .await?
            .is_none()
        {
            return Ok(GetUserRoleHistoryResponse::NotFound);
        };

        let q = UserRoleHistory::Entity::find()
            .filter(UserRoleHistory::Column::UserId.eq(id.0))
            .filter(UserRoleHistory::Column::RoleId.eq(role_id.0))
            .order_by_desc(UserRoleHistory::Column::OccurredAt);

        let response = PaginatedResponse::new(
            q,
            PaginationParams {
                offset: *offset,
                limit: *limit,
            },
            &*db,
            |entry| {
                let details: UserRoleHistoryDetails = serde_json::from_value(entry.details.clone())
                    .unwrap_or_else(|_| UserRoleHistoryDetails {
                        role_id: entry.role_id,
                        role_name: String::new(),
                        user_id: entry.user_id,
                        user_username: String::new(),
                        expires_at: None,
                        old_expires_at: None,
                        new_expires_at: None,
                        actor_id: entry.actor_id,
                        actor_username: None,
                    });

                UserRoleHistoryEntry {
                    id: entry.id,
                    user_id: entry.user_id,
                    role_id: entry.role_id,
                    action: entry.action,
                    occurred_at: entry.occurred_at,
                    actor_id: entry.actor_id,
                    actor_username: details.actor_username.clone(),
                    details,
                }
            },
        )
        .await?;

        Ok(GetUserRoleHistoryResponse::Ok(Json(response)))
    }

    /// Get all role history for a user
    #[oai(
        path = "/users/:id/role-history",
        method = "get",
        operation_id = "get_user_all_role_history"
    )]
    async fn api_get_user_all_role_history(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        offset: Query<Option<u64>>,
        limit: Query<Option<u64>>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetUserRoleHistoryResponse, WarpgateError> {
        let db = db.lock().await;

        // Check user exists
        if User::Entity::find_by_id(id.0).one(&*db).await?.is_none() {
            return Ok(GetUserRoleHistoryResponse::NotFound);
        }

        let q = UserRoleHistory::Entity::find()
            .filter(UserRoleHistory::Column::UserId.eq(id.0))
            .order_by_desc(UserRoleHistory::Column::OccurredAt);

        let response = PaginatedResponse::new(
            q,
            PaginationParams {
                offset: *offset,
                limit: *limit,
            },
            &*db,
            |entry| {
                let details: UserRoleHistoryDetails = serde_json::from_value(entry.details.clone())
                    .unwrap_or_else(|_| UserRoleHistoryDetails {
                        role_id: entry.role_id,
                        role_name: String::new(),
                        user_id: entry.user_id,
                        user_username: String::new(),
                        expires_at: None,
                        old_expires_at: None,
                        new_expires_at: None,
                        actor_id: entry.actor_id,
                        actor_username: None,
                    });

                UserRoleHistoryEntry {
                    id: entry.id,
                    user_id: entry.user_id,
                    role_id: entry.role_id,
                    action: entry.action,
                    occurred_at: entry.occurred_at,
                    actor_id: entry.actor_id,
                    actor_username: details.actor_username.clone(),
                    details,
                }
            },
        )
        .await?;

        Ok(GetUserRoleHistoryResponse::Ok(Json(response)))
    }
}
