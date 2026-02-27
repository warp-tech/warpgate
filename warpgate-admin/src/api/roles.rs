use std::sync::Arc;

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
use uuid::Uuid;
use warpgate_common::{
    Role as RoleConfig, Target as TargetConfig, User as UserConfig, WarpgateError,
};
use warpgate_core::consts::BUILTIN_ADMIN_ROLE_NAME;
use warpgate_db_entities::{Role, Target, User};

use super::AnySecurityScheme;

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
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        search: Query<Option<String>>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetRolesResponse, WarpgateError> {
        let db = db.lock().await;

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
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        body: Json<RoleDataRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<CreateRoleResponse, WarpgateError> {
        use warpgate_db_entities::Role;

        if body.name.is_empty() {
            return Ok(CreateRoleResponse::BadRequest(Json("name".into())));
        }

        let db = db.lock().await;

        let values = Role::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(body.name.clone()),
            description: Set(body.description.clone().unwrap_or_default()),
            // Default file transfer settings for new roles
            allow_file_upload: Set(true),
            allow_file_download: Set(true),
            allowed_paths: Set(None),
            blocked_extensions: Set(None),
            max_file_size: Set(None),
            file_transfer_only: Set(false),
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
    #[oai(status = 403)]
    Forbidden,
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteRoleResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 403)]
    Forbidden,
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
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetRoleResponse, WarpgateError> {
        let db = db.lock().await;

        let role = Role::Entity::find_by_id(id.0).one(&*db).await?;

        Ok(match role {
            Some(role) => GetRoleResponse::Ok(Json(role.into())),
            None => GetRoleResponse::NotFound,
        })
    }

    #[oai(path = "/role/:id", method = "put", operation_id = "update_role")]
    async fn api_update_role(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        body: Json<RoleDataRequest>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UpdateRoleResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(role) = Role::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(UpdateRoleResponse::NotFound);
        };

        if role.name == BUILTIN_ADMIN_ROLE_NAME {
            return Ok(UpdateRoleResponse::Forbidden);
        }

        let mut model: Role::ActiveModel = role.into();
        model.name = Set(body.name.clone());
        model.description = Set(body.description.clone().unwrap_or_default());
        let role = model.update(&*db).await?;

        Ok(UpdateRoleResponse::Ok(Json(role.into())))
    }

    #[oai(path = "/role/:id", method = "delete", operation_id = "delete_role")]
    async fn api_delete_role(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteRoleResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(role) = Role::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(DeleteRoleResponse::NotFound);
        };

        if role.name == BUILTIN_ADMIN_ROLE_NAME {
            return Ok(DeleteRoleResponse::Forbidden);
        }

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
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetRoleTargetsResponse, WarpgateError> {
        let db = db.lock().await;

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
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetRoleUsersResponse, WarpgateError> {
        let db = db.lock().await;

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

// ========== File Transfer Defaults API ==========

/// Request/response for role file transfer defaults
#[derive(Object, Serialize, Deserialize, Clone, Debug)]
struct RoleFileTransferDefaults {
    /// Allow file uploads by default for targets with this role
    allow_file_upload: bool,
    /// Allow file downloads by default for targets with this role
    allow_file_download: bool,
    /// Default allowed paths (null = all paths allowed)
    allowed_paths: Option<Vec<String>>,
    /// Default blocked file extensions (null = no extensions blocked)
    blocked_extensions: Option<Vec<String>>,
    /// Default maximum file size in bytes (null = no limit)
    max_file_size: Option<i64>,
    /// When true, users with this role can ONLY use SFTP. Shell/exec/forwarding are blocked.
    #[oai(default)]
    #[serde(default)]
    file_transfer_only: bool,
}

#[derive(ApiResponse)]
enum GetRoleFileTransferResponse {
    #[oai(status = 200)]
    Ok(Json<RoleFileTransferDefaults>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum UpdateRoleFileTransferResponse {
    #[oai(status = 200)]
    Ok(Json<RoleFileTransferDefaults>),
    #[oai(status = 403)]
    Forbidden,
    #[oai(status = 404)]
    NotFound,
}

pub struct FileTransferApi;

#[OpenApi]
impl FileTransferApi {
    /// Get file transfer defaults for a role
    #[oai(
        path = "/role/:id/file-transfer",
        method = "get",
        operation_id = "get_role_file_transfer_defaults"
    )]
    async fn api_get_role_file_transfer(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetRoleFileTransferResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(role) = Role::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(GetRoleFileTransferResponse::NotFound);
        };

        let allowed_paths: Option<Vec<String>> = role
            .allowed_paths
            .as_ref()
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        let blocked_extensions: Option<Vec<String>> = role
            .blocked_extensions
            .as_ref()
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        Ok(GetRoleFileTransferResponse::Ok(Json(
            RoleFileTransferDefaults {
                allow_file_upload: role.allow_file_upload,
                allow_file_download: role.allow_file_download,
                allowed_paths,
                blocked_extensions,
                max_file_size: role.max_file_size,
                file_transfer_only: role.file_transfer_only,
            },
        )))
    }

    /// Update file transfer defaults for a role
    #[oai(
        path = "/role/:id/file-transfer",
        method = "put",
        operation_id = "update_role_file_transfer_defaults"
    )]
    async fn api_update_role_file_transfer(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        body: Json<RoleFileTransferDefaults>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UpdateRoleFileTransferResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(role) = Role::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(UpdateRoleFileTransferResponse::NotFound);
        };

        if role.name == BUILTIN_ADMIN_ROLE_NAME {
            return Ok(UpdateRoleFileTransferResponse::Forbidden);
        }

        let mut model: Role::ActiveModel = role.into();
        model.allow_file_upload = Set(body.allow_file_upload);
        model.allow_file_download = Set(body.allow_file_download);
        model.allowed_paths = Set(body
            .allowed_paths
            .as_ref()
            .and_then(|v| serde_json::to_value(v).ok()));
        model.blocked_extensions = Set(body
            .blocked_extensions
            .as_ref()
            .and_then(|v| serde_json::to_value(v).ok()));
        model.max_file_size = Set(body.max_file_size);
        model.file_transfer_only = Set(body.file_transfer_only);

        let updated = model.update(&*db).await?;

        let allowed_paths: Option<Vec<String>> = updated
            .allowed_paths
            .as_ref()
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        let blocked_extensions: Option<Vec<String>> = updated
            .blocked_extensions
            .as_ref()
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        Ok(UpdateRoleFileTransferResponse::Ok(Json(
            RoleFileTransferDefaults {
                allow_file_upload: updated.allow_file_upload,
                allow_file_download: updated.allow_file_download,
                allowed_paths,
                blocked_extensions,
                max_file_size: updated.max_file_size,
                file_transfer_only: updated.file_transfer_only,
            },
        )))
    }
}
