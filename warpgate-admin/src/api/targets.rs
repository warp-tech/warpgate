use std::sync::Arc;

use poem::web::Data;
use poem_openapi::param::{Path, Query};
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, ModelTrait, QueryFilter,
    QueryOrder, Set,
};
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::{
    Role as RoleConfig, Target as TargetConfig, TargetOptions, TargetSSHOptions, WarpgateError,
};
use warpgate_core::consts::BUILTIN_ADMIN_ROLE_NAME;
use warpgate_core::Services;
use warpgate_db_entities::Target::TargetKind;
use warpgate_db_entities::{KnownHost, Role, Target, TargetRoleAssignment};

use super::AnySecurityScheme;

#[derive(Object)]
struct TargetDataRequest {
    name: String,
    description: Option<String>,
    options: TargetOptions,
    rate_limit_bytes_per_second: Option<u32>,
    group_id: Option<Uuid>,
}

#[derive(ApiResponse)]
enum GetTargetsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<TargetConfig>>),
}

#[allow(clippy::large_enum_variant)]
#[derive(ApiResponse)]
enum CreateTargetResponse {
    #[oai(status = 201)]
    Created(Json<TargetConfig>),

    #[oai(status = 409)]
    Conflict(Json<String>),

    #[oai(status = 400)]
    BadRequest(Json<String>),
}

pub struct ListApi;

#[OpenApi]
impl ListApi {
    #[oai(path = "/targets", method = "get", operation_id = "get_targets")]
    async fn api_get_all_targets(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        search: Query<Option<String>>,
        group_id: Query<Option<Uuid>>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetTargetsResponse, WarpgateError> {
        let db = db.lock().await;

        let mut targets = Target::Entity::find().order_by_asc(Target::Column::Name);

        if let Some(ref search) = *search {
            let search = format!("%{search}%");
            targets = targets.filter(Target::Column::Name.like(search));
        }

        if let Some(group_id) = *group_id {
            targets = targets.filter(Target::Column::GroupId.eq(group_id));
        }

        let targets = targets.all(&*db).await.map_err(WarpgateError::from)?;

        let targets: Result<Vec<TargetConfig>, _> =
            targets.into_iter().map(|t| t.try_into()).collect();
        let targets = targets.map_err(WarpgateError::from)?;

        Ok(GetTargetsResponse::Ok(Json(targets)))
    }

    #[oai(path = "/targets", method = "post", operation_id = "create_target")]
    async fn api_create_target(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        body: Json<TargetDataRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<CreateTargetResponse, WarpgateError> {
        if body.name.is_empty() {
            return Ok(CreateTargetResponse::BadRequest(Json("name".into())));
        }

        if let TargetOptions::WebAdmin(_) = body.options {
            return Ok(CreateTargetResponse::BadRequest(Json("kind".into())));
        }

        let db = db.lock().await;
        let existing = Target::Entity::find()
            .filter(Target::Column::Name.eq(body.name.clone()))
            .one(&*db)
            .await?;
        if existing.is_some() {
            return Ok(CreateTargetResponse::Conflict(Json(
                "Name already exists".into(),
            )));
        }

        let values = Target::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(body.name.clone()),
            description: Set(body.description.clone().unwrap_or_default()),
            kind: Set((&body.options).into()),
            options: Set(serde_json::to_value(body.options.clone()).map_err(WarpgateError::from)?),
            rate_limit_bytes_per_second: Set(None),
            group_id: Set(body.group_id),
        };

        let target = values.insert(&*db).await.map_err(WarpgateError::from)?;

        Ok(CreateTargetResponse::Created(Json(
            target.try_into().map_err(WarpgateError::from)?,
        )))
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(ApiResponse)]
enum GetTargetResponse {
    #[oai(status = 200)]
    Ok(Json<TargetConfig>),
    #[oai(status = 404)]
    NotFound,
}

#[allow(clippy::large_enum_variant)]
#[derive(ApiResponse)]
enum UpdateTargetResponse {
    #[oai(status = 200)]
    Ok(Json<TargetConfig>),
    #[oai(status = 400)]
    BadRequest,
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteTargetResponse {
    #[oai(status = 204)]
    Deleted,

    #[oai(status = 403)]
    Forbidden,

    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum TargetKnownSshHostKeysResponse {
    #[oai(status = 200)]
    Found(Json<Vec<KnownHost::Model>>),

    #[oai(status = 400)]
    InvalidType,

    #[oai(status = 404)]
    NotFound,
}

pub struct DetailApi;

#[OpenApi]
impl DetailApi {
    #[oai(path = "/targets/:id", method = "get", operation_id = "get_target")]
    async fn api_get_target(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetTargetResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(target) = Target::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(GetTargetResponse::NotFound);
        };

        Ok(GetTargetResponse::Ok(Json(target.try_into()?)))
    }

    #[oai(path = "/targets/:id", method = "put", operation_id = "update_target")]
    async fn api_update_target(
        &self,
        services: Data<&Services>,
        body: Json<TargetDataRequest>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UpdateTargetResponse, WarpgateError> {
        let db = services.db.lock().await;

        let Some(target) = Target::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(UpdateTargetResponse::NotFound);
        };

        if target.kind != (&body.options).into() {
            return Ok(UpdateTargetResponse::BadRequest);
        }

        let mut model: Target::ActiveModel = target.into();
        model.name = Set(body.name.clone());
        model.description = Set(body.description.clone().unwrap_or_default());
        model.options =
            Set(serde_json::to_value(body.options.clone()).map_err(WarpgateError::from)?);
        model.rate_limit_bytes_per_second = Set(body.rate_limit_bytes_per_second.map(|x| x as i64));
        model.group_id = Set(body.group_id);
        let target = model.update(&*db).await?;

        drop(db);

        services
            .rate_limiter_registry
            .lock()
            .await
            .apply_new_rate_limits(&mut *services.state.lock().await)
            .await?;

        Ok(UpdateTargetResponse::Ok(Json(
            target.try_into().map_err(WarpgateError::from)?,
        )))
    }

    #[oai(
        path = "/targets/:id",
        method = "delete",
        operation_id = "delete_target"
    )]
    async fn api_delete_target(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteTargetResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(target) = Target::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(DeleteTargetResponse::NotFound);
        };

        if target.kind == TargetKind::WebAdmin {
            return Ok(DeleteTargetResponse::Forbidden);
        }

        TargetRoleAssignment::Entity::delete_many()
            .filter(TargetRoleAssignment::Column::TargetId.eq(target.id))
            .exec(&*db)
            .await?;

        if target.kind == TargetKind::Ssh {
            let options: TargetOptions = serde_json::from_value(target.options.clone())?;
            if let TargetOptions::Ssh(ssh_options) = options {
                use warpgate_db_entities::KnownHost;
                KnownHost::Entity::delete_many()
                    .filter(KnownHost::Column::Host.eq(&ssh_options.host))
                    .filter(KnownHost::Column::Port.eq(ssh_options.port as i32))
                    .exec(&*db)
                    .await?;
            }
        }

        target.delete(&*db).await?;
        Ok(DeleteTargetResponse::Deleted)
    }

    #[oai(
        path = "/targets/:id/known-ssh-host-keys",
        method = "get",
        operation_id = "get_ssh_target_known_ssh_host_keys"
    )]
    async fn get_ssh_target_known_ssh_host_keys(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<TargetKnownSshHostKeysResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(target) = Target::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(TargetKnownSshHostKeysResponse::NotFound);
        };

        let target: TargetConfig = target.try_into()?;

        let options: TargetSSHOptions = match target.options {
            TargetOptions::Ssh(x) => x,
            _ => return Ok(TargetKnownSshHostKeysResponse::InvalidType),
        };

        let known_hosts = KnownHost::Entity::find()
            .filter(
                KnownHost::Column::Host
                    .eq(&options.host)
                    .and(KnownHost::Column::Port.eq(options.port)),
            )
            .all(&*db)
            .await?;

        Ok(TargetKnownSshHostKeysResponse::Found(Json(known_hosts)))
    }
}

#[derive(ApiResponse)]
enum GetTargetRolesResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<RoleConfig>>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum AddTargetRoleResponse {
    #[oai(status = 201)]
    Created,
    #[oai(status = 409)]
    AlreadyExists,
}

#[derive(ApiResponse)]
enum DeleteTargetRoleResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 403)]
    Forbidden,
    #[oai(status = 404)]
    NotFound,
}

/// Request/response for file transfer permissions with inheritance support
#[derive(Object, Clone, Debug)]
struct FileTransferPermissionData {
    /// Allow file uploads via SFTP (null = inherit from role)
    allow_file_upload: Option<bool>,
    /// Allow file downloads via SFTP (null = inherit from role)
    allow_file_download: Option<bool>,
    /// Allowed paths (null = inherit from role)
    allowed_paths: Option<Vec<String>>,
    /// Blocked file extensions (null = inherit from role)
    blocked_extensions: Option<Vec<String>>,
    /// Maximum file size in bytes (null = inherit from role)
    max_file_size: Option<i64>,
    /// File transfer only mode (null = inherit from role)
    file_transfer_only: Option<bool>,
}

#[derive(ApiResponse)]
enum GetFileTransferPermissionResponse {
    #[oai(status = 200)]
    Ok(Json<FileTransferPermissionData>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum UpdateFileTransferPermissionResponse {
    #[oai(status = 200)]
    Ok(Json<FileTransferPermissionData>),
    #[oai(status = 404)]
    NotFound,
}

pub struct RolesApi;

#[OpenApi]
impl RolesApi {
    #[oai(
        path = "/targets/:id/roles",
        method = "get",
        operation_id = "get_target_roles"
    )]
    async fn api_get_target_roles(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetTargetRolesResponse, WarpgateError> {
        let db = db.lock().await;

        let Some((_, roles)) = Target::Entity::find_by_id(*id)
            .find_with_related(Role::Entity)
            .all(&*db)
            .await
            .map(|x| x.into_iter().next())
            .map_err(WarpgateError::from)?
        else {
            return Ok(GetTargetRolesResponse::NotFound);
        };

        Ok(GetTargetRolesResponse::Ok(Json(
            roles.into_iter().map(|x| x.into()).collect(),
        )))
    }

    #[oai(
        path = "/targets/:id/roles/:role_id",
        method = "post",
        operation_id = "add_target_role"
    )]
    async fn api_add_target_role(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<AddTargetRoleResponse, WarpgateError> {
        let db = db.lock().await;

        if !TargetRoleAssignment::Entity::find()
            .filter(TargetRoleAssignment::Column::TargetId.eq(id.0))
            .filter(TargetRoleAssignment::Column::RoleId.eq(role_id.0))
            .all(&*db)
            .await
            .map_err(WarpgateError::from)?
            .is_empty()
        {
            return Ok(AddTargetRoleResponse::AlreadyExists);
        }

        let values = TargetRoleAssignment::ActiveModel {
            target_id: Set(id.0),
            role_id: Set(role_id.0),
            ..Default::default()
        };

        values.insert(&*db).await.map_err(WarpgateError::from)?;

        Ok(AddTargetRoleResponse::Created)
    }

    #[oai(
        path = "/targets/:id/roles/:role_id",
        method = "delete",
        operation_id = "delete_target_role"
    )]
    async fn api_delete_target_role(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteTargetRoleResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(target) = Target::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(DeleteTargetRoleResponse::NotFound);
        };

        let Some(role) = Role::Entity::find_by_id(role_id.0).one(&*db).await? else {
            return Ok(DeleteTargetRoleResponse::NotFound);
        };

        if role.name == BUILTIN_ADMIN_ROLE_NAME && target.kind == TargetKind::WebAdmin {
            return Ok(DeleteTargetRoleResponse::Forbidden);
        }

        let Some(model) = TargetRoleAssignment::Entity::find()
            .filter(TargetRoleAssignment::Column::TargetId.eq(id.0))
            .filter(TargetRoleAssignment::Column::RoleId.eq(role_id.0))
            .one(&*db)
            .await
            .map_err(WarpgateError::from)?
        else {
            return Ok(DeleteTargetRoleResponse::NotFound);
        };

        model.delete(&*db).await.map_err(WarpgateError::from)?;

        Ok(DeleteTargetRoleResponse::Deleted)
    }

    /// Get file transfer permissions for a target-role assignment
    #[oai(
        path = "/targets/:id/roles/:role_id/file-transfer",
        method = "get",
        operation_id = "get_target_role_file_transfer_permission"
    )]
    async fn api_get_target_role_file_transfer(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetFileTransferPermissionResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(assignment) = TargetRoleAssignment::Entity::find()
            .filter(TargetRoleAssignment::Column::TargetId.eq(id.0))
            .filter(TargetRoleAssignment::Column::RoleId.eq(role_id.0))
            .one(&*db)
            .await
            .map_err(WarpgateError::from)?
        else {
            return Ok(GetFileTransferPermissionResponse::NotFound);
        };

        let allowed_paths: Option<Vec<String>> = assignment
            .allowed_paths
            .as_ref()
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        let blocked_extensions: Option<Vec<String>> = assignment
            .blocked_extensions
            .as_ref()
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        Ok(GetFileTransferPermissionResponse::Ok(Json(
            FileTransferPermissionData {
                allow_file_upload: assignment.allow_file_upload,
                allow_file_download: assignment.allow_file_download,
                allowed_paths,
                blocked_extensions,
                max_file_size: assignment.max_file_size,
                file_transfer_only: assignment.file_transfer_only,
            },
        )))
    }

    /// Update file transfer permissions for a target-role assignment
    #[oai(
        path = "/targets/:id/roles/:role_id/file-transfer",
        method = "put",
        operation_id = "update_target_role_file_transfer_permission"
    )]
    async fn api_update_target_role_file_transfer(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        body: Json<FileTransferPermissionData>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UpdateFileTransferPermissionResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(assignment) = TargetRoleAssignment::Entity::find()
            .filter(TargetRoleAssignment::Column::TargetId.eq(id.0))
            .filter(TargetRoleAssignment::Column::RoleId.eq(role_id.0))
            .one(&*db)
            .await
            .map_err(WarpgateError::from)?
        else {
            return Ok(UpdateFileTransferPermissionResponse::NotFound);
        };

        let mut model: TargetRoleAssignment::ActiveModel = assignment.into();
        // Nullable booleans for inheritance support
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

        let updated = model.update(&*db).await.map_err(WarpgateError::from)?;

        let allowed_paths: Option<Vec<String>> = updated
            .allowed_paths
            .as_ref()
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        let blocked_extensions: Option<Vec<String>> = updated
            .blocked_extensions
            .as_ref()
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        Ok(UpdateFileTransferPermissionResponse::Ok(Json(
            FileTransferPermissionData {
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
