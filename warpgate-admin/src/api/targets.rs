use poem_openapi::param::{Path, Query};
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use tracing::warn;
use uuid::Uuid;
use warpgate_common::{
    AdminPermission, Role as RoleConfig, StoredSecrets, Target as TargetConfig, TargetOptions,
    TargetSSHOptions, WarpgateError,
};
use warpgate_common_http::errors::invalid_field;
use warpgate_core::resources::ResourceError;
use warpgate_core::resources::targets::{self as store, TargetDataRequest};
use warpgate_db_entities::Target::fuzzy_filter_targets;
use warpgate_db_entities::{KnownHost, Role, Target, TargetGroup};

use super::AdminContext;

pub(crate) fn maybe_redacted_target(
    admin: &AdminContext,
    model: Target::Model,
) -> Result<TargetConfig, WarpgateError> {
    let mut target: TargetConfig = model.try_into()?;
    if !admin.has_permission(AdminPermission::TargetsEdit) {
        target.redact();
    }
    Ok(target)
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
        admin: AdminContext,
        search: Query<Option<String>>,
        group_id: Query<Option<Uuid>>,
    ) -> Result<GetTargetsResponse, WarpgateError> {
        let db = &admin.services().db;

        let groups: Vec<TargetGroup::Model> = TargetGroup::Entity::find().all(db).await?;

        let mut targets = Target::Entity::find().order_by_asc(Target::Column::Name);
        if let Some(group_id) = *group_id {
            targets = targets.filter(Target::Column::GroupId.eq(group_id));
        }

        let all_targets = targets.all(db).await.map_err(WarpgateError::from)?;

        let targets =
            fuzzy_filter_targets(&all_targets, &groups, search.as_deref().unwrap_or_default());

        let targets = targets
            .into_iter()
            .map(|t| maybe_redacted_target(&admin, t.clone()))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(GetTargetsResponse::Ok(Json(targets)))
    }

    #[oai(path = "/targets", method = "post", operation_id = "create_target")]
    async fn api_create_target(
        &self,
        admin: AdminContext,
        body: Json<TargetDataRequest>,
    ) -> Result<CreateTargetResponse, WarpgateError> {
        admin.require(AdminPermission::TargetsCreate)?;

        match store::create(&admin.services().db, &body).await {
            Ok(target) => Ok(CreateTargetResponse::Created(Json(maybe_redacted_target(
                &admin, target,
            )?))),
            Err(ResourceError::EmptyName) => Ok(CreateTargetResponse::BadRequest(invalid_field(
                "name",
                "target name is empty",
            ))),
            Err(ResourceError::NameTaken) => Ok(CreateTargetResponse::Conflict(Json(
                "Name already exists".into(),
            ))),
            Err(err) => Err(err.into()),
        }
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
    #[oai(status = 409)]
    Conflict(Json<String>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteTargetResponse {
    #[oai(status = 204)]
    Deleted,

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
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<GetTargetResponse, WarpgateError> {
        let db = &admin.services().db;

        let Some(target) = Target::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(GetTargetResponse::NotFound);
        };

        Ok(GetTargetResponse::Ok(Json(maybe_redacted_target(
            &admin, target,
        )?)))
    }

    #[oai(path = "/targets/:id", method = "put", operation_id = "update_target")]
    async fn api_update_target(
        &self,
        admin: AdminContext,
        body: Json<TargetDataRequest>,
        id: Path<Uuid>,
    ) -> Result<UpdateTargetResponse, WarpgateError> {
        admin.require(AdminPermission::TargetsEdit)?;

        let services = admin.services();
        let target = match store::update(&services.db, id.0, &body).await {
            Ok(target) => target,
            Err(ResourceError::EmptyName) => {
                warn!("Rejecting request: target name is empty");
                return Ok(UpdateTargetResponse::BadRequest);
            }
            Err(ResourceError::ProtocolChange) => {
                warn!("Rejecting request: a target's protocol cannot be changed after creation");
                return Ok(UpdateTargetResponse::BadRequest);
            }
            Err(ResourceError::NameTaken) => {
                return Ok(UpdateTargetResponse::Conflict(Json(
                    "Name already exists".into(),
                )));
            }
            Err(ResourceError::NotFound) => return Ok(UpdateTargetResponse::NotFound),
            Err(err) => return Err(err.into()),
        };

        warpgate_core::rate_limiting::apply_new_rate_limits(
            &services.rate_limiter_registry,
            &services.state,
        )
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
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<DeleteTargetResponse, WarpgateError> {
        admin.require(AdminPermission::TargetsDelete)?;

        let services = admin.services();
        match store::delete(&services.db, id.0).await {
            Ok(admitted) => {
                services.close_admitted_sessions(admitted).await?;
                Ok(DeleteTargetResponse::Deleted)
            }
            Err(ResourceError::NotFound) => Ok(DeleteTargetResponse::NotFound),
            Err(err) => Err(err.into()),
        }
    }

    #[oai(
        path = "/targets/:id/known-ssh-host-keys",
        method = "get",
        operation_id = "get_ssh_target_known_ssh_host_keys"
    )]
    async fn get_ssh_target_known_ssh_host_keys(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<TargetKnownSshHostKeysResponse, WarpgateError> {
        admin.require(AdminPermission::TargetsEdit)?;

        let db = &admin.services().db;

        let Some(target) = Target::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(TargetKnownSshHostKeysResponse::NotFound);
        };

        let target: TargetConfig = target.try_into()?;

        let options: TargetSSHOptions = match target.options {
            TargetOptions::Ssh(x) => x,
            _ => {
                warn!("Rejecting request: known SSH host keys are only kept for SSH targets");
                return Ok(TargetKnownSshHostKeysResponse::InvalidType);
            }
        };

        let known_hosts = KnownHost::Entity::find()
            .filter(
                KnownHost::Column::Host
                    .eq(&options.host)
                    .and(KnownHost::Column::Port.eq(options.port)),
            )
            .all(db)
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
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<GetTargetRolesResponse, WarpgateError> {
        let db = &admin.services().db;

        let Some((_, roles)) = Target::Entity::find_by_id(*id)
            .find_with_related(Role::Entity)
            .all(db)
            .await
            .map(|x| x.into_iter().next())
            .map_err(WarpgateError::from)?
        else {
            return Ok(GetTargetRolesResponse::NotFound);
        };

        Ok(GetTargetRolesResponse::Ok(Json(
            roles.into_iter().map(Into::into).collect(),
        )))
    }

    #[oai(
        path = "/targets/:id/roles/:role_id",
        method = "post",
        operation_id = "add_target_role"
    )]
    async fn api_add_target_role(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
    ) -> Result<AddTargetRoleResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;

        match store::add_role(&admin.services().db, id.0, role_id.0).await {
            Ok(()) => Ok(AddTargetRoleResponse::Created),
            Err(ResourceError::RoleAlreadyAssigned) => Ok(AddTargetRoleResponse::AlreadyExists),
            Err(err) => Err(err.into()),
        }
    }

    #[oai(
        path = "/targets/:id/roles/:role_id",
        method = "delete",
        operation_id = "delete_target_role"
    )]
    async fn api_delete_target_role(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
    ) -> Result<DeleteTargetRoleResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;

        match store::remove_role(&admin.services().db, id.0, role_id.0).await {
            Ok(()) => Ok(DeleteTargetRoleResponse::Deleted),
            Err(ResourceError::NotFound) => Ok(DeleteTargetRoleResponse::NotFound),
            Err(err) => Err(err.into()),
        }
    }
}
