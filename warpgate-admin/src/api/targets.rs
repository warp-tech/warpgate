use poem_openapi::param::{Path, Query};
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::prelude::Expr;
use sea_orm::sea_query::{Func, SimpleExpr};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter, QueryOrder, Set,
};
use uuid::Uuid;
use warpgate_common::encryption::idempotent_maybe_encrypt_secret;
use warpgate_common::{
    AdminPermission, Role as RoleConfig, SSHTargetAuth, Target as TargetConfig, TargetOptions,
    TargetSSHOptions, WarpgateError, map_target_secrets,
};
use warpgate_db_entities::Target::TargetKind;
use warpgate_db_entities::{KnownHost, Role, Target, TargetRoleAssignment, Ticket, TicketRequest};

use super::AdminContext;
use crate::api::common::{case_insensitive_search, is_unique_violation};

/// Normalize, encrypt and serialize options
fn serialize_options_for_storage(
    mut options: TargetOptions,
) -> Result<serde_json::Value, WarpgateError> {
    match &mut options {
        TargetOptions::MySql(opts) => opts.normalize(),
        TargetOptions::Postgres(opts) => opts.normalize(),
        _ => {}
    }

    let mut value = serde_json::to_value(options).map_err(WarpgateError::from)?;
    map_target_secrets(&mut value, &mut idempotent_maybe_encrypt_secret)?;
    Ok(value)
}

#[derive(Object)]
struct TargetDataRequest {
    name: String,
    description: Option<String>,
    options: TargetOptions,
    rate_limit_bytes_per_second: Option<u32>,
    group_id: Option<Uuid>,
    ticket_max_duration_seconds: Option<i64>,
    ticket_requests_disabled: Option<bool>,
    ticket_require_approval: Option<bool>,
    ticket_max_uses: Option<i16>,
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

/// Whether a target's options name a Vault role the signing path could use.
///
/// Checked when the target is saved, not only when a session tries to use it.
/// The connect path validates the role and refuses — correctly, and hours later,
/// with an error naming the session rather than the form that accepted the typo.
fn vault_role_is_usable(options: &TargetOptions) -> bool {
    let TargetOptions::Ssh(ssh) = options else {
        return true;
    };
    let SSHTargetAuth::Certificate(certificate) = &ssh.auth else {
        return true;
    };
    certificate
        .role
        .as_ref()
        .is_none_or(|role| warpgate_common::vault_name_is_well_formed(role))
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

        let mut targets = Target::Entity::find();

        if let Some(ref search) = *search {
            let search_pattern = format!("%{}%", search.to_lowercase());
            targets = targets
                .filter(case_insensitive_search(
                    search,
                    [Target::Column::Name, Target::Column::Description],
                ))
                .order_by_asc({
                    let case_expr: SimpleExpr = Expr::case(
                        Expr::expr(Func::lower(Expr::col(Target::Column::Name)))
                            .like(&search_pattern),
                        0,
                    )
                    .finally(1)
                    .into();
                    case_expr
                })
                .order_by_asc(Target::Column::Name);
        } else {
            targets = targets.order_by_asc(Target::Column::Name);
        }

        if let Some(group_id) = *group_id {
            targets = targets.filter(Target::Column::GroupId.eq(group_id));
        }

        let targets = targets.all(db).await.map_err(WarpgateError::from)?;

        let targets: Result<Vec<TargetConfig>, _> =
            targets.into_iter().map(TryInto::try_into).collect();
        let targets = targets.map_err(WarpgateError::from)?;

        Ok(GetTargetsResponse::Ok(Json(targets)))
    }

    #[oai(path = "/targets", method = "post", operation_id = "create_target")]
    async fn api_create_target(
        &self,
        admin: AdminContext,
        body: Json<TargetDataRequest>,
    ) -> Result<CreateTargetResponse, WarpgateError> {
        admin.require(AdminPermission::TargetsCreate)?;

        if body.name.is_empty() {
            return Ok(CreateTargetResponse::BadRequest(Json("name".into())));
        }

        if !vault_role_is_usable(&body.options) {
            return Ok(CreateTargetResponse::BadRequest(Json("role".into())));
        }

        let db = &admin.services().db;
        let values = Target::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(body.name.clone()),
            description: Set(body.description.clone().unwrap_or_default()),
            kind: Set((&body.options).into()),
            options: Set(serialize_options_for_storage(body.options.clone())?),
            rate_limit_bytes_per_second: Set(None),
            group_id: Set(body.group_id),
            ticket_max_duration_seconds: Set(body.ticket_max_duration_seconds),
            ticket_requests_disabled: Set(body.ticket_requests_disabled.unwrap_or(false)),
            ticket_require_approval: Set(body.ticket_require_approval.unwrap_or(false)),
            ticket_max_uses: Set(body.ticket_max_uses),
        };

        let target = match values.insert(db).await {
            Ok(target) => target,
            Err(err) if is_unique_violation(&err) => {
                return Ok(CreateTargetResponse::Conflict(Json(
                    "Name already exists".into(),
                )));
            }
            Err(err) => return Err(WarpgateError::from(err)),
        };

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

        Ok(GetTargetResponse::Ok(Json(target.try_into()?)))
    }

    #[oai(path = "/targets/:id", method = "put", operation_id = "update_target")]
    async fn api_update_target(
        &self,
        admin: AdminContext,
        body: Json<TargetDataRequest>,
        id: Path<Uuid>,
    ) -> Result<UpdateTargetResponse, WarpgateError> {
        admin.require(AdminPermission::TargetsEdit)?;

        if body.name.is_empty() {
            return Ok(UpdateTargetResponse::BadRequest);
        }

        let db = &admin.services().db;

        let Some(target) = Target::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(UpdateTargetResponse::NotFound);
        };

        if target.kind != (&body.options).into() || !vault_role_is_usable(&body.options) {
            return Ok(UpdateTargetResponse::BadRequest);
        }

        let services = admin.services();
        let mut model: Target::ActiveModel = target.into();
        model.name = Set(body.name.clone());
        model.description = Set(body.description.clone().unwrap_or_default());
        model.options = Set(serialize_options_for_storage(body.options.clone())?);
        model.rate_limit_bytes_per_second = Set(body.rate_limit_bytes_per_second.map(i64::from));
        model.group_id = Set(body.group_id);
        model.ticket_max_duration_seconds = Set(body.ticket_max_duration_seconds);
        model.ticket_requests_disabled = Set(body.ticket_requests_disabled.unwrap_or(false));
        model.ticket_require_approval = Set(body.ticket_require_approval.unwrap_or(false));
        model.ticket_max_uses = Set(body.ticket_max_uses);
        let target = match model.update(db).await {
            Ok(target) => target,
            Err(err) if is_unique_violation(&err) => {
                return Ok(UpdateTargetResponse::Conflict(Json(
                    "Name already exists".into(),
                )));
            }
            Err(err) => return Err(WarpgateError::from(err)),
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

        let db = &admin.services().db;

        let Some(target) = Target::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(DeleteTargetResponse::NotFound);
        };

        TargetRoleAssignment::Entity::delete_many()
            .filter(TargetRoleAssignment::Column::TargetId.eq(target.id))
            .exec(db)
            .await?;

        TicketRequest::Entity::delete_many()
            .filter(TicketRequest::Column::TargetId.eq(target.id))
            .exec(db)
            .await?;

        Ticket::Entity::delete_many()
            .filter(Ticket::Column::TargetId.eq(target.id))
            .exec(db)
            .await?;

        if target.kind == TargetKind::Ssh {
            let options: TargetOptions = serde_json::from_value(target.options.clone())?;
            if let TargetOptions::Ssh(ssh_options) = options {
                use warpgate_db_entities::KnownHost;
                KnownHost::Entity::delete_many()
                    .filter(KnownHost::Column::Host.eq(&ssh_options.host))
                    .filter(KnownHost::Column::Port.eq(i32::from(ssh_options.port)))
                    .exec(db)
                    .await?;
            }
        }

        target.delete(db).await?;
        Ok(DeleteTargetResponse::Deleted)
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
            _ => return Ok(TargetKnownSshHostKeysResponse::InvalidType),
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

        let db = &admin.services().db;

        if !TargetRoleAssignment::Entity::find()
            .filter(TargetRoleAssignment::Column::TargetId.eq(id.0))
            .filter(TargetRoleAssignment::Column::RoleId.eq(role_id.0))
            .all(db)
            .await
            .map_err(WarpgateError::from)?
            .is_empty()
        {
            return Ok(AddTargetRoleResponse::AlreadyExists);
        }

        let values = TargetRoleAssignment::ActiveModel {
            target_id: Set(id.0),
            role_id: Set(role_id.0),
        };

        values.insert(db).await.map_err(WarpgateError::from)?;

        Ok(AddTargetRoleResponse::Created)
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

        let db = &admin.services().db;

        let Some(model) = TargetRoleAssignment::Entity::find()
            .filter(TargetRoleAssignment::Column::TargetId.eq(id.0))
            .filter(TargetRoleAssignment::Column::RoleId.eq(role_id.0))
            .one(db)
            .await
            .map_err(WarpgateError::from)?
        else {
            return Ok(DeleteTargetRoleResponse::NotFound);
        };

        model.delete(db).await.map_err(WarpgateError::from)?;

        Ok(DeleteTargetRoleResponse::Deleted)
    }
}

#[cfg(test)]
mod tests {
    use warpgate_common::{
        SSHTargetAuth, SshTargetCertificateAuth, SshTargetPublicKeyAuth, TargetOptions,
        TargetSSHOptions,
    };

    use super::vault_role_is_usable;

    fn ssh_target(auth: SSHTargetAuth) -> TargetOptions {
        TargetOptions::Ssh(TargetSSHOptions {
            host: "localhost".to_owned(),
            port: 22,
            username: "root".to_owned(),
            allow_insecure_algos: None,
            auth,
            jump_host: None,
        })
    }

    fn certificate_target(role: Option<&str>) -> TargetOptions {
        ssh_target(SSHTargetAuth::Certificate(SshTargetCertificateAuth {
            role: role.map(str::to_owned),
            ..Default::default()
        }))
    }

    /// An admin API that takes a role the signing path would refuse leaves the
    /// operator to learn of the typo from a broken session rather than from the
    /// form that accepted it.
    #[test]
    fn a_role_the_signing_path_would_refuse_is_refused_at_save_time() {
        assert!(vault_role_is_usable(&certificate_target(Some("warpgate"))));
        assert!(vault_role_is_usable(&certificate_target(None)));
        assert!(
            !vault_role_is_usable(&certificate_target(Some("warp/gate"))),
            "a role with a path separator was accepted at save time"
        );
        assert!(
            !vault_role_is_usable(&certificate_target(Some(""))),
            "an empty role was accepted at save time"
        );
    }

    /// A target with no Vault role has nothing to check, and must not be
    /// refused for lacking one.
    #[test]
    fn a_target_without_a_vault_role_is_left_alone() {
        assert!(vault_role_is_usable(&ssh_target(SSHTargetAuth::PublicKey(
            SshTargetPublicKeyAuth::default()
        ))));
    }
}
