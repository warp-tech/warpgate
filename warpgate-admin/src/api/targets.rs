use poem::web::Data;
use poem_openapi::param::{Path, Query};
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::prelude::Expr;
use sea_orm::sea_query::SimpleExpr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, EntityTrait, ModelTrait, QueryFilter, QueryOrder, Set,
};
use uuid::Uuid;
use warpgate_common::{
    AdminPermission, Role as RoleConfig, Target as TargetConfig, TargetOptions, TargetSSHOptions,
    WarpgateError,
};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_db_entities::Target::TargetKind;
use warpgate_db_entities::{KnownHost, Role, Target, TargetRoleAssignment};

use super::AnySecurityScheme;
use crate::api::common::require_admin_permission;

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

pub struct ListApi;

#[OpenApi]
impl ListApi {
    #[oai(path = "/targets", method = "get", operation_id = "get_targets")]
    async fn api_get_all_targets(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        search: Query<Option<String>>,
        group_id: Query<Option<Uuid>>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetTargetsResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;

        let db = ctx.services.db.lock().await;

        let mut targets = Target::Entity::find();

        if let Some(ref search) = *search {
            let search_pattern = format!("%{}%", search.to_lowercase());
            targets = targets
                .filter(
                    Condition::any()
                        .add(Target::Column::Name.like(&search_pattern))
                        .add(Target::Column::Description.like(&search_pattern)),
                )
                .order_by_asc({
                    let case_expr: SimpleExpr = Expr::case(
                        Expr::col((Target::Entity, Target::Column::Name)).like(&search_pattern),
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

        let targets = targets.all(&*db).await.map_err(WarpgateError::from)?;

        let targets: Result<Vec<TargetConfig>, _> =
            targets.into_iter().map(|t| t.try_into()).collect();
        let targets = targets.map_err(WarpgateError::from)?;

        Ok(GetTargetsResponse::Ok(Json(targets)))
    }

    #[oai(path = "/targets", method = "post", operation_id = "create_target")]
    async fn api_create_target(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        body: Json<TargetDataRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<CreateTargetResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::TargetsCreate)).await?;

        if body.name.is_empty() {
            return Ok(CreateTargetResponse::BadRequest(Json("name".into())));
        }

        let db = ctx.services.db.lock().await;
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
            ticket_max_duration_seconds: Set(body.ticket_max_duration_seconds),
            ticket_requests_disabled: Set(body.ticket_requests_disabled.unwrap_or(false)),
            ticket_require_approval: Set(body.ticket_require_approval.unwrap_or(false)),
            ticket_max_uses: Set(body.ticket_max_uses),
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
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetTargetResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;

        let db = ctx.services.db.lock().await;

        let Some(target) = Target::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(GetTargetResponse::NotFound);
        };

        Ok(GetTargetResponse::Ok(Json(target.try_into()?)))
    }

    #[oai(path = "/targets/:id", method = "put", operation_id = "update_target")]
    async fn api_update_target(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        body: Json<TargetDataRequest>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UpdateTargetResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::TargetsEdit)).await?;

        let db = ctx.services.db.lock().await;

        let Some(target) = Target::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(UpdateTargetResponse::NotFound);
        };

        if target.kind != (&body.options).into() {
            return Ok(UpdateTargetResponse::BadRequest);
        }

        let services = &ctx.services;
        let mut model: Target::ActiveModel = target.into();
        model.name = Set(body.name.clone());
        model.description = Set(body.description.clone().unwrap_or_default());
        model.options =
            Set(serde_json::to_value(body.options.clone()).map_err(WarpgateError::from)?);
        model.rate_limit_bytes_per_second = Set(body.rate_limit_bytes_per_second.map(|x| x as i64));
        model.group_id = Set(body.group_id);
        model.ticket_max_duration_seconds = Set(body.ticket_max_duration_seconds);
        if let Some(v) = body.ticket_requests_disabled {
            model.ticket_requests_disabled = Set(v);
        }
        if let Some(v) = body.ticket_require_approval {
            model.ticket_require_approval = Set(v);
        }
        model.ticket_max_uses = Set(body.ticket_max_uses);
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
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteTargetResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::TargetsDelete)).await?;

        let db = ctx.services.db.lock().await;

        let Some(target) = Target::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(DeleteTargetResponse::NotFound);
        };

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
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<TargetKnownSshHostKeysResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::TargetsEdit)).await?;

        let db = ctx.services.db.lock().await;

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
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetTargetRolesResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;

        let db = ctx.services.db.lock().await;

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
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<AddTargetRoleResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::AccessRolesAssign)).await?;

        let db = ctx.services.db.lock().await;

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
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteTargetRoleResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::AccessRolesAssign)).await?;

        let db = ctx.services.db.lock().await;

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
}
