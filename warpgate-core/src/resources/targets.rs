use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, ModelTrait, QueryFilter, Set,
    TransactionTrait,
};
use uuid::Uuid;
pub use warpgate_common::TargetDataRequest;
use warpgate_common::{ProviderId, StoredSecrets, TargetId, TargetOptions, WarpgateError};
use warpgate_db_entities::{
    KnownHost, Target, TargetRoleAssignment, TargetSession, Ticket, TicketRequest,
};
use warpgate_gitops::types::ResourceKind;

use super::{Actor, AdmittedSessions, OwnedEntity, ResourceError, check_name, name_taken};
use crate::db::is_unique_violation;

impl OwnedEntity for Target::Entity {
    const KIND: ResourceKind = ResourceKind::Target;
    const ID: Self::Column = Target::Column::Id;
    const PROVIDER: Self::Column = Target::Column::Provider;
}

fn serialize_options_for_storage(
    mut options: TargetOptions,
) -> Result<serde_json::Value, WarpgateError> {
    options.encrypt_all()?;
    Ok(serde_json::to_value(options)?)
}

fn set_data(
    model: &mut Target::ActiveModel,
    data: &TargetDataRequest,
) -> Result<(), ResourceError> {
    model.name = Set(data.name.clone());
    model.description = Set(data.description.clone().unwrap_or_default());
    model.options = Set(serialize_options_for_storage(data.options.clone())?);
    model.rate_limit_bytes_per_second = Set(data.rate_limit_bytes_per_second.map(i64::from));
    model.group_id = Set(data.group_id);
    model.ticket_max_duration_seconds = Set(data.ticket_max_duration_seconds);
    model.ticket_requests_disabled = Set(data.ticket_requests_disabled);
    model.ticket_require_approval = Set(data.ticket_require_approval);
    model.require_approval = Set(data.require_approval);
    model.ticket_max_uses = Set(data.ticket_max_uses);
    Ok(())
}

pub async fn create<C: ConnectionTrait>(
    db: &C,
    actor: Actor,
    data: &TargetDataRequest,
) -> Result<Target::Model, ResourceError> {
    check_name(&data.name)?;
    let mut model = Target::ActiveModel {
        id: Set(TargetId(Uuid::new_v4())),
        kind: Set((&data.options).into()),
        provider: Set(actor.provider_id()),
        ..Default::default()
    };
    set_data(&mut model, data)?;
    model.insert(db).await.map_err(name_taken)
}

pub async fn update<C: ConnectionTrait>(
    db: &C,
    actor: Actor,
    id: TargetId,
    data: &TargetDataRequest,
) -> Result<Target::Model, ResourceError> {
    check_name(&data.name)?;
    let target = Target::Entity::find_by_id(id)
        .one(db)
        .await?
        .ok_or(ResourceError::NotFound)?;
    actor.may_write(target.provider)?;
    if target.kind != (&data.options).into() {
        return Err(ResourceError::ProtocolChange);
    }

    let mut model: Target::ActiveModel = target.into();
    set_data(&mut model, data)?;
    model.update(db).await.map_err(name_taken)
}

pub async fn delete<C: ConnectionTrait + TransactionTrait>(
    db: &C,
    actor: Actor,
    id: TargetId,
) -> Result<AdmittedSessions, ResourceError> {
    let txn = db.begin().await?;
    let target = Target::Entity::find_by_id(id)
        .one(&txn)
        .await?
        .ok_or(ResourceError::NotFound)?;
    actor.may_write(target.provider)?;

    TargetRoleAssignment::Entity::delete_many()
        .filter(TargetRoleAssignment::Column::TargetId.eq(target.id))
        .exec(&txn)
        .await?;

    TicketRequest::Entity::delete_many()
        .filter(TicketRequest::Column::TargetId.eq(target.id))
        .exec(&txn)
        .await?;

    let admitted = TargetSession::open_user_sessions_admitted_by_tickets(
        &txn,
        Ticket::Column::TargetId.eq(target.id),
    )
    .await?;
    Ticket::Entity::delete_many()
        .filter(Ticket::Column::TargetId.eq(target.id))
        .exec(&txn)
        .await?;

    let options = serde_json::from_value::<TargetOptions>(target.options.clone())
        .map_err(WarpgateError::from)?;
    if let TargetOptions::Ssh(ssh_options) = &options {
        KnownHost::Entity::delete_many()
            .filter(KnownHost::Column::Host.eq(&ssh_options.host))
            .filter(KnownHost::Column::Port.eq(i32::from(ssh_options.port)))
            .exec(&txn)
            .await?;
    }

    target.delete(&txn).await?;
    txn.commit().await?;
    Ok(AdmittedSessions(admitted))
}

/// Role assignments have no owner column. The target's owner decides who may
/// change them.
async fn target_owner<C: ConnectionTrait>(
    db: &C,
    target_id: TargetId,
) -> Result<Option<ProviderId>, ResourceError> {
    Ok(Target::Entity::find_by_id(target_id)
        .one(db)
        .await?
        .ok_or(ResourceError::NotFound)?
        .provider)
}

pub async fn add_role<C: ConnectionTrait>(
    db: &C,
    actor: Actor,
    target_id: TargetId,
    role_id: Uuid,
) -> Result<(), ResourceError> {
    actor.may_write(target_owner(db, target_id).await?)?;
    TargetRoleAssignment::ActiveModel {
        target_id: Set(target_id),
        role_id: Set(role_id),
    }
    .insert(db)
    .await
    .map_err(|err| {
        if is_unique_violation(&err) {
            ResourceError::RoleAlreadyAssigned
        } else {
            err.into()
        }
    })?;
    Ok(())
}

pub async fn remove_role<C: ConnectionTrait>(
    db: &C,
    actor: Actor,
    target_id: TargetId,
    role_id: Uuid,
) -> Result<(), ResourceError> {
    actor.may_write(target_owner(db, target_id).await?)?;
    let result = TargetRoleAssignment::Entity::delete_by_id((target_id, role_id))
        .exec(db)
        .await?;
    if result.rows_affected == 0 {
        return Err(ResourceError::NotFound);
    }
    Ok(())
}
