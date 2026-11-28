use std::collections::HashMap;

use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, ModelTrait, QueryFilter,
    Set, TransactionSession, TransactionTrait,
};
use uuid::Uuid;
pub use warpgate_common::TargetDataRequest;
use warpgate_common::{
    RoleId, RowId, SSHTargetAuth, SshClientKeyId, StoredSecrets, Target as TargetConfig,
    TargetGroupId, TargetId, TargetOptions, TargetSecrets, WarpgateError,
};
use warpgate_db_entities::{
    KnownHost, Role, SshClientKey, Target, TargetGroup, TargetRoleAssignment, TargetSession,
    Ticket, TicketRequest, begin_write,
};
use warpgate_resources::{
    Comparable, ComparableValues, OptionReferences, ResourceKind, Row, TargetSpec,
};

use super::audit::{Audited, ChangedBy, Subject, Unaudited};
use super::{
    Actor, AdmittedSessions, OwnedEntity, ResourceError, check_name, name_taken, names_of,
    reveal_inline,
};
use crate::db::is_unique_violation;
use crate::logging::AuditEvent;

impl OwnedEntity for Target::Entity {
    type Id = TargetId;
    const KIND: ResourceKind = ResourceKind::Target;
    const ID: Self::Column = Target::Column::Id;
    const NAME: Self::Column = Target::Column::Name;
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

/// Names of the rows that targets reference by ID
#[derive(Default)]
pub(super) struct Names {
    pub(super) groups: HashMap<TargetGroupId, String>,
    pub(super) keys: HashMap<SshClientKeyId, String>,
    pub(super) targets: HashMap<TargetId, String>,
}

impl Names {
    /// Loads only the names that `targets` reference
    pub(super) async fn referenced_by<C: ConnectionTrait>(
        db: &C,
        targets: &[&TargetConfig],
    ) -> Result<Self, DbErr> {
        let (mut groups, mut keys, mut jump_hosts) = (vec![], vec![], vec![]);
        for target in targets {
            groups.extend(target.group_id);
            if let TargetOptions::Ssh(ssh) = &target.options {
                jump_hosts.extend(ssh.jump_host);
                if let SSHTargetAuth::PublicKey(auth) = &ssh.auth {
                    keys.extend(auth.key_id);
                }
            }
        }

        Ok(Self {
            groups: names_of::<TargetGroup::Entity, _>(db, groups).await?,
            keys: names_of::<SshClientKey::Entity, _>(db, keys).await?,
            targets: names_of::<Target::Entity, _>(db, jump_hosts).await?,
        })
    }
}

/// Inline credentials come back decrypted, so the result must not be logged
pub(super) fn row(
    mut target: TargetConfig,
    roles: Vec<String>,
    names: &Names,
) -> Result<Row<TargetSpec>, WarpgateError> {
    let mut references = OptionReferences::default();
    if let TargetOptions::Ssh(ssh) = &mut target.options {
        // A deleted jump host keeps its ID as the name. No row is called
        // that, so a plan refuses the target.
        references.jump_host = ssh.jump_host.take().map(|id| {
            let name = names.targets.get(&id).cloned();
            name.unwrap_or_else(|| id.to_string())
        });
        if let SSHTargetAuth::PublicKey(auth) = &mut ssh.auth {
            // A deleted key is treated as no key. A connection falls back
            // to the default keys in the same way.
            references.client_key = auth
                .key_id
                .take()
                .and_then(|id| names.keys.get(&id).cloned());
        }
    }
    for slot in target.options.secrets_mut() {
        reveal_inline(slot)?;
    }
    Ok(Row {
        id: target.id.uuid(),
        name: target.name,
        provider: target.provider,
        live: TargetSpec {
            description: target.description,
            group: target
                .group_id
                .and_then(|id| names.groups.get(&id).cloned()),
            roles,
            options: target.options,
            rate_limit_bytes_per_second: target.rate_limit_bytes_per_second,
            ticket_max_duration_seconds: target.ticket_max_duration_seconds,
            ticket_requests_disabled: target.ticket_requests_disabled,
            ticket_require_approval: target.ticket_require_approval,
            require_approval: target.require_approval,
            ticket_max_uses: target.ticket_max_uses,
            references,
        },
    })
}

impl Audited for Target::Model {
    fn subject(&self) -> Subject {
        Subject::of::<Target::Entity>(self.id)
    }

    fn name(&self) -> String {
        self.name.clone()
    }

    async fn compared<C: ConnectionTrait>(
        &self,
        db: &C,
    ) -> Result<ComparableValues, WarpgateError> {
        let target = TargetConfig::try_from(self.clone())?;
        let names = Names::referenced_by(db, &[&target]).await?;
        // A role assignment has a log entry of its own
        Ok(row(target, vec![], &names)?.live.compared())
    }
}

pub async fn create<C: ConnectionTrait>(
    db: &C,
    actor: Actor,
    data: &TargetDataRequest,
) -> Result<Unaudited<Target::Model>, ResourceError> {
    check_name(&data.name)?;
    let mut model = Target::ActiveModel {
        id: Set(TargetId(Uuid::new_v4())),
        kind: Set((&data.options).into()),
        provider: Set(actor.provider_id()),
        ..Default::default()
    };
    set_data(&mut model, data)?;
    let target = model.insert(db).await.map_err(name_taken)?;
    Ok(Unaudited::created(target))
}

fn options_changed(old_json: &serde_json::Value, new_options: &TargetOptions) -> bool {
    let Ok(mut old_options) = serde_json::from_value::<TargetOptions>(old_json.clone()) else {
        return true;
    };
    let mut new_options = new_options.clone();
    for slot in old_options
        .secrets_mut()
        .into_iter()
        .chain(new_options.secrets_mut())
    {
        if reveal_inline(slot).is_err() {
            return true;
        }
    }
    old_options != new_options
}

pub async fn update<C: ConnectionTrait>(
    db: &C,
    actor: Actor,
    id: TargetId,
    data: &TargetDataRequest,
) -> Result<(Unaudited<Target::Model>, AdmittedSessions), ResourceError> {
    check_name(&data.name)?;
    let before = Target::Entity::find_by_id(id)
        .one(db)
        .await?
        .ok_or(ResourceError::NotFound)?;
    actor.may_write(before.provider)?;
    if before.kind != (&data.options).into() {
        return Err(ResourceError::ProtocolChange);
    }

    let should_close_sessions = (!before.require_approval && data.require_approval)
        || options_changed(&before.options, &data.options);

    let mut model: Target::ActiveModel = before.clone().into();
    set_data(&mut model, data)?;
    let after = model.update(db).await.map_err(name_taken)?;
    let admitted = if should_close_sessions {
        TargetSession::open_user_sessions_for_target(db, id).await?
    } else {
        vec![]
    };
    Ok((Unaudited::updated(before, after), AdmittedSessions(admitted)))
}

pub async fn delete<C: ConnectionTrait + TransactionTrait>(
    db: &C,
    actor: Actor,
    id: TargetId,
) -> Result<(Unaudited<Target::Model>, AdmittedSessions), ResourceError> {
    let txn = begin_write(db).await?;
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

    let admitted = TargetSession::open_user_sessions_for_target(&txn, target.id).await?;
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

    target.clone().delete(&txn).await?;
    txn.commit().await?;
    Ok((Unaudited::deleted(target), AdmittedSessions(admitted)))
}

/// Logged with [`RoleAssignmentChange::audit`]
#[derive(Debug)]
#[must_use]
pub struct RoleAssignmentChange {
    pub(super) target: Target::Model,
    pub(super) role: Role::Model,
    pub(super) added: bool,
}

impl RoleAssignmentChange {
    pub fn audit(&self, by: ChangedBy) {
        AuditEvent::TargetRoleChanged {
            added: self.added,
            target_id: self.target.id,
            target_name: self.target.name.clone(),
            role_id: self.role.id,
            role_name: self.role.name.clone(),
            by,
        }
        .emit();
    }
}

/// The rows of an assignment that `actor` may change. Role assignments have
/// no owner column, so the target's owner decides
async fn assignment_rows<C: ConnectionTrait>(
    db: &C,
    actor: Actor,
    target_id: TargetId,
    role_id: RoleId,
) -> Result<(Target::Model, Role::Model), ResourceError> {
    let target = Target::Entity::find_by_id(target_id)
        .one(db)
        .await?
        .ok_or(ResourceError::NotFound)?;
    actor.may_write(target.provider)?;
    let role = Role::Entity::find_by_id(role_id)
        .one(db)
        .await?
        .ok_or(ResourceError::NotFound)?;
    Ok((target, role))
}

pub async fn add_role<C: ConnectionTrait>(
    db: &C,
    actor: Actor,
    target_id: TargetId,
    role_id: RoleId,
) -> Result<RoleAssignmentChange, ResourceError> {
    let (target, role) = assignment_rows(db, actor, target_id, role_id).await?;
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
    Ok(RoleAssignmentChange {
        target,
        role,
        added: true,
    })
}

pub async fn remove_role<C: ConnectionTrait>(
    db: &C,
    actor: Actor,
    target_id: TargetId,
    role_id: RoleId,
) -> Result<RoleAssignmentChange, ResourceError> {
    let (target, role) = assignment_rows(db, actor, target_id, role_id).await?;
    let result = TargetRoleAssignment::Entity::delete_by_id((target_id, role_id))
        .exec(db)
        .await?;
    if result.rows_affected == 0 {
        return Err(ResourceError::NotFound);
    }
    Ok(RoleAssignmentChange {
        target,
        role,
        added: false,
    })
}
