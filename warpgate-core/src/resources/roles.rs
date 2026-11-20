use poem_openapi::Object;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, ModelTrait, QueryFilter, Set,
    TransactionSession, TransactionTrait,
};
use uuid::Uuid;
use warpgate_common::{RoleId, RowId, WarpgateError};
use warpgate_db_entities::{Role, TargetRoleAssignment, UserRoleAssignment, begin_write};
use warpgate_resources::{Comparable, ComparableValues, ResourceKind, RoleSpec, Row};

use super::audit::{Audited, Subject, Unaudited};
use super::{Actor, OwnedEntity, ResourceError, check_name, name_taken};

impl OwnedEntity for Role::Entity {
    type Id = RoleId;
    const KIND: ResourceKind = ResourceKind::Role;
    const ID: Self::Column = Role::Column::Id;
    const NAME: Self::Column = Role::Column::Name;
    const PROVIDER: Self::Column = Role::Column::Provider;
}

#[derive(Object)]
pub struct RoleDataRequest {
    pub name: String,
    pub description: Option<String>,
    pub is_default: Option<bool>,
}

fn set_data(model: &mut Role::ActiveModel, data: &RoleDataRequest) {
    model.name = Set(data.name.clone());
    model.description = Set(data.description.clone().unwrap_or_default());
    if let Some(is_default) = data.is_default {
        model.is_default = Set(is_default);
    }
}

pub(super) fn row(role: Role::Model) -> Row<RoleSpec> {
    Row {
        id: role.id.uuid(),
        name: role.name,
        provider: role.provider,
        live: RoleSpec {
            description: role.description,
            is_default: role.is_default,
        },
    }
}

impl Audited for Role::Model {
    fn subject(&self) -> Subject {
        Subject::of::<Role::Entity>(self.id)
    }

    fn name(&self) -> String {
        self.name.clone()
    }

    async fn compared<C: ConnectionTrait>(
        &self,
        _db: &C,
    ) -> Result<ComparableValues, WarpgateError> {
        Ok(row(self.clone()).live.compared())
    }
}

pub async fn create<C: ConnectionTrait>(
    db: &C,
    actor: Actor,
    data: &RoleDataRequest,
) -> Result<Unaudited<Role::Model>, ResourceError> {
    check_name(&data.name)?;
    let mut model = Role::ActiveModel {
        id: Set(RoleId(Uuid::new_v4())),
        is_default: Set(false),
        provider: Set(actor.provider_id()),
        ..Default::default()
    };
    set_data(&mut model, data);
    let role = model.insert(db).await.map_err(name_taken)?;
    Ok(Unaudited::created(role))
}

pub async fn update<C: ConnectionTrait>(
    db: &C,
    actor: Actor,
    id: RoleId,
    data: &RoleDataRequest,
) -> Result<Unaudited<Role::Model>, ResourceError> {
    check_name(&data.name)?;
    let before = Role::Entity::find_by_id(id)
        .one(db)
        .await?
        .ok_or(ResourceError::NotFound)?;
    actor.may_write(before.provider)?;

    let mut model: Role::ActiveModel = before.clone().into();
    set_data(&mut model, data);
    let after = model.update(db).await.map_err(name_taken)?;
    Ok(Unaudited::updated(before, after))
}

/// Also removes every assignment of the role, including revoked ones
pub async fn delete<C: ConnectionTrait + TransactionTrait>(
    db: &C,
    actor: Actor,
    id: RoleId,
) -> Result<Unaudited<Role::Model>, ResourceError> {
    let txn = begin_write(db).await?;
    let role = Role::Entity::find_by_id(id)
        .one(&txn)
        .await?
        .ok_or(ResourceError::NotFound)?;
    actor.may_write(role.provider)?;

    UserRoleAssignment::Entity::delete_many()
        .filter(UserRoleAssignment::Column::RoleId.eq(id))
        .exec(&txn)
        .await?;

    TargetRoleAssignment::Entity::delete_many()
        .filter(TargetRoleAssignment::Column::RoleId.eq(id))
        .exec(&txn)
        .await?;

    role.clone().delete(&txn).await?;
    txn.commit().await?;
    Ok(Unaudited::deleted(role))
}
