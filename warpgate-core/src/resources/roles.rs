use poem_openapi::Object;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, ModelTrait, QueryFilter, Set,
    TransactionSession, TransactionTrait,
};
use uuid::Uuid;
use warpgate_common::RoleId;
use warpgate_db_entities::{Role, TargetRoleAssignment, UserRoleAssignment};
use warpgate_gitops::types::ResourceKind;

use super::{Actor, OwnedEntity, ResourceError, check_name, name_taken};

impl OwnedEntity for Role::Entity {
    type Id = RoleId;
    const KIND: ResourceKind = ResourceKind::Role;
    const ID: Self::Column = Role::Column::Id;
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

pub async fn create<C: ConnectionTrait>(
    db: &C,
    actor: Actor,
    data: &RoleDataRequest,
) -> Result<Role::Model, ResourceError> {
    check_name(&data.name)?;
    let mut model = Role::ActiveModel {
        id: Set(RoleId(Uuid::new_v4())),
        is_default: Set(false),
        provider: Set(actor.provider_id()),
        ..Default::default()
    };
    set_data(&mut model, data);
    model.insert(db).await.map_err(name_taken)
}

pub async fn update<C: ConnectionTrait>(
    db: &C,
    actor: Actor,
    id: RoleId,
    data: &RoleDataRequest,
) -> Result<Role::Model, ResourceError> {
    check_name(&data.name)?;
    let role = Role::Entity::find_by_id(id)
        .one(db)
        .await?
        .ok_or(ResourceError::NotFound)?;
    actor.may_write(role.provider)?;

    let mut model: Role::ActiveModel = role.into();
    set_data(&mut model, data);
    model.update(db).await.map_err(name_taken)
}

/// Also removes every assignment of the role, including revoked ones
pub async fn delete<C: ConnectionTrait + TransactionTrait>(
    db: &C,
    actor: Actor,
    id: RoleId,
) -> Result<Role::Model, ResourceError> {
    let txn = db.begin().await?;
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
    Ok(role)
}
