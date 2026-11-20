use poem_openapi::Object;
use sea_orm::prelude::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, ModelTrait, QueryFilter, Set,
    TransactionSession, TransactionTrait,
};
use uuid::Uuid;
use warpgate_common::{RowId, TargetGroupId, WarpgateError};
use warpgate_db_entities::TargetGroup::BootstrapThemeColor;
use warpgate_db_entities::{Target, TargetGroup};
use warpgate_resources::{Comparable, ComparableValues, ResourceKind, Row, TargetGroupSpec};

use super::audit::{Audited, Subject, Unaudited};
use super::{Actor, OwnedEntity, ResourceError, check_name, name_taken};

impl OwnedEntity for TargetGroup::Entity {
    type Id = TargetGroupId;
    const KIND: ResourceKind = ResourceKind::TargetGroup;
    const ID: Self::Column = TargetGroup::Column::Id;
    const NAME: Self::Column = TargetGroup::Column::Name;
    const PROVIDER: Self::Column = TargetGroup::Column::Provider;
}

#[derive(Object)]
pub struct TargetGroupDataRequest {
    pub name: String,
    pub description: Option<String>,
    pub color: Option<BootstrapThemeColor>,
}

fn set_data(model: &mut TargetGroup::ActiveModel, data: &TargetGroupDataRequest) {
    model.name = Set(data.name.clone());
    model.description = Set(data.description.clone().unwrap_or_default());
    model.color = Set(data.color.clone());
}

pub(super) fn row(group: TargetGroup::Model) -> Row<TargetGroupSpec> {
    Row {
        id: group.id.uuid(),
        name: group.name,
        provider: group.provider,
        live: TargetGroupSpec {
            description: group.description,
            color: group.color,
        },
    }
}

impl Audited for TargetGroup::Model {
    fn subject(&self) -> Subject {
        Subject::of::<TargetGroup::Entity>(self.id)
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
    data: &TargetGroupDataRequest,
) -> Result<Unaudited<TargetGroup::Model>, ResourceError> {
    check_name(&data.name)?;
    let mut model = TargetGroup::ActiveModel {
        id: Set(TargetGroupId(Uuid::new_v4())),
        provider: Set(actor.provider_id()),
        ..Default::default()
    };
    set_data(&mut model, data);
    let group = model.insert(db).await.map_err(name_taken)?;
    Ok(Unaudited::created(group))
}

pub async fn update<C: ConnectionTrait>(
    db: &C,
    actor: Actor,
    id: TargetGroupId,
    data: &TargetGroupDataRequest,
) -> Result<Unaudited<TargetGroup::Model>, ResourceError> {
    check_name(&data.name)?;
    let before = TargetGroup::Entity::find_by_id(id)
        .one(db)
        .await?
        .ok_or(ResourceError::NotFound)?;
    actor.may_write(before.provider)?;

    let mut model: TargetGroup::ActiveModel = before.clone().into();
    set_data(&mut model, data);
    let after = model.update(db).await.map_err(name_taken)?;
    Ok(Unaudited::updated(before, after))
}

pub async fn delete<C: ConnectionTrait + TransactionTrait>(
    db: &C,
    actor: Actor,
    id: TargetGroupId,
) -> Result<Unaudited<TargetGroup::Model>, ResourceError> {
    let txn = db.begin().await?;
    let group = TargetGroup::Entity::find_by_id(id)
        .one(&txn)
        .await?
        .ok_or(ResourceError::NotFound)?;
    actor.may_write(group.provider)?;

    Target::Entity::update_many()
        .col_expr(Target::Column::GroupId, Expr::value(Option::<Uuid>::None))
        .filter(Target::Column::GroupId.eq(id))
        .exec(&txn)
        .await?;

    group.clone().delete(&txn).await?;
    txn.commit().await?;
    Ok(Unaudited::deleted(group))
}
