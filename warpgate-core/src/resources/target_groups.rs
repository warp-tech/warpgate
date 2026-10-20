use poem_openapi::Object;
use sea_orm::prelude::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, ModelTrait, QueryFilter, Set,
    TransactionTrait,
};
use uuid::Uuid;
use warpgate_db_entities::TargetGroup::BootstrapThemeColor;
use warpgate_db_entities::{Target, TargetGroup};

use super::{ResourceError, check_name, name_taken};

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

pub async fn create<C: ConnectionTrait>(
    db: &C,
    data: &TargetGroupDataRequest,
) -> Result<TargetGroup::Model, ResourceError> {
    check_name(&data.name)?;
    let mut model = TargetGroup::ActiveModel {
        id: Set(Uuid::new_v4()),
        ..Default::default()
    };
    set_data(&mut model, data);
    model.insert(db).await.map_err(name_taken)
}

pub async fn update<C: ConnectionTrait>(
    db: &C,
    id: Uuid,
    data: &TargetGroupDataRequest,
) -> Result<TargetGroup::Model, ResourceError> {
    check_name(&data.name)?;
    let group = TargetGroup::Entity::find_by_id(id)
        .one(db)
        .await?
        .ok_or(ResourceError::NotFound)?;

    let mut model: TargetGroup::ActiveModel = group.into();
    set_data(&mut model, data);
    model.update(db).await.map_err(name_taken)
}

pub async fn delete<C: ConnectionTrait + TransactionTrait>(
    db: &C,
    id: Uuid,
) -> Result<(), ResourceError> {
    let txn = db.begin().await?;
    let group = TargetGroup::Entity::find_by_id(id)
        .one(&txn)
        .await?
        .ok_or(ResourceError::NotFound)?;

    Target::Entity::update_many()
        .col_expr(Target::Column::GroupId, Expr::value(Option::<Uuid>::None))
        .filter(Target::Column::GroupId.eq(id))
        .exec(&txn)
        .await?;

    group.delete(&txn).await?;
    txn.commit().await?;
    Ok(())
}
