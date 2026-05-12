use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use sea_orm::{ColumnTrait, QueryFilter};
use serde::Serialize;
use uuid::Uuid;
use warpgate_common::Role;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "roles")]
#[oai(rename = "Role")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub name: String,
    #[sea_orm(column_type = "Text")]
    pub description: String,
    pub is_default: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl Related<super::Target::Entity> for Entity {
    fn to() -> RelationDef {
        super::TargetRoleAssignment::Relation::Target.def()
    }

    fn via() -> Option<RelationDef> {
        Some(super::TargetRoleAssignment::Relation::Role.def().rev())
    }
}

impl Related<super::User::Entity> for Entity {
    fn to() -> RelationDef {
        super::UserRoleAssignment::Relation::User.def()
    }

    fn via() -> Option<RelationDef> {
        Some(super::UserRoleAssignment::Relation::Role.def().rev())
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl Entity {
    pub async fn get_default_roles(db: &DatabaseConnection) -> Result<Vec<Model>, DbErr> {
        Self::find()
            .filter(Column::IsDefault.eq(true))
            .all(db)
            .await
    }

    pub async fn grant_default_roles(
        db: &DatabaseConnection,
        user_id: Uuid,
    ) -> Result<Vec<Model>, DbErr> {
        let roles = Self::get_default_roles(db).await?;

        for role in &roles {
            super::UserRoleAssignment::Entity::idempotent_grant(db, user_id, role.id, None).await?;
        }

        Ok(roles)
    }
}

impl From<Model> for Role {
    fn from(model: Model) -> Self {
        Self {
            id: model.id,
            name: model.name,
            description: model.description,
            is_default: model.is_default,
        }
    }
}
