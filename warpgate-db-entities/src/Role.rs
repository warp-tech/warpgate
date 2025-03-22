use poem_openapi::Object;
use sea_orm::entity::prelude::*;
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

impl From<Model> for Role {
    fn from(model: Model) -> Self {
        Self {
            id: model.id,
            name: model.name,
            description: model.description,
        }
    }
}
