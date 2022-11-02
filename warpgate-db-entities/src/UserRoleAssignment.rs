use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "user_roles")]
#[oai(rename = "UserRoleAssignment")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: u32,
    pub user_id: Uuid,
    pub role_id: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {
    User,
    Role,
}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        match self {
            Self::User => Entity::belongs_to(super::User::Entity)
                .from(Column::UserId)
                .to(super::User::Column::Id)
                .into(),
            Self::Role => Entity::belongs_to(super::Role::Entity)
                .from(Column::RoleId)
                .to(super::Role::Column::Id)
                .into(),
        }
    }
}

impl ActiveModelBehavior for ActiveModel {}
