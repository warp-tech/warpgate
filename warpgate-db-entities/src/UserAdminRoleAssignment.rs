use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "user_admin_roles")]
#[oai(rename = "UserAdminRoleAssignment")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i32,
    pub user_id: Uuid,
    pub admin_role_id: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {
    User,
    AdminRole,
}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        match self {
            Self::User => Entity::belongs_to(super::User::Entity)
                .from(Column::UserId)
                .to(super::User::Column::Id)
                .into(),
            Self::AdminRole => Entity::belongs_to(super::AdminRole::Entity)
                .from(Column::AdminRoleId)
                .to(super::AdminRole::Column::Id)
                .into(),
        }
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl Related<super::AdminRole::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::AdminRole.def()
    }
}

impl Related<super::User::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}
