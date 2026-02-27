use chrono::{DateTime, Utc};
use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "user_roles")]
#[oai(rename = "UserRoleAssignment")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i32,
    pub user_id: Uuid,
    pub role_id: Uuid,
    /// When this role assignment was granted (nullable in DB for SQLite compat, but always set by app)
    pub granted_at: Option<DateTime<Utc>>,
    /// Who granted this role assignment (admin user ID, null for system/SSO)
    pub granted_by: Option<Uuid>,
    /// When this role assignment expires (null = never)
    pub expires_at: Option<DateTime<Utc>>,
    /// When this role assignment was revoked (null = not revoked)
    pub revoked_at: Option<DateTime<Utc>>,
    /// Who revoked this role assignment
    pub revoked_by: Option<Uuid>,
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
