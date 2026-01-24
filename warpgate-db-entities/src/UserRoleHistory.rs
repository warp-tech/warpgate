use chrono::{DateTime, Utc};
use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize, Object)]
#[sea_orm(table_name = "user_role_history")]
#[oai(rename = "UserRoleHistory")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub user_id: Uuid,
    pub role_id: Uuid,
    /// Action type: 'granted', 'revoked', 'expired', 'renewed', 'expiry_changed'
    pub action: String,
    pub occurred_at: DateTime<Utc>,
    /// Who performed this action (admin user ID, null for system)
    pub actor_id: Option<Uuid>,
    /// JSON details about the action (snapshot of assignment state)
    #[sea_orm(column_type = "JsonBinary")]
    pub details: serde_json::Value,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
