use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "user_lockouts")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,

    /// Username that is locked (unique constraint)
    #[sea_orm(unique)]
    pub username: String,

    /// When the lockout started
    pub locked_at: DateTime<Utc>,

    /// When the lockout expires (None = manual unlock required)
    pub expires_at: Option<DateTime<Utc>>,

    /// Reason for the lockout
    pub reason: String,

    /// Number of failed attempts that triggered this lockout
    pub failed_attempt_count: i32,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        panic!("No relations defined")
    }
}

impl ActiveModelBehavior for ActiveModel {}
