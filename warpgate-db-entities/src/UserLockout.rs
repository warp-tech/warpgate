use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
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
    pub locked_at: OffsetDateTime,

    /// When the lockout expires (None = manual unlock required)
    pub expires_at: Option<OffsetDateTime>,

    /// Reason for the lockout
    pub reason: String,

    /// Number of failed attempts that triggered this lockout
    pub failed_attempt_count: i32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
