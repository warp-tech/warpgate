use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "ip_blocks")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,

    /// IP address that is blocked (unique constraint)
    #[sea_orm(unique)]
    pub ip_address: String,

    /// Number of times this IP has been blocked (for exponential backoff)
    pub block_count: i32,

    /// When the current block started
    pub blocked_at: DateTime<Utc>,

    /// When the current block expires
    pub expires_at: DateTime<Utc>,

    /// Reason for the block
    pub reason: String,

    /// Last failed attempt time (for cooldown reset tracking)
    pub last_attempt_at: DateTime<Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        panic!("No relations defined")
    }
}

impl ActiveModelBehavior for ActiveModel {}
