use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

/// A running process in a cluster
/// Nodes self-register on start
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "nodes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// How peers reach this node directly (host:port), for cross-node proxying.
    pub address: String,
    pub hostname: String,
    pub last_seen: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
