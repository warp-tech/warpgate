use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

/// A shell command detected in a session's terminal stream.
///
/// Detection is a heuristic on top of opaque PTY traffic (see
/// `warpgate_protocol_ssh::command_detector`), so rows are an audit aid, not a
/// record of intent. No foreign keys: session rows are pruned independently and
/// a command outliving its session is still worth keeping.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "commands")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub timestamp: OffsetDateTime,
    pub user_session_id: Uuid,
    pub username: Option<String>,
    #[sea_orm(column_type = "Text")]
    pub command: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
