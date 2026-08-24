use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "http_sessions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub expires: Option<OffsetDateTime>,
    #[sea_orm(column_type = "Text")]
    pub data: String,
    pub updated: OffsetDateTime,
    /// The Warpgate user session this browser session backs, mirrored out of
    /// `data` at save time so that ending, revocation and reaping are indexed
    /// SQL instead of JSON parsing. `None` until a session registers one (or
    /// for rows written by nodes predating the column — those fall back to
    /// the JSON).
    pub user_session_id: Option<Uuid>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// Key under which the stored `data` JSON carries the Warpgate user session
/// id. The canonical home of the key: the HTTP session middleware reads and
/// writes it, and the m00081 backfill mirrors it into `user_session_id`.
pub const SESSION_ID_DATA_KEY: &str = "session_id";
