use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

/// A Warpgate login/authentication lifetime. Target connections are recorded
/// separately as [`super::TargetSession`] rows, linked through
/// `user_session_id`.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "user_sessions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub username: Option<String>,
    pub user_id: Option<Uuid>,
    pub remote_address: String,
    pub started: OffsetDateTime,
    pub ended: Option<OffsetDateTime>,
    pub protocol: String,
    /// The node whose registration this session's lifetime is bound to, for
    /// connection-bound protocols; NULL for shared (DB-backed) sessions, which
    /// any node serves and no node's death ends. See
    /// `warpgate_common::SessionLifecycle`.
    pub node_id: Option<Uuid>,
    /// The node holding this session's in-flight login state
    /// (`AuthStateStore` is in-memory), stamped whenever a node creates an
    /// auth state for the session. Login steps and web approvals landing
    /// elsewhere are forwarded here. Stale after the login completes — a
    /// forwarded miss falls back to a local not-found.
    pub auth_state_node_id: Option<Uuid>,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {
    TargetSessions,
}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        match self {
            Self::TargetSessions => Entity::has_many(super::TargetSession::Entity)
                .from(Column::Id)
                .to(super::TargetSession::Column::UserSessionId)
                .into(),
        }
    }
}

impl Related<super::TargetSession::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::TargetSessions.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
