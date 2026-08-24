use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

/// One target connection/access instance owned by a [`super::UserSession`].
/// The identity of the login (user, origin address, protocol) lives on the
/// parent row. Keeps the pre-split `sessions` table name: renaming a released
/// table would break older nodes that still write to it during a rolling
/// upgrade.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sessions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The authenticated login that owns this target connection. The migration
    /// pairs every pre-split row with a parent of the same id, so no row is
    /// ever without one.
    pub user_session_id: Uuid,
    pub target_snapshot: String,
    pub target_id: Uuid,
    pub started: OffsetDateTime,
    pub ended: Option<OffsetDateTime>,
    pub ticket_id: Option<Uuid>,
    /// The node serving this target connection, for connection-bound
    /// protocols — live streams (recordings) route here. NULL for shared
    /// (HTTP) target sessions, which are access records any node serves and
    /// which end with their parent rather than with a node.
    pub node_id: Option<Uuid>,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {
    Recordings,
    Ticket,
    UserSession,
}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        match self {
            Self::Recordings => Entity::has_many(super::Recording::Entity)
                .from(Column::Id)
                .to(super::Recording::Column::SessionId)
                .into(),
            Self::Ticket => Entity::belongs_to(super::Ticket::Entity)
                .from(Column::TicketId)
                .to(super::Ticket::Column::Id)
                .on_delete(ForeignKeyAction::SetNull)
                .into(),
            // The schema has no foreign key for this relation and no cascade:
            // `cleanup_db` owns the deletion order, since recording files must
            // be removed before their rows and a parent must outlive its
            // children there.
            Self::UserSession => Entity::belongs_to(super::UserSession::Entity)
                .from(Column::UserSessionId)
                .to(super::UserSession::Column::Id)
                .into(),
        }
    }
}

impl Related<super::Ticket::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Ticket.def()
    }
}

impl Related<super::UserSession::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::UserSession.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
