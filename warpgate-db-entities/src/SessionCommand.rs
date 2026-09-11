use sea_orm::entity::prelude::*;
use sea_orm::ActiveValue::Set;
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::{NodeId, TargetSessionId};

/// A shell command submitted during an SSH target session, recovered from the
/// terminal output stream by the command detector and persisted for search.
/// Only exists for sessions recorded after this table was introduced; the
/// detector is heuristic (see `warpgate-protocol-ssh`'s command detector docs).
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "session_commands")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub target_session_id: TargetSessionId,
    #[sea_orm(column_type = "Text")]
    pub command: String,
    pub time: OffsetDateTime,
    /// The node that recorded the command, for cluster routing
    pub node_id: Option<NodeId>,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {
    TargetSession,
}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        match self {
            // Like recordings: removed together with their target session
            // (`cleanup_db` deletes the parent row explicitly).
            Self::TargetSession => Entity::belongs_to(super::TargetSession::Entity)
                .from(Column::TargetSessionId)
                .to(super::TargetSession::Column::Id)
                .on_delete(ForeignKeyAction::Cascade)
                .into(),
        }
    }
}

impl Related<super::TargetSession::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::TargetSession.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl Entity {
    /// Persist one detected command. Recording must never break the session,
    /// so callers treat an error as terminal for persistence (and fall back to
    /// logging) rather than retrying.
    pub async fn insert_detected(
        db: &DatabaseConnection,
        target_session_id: TargetSessionId,
        command: &str,
        node_id: Option<NodeId>,
    ) -> Result<(), DbErr> {
        Entity::insert(ActiveModel {
            id: Set(Uuid::new_v4()),
            target_session_id: Set(target_session_id),
            command: Set(command.to_string()),
            time: Set(OffsetDateTime::now_utc()),
            node_id: Set(node_id),
        })
        .exec_without_returning(db)
        .await?;
        Ok(())
    }
}
