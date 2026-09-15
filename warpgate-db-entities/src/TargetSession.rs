use sea_orm::entity::prelude::*;
use sea_orm::sea_query::OnConflict;
use sea_orm::TransactionTrait;
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::audit::AuditEvent;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{NodeId, Target, TargetSessionId, UserSessionId, WarpgateError};

use crate::TargetSession;

/// Target session owned by a [`super::UserSession`] (in DB only, no handle).
/// One user session can have one or more (for HTTP) target sessions
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "target_sessions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: TargetSessionId,
    pub user_session_id: UserSessionId,
    pub target_snapshot: String,
    pub target_id: Uuid,
    pub started: OffsetDateTime,
    pub ended: Option<OffsetDateTime>,
    pub ticket_id: Option<Uuid>,
    /// The node that served this session, for cluster routing
    pub node_id: Option<NodeId>,
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

pub enum TargetSessionOpenOutcome {
    Created(Model),
    AlreadyExists(Model),
}

/// (user_session, target) is unique, a user session cannot connect to a target twice
pub async fn open_or_lookup(
    db: &DatabaseConnection,
    preferred_id: TargetSessionId,
    user_session_id: UserSessionId,
    target: &Target,
    node_id: Option<NodeId>,
    ticket_id: Option<Uuid>,
    user_info: &AuthStateUserInfo,
) -> Result<TargetSessionOpenOutcome, WarpgateError> {
    use sea_orm::ActiveValue::Set;

    let transaction = db.begin().await?;
    let Some(parent) = super::UserSession::lock_for_update(&transaction, user_session_id).await?
    else {
        return Err(WarpgateError::UserSessionEnded);
    };
    if parent.ended.is_some() {
        return Err(WarpgateError::UserSessionEnded);
    }

    let mut snapshot = serde_json::to_value(target)?;
    warpgate_common::redact_target_secrets(&mut snapshot);
    let model = TargetSession::ActiveModel {
        id: Set(preferred_id),
        user_session_id: Set(user_session_id),
        target_snapshot: Set(snapshot.to_string()),
        target_id: Set(target.id),
        started: Set(OffsetDateTime::now_utc()),
        ended: Set(None),
        ticket_id: Set(ticket_id),
        node_id: Set(node_id),
    };

    insert_unless_already_open(model)
        .do_nothing()
        .exec_without_returning(&transaction)
        .await?;
    let row = Entity::find()
        .filter(Column::UserSessionId.eq(user_session_id))
        .filter(Column::TargetId.eq(target.id))
        .one(&transaction)
        .await?
        .ok_or_else(|| {
            WarpgateError::InconsistentState("recorded target access not found".into())
        })?;
    transaction.commit().await?;

    let created = row.id == preferred_id;
    if created {
        AuditEvent::TargetSessionStarted {
            session_id: preferred_id.0,
            target_id: target.id,
            target_name: target.name.clone(),
            user_id: user_info.id,
            username: user_info.username.clone(),
        }
        .emit();
        return Ok(TargetSessionOpenOutcome::Created(row));
    }

    Ok(TargetSessionOpenOutcome::AlreadyExists(row))
}

/// The insert half of [`open_or_lookup`]: a row per `(user_session, target)`,
/// left exactly as it is when one already exists. Built separately so a test
/// can check the SQL it renders on every backend — the natural spelling,
/// `OnConflict::do_nothing()`, renders as `ON DUPLICATE KEY IGNORE` on MySQL,
/// which is not MySQL syntax; the no-op self-assignment is the portable form.
fn insert_unless_already_open(model: ActiveModel) -> sea_orm::Insert<ActiveModel> {
    Entity::insert(model).on_conflict(
        OnConflict::columns([Column::UserSessionId, Column::TargetId])
            .update_column(Column::UserSessionId)
            .to_owned(),
    )
}

pub async fn is_open(
    db: &DatabaseConnection,
    user_session_id: UserSessionId,
    target_id: Uuid,
) -> Result<bool, WarpgateError> {
    Ok(Entity::find()
        .filter(Column::UserSessionId.eq(user_session_id))
        .filter(Column::TargetId.eq(target_id))
        .filter(Column::Ended.is_null())
        .one(db)
        .await?
        .is_some())
}

pub fn emit_ended_audit_event(session: &TargetSession::Model, user_id: Uuid, username: &str) {
    let Some(target_name) = serde_json::from_str::<serde_json::Value>(&session.target_snapshot)
        .ok()
        .and_then(|value| {
            value
                .get("name")
                .and_then(|name| name.as_str())
                .map(str::to_owned)
        })
    else {
        return;
    };
    AuditEvent::TargetSessionEnded {
        session_id: session.id.0,
        target_id: session.target_id,
        target_name,
        user_id,
        username: username.into(),
    }
    .emit();
}

#[cfg(test)]
mod tests {
    use sea_orm::{DbBackend, QueryTrait, Set};

    use super::*;

    /// The statement [`open_or_lookup`] executes must be valid SQL on every
    /// backend it can meet. This failed silently once: sea-query renders
    /// `OnConflict::do_nothing()` as `ON DUPLICATE KEY IGNORE` on MySQL —
    /// ERROR 1064 on a real server — and nothing before a MySQL deployment
    /// would have said so, because the protocol test suites run on SQLite.
    #[test]
    fn the_open_conflict_clause_renders_valid_sql_on_every_backend() {
        let model = ActiveModel {
            id: Set(TargetSessionId(Uuid::new_v4())),
            user_session_id: Set(UserSessionId(Uuid::new_v4())),
            target_snapshot: Set("{}".into()),
            target_id: Set(Uuid::new_v4()),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            ticket_id: Set(None),
            node_id: Set(None),
        };

        for backend in [DbBackend::MySql, DbBackend::Postgres, DbBackend::Sqlite] {
            let sql = insert_unless_already_open(model.clone())
                .build(backend)
                .to_string();
            assert!(
                !sql.contains("ON DUPLICATE KEY IGNORE"),
                "{backend:?} rendered sea-query's invalid MySQL construct: {sql}",
            );
            let has_valid_conflict_action =
                sql.contains("ON DUPLICATE KEY UPDATE") || sql.contains("ON CONFLICT");
            assert!(has_valid_conflict_action, "{backend:?}: {sql}");
        }
    }
}
