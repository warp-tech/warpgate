//! Ending user sessions, with the audit events and cleanup that follow

use sea_orm::sea_query::IntoCondition;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect};
use tracing::error;
use uuid::Uuid;
use warpgate_common::{UserId, UserSessionId, WarpgateError};
use warpgate_db_entities::UserSession::{EndedTargetSessions, mark_ended_in_transaction};
use warpgate_db_entities::{
    HttpSession, SessionApprovalRequest, TargetSession, UserSession, begin_write,
};

use crate::logging::AuditEvent;

/// Logs the ended target sessions and closes the session's approval requests.
/// Call it only after the transaction that ended them has committed
pub async fn settle(ended: EndedTargetSessions, db: &DatabaseConnection) {
    let id = ended.id;
    if let (Some(user_id), Some(username)) = (ended.user_id, &ended.username) {
        for child in &ended.children {
            emit_ended_audit_event(child, user_id, username);
        }
    }
    if let Err(error) = SessionApprovalRequest::abandon_requests_for_session(db, id).await {
        error!(%error, %id, "Could not close the session's approval requests");
    }
}

fn emit_ended_audit_event(session: &TargetSession::Model, user_id: UserId, username: &str) {
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

pub async fn mark_ended_including_target_sessions(
    db: &DatabaseConnection,
    id: UserSessionId,
) -> Result<(), WarpgateError> {
    let transaction = begin_write(db).await?;
    let ended = mark_ended_in_transaction(&transaction, id).await?;
    transaction.commit().await?;
    settle(ended, db).await;
    Ok(())
}

/// The definite way to close a session
pub async fn revoke(db: &DatabaseConnection, id: UserSessionId) -> Result<(), WarpgateError> {
    let transaction = begin_write(db).await?;
    let ended = mark_ended_in_transaction(&transaction, id).await?;
    HttpSession::Entity::delete_many()
        .filter(HttpSession::Column::UserSessionId.eq(id))
        .exec(&transaction)
        .await?;
    transaction.commit().await?;
    settle(ended, db).await;
    Ok(())
}

/// Returns the ids it ended.
pub async fn revoke_open_matching(
    db: &DatabaseConnection,
    filter: impl IntoCondition,
) -> Result<Vec<UserSessionId>, WarpgateError> {
    let open: Vec<Uuid> = UserSession::Entity::find()
        .filter(UserSession::Column::Ended.is_null())
        .filter(filter)
        .select_only()
        .column(UserSession::Column::Id)
        .into_tuple()
        .all(db)
        .await?;
    let open: Vec<UserSessionId> = open.into_iter().map(UserSessionId).collect();
    for id in &open {
        // one at a time to emit audit events
        revoke(db, *id).await?;
    }
    Ok(open)
}
