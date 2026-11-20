use std::time::Duration;

use sea_orm::DatabaseConnection;
use sea_orm::sea_query::IntoCondition;
use time::OffsetDateTime;
use tracing::warn;
use warpgate_common::auth::ApprovalKind;
use warpgate_common::{NodeId, UserSessionId, WarpgateError};
use warpgate_db_entities::SessionApprovalRequest::{
    self, Advertised, ApprovalActor, close_request, mark_consumed, upsert_request,
};

use super::*;
use crate::logging::AuditEvent;

// An "owning" close-on-drop guard for an approval
pub(super) struct PendingApproval {
    session_id: UserSessionId,
    target: String,
    db: DatabaseConnection,
    /// How to close the request if there is no decision
    close_as: Option<SessionApprovalRequest::UndecidedApprovalRequestStatus>,
}

impl Drop for PendingApproval {
    fn drop(&mut self) {
        let session_id = self.session_id;
        let target = std::mem::take(&mut self.target);
        let db = self.db.clone();
        let close_as = self.close_as;
        tokio::spawn(async move {
            let _ = match close_as {
                Some(status) => {
                    close_request(&db, session_id, ApprovalKind::Admin, &target, status)
                        .await
                        .map(|_| ())
                }
                None => {
                    mark_consumed(
                        &db,
                        SessionApprovalRequest::Key::new(session_id, ApprovalKind::Admin, &target),
                    )
                    .await
                }
            };
        });
    }
}

impl PendingApproval {
    pub(super) fn guarding(db: DatabaseConnection, subject: &ApprovalSubject) -> Self {
        Self {
            session_id: subject.session_id,
            target: subject.target_name.clone(),
            db,
            close_as: Some(SessionApprovalRequest::UndecidedApprovalRequestStatus::Abandoned),
        }
    }

    pub(super) const fn timed_out(&mut self) {
        self.close_as = Some(SessionApprovalRequest::UndecidedApprovalRequestStatus::TimedOut);
    }

    pub(super) const fn decided(&mut self) {
        self.close_as = None;
    }
}

/// Idempotently write a request rentry
pub(super) async fn advertise_admin_request(
    db: &DatabaseConnection,
    node_id: NodeId,
    subject: &ApprovalSubject,
) -> Result<Advertised, WarpgateError> {
    upsert_request(
        db,
        SessionApprovalRequest::NewRequest {
            session_id: subject.session_id,
            target: subject.target_name.clone(),
            node_id,
            protocol: subject.protocol.to_string(),
            username: subject.user_info.username.clone(),
            user_id: subject.user_info.id,
            remote_address: subject.remote_ip.map(|ip| ip.to_string()),
            match_digest: subject.match_digest(),
            started: OffsetDateTime::now_utc(),
            about: SessionApprovalRequest::RequestAsk::Admin {
                ticket_id: subject.ticket_id,
            },
        },
    )
    .await
}

pub(super) const POLL_INTERVAL: Duration = Duration::from_secs(1);

pub(super) enum DecisionWaitOutcome {
    Decided(ApprovalDecision),
    /// The row is gone
    Ended,
    TimedOut,
}

pub(super) enum RowState {
    /// Still a live question.
    Pending,
    Decided(ApprovalDecision),
    Ended,
}

pub(super) fn row_state(row: &SessionApprovalRequest::Model) -> Result<RowState, WarpgateError> {
    use SessionApprovalRequest::ApprovalRequestStatus;

    let decision = match row.status {
        ApprovalRequestStatus::Pending => return Ok(RowState::Pending),
        ApprovalRequestStatus::TimedOut | ApprovalRequestStatus::Abandoned => {
            return Ok(RowState::Ended);
        }
        ApprovalRequestStatus::Rejected => ApprovalDecision::Rejected,
        ApprovalRequestStatus::Approved => {
            ApprovalDecision::Approved(row.scope.unwrap_or(ApprovalScope::Once))
        }
    };
    Ok(RowState::Decided(decision))
}

pub(super) async fn find_row(
    db: &DatabaseConnection,
    session_id: UserSessionId,
    kind: ApprovalKind,
    target: &str,
) -> Result<Option<SessionApprovalRequest::Model>, WarpgateError> {
    Ok(SessionApprovalRequest::Entity::find()
        .filter(SessionApprovalRequest::Key::new(session_id, kind, target).into_condition())
        .one(db)
        .await?)
}

/// The decision recorded on the row, if there is one
pub(super) async fn row_decision(
    db: &DatabaseConnection,
    session_id: UserSessionId,
    kind: ApprovalKind,
    target: &str,
) -> Result<Option<ApprovalDecision>, WarpgateError> {
    let Some(row) = find_row(db, session_id, kind, target).await? else {
        return Ok(None);
    };
    Ok(match row_state(&row)? {
        RowState::Decided(decision) => Some(decision),
        RowState::Pending | RowState::Ended => None,
    })
}

/// Close the request as timed out. Returns whether this close is what ended
/// it, in which case the timeout is also audited; `false` means a decision or
/// another close got there first.
pub(super) async fn close_timed_out(
    db: &DatabaseConnection,
    subject: &ApprovalSubject,
) -> Result<bool, WarpgateError> {
    let closed = close_request(
        db,
        subject.session_id,
        ApprovalKind::Admin,
        &subject.target_name,
        SessionApprovalRequest::UndecidedApprovalRequestStatus::TimedOut,
    )
    .await?;
    if closed {
        subject.emit_timed_out_event();
    }
    Ok(closed)
}

pub(super) async fn await_row_decision(
    db: &DatabaseConnection,
    session_id: UserSessionId,
    kind: ApprovalKind,
    target: &str,
    timeout: Duration,
) -> Result<DecisionWaitOutcome, WarpgateError> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut ticker = tokio::time::interval(POLL_INTERVAL);

    loop {
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => return Ok(DecisionWaitOutcome::TimedOut),
            // The first tick is immediate
            _ = ticker.tick() => {
                match find_row(db, session_id, kind, target).await {
                    Ok(Some(row)) => match row_state(&row)? {
                        RowState::Pending => {}
                        RowState::Decided(decision) => {
                            return Ok(DecisionWaitOutcome::Decided(decision));
                        }
                        // Something else ended it
                        RowState::Ended => return Ok(DecisionWaitOutcome::Ended),
                    },
                    // row is gone
                    Ok(None) => return Ok(DecisionWaitOutcome::Ended),
                    Err(error) => {
                        // Do not fail the wait because of a single DB error
                        warn!(%error, "Failed to read a session approval request");
                    }
                }
            }
        }
    }
}

pub async fn record_decision(
    db: &DatabaseConnection,
    session_id: UserSessionId,
    kind: ApprovalKind,
    target: &str,
    decision: ApprovalDecision,
    actor: ApprovalActor,
) -> Result<bool, WarpgateError> {
    use SessionApprovalRequest::ApprovalRequestStatus;

    let (status, scope) = match decision {
        ApprovalDecision::Approved(scope) => (ApprovalRequestStatus::Approved, Some(scope)),
        ApprovalDecision::Rejected => (ApprovalRequestStatus::Rejected, None),
    };

    let Some(row) = find_row(db, session_id, kind, target)
        .await?
        .filter(|row| row.status == ApprovalRequestStatus::Pending)
    else {
        // entry is gone or already decided
        return Ok(false);
    };

    let recorded = SessionApprovalRequest::settle_request(db, &row, status, scope, &actor).await?;
    if recorded {
        emit_resolved_event(
            &row,
            &actor,
            matches!(decision, ApprovalDecision::Approved(_)),
        );
    }
    Ok(recorded)
}

/// Audit is emitted by the node that changes the stored status (not by the session-owned node which might be gone)
pub(super) fn emit_resolved_event(
    row: &SessionApprovalRequest::Model,
    actor: &ApprovalActor,
    approved: bool,
) {
    AuditEvent::SessionApprovalResolved {
        session_id: row.session_id,
        client_ip: row
            .remote_address
            .clone()
            .unwrap_or_else(|| "<unknown>".into()),
        user_id: row.user_id,
        username: row.username.clone(),
        protocol: row.protocol.clone(),
        target_name: row.target.clone(),
        kind: row.kind,
        resolved_by: actor.username.clone().unwrap_or_else(|| "<unknown>".into()),
        resolved_by_user_id: actor.user_id,
        approved,
    }
    .emit();
}
