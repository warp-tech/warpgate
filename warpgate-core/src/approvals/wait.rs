use std::time::Duration;

use sea_orm::DatabaseConnection;
use sea_orm::sea_query::IntoCondition;
use time::OffsetDateTime;
use tracing::{info, warn};
use warpgate_common::auth::ApprovalKind;
use warpgate_common::helpers::logging::format_related_ids;
use warpgate_common::{NodeId, UserSessionId, WarpgateError};
use warpgate_db_entities::SessionApprovalRequest::{
    self, Advertised, ApprovalActor, close_request, mark_consumed, upsert_request,
};

use super::*;

// An "owning" close-on-drop guard for an approval
pub(super) struct PendingApproval {
    session_id: UserSessionId,
    target: String,
    db: DatabaseConnection,
    on_drop: OnDrop,
    /// Already closed in-line, nothing left to do on drop
    closed: bool,
}

#[derive(Clone, Copy)]
enum OnDrop {
    /// No decision: close the request as this
    Close(SessionApprovalRequest::UndecidedApprovalRequestStatus),
    /// Acknowledge the decision read from the asking that started then
    Consume(OffsetDateTime),
}

impl Drop for PendingApproval {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        let session_id = self.session_id;
        let target = std::mem::take(&mut self.target);
        let db = self.db.clone();
        let on_drop = self.on_drop;
        tokio::spawn(async move {
            let result = match on_drop {
                OnDrop::Close(status) => {
                    close_request(&db, session_id, ApprovalKind::Admin, &target, status)
                        .await
                        .map(|_| ())
                }
                OnDrop::Consume(started) => mark_consumed(
                    &db,
                    SessionApprovalRequest::Key::new(session_id, ApprovalKind::Admin, &target),
                    started,
                )
                .await
                .map(|_| ()),
            };
            if let Err(error) = result {
                warn!(%error, %session_id, %target, "Failed to close an approval request");
            }
        });
    }
}

impl PendingApproval {
    pub(super) fn guarding(db: DatabaseConnection, subject: &ApprovalSubject) -> Self {
        Self {
            session_id: subject.session_id,
            target: subject.target_name.clone(),
            db,
            on_drop: OnDrop::Close(
                SessionApprovalRequest::UndecidedApprovalRequestStatus::Abandoned,
            ),
            closed: false,
        }
    }

    /// Unlike the drop, this is awaited: the caller ends the session next, and
    /// a question still open by then takes an answer the session never sees.
    pub(super) async fn close_timed_out(&mut self) -> Result<TimeoutClose, WarpgateError> {
        use SessionApprovalRequest::UndecidedApprovalRequestStatus::TimedOut;

        // Stays armed until the outcome is known, so a failure at either step
        // leaves the drop to try again
        self.on_drop = OnDrop::Close(TimedOut);
        if close_request(
            &self.db,
            self.session_id,
            ApprovalKind::Admin,
            &self.target,
            TimedOut,
        )
        .await?
        {
            self.closed = true;
            return Ok(TimeoutClose::Closed);
        }
        if let Some((decision, started)) =
            row_decision(&self.db, self.session_id, ApprovalKind::Admin, &self.target).await?
        {
            self.decided(started);
            Ok(TimeoutClose::Decided(decision))
        } else {
            self.closed = true;
            Ok(TimeoutClose::Ended)
        }
    }

    pub(super) const fn decided(&mut self, started: OffsetDateTime) {
        self.on_drop = OnDrop::Consume(started);
    }
}

pub(super) enum TimeoutClose {
    Closed,
    /// A decision reached the row first
    Decided(ApprovalDecision),
    /// Something else ended it
    Ended,
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
    /// With the `started` of the asking it was read from
    Decided(ApprovalDecision, OffsetDateTime),
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

/// The decision on the row and the `started` of its asking, if it carries one
pub(super) async fn row_decision(
    db: &DatabaseConnection,
    session_id: UserSessionId,
    kind: ApprovalKind,
    target: &str,
) -> Result<Option<(ApprovalDecision, OffsetDateTime)>, WarpgateError> {
    let Some(row) = SessionApprovalRequest::Entity::find()
        .filter(SessionApprovalRequest::Key::new(session_id, kind, target).into_condition())
        .one(db)
        .await?
    else {
        return Ok(None);
    };
    Ok(match row_state(&row)? {
        RowState::Decided(decision) => Some((decision, row.started)),
        RowState::Pending | RowState::Ended => None,
    })
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
                match SessionApprovalRequest::Entity::find().filter(
                    SessionApprovalRequest::Key::new(session_id, kind, target).into_condition()
                ).one(db).await {
                    Ok(Some(row)) => match row_state(&row)? {
                        RowState::Pending => {}
                        RowState::Decided(decision) => {
                            return Ok(DecisionWaitOutcome::Decided(decision, row.started));
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

    let Some(row) = SessionApprovalRequest::Entity::find()
        .filter(SessionApprovalRequest::Key::new(session_id, kind, target).into_condition())
        .one(db)
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
    // A user approving their own session is both parties — don't list twice.
    let mut related = vec![row.user_id];

    if actor.user_id != row.user_id {
        related.push(actor.user_id);
    }

    info!(
        target: "audit",
        _type = "SessionApprovalResolved1",
        session = %row.session_id,
        client_ip = %row.remote_address.as_deref().unwrap_or("<unknown>"),
        user_id = %row.user_id,
        username = %row.username,
        protocol = %row.protocol,
        target = %row.target,
        kind = ?row.kind,
        resolved_by = %actor.username.clone().unwrap_or("<unknown>".into()),
        approved = approved,
        related_users = %format_related_ids(&related),
        "Session approval resolved",
    );
}
