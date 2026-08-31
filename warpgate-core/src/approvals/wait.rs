use std::time::Duration;

use sea_orm::sea_query::IntoCondition;
use sea_orm::ActiveValue::Set;
use sea_orm::DatabaseConnection;
use time::OffsetDateTime;
use tracing::{info, warn};
use warpgate_common::auth::ApprovalKind;
use warpgate_common::helpers::logging::format_related_ids;
use warpgate_common::{NodeId, UserSessionId, WarpgateError};
use warpgate_db_entities::SessionApprovalRequest;
use warpgate_db_entities::SessionApprovalRequest::{
    close_request, mark_consumed, upsert_request, Advertised,
};

use super::*;

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
        SessionApprovalRequest::ActiveModel {
            session_id: Set(subject.session_id),
            kind: Set(ApprovalKind::Admin.into()),
            node_id: Set(node_id),
            protocol: Set(subject.protocol.to_string()),
            username: Set(subject.user_info.username.clone()),
            user_id: Set(subject.user_info.id),
            target: Set(subject.target_name.clone()),
            remote_address: Set(subject.remote_ip.map(|ip| ip.to_string())),
            identification_string: Set(None),
            match_digest: Set(subject.match_digest()),
            ticket_id: Set(subject.ticket_id),
            started: Set(OffsetDateTime::now_utc()),
            status: Set(SessionApprovalRequest::ApprovalRequestStatus::Pending),
            scope: Set(None),
            resolved_by_username: Set(None),
            resolved_by_user_id: Set(None),
            resolved_at: Set(None),
            consumed_at: Set(None),
        },
    )
    .await
}

pub(super) const POLL_INTERVAL: Duration = Duration::from_secs(1);

pub(super) enum DecisionWaitOutcome {
    /// A decision was written to the row. The resolver is not carried along:
    /// they are recorded and audited where the decision is made, so a waiting
    /// gate only needs to know the answer.
    Decided(ApprovalDecision),
    /// The row stopped being a live question underneath the wait — the session
    /// ended, or it was reaped because this node looked dead. Nothing approved
    /// the connection.
    Ended,
    TimedOut,
}

/// What a request row currently says.
///
/// Three states, not an `Option`: "nobody has answered yet" and "this will never
/// be answered" both carry no decision but mean opposite things to a waiter, and
/// an `Option` makes them the same value with the difference left on the row for
/// each caller to re-derive.
pub(super) enum RowState {
    /// Still a live question.
    Pending,
    Decided(ApprovalDecision, ApprovalActor),
    /// Terminal with no decision — nobody answered in time, or nobody was left
    /// to answer for.
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
        // A missing scope reads as granting this connection only, the safe
        // reading of an approval that somehow recorded none.
        ApprovalRequestStatus::Approved => {
            ApprovalDecision::Approved(row.scope.unwrap_or(ApprovalScope::Once))
        }
    };
    // Both resolver columns are optional on the row for the same reason they
    // are on the actor: a resolver that isn't a user (the admin API token)
    // has neither.
    Ok(RowState::Decided(
        decision,
        ApprovalActor {
            username: row.resolved_by_username.clone(),
            user_id: row.resolved_by_user_id.unwrap_or(Uuid::nil()),
        },
    ))
}

/// Waits for a decision to be written to this question's row, giving up at
/// `timeout`.
///
/// Giving up early, when the client the gate is holding goes away, is the
/// caller's to arrange by dropping this future: the guards it is holding close
/// the row and refund the ticket on the way out.
///
/// A read failure keeps the wait going rather than ending it: a database blip
/// must not deny a connection an administrator is in the middle of approving,
/// and the timeout still bounds the wait.
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
                        RowState::Decided(decision, _) => {
                            return Ok(DecisionWaitOutcome::Decided(decision));
                        }
                        // Something else ended it
                        RowState::Ended => return Ok(DecisionWaitOutcome::Ended),
                    },
                    // row is gone
                    Ok(None) => return Ok(DecisionWaitOutcome::Ended),
                    Err(error) => {
                        warn!(%error, "Failed to read a session approval request");
                    }
                }
            }
        }
    }
}

/// Records a decision against a pending request, from whichever node the
/// approver happens to be talking to. `Ok(false)` when there is no longer a
/// pending request to decide — already resolved, or the waiter gave up and
/// closed it.
///
/// `target` is the question the approver believes they are answering — what
/// their screen said, or what the row said when it was looked up. A stale
/// click can only ever land on the question it was shown for, never on
/// another of the session's questions.
pub async fn record_decision(
    db: &DatabaseConnection,
    session_id: UserSessionId,
    kind: ApprovalKind,
    target: &str,
    decision: ApprovalDecision,
    actor: &ApprovalActor,
) -> Result<bool, WarpgateError> {
    use SessionApprovalRequest::ApprovalRequestStatus;

    let (status, scope) = match decision {
        ApprovalDecision::Approved(scope) => (ApprovalRequestStatus::Approved, Some(scope)),
        ApprovalDecision::Rejected => (ApprovalRequestStatus::Rejected, None),
    };

    // Read ahead of the write, off the pending row only: a question that is
    // already settled is not this call's to decide or audit, and the write
    // below is pinned to the asking read here — a question closed and asked
    // afresh in the window is one this decision must not land on. The row also
    // carries what the audit event says about the asker, and the ticket use a
    // rejection gives back.
    let Some(row) = SessionApprovalRequest::Entity::find()
        .filter(SessionApprovalRequest::Key::new(session_id, kind, target).into_condition())
        .one(db)
        .await?
        .filter(|row| row.status == ApprovalRequestStatus::Pending)
    else {
        return Ok(false);
    };

    let recorded = SessionApprovalRequest::decide_asking(
        db,
        &row,
        status,
        scope,
        actor.username.clone(),
        Some(actor.user_id),
    )
    .await?;
    // Audited here rather than where a gate reads the decision back: the
    // administrator acted, and that stands as a fact even if the connection
    // they were deciding about has already gone. Gated on the transition, so
    // of two approvers racing one question only the one that moved it logs.
    if recorded {
        emit_resolved_event(
            &row,
            actor,
            matches!(decision, ApprovalDecision::Approved(_)),
        );
    }
    Ok(recorded)
}

/// Audits a decision, from the row it was just written to.
///
/// Emitted by whoever moves the row out of `pending`, so an administrator's
/// approve or reject is recorded whether or not the held connection is still
/// there to receive it — a session that gave up, or an owning node that died,
/// must not make the decision disappear from the audit trail.
///
/// `session` is the user session id the session page filters its log by, and
/// the audit sink drops any event without it. `actor.user_id` is `None` when
/// the resolver isn't a user (the admin API token); it joins `related_users`
/// so the decision also shows up in the resolver's own trail, matching how
/// every other actor-driven event is attributed.
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
