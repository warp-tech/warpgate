use std::time::Duration;

use sea_orm::ActiveValue::Set;
use sea_orm::DatabaseConnection;
use time::OffsetDateTime;
use tracing::{info, warn};
use warpgate_common::auth::{ApprovalKind, CredentialDigestSalt};
use warpgate_common::helpers::logging::format_related_ids;
use warpgate_common::{NodeId, UserSessionId, WarpgateError};
use warpgate_db_entities::SessionApprovalRequest;
use warpgate_db_entities::SessionApprovalRequest::{
    StatusTransition, close_request, find_question, mark_consumed, one_question, upsert_request,
};

use super::*;
use crate::config_providers::{consume_ticket, refund_ticket};

/// The request row an administrator gate is waiting on, closed when the wait
/// ends however it ends — resolved, timed out, cancelled, or the future dropped.
///
/// The guard names the whole question — session, kind and target — so a
/// straggling close can only ever land on its own row, never on one of the
/// session's other questions.
pub(super) struct PendingApproval {
    session_id: UserSessionId,
    target: String,
    db: DatabaseConnection,
    /// How to end the row if the wait produces no decision. `None` once one
    /// has, when the row is stamped as picked up instead.
    close_as: Option<SessionApprovalRequest::ApprovalRequestStatus>,
}

impl Drop for PendingApproval {
    fn drop(&mut self) {
        // Drop can't await. `reap_stale` and the session-teardown sweep both
        // cover a row this spawn never gets to close.
        let session_id = self.session_id;
        let target = std::mem::take(&mut self.target);
        let db = self.db.clone();
        let close_as = self.close_as;
        tokio::spawn(async move {
            let _ = match close_as {
                Some(status) => {
                    close_request(&db, session_id, ApprovalKind::Admin, &target, status).await
                }
                None => {
                    mark_consumed(&db, one_question(session_id, ApprovalKind::Admin, &target)).await
                }
            };
        });
    }
}

impl PendingApproval {
    /// Advertises the request and hands back a guard that owns the row, so no
    /// path can leave one behind however the wait ends.
    ///
    /// A failed advertise returns through the dropped guard, which cleans up
    /// after a partial write rather than leaving it to the reaper.
    pub(super) async fn begin(
        db: DatabaseConnection,
        node_id: NodeId,
        salt: &CredentialDigestSalt,
        subject: &ApprovalSubject,
    ) -> Result<Self, WarpgateError> {
        let guard = Self {
            session_id: subject.session_id,
            target: subject.target_name.clone(),
            db,
            close_as: Some(SessionApprovalRequest::ApprovalRequestStatus::Abandoned),
        };
        advertise_admin_request(&guard.db, node_id, salt, subject).await?;
        Ok(guard)
    }

    /// The window ran out with nobody having decided.
    pub(super) const fn timed_out(&mut self) {
        self.close_as = Some(SessionApprovalRequest::ApprovalRequestStatus::TimedOut);
    }

    /// A decision was read off the row and acted on, so the row keeps it and is
    /// only stamped as picked up.
    pub(super) const fn decided(&mut self) {
        self.close_as = None;
    }
}

/// Writes (idempotently) the request row an administrator gate advertises. Kept
/// beside [`PendingApproval::begin`], its only caller, so the row a guard owns
/// and the row this writes stay in step.
pub(super) async fn advertise_admin_request(
    db: &DatabaseConnection,
    node_id: NodeId,
    salt: &CredentialDigestSalt,
    subject: &ApprovalSubject,
) -> Result<(), WarpgateError> {
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
            credentials_digest: Set(subject.credentials_digest(salt)),
            consumes_ticket_id: Set(subject.consumes_ticket_id),
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

/// How often a waiting gate re-reads its row.
///
/// ponytail: one query per waiting session per tick. Approvals are human-paced
/// and few at a time; batch them into one node-wide query if the number of
/// simultaneous holds ever makes this show up.
pub(super) const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// How a wait on a request row ended.
pub(super) enum RowOutcome {
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
    let Some(resolved_by_username) = &row.resolved_by_username else {
        return Err(WarpgateError::InconsistentState(
            "Approval request row is decided but has no resolver".to_string(),
        ));
    };
    Ok(RowState::Decided(
        decision,
        ApprovalActor {
            username: resolved_by_username.clone(),
            user_id: row.resolved_by_user_id,
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
) -> Result<RowOutcome, WarpgateError> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut ticker = tokio::time::interval(POLL_INTERVAL);

    loop {
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => return Ok(RowOutcome::TimedOut),
            // The first tick is immediate, catching a decision that landed
            // between advertising the row and starting the wait.
            _ = ticker.tick() => {
                match find_question(db, session_id, kind, target).await {
                    Ok(Some(row)) => match row_state(&row)? {
                        RowState::Pending => {}
                        RowState::Decided(decision, _) => {
                            return Ok(RowOutcome::Decided(decision));
                        }
                        // Something else ended this wait, so there is nothing
                        // left to wait for.
                        RowState::Ended => return Ok(RowOutcome::Ended),
                    },
                    // The row is gone (retention never prunes one this young),
                    // so the question is no longer being asked.
                    Ok(None) => return Ok(RowOutcome::Ended),
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
    use SessionApprovalRequest::{ApprovalRequestStatus, Column};

    let (status, scope) = match decision {
        ApprovalDecision::Approved(scope) => (ApprovalRequestStatus::Approved, Some(scope)),
        ApprovalDecision::Rejected => (ApprovalRequestStatus::Rejected, None),
    };

    // Read ahead of the transition, off the pending row only: a question that is
    // already answered or closed has no spend riding on this decision and is not
    // this call's to audit, and the transition below moves nothing but the row
    // read here. The row also carries what the audit event says about the asker.
    let Some(row) = find_question(db, session_id, kind, target)
        .await?
        .filter(|row| row.status == ApprovalRequestStatus::Pending)
    else {
        return Ok(false);
    };
    let consumes_ticket_id = if matches!(decision, ApprovalDecision::Approved(_)) {
        row.consumes_ticket_id
    } else {
        None
    };

    // The deferred ticket is spent before the approval is recorded: an
    // exhausted ticket must fail the approval, and once the row says approved
    // the waiting gate admits the session — there is no turning it away for a
    // spend that turns out not to be there. The pending→approved transition is
    // still what makes the spend one-shot across the cluster: a concurrent
    // approver's use is given back below when its transition finds the
    // question already answered.
    if let Some(ticket_id) = consumes_ticket_id {
        consume_ticket(db, &ticket_id).await?;
    }

    let moved = StatusTransition::from_pending(status)
        .set(Column::Scope, scope)
        .set(Column::ResolvedByUsername, actor.username.clone())
        .set(Column::ResolvedByUserId, actor.user_id)
        // Pinned by `started` to the asking read above, so the row moved is the
        // row the ticket was spent for and the audit event describes. Without
        // it a question closed and asked afresh in that window would be decided
        // on the strength of its predecessor's ticket.
        //
        // The pin cannot tell whether the *approver* saw this asking — their
        // click carries no identity for it — so a re-advertise landing in the
        // window makes the decision a no-op the approver simply repeats.
        .apply(
            db,
            one_question(session_id, kind, target).add(Column::Started.eq(row.started)),
        )
        .await;

    if !matches!(moved, Ok(n) if n > 0)
        && let Some(ticket_id) = consumes_ticket_id
        && let Err(error) = refund_ticket(db, ticket_id).await
    {
        warn!(%error, %ticket_id, "Failed to refund the ticket of an unrecorded approval");
    }

    let recorded = moved? > 0;
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
    if let Some(id) = actor.user_id.filter(|id| *id != row.user_id) {
        related.push(id);
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
        resolved_by = %actor.username,
        approved = approved,
        related_users = %format_related_ids(&related),
        "Session approval resolved",
    );
}
