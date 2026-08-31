use std::net::IpAddr;
use std::sync::Arc;

use sea_orm::sea_query::IntoCondition;
use sea_orm::{EntityTrait, QueryFilter};
use tokio::sync::Mutex;
use tracing::warn;
use warpgate_common::auth::{ApprovalKind, RememberApprovalBy};
use warpgate_common::{UserSessionId, WarpgateError};
use warpgate_db_entities::SessionApprovalRequest;
use warpgate_db_entities::SessionApprovalRequest::{
    Advertised, UndecidedApprovalRequestStatus, close_request, mark_consumed,
};

use super::*;
use crate::config_providers::{ApprovedTarget, TargetAuthorization};
use crate::protocols::AdmittedTarget;
use crate::services::Services;
use crate::{TargetSessionStart, WarpgateServerHandle};

#[must_use]
pub enum GateOutcome<O = warpgate_common::TargetOptions> {
    Approved(ApprovedTarget<O>),
    Refused,
    // timeout / disconnected / gone from the DB (may ask again)
    Expired,
}

impl<O> GateOutcome<O> {
    pub fn approved(self) -> Option<ApprovedTarget<O>> {
        match self {
            Self::Approved(target) => Some(target),
            Self::Refused | Self::Expired => None,
        }
    }
}

/// Where a session's administrator gate has got to.
///
/// Request/response protocols answer each request on its own rather than
/// holding a connection open, so they need to *observe* the gate instead of
/// awaiting it.
#[must_use = "a polled gate that is dropped is a gate that was never applied"]
pub enum PolledGate<O = warpgate_common::TargetOptions> {
    Approved(ApprovedTarget<O>),
    /// An administrator has been asked and has yet to answer.
    Pending,
    Denied,
}

/// Everything about the *connection* a gate is being asked about. What it is
/// asked about — the user, the target, the ticket that authenticated — comes
/// from the authorization, so the two can never disagree.
pub struct AdminApprovalContext {
    pub session_id: UserSessionId,
    pub remote_ip: Option<IpAddr>,
    /// What a grant to this session may be remembered on, keying the bypass for
    /// a later identical connection. [`RememberedBy::Nothing`] wherever the
    /// authenticating credential has no stable fingerprint (ticket auth) or
    /// isn't carried on the request at all (HTTP, Kubernetes).
    pub credentials: RememberApprovalBy,
}

impl AdminApprovalContext {
    /// The question this connection poses about `authorization`. The ticket is
    /// read off the authorization it rode in on — no wait site states a ticket
    /// story, so none can state a wrong one; its use is settled by whatever
    /// ends the question's row.
    fn subject_for<O>(self, authorization: &TargetAuthorization<O>) -> ApprovalSubject {
        ApprovalSubject {
            kind: ApprovalKind::Admin,
            session_id: self.session_id,
            user_info: authorization.user_info().clone(),
            protocol: authorization.protocol(),
            target_name: authorization.target().name.clone(),
            remote_ip: self.remote_ip,
            credentials: self.credentials,
            ticket_id: authorization.ticket_id(),
        }
    }
}

/// How a connection presents itself to the gate, minus the session it belongs
/// to — [`admit_target_session`] reads that off the handle, so the two can't
/// disagree about which session is being held.
pub struct GatedConnection {
    pub remote_ip: Option<IpAddr>,
    /// See [`AdminApprovalContext::credentials`].
    pub credentials: RememberApprovalBy,
}

/// Starts a target session, holding the connection at the administrator gate
/// when the target requires one, and registers what the gate mints.
///
/// The single path from "authorized" to "admitted" for every protocol that can
/// simply park on the gate: the connection is already established and there is
/// nothing to tell the client while it waits, so the wait is silent and ends
/// only with a decision, the window running out, or the session going away.
/// Protocols that must say something meanwhile (SSH's notice, HTTP's
/// interstitial) drive [`Services::require_admin_approval`] or
/// [`Services::poll_admin_approval`] themselves.
///
/// A refused connection is [`WarpgateError::SessionNotApproved`]. The order —
/// hold, and only then register — is the point of gathering this in one place:
/// the target session is recorded from the proof the gate returned, never from
/// the authorization that went in.
pub async fn admit_target_session<O: Send + Sync>(
    services: &Services,
    handle: &Arc<Mutex<WarpgateServerHandle>>,
    authorization: TargetAuthorization<O>,
    connection: GatedConnection,
) -> Result<AdmittedTarget<O>, WarpgateError> {
    let started = handle
        .lock()
        .await
        .start_target_session(authorization)
        .await?;
    let authorization = match started {
        TargetSessionStart::Started(started) => return Ok(started),
        TargetSessionStart::NeedsApproval(authorization) => authorization,
    };

    let GatedConnection {
        remote_ip,
        credentials,
    } = connection;
    let session_id = handle.lock().await.user_session_id();

    let outcome: GateOutcome<O> = services
        .require_admin_approval(
            authorization,
            AdminApprovalContext {
                session_id,
                remote_ip,
                credentials,
            },
            || async { Ok::<_, WarpgateError>(()) },
        )
        .await?;

    let Some(approved) = outcome.approved() else {
        warn!(%session_id, "Session was not approved by an administrator");
        return Err(WarpgateError::SessionNotApproved);
    };

    handle
        .lock()
        .await
        .register_approved_target_session(approved)
        .await
}

impl Services {
    /// Holds an authenticated connection until an administrator approves it,
    /// when the target requires approval. Returns whether it may proceed.
    ///
    /// Call this at the end of the authentication flow, once the target is
    /// known and before the client is told it is connected. The ticket that
    /// authenticated the session was spent with the authentication; its use is
    /// settled by whatever ends this question's row — kept by an approval,
    /// given back by any other end, on whichever node does the ending.
    ///
    /// The ordering here is the point of the function: a remembered approval
    /// short-circuits before anything is announced, the request is advertised
    /// before the wait begins (so it can never be resolved by an administrator
    /// who cannot see it), and only then does `notify_waiting` tell the client
    /// what is happening. Protocols with no in-band channel for that message
    /// pass a no-op.
    ///
    /// Ending the hold early, when the client goes away, is done by dropping
    /// this future: the guard it carries closes the row, and closing the row
    /// settles the ticket, so no path can leave either behind. A caller that
    /// holds the connection inline gets that for free; one that spawns the
    /// gate off its event loop selects on its own disconnect signal against
    /// this future.
    pub async fn require_admin_approval<E, F, Fut, O>(
        &self,
        authorization: TargetAuthorization<O>,
        context: AdminApprovalContext,
        notify_waiting: F,
    ) -> Result<GateOutcome<O>, E>
    where
        E: From<WarpgateError>,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        let subject = context.subject_for(&authorization);
        // Read off the authorization rather than re-resolved: the target it
        // names is the row the user was authorized against, and a lookup by
        // name here could answer about a different one — or, if the target had
        // since been renamed, about none at all, which would read as "no
        // approval needed".
        if !authorization.target().require_approval {
            return Ok(GateOutcome::Approved(ApprovedTarget::new(authorization)));
        }

        let session_id = subject.session_id;

        if self.admin_approval_is_remembered(&subject).await? {
            subject.emit_bypassed_event();
            return Ok(GateOutcome::Approved(ApprovedTarget::new(authorization)));
        }

        let mut guard = PendingApproval::guarding(self.db.clone(), &subject);
        // Asking again needs the ticket use the previous asking gave back; a
        // session whose ticket can no longer pay is turned away, not parked on
        // a question that was never opened. (The guard closes nothing here —
        // there is no pending row to close.)
        if matches!(
            self.announce_admin_request(&subject).await?,
            Advertised::TicketExhausted
        ) {
            return Ok(GateOutcome::Refused);
        }

        notify_waiting().await?;

        let timeout = self.admin_approval_timeout().await?;
        // The resolver is recorded and audited where the decision is written;
        // this side only needs to know what was decided.
        let decision = match await_row_decision(
            &self.db,
            session_id,
            ApprovalKind::Admin,
            &subject.target_name,
            timeout,
        )
        .await?
        {
            RowOutcome::Decided(decision) => {
                guard.decided();
                decision
            }
            RowOutcome::TimedOut => {
                guard.timed_out();
                subject.emit_timed_out_event();
                return Ok(GateOutcome::Expired);
            }
            RowOutcome::Ended => return Ok(GateOutcome::Expired),
        };

        match decision {
            // The approved row is itself the remembered approval, scope and
            // all — there is nothing to record beyond what the resolver wrote.
            ApprovalDecision::Approved(_) => {
                Ok(GateOutcome::Approved(ApprovedTarget::new(authorization)))
            }
            ApprovalDecision::Rejected => Ok(GateOutcome::Refused),
        }
    }

    /// Puts the question on the record and tells the inbox — but only when one
    /// was actually asked. A re-advertise that found the question already live,
    /// or an answer standing, announces nothing: the audit trail and the inbox
    /// signal carry one entry per asking, however many times the asker returns.
    async fn announce_admin_request(
        &self,
        subject: &ApprovalSubject,
    ) -> Result<Advertised, WarpgateError> {
        let advertised = advertise_admin_request(&self.db, self.cluster.node_id, subject).await?;
        if matches!(advertised, Advertised::Asked) {
            subject.emit_requested_event();
            let _ = self.admin_approval_request_tx.send(subject.session_id);
        }
        Ok(advertised)
    }

    /// Non-blocking form of [`Self::require_admin_approval`], for protocols
    /// that answer each request separately and so cannot park on the gate.
    ///
    /// Each call answers from the request row: the row carries both the
    /// question and its answer, so where the gate stands *is* what the row
    /// says, on whichever node the request happens to land. No wait runs
    /// anywhere — the client's retry cadence is the poll.
    ///
    /// The caller that finds no live question asks it (idempotently — a
    /// concurrent asker's row is simply refreshed), and the one that finds the
    /// window run out closes the question as timed out and asks afresh, so
    /// expiry needs no waiter to notice it either. A client that stops polling
    /// leaves its question to the age sweep, exactly like a waiter that died.
    ///
    /// A ticket's use rides on the question's row like everywhere else: kept
    /// by an approval, given back by whatever else ends the row — including
    /// the timeout this poll itself records.
    pub async fn poll_admin_approval<O>(
        &self,
        authorization: TargetAuthorization<O>,
        context: AdminApprovalContext,
    ) -> Result<PolledGate<O>, WarpgateError> {
        // Read off the authorization for the same reason the blocking gate
        // does; it also means a recorded denial stops applying the moment the
        // target stops requiring approval.
        if !authorization.target().require_approval {
            return Ok(PolledGate::Approved(ApprovedTarget::new(authorization)));
        }

        let subject = context.subject_for(&authorization);

        if self.admin_approval_is_remembered(&subject).await? {
            subject.emit_bypassed_event();
            return Ok(PolledGate::Approved(ApprovedTarget::new(authorization)));
        }

        let key = || {
            SessionApprovalRequest::Key::new(
                subject.session_id,
                ApprovalKind::Admin,
                &subject.target_name,
            )
        };
        let row = SessionApprovalRequest::Entity::find()
            .filter(key().into_condition())
            .one(&self.db)
            .await?;
        let Some(row) = row else {
            // A fresh question is paid for by the use taken at authentication,
            // so this cannot come back exhausted; matched anyway so the enum
            // stays honest.
            return Ok(match self.announce_admin_request(&subject).await? {
                Advertised::TicketExhausted => PolledGate::Denied,
                _ => PolledGate::Pending,
            });
        };

        match row_state(&row)? {
            // A question that ended unanswered is history; this request is a
            // fresh asking.
            RowState::Ended => {
                // Asking afresh re-spends; a ticket that can no longer pay is
                // a denial, not an eternal 202.
                Ok(match self.announce_admin_request(&subject).await? {
                    Advertised::TicketExhausted => PolledGate::Denied,
                    _ => PolledGate::Pending,
                })
            }
            RowState::Pending => {
                let timeout = self.admin_approval_timeout().await?;
                #[allow(clippy::cast_possible_wrap)]
                let window = time::Duration::seconds(timeout.as_secs() as i64);
                if time::OffsetDateTime::now_utc() - row.started >= window {
                    // The transition names its source state, so a decision that
                    // landed in the meantime wins and nothing is emitted for a
                    // timeout that didn't happen.
                    if close_request(
                        &self.db,
                        subject.session_id,
                        ApprovalKind::Admin,
                        &subject.target_name,
                        UndecidedApprovalRequestStatus::TimedOut,
                    )
                    .await?
                    {
                        subject.emit_timed_out_event();
                    }
                    if matches!(
                        self.announce_admin_request(&subject).await?,
                        Advertised::TicketExhausted
                    ) {
                        return Ok(PolledGate::Denied);
                    }
                }
                Ok(PolledGate::Pending)
            }
            RowState::Decided(decision, _) => {
                mark_consumed(&self.db, key()).await?;
                match decision {
                    ApprovalDecision::Approved(_) => {
                        Ok(PolledGate::Approved(ApprovedTarget::new(authorization)))
                    }
                    ApprovalDecision::Rejected => Ok(PolledGate::Denied),
                }
            }
        }
    }

    async fn admin_approval_is_remembered(
        &self,
        subject: &ApprovalSubject,
    ) -> Result<bool, WarpgateError> {
        // The key first: a subject with nothing to match on (HTTP passes no
        // credentials) answers without the Parameters read — and this now runs
        // per request on the polled path.
        let Some(key) = subject.match_key() else {
            return Ok(false);
        };
        let Some(grace) = self.admin_approval_grace_period().await? else {
            return Ok(false);
        };
        approval_is_remembered(&self.db, &key, grace).await
    }
}
