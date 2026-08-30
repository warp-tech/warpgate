use std::net::IpAddr;
use std::sync::Arc;

use sea_orm::sea_query::IntoCondition;
use sea_orm::{EntityTrait, QueryFilter};
use tokio::sync::Mutex;
use tracing::warn;
use uuid::Uuid;
use warpgate_common::auth::{ApprovalKind, RememberApprovalBy};
use warpgate_common::{UserSessionId, WarpgateError};
use warpgate_db_entities::SessionApprovalRequest;
use warpgate_db_entities::SessionApprovalRequest::{
    Advertised, UndecidedApprovalRequestStatus, close_request, mark_consumed,
};

use super::*;
use crate::config_providers::{ApprovedTarget, TargetAuthorization, TicketRefund};
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

/// The connection's stake in a ticket, settled by the gate.
///
/// The gate is the only thing that may refuse a session after it has
/// authenticated, so it is also the one place that knows whether a ticket's
/// use should stand — putting the settlement here means no wait site can
/// forget it.
pub enum TicketStake {
    /// The session didn't authenticate with a ticket, or its ticket is beyond
    /// refunding.
    None,
    /// A ticket spent by having authenticated, held so that a refusal — or a
    /// gate that never reached anyone — can refund it. For connection-holding
    /// protocols, whose session dies with the gate: an approval disarms the
    /// guard so the spend stands, and on every other outcome its drop refunds.
    Held(TicketRefund),
    /// A ticket consumed only by an approval, recorded on the request row so
    /// that whichever node records the decision consumes it exactly once. For
    /// request/response protocols, whose session outlives any one gate.
    ConsumedOnApproval(Uuid),
}

/// Everything about the *connection* a gate is being asked about. What it is
/// asked about — the user and the target — comes from the authorization, so the
/// two can never disagree.
pub struct AdminApprovalContext {
    pub session_id: UserSessionId,
    pub remote_ip: Option<IpAddr>,
    /// What a grant to this session may be remembered on, keying the bypass for
    /// a later identical connection. [`RememberedBy::Nothing`] wherever the
    /// authenticating credential has no stable fingerprint (ticket auth) or
    /// isn't carried on the request at all (HTTP, Kubernetes).
    pub credentials: RememberApprovalBy,
    /// The ticket riding on this gate's outcome. Naming it here is what makes
    /// the refund rule unforgettable: a wait site states its ticket story to
    /// build the context at all.
    pub ticket: TicketStake,
}

impl AdminApprovalContext {
    /// The question this connection poses about `authorization`, plus the held
    /// ticket guard — whose settlement stays with the caller, because only the
    /// caller knows how its gate ends.
    fn subject_for<O>(
        self,
        authorization: &TargetAuthorization<O>,
    ) -> (ApprovalSubject, Option<TicketRefund>) {
        let (held_ticket, consumes_ticket_id) = match self.ticket {
            TicketStake::None => (None, None),
            TicketStake::Held(guard) => (Some(guard), None),
            TicketStake::ConsumedOnApproval(id) => (None, Some(id)),
        };
        (
            ApprovalSubject {
                kind: ApprovalKind::Admin,
                session_id: self.session_id,
                user_info: authorization.user_info().clone(),
                protocol: authorization.protocol(),
                target_name: authorization.target().name.clone(),
                remote_ip: self.remote_ip,
                credentials: self.credentials,
                consumes_ticket_id,
            },
            held_ticket,
        )
    }
}

/// How a connection presents itself to the gate, minus the session it belongs
/// to — [`admit_target_session`] reads that off the handle, so the two can't
/// disagree about which session is being held.
pub struct GatedConnection {
    pub remote_ip: Option<IpAddr>,
    /// See [`AdminApprovalContext::credentials`].
    pub credentials: RememberApprovalBy,
    /// See [`AdminApprovalContext::ticket`].
    pub ticket: TicketStake,
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
        ticket,
    } = connection;
    let session_id = handle.lock().await.user_session_id();

    let outcome: GateOutcome<O> = services
        .require_admin_approval(
            authorization,
            AdminApprovalContext {
                session_id,
                remote_ip,
                credentials,
                ticket,
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
    /// authenticated the session rides on the outcome through
    /// [`AdminApprovalContext::ticket`]: a held guard is refunded on every
    /// outcome but an approval, and a consumption deferred to the request row
    /// is performed by whichever node records an approval.
    ///
    /// The ordering here is the point of the function: a remembered approval
    /// short-circuits before anything is announced, the request is advertised
    /// before the wait begins (so it can never be resolved by an administrator
    /// who cannot see it), and only then does `notify_waiting` tell the client
    /// what is happening. Protocols with no in-band channel for that message
    /// pass a no-op.
    ///
    /// Ending the hold early, when the client goes away, is done by dropping
    /// this future: the row is closed and a held ticket refunded by the guards
    /// it carries, so no path can leave either behind. A caller that holds the
    /// connection inline gets that for free; one that spawns the gate off its
    /// event loop selects on its own disconnect signal against this future.
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
        let (subject, held_ticket) = context.subject_for(&authorization);

        let result = self
            .hold_at_admin_gate(authorization, subject, notify_waiting)
            .await;

        // A refusal — the administrator's, an expired window, or a gate that
        // failed outright — is not the user's doing, so the ticket gets its
        // use back through the guard's drop. Only an approval keeps the spend.
        if let Some(mut refund) = held_ticket
            && matches!(result, Ok(GateOutcome::Approved(_)))
        {
            refund.disarm();
        }

        result
    }

    /// The wait itself, factored out so [`Self::require_admin_approval`] can
    /// settle the ticket stake on every way out, error paths included.
    async fn hold_at_admin_gate<E, F, Fut, O>(
        &self,
        authorization: TargetAuthorization<O>,
        subject: ApprovalSubject,
        notify_waiting: F,
    ) -> Result<GateOutcome<O>, E>
    where
        E: From<WarpgateError>,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
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
        self.announce_admin_request(&subject).await?;

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
    /// A ticket rides through here as [`TicketStake::ConsumedOnApproval`],
    /// settled by whichever node records the approval. [`TicketStake::Held`]
    /// belongs to the blocking form, whose return settles it — here there is
    /// nothing to hold the guard across, and dropping it would refund a spend
    /// whose question still stands.
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

        let (subject, held_ticket) = context.subject_for(&authorization);
        if held_ticket.is_some() {
            return Err(WarpgateError::InconsistentState(
                "a held ticket cannot ride on the polled gate".into(),
            ));
        }

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
            self.announce_admin_request(&subject).await?;
            return Ok(PolledGate::Pending);
        };

        match row_state(&row)? {
            // A question that ended unanswered is history; this request is a
            // fresh asking.
            RowState::Ended => {
                self.announce_admin_request(&subject).await?;
                Ok(PolledGate::Pending)
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
                    self.announce_admin_request(&subject).await?;
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
