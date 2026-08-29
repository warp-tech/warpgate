use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::Mutex;
use tracing::{error, warn};
use uuid::Uuid;
use warpgate_common::auth::{ApprovalKind, RememberedBy};
use warpgate_common::{UserSessionId, WarpgateError};

use super::*;
use crate::config_providers::{ApprovedTarget, TargetAuthorization, TicketRefund};
use crate::protocols::AdmittedTarget;
use crate::services::Services;
use crate::{TargetSessionStart, WarpgateServerHandle};

/// How a gate ended for a connection that was waiting on it.
///
/// `Refused` and `Expired` are kept apart because they mean opposite things to
/// a protocol that can ask again: an administrator said no, versus nobody was
/// there to say anything. Treating the second as the first locks a session out
/// of a target for good on the strength of one unattended window.
#[must_use = "a gate outcome that is dropped is a gate that was never applied"]
pub enum GateOutcome<O = warpgate_common::TargetOptions> {
    /// Let through, with the proof needed to reach the target.
    Approved(ApprovedTarget<O>),
    /// An administrator decided against it.
    Refused,
    /// The window ran out, the client left, or the request stopped being a live
    /// question. Nothing was decided, and asking again is legitimate.
    Expired,
}

impl<O> GateOutcome<O> {
    /// The proof, for a caller that treats every non-approval the same way —
    /// a connection-holding protocol has nothing to retry with.
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

/// What a session's gate has settled on, for the non-blocking path.
///
/// Only settled outcomes are recorded: a wait that expired without a decision
/// leaves no entry, so the next request starts a fresh one rather than
/// inheriting an unattended window as a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SettledGate {
    Approved,
    Denied,
}

/// One session's gates, for the non-blocking path: which targets have a wait
/// running, and what has already settled for which target. Both are keyed by
/// target because a gate answers a question about one target and a session is
/// not confined to one — a session reaching two gated targets asks about both,
/// and each answer belongs to the target it was given for.
#[derive(Debug, Default)]
struct SessionGateState {
    /// Targets whose waits are running. One per target: a second request for a
    /// target already being waited on joins that wait rather than starting a
    /// duplicate.
    running: HashSet<String>,
    settled: HashMap<String, SettledGate>,
}

/// The administrator-gate ledger for sessions that observe the gate rather
/// than parking on it, owned by [`State`] so a session's entries are dropped
/// with the session. All access goes through the poll/settle/forget methods:
/// the one-wait-per-target rule and the only-while-the-session-lives rule
/// live here, not at the call sites.
///
/// [`State`]: crate::State
#[derive(Default)]
pub struct SessionGates {
    sessions: Mutex<HashMap<UserSessionId, SessionGateState>>,
}

/// What [`SessionGates::poll`] answered without touching the database.
enum SlotPoll {
    /// This target's gate already settled for this session.
    Settled(SettledGate),
    /// A wait for this target is already running, so the question is already
    /// in front of an administrator.
    Waiting,
    /// The caller took on this target's wait and must start it.
    Claimed,
}

impl SessionGates {
    /// Answers from the ledger, or takes on the wait — under one lock, so
    /// concurrent requests for one target start exactly one wait between them,
    /// and a settle landing between a lookup and a claim cannot be missed.
    async fn poll(&self, session_id: UserSessionId, target: &str) -> SlotPoll {
        let mut sessions = self.sessions.lock().await;
        let state = sessions.entry(session_id).or_default();
        if let Some(settled) = state.settled.get(target) {
            return SlotPoll::Settled(*settled);
        }
        if !state.running.insert(target.to_string()) {
            return SlotPoll::Waiting;
        }
        SlotPoll::Claimed
    }

    /// Ends `target`'s claim on the slot, recording the outcome if the wait
    /// settled one. Applied only while the session still has its entry: a
    /// teardown drops it, and an outcome for a dead session must not resurrect
    /// one — nothing would ever remove it again.
    async fn settle(&self, session_id: UserSessionId, target: &str, outcome: Option<SettledGate>) {
        let mut sessions = self.sessions.lock().await;
        let Some(state) = sessions.get_mut(&session_id) else {
            return;
        };
        state.running.remove(target);
        if let Some(outcome) = outcome {
            state.settled.insert(target.to_string(), outcome);
        }
        // An entry holding nothing means nothing — and for a session already
        // torn down (a poll can race the teardown and re-create its entry),
        // dropping it here is the only removal it will ever get.
        if state.running.is_empty() && state.settled.is_empty() {
            sessions.remove(&session_id);
        }
    }

    /// Drops everything the ledger holds for a session, for when it ends.
    pub(crate) async fn forget_session(&self, session_id: &UserSessionId) {
        self.sessions.lock().await.remove(session_id);
    }
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
    pub credentials: RememberedBy,
    /// The ticket riding on this gate's outcome. Naming it here is what makes
    /// the refund rule unforgettable: a wait site states its ticket story to
    /// build the context at all.
    pub ticket: TicketStake,
}

/// How a connection presents itself to the gate, minus the session it belongs
/// to — [`admit_target_session`] reads that off the handle, so the two can't
/// disagree about which session is being held.
pub struct GatedConnection {
    pub remote_ip: Option<IpAddr>,
    /// See [`AdminApprovalContext::credentials`].
    pub credentials: RememberedBy,
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
        let AdminApprovalContext {
            session_id,
            remote_ip,
            credentials,
            ticket,
        } = context;
        let (held_ticket, consumes_ticket_id) = match ticket {
            TicketStake::None => (None, None),
            TicketStake::Held(guard) => (Some(guard), None),
            TicketStake::ConsumedOnApproval(id) => (None, Some(id)),
        };

        let subject = ApprovalSubject {
            kind: ApprovalKind::Admin,
            session_id,
            user_info: authorization.user_info().clone(),
            protocol: authorization.protocol(),
            target_name: authorization.target().name.clone(),
            remote_ip,
            credentials,
            consumes_ticket_id,
        };

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

        let mut guard = PendingApproval::begin(
            self.db.clone(),
            self.cluster.node_id,
            &self.credential_digest_salt,
            &subject,
        )
        .await?;

        subject.emit_requested_event();
        let _ = self.admin_approval_request_tx.send(session_id);

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

    /// Non-blocking form of [`Self::require_admin_approval`], for protocols
    /// that answer each request separately and so cannot park on the gate.
    ///
    /// The first call for a session's target starts the ordinary blocking wait
    /// on a background task; every call reports where that wait has got to.
    /// Routing it through the same wait means the grace bypass, timeout, audit
    /// trail, ticket settlement and request-row lifecycle all behave
    /// identically to the connection-holding protocols — the only thing that
    /// differs is who does the waiting.
    ///
    /// A session's targets gate independently: each gets its own wait,
    /// concurrent requests for one target share the wait already running, and
    /// settled outcomes are kept per target for the life of the session.
    ///
    /// A ticket rides through here as [`TicketStake::ConsumedOnApproval`]. A
    /// [`TicketStake::Held`] guard belongs to the blocking form, whose return
    /// settles it — dropped on a `Pending` answer here, it would read as an
    /// approval and spend the ticket while the question still stands.
    ///
    /// A wait that expires without a decision records nothing, so the next
    /// request asks again. An unattended window is not an answer, and caching
    /// it as one would shut a session out of the target until it is rebuilt.
    pub async fn poll_admin_approval<O: Send + Sync + 'static>(
        &self,
        authorization: TargetAuthorization<O>,
        context: AdminApprovalContext,
    ) -> Result<PolledGate<O>, WarpgateError> {
        // Read off the authorization for the same reason the blocking gate
        // does; it also means a settled denial stops applying the moment the
        // target stops requiring approval.
        if !authorization.target().require_approval {
            return Ok(PolledGate::Approved(ApprovedTarget::new(authorization)));
        }

        let session_id = context.session_id;
        let target_name = authorization.target().name.clone();
        let gates = self.admin_approval_gates().await;

        match gates.poll(session_id, &target_name).await {
            SlotPoll::Settled(SettledGate::Approved) => {
                return Ok(PolledGate::Approved(ApprovedTarget::new(authorization)));
            }
            SlotPoll::Settled(SettledGate::Denied) => return Ok(PolledGate::Denied),
            SlotPoll::Waiting => return Ok(PolledGate::Pending),
            SlotPoll::Claimed => {}
        }

        let services = self.clone();
        tokio::spawn(async move {
            let outcome = services
                .require_admin_approval(authorization, context, || async {
                    Ok::<_, WarpgateError>(())
                })
                .await;

            let settled = match outcome {
                Ok(GateOutcome::Approved(_)) => Some(SettledGate::Approved),
                Ok(GateOutcome::Refused) => Some(SettledGate::Denied),
                // Nothing was decided. Recording nothing lets the next request
                // start a fresh wait instead of inheriting this one.
                Ok(GateOutcome::Expired) => None,
                // A hold that failed is not an answer either: the request wasn't
                // refused, it never reached anyone. Caching it as a denial would
                // shut the session out of the target for as long as it lives on
                // the strength of one database blip, so the next request retries.
                Err(error) => {
                    error!(%error, "Failed to hold the session for administrator approval");
                    None
                }
            };
            gates.settle(session_id, &target_name, settled).await;
        });

        Ok(PolledGate::Pending)
    }

    async fn admin_approval_is_remembered(
        &self,
        subject: &ApprovalSubject,
    ) -> Result<bool, WarpgateError> {
        let Some(grace) = self.admin_approval_grace_period().await? else {
            return Ok(false);
        };
        let Some(key) = subject.match_key() else {
            return Ok(false);
        };
        approval_is_remembered(&self.db, &key, grace, &self.credential_digest_salt).await
    }
}
