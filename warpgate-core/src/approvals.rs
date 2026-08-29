//! Out-of-band approval requests: in-browser self approval, and administrator
//! just-in-time approval of a session.
//!
//! The two are deliberately different mechanisms. Self approval is a
//! *credential* — it satisfies a pending [`CredentialKind::WebUserApproval`] on
//! an in-memory auth state, held by the node that keyed it under the same
//! session id the row is keyed by. Administrator approval is a *gate on the
//! connection*,
//! decided once the target is known and after the credentials are settled; it
//! touches no auth state at all.
//!
//! What they share is the record, and the record is the whole substrate: a
//! `session_approval_requests` row keyed by `(session_id, kind)` carries both
//! the question and its answer. Any node can list the rows and any node can
//! resolve one by writing the decision to it — there is no cross-node delivery,
//! because nothing has to reach the owner. The owner instead reads the decision
//! back off the row: an administrator gate polls its own row while it holds the
//! connection, and self approvals are applied by a node-wide sweep, since only
//! the node holding an auth state can satisfy a credential on it.
//!
//! No row is ever deleted while it still means something. A request that ends —
//! consumed, timed out, given up on, torn down with its session, or aged out
//! because its owner died — moves to a terminal status and stays as the record
//! of what was asked and who answered. Only the audit retention removes one.
//! That is also what makes the row safe to read: a gate can tell "answered, and
//! I have yet to see it" from "no longer a live question", where a row that
//! could disappear underneath a wait can only ever mean the second.
//!
//! An approved row is also the remembered approval: the grace-period bypass
//! looks for a recent approval matching the same kind, user, origin,
//! credentials and scope among the rows themselves, so a grant given while
//! talking to one node bypasses the gate on every node, and the record an
//! auditor reads is the record the bypass ran on. The corollary is that a
//! grace period only reaches as far as the audit retention keeps the rows.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::{Condition, IntoCondition, OnConflict, SimpleExpr};
use sea_orm::{ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use uuid::Uuid;
use warpgate_common::auth::{
    ApprovalKind, AuthCredential, AuthResult, AuthState, AuthStateUserInfo, CredentialDigestSalt,
    CredentialKind, RememberedBy, WebApprovalMatchKey, WebApprovalScopeKey,
};
use warpgate_common::helpers::logging::format_related_ids;
use warpgate_common::helpers::username::username_eq_ci;
use warpgate_common::{NodeId, Protocol, TargetSessionId, UserSessionId, WarpgateError};
use warpgate_db_entities::{Parameters, SessionApprovalRequest};

use crate::auth_state_store::TIMEOUT;
use crate::config_providers::{ApprovedTarget, TargetAuthorization, TicketRefund, consume_ticket};
use crate::services::Services;
use crate::{TargetSessionStart, WarpgateServerHandle};

/// How an approval should be remembered for later bypass.
///
/// Derives the OpenAPI enum directly so both the administrator and the
/// self-approval endpoints can take it as-is; a per-API copy would be three
/// identical enums and two conversions that only exist to satisfy the derive.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, poem_openapi::Enum,
)]
pub enum ApprovalScope {
    Once,
    Target,
    AllTargets,
}

/// A decision delivered to the waiting side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ApprovalDecision {
    Approved(ApprovalScope),
    Rejected,
}

/// Who resolved an approval. Travels with the decision so the owning node can
/// attribute the audit entry to them.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApprovalActor {
    pub username: String,
    /// `None` when the resolver isn't a user — e.g. the admin API token.
    pub user_id: Option<Uuid>,
}

/// The session an approval is about, and the single source for its request row,
/// audit events and grace key.
///
/// The administrator gate owns one directly — that is the point of the gate, no
/// auth state need exist. The self-approval path builds one from its auth state
/// via [`ApprovalSubject::from_auth_state`], so both kinds audit through the
/// same code.
#[derive(Debug, Clone)]
struct ApprovalSubject {
    /// Which approval this subject describes. Part of every key it produces, so
    /// a grant of one kind can never satisfy a request of the other.
    kind: ApprovalKind,
    session_id: UserSessionId,
    user_info: AuthStateUserInfo,
    protocol: Protocol,
    target_name: String,
    remote_ip: Option<IpAddr>,
    /// What a grant to this session could be remembered on. Where that is
    /// nothing, remembering is disabled rather than keyed on less.
    credentials: RememberedBy,
    /// The ticket an approval of this request consumes, where consumption is
    /// deferred to the gate — see [`TicketStake::ConsumedOnApproval`].
    consumes_ticket_id: Option<Uuid>,
}

impl ApprovalSubject {
    fn from_auth_state(state: &AuthState) -> Self {
        Self {
            kind: ApprovalKind::User,
            session_id: *state.session_id(),
            user_info: state.user_info().clone(),
            protocol: state.protocol(),
            target_name: state.target_name().to_string(),
            remote_ip: state.remote_ip(),
            credentials: state.remembered_by(),
            consumes_ticket_id: None,
        }
    }

    /// What the request row stores to match this session's credentials against
    /// a later connection. `None` mirrors [`Self::match_key`]'s: a row without
    /// a digest can never serve as a remembered approval.
    fn credentials_digest(&self, salt: &CredentialDigestSalt) -> Option<String> {
        self.credentials.credentials().map(|c| c.digest(salt))
    }

    fn client_ip_for_logging(&self) -> String {
        self.remote_ip
            .map_or_else(|| "<unknown>".to_string(), |ip| ip.to_string())
    }

    /// The key this session's approval is remembered under. `None` when
    /// [`WebApprovalMatchKey::build`] has nothing to pin a grant to.
    fn match_key(&self) -> Option<WebApprovalMatchKey> {
        WebApprovalMatchKey::build(
            self.kind,
            self.remote_ip,
            self.protocol,
            &self.user_info.username,
            &self.target_name,
            &self.credentials,
        )
    }

    fn emit_requested_event(&self) {
        info!(
            target: "audit",
            _type = "SessionApprovalRequested1",
            session = %self.session_id,
            client_ip = %self.client_ip_for_logging(),
            user_id = %self.user_info.id,
            username = %self.user_info.username,
            protocol = %self.protocol,
            target = %self.target_name,
            related_users = %format_related_ids(&[self.user_info.id]),
            "Session is awaiting administrator approval",
        );
    }

    /// `actor.user_id` is `None` when the resolver isn't a user (the admin API
    /// token). It is recorded in `related_users` so the decision also shows up
    /// in the resolver's own audit trail, matching how every other actor-driven
    /// event is attributed.
    fn emit_resolved_event(&self, actor: &ApprovalActor, approved: bool) {
        // A user approving their own session is both parties — don't list twice.
        let mut related = vec![self.user_info.id];
        if let Some(id) = actor.user_id.filter(|id| *id != self.user_info.id) {
            related.push(id);
        }

        info!(
            target: "audit",
            _type = "SessionApprovalResolved1",
            session = %self.session_id,
            client_ip = %self.client_ip_for_logging(),
            user_id = %self.user_info.id,
            username = %self.user_info.username,
            protocol = %self.protocol,
            target = %self.target_name,
            resolved_by = %actor.username,
            approved = approved,
            related_users = %format_related_ids(&related),
            "Session approval resolved",
        );
    }

    fn emit_timed_out_event(&self) {
        info!(
            target: "audit",
            _type = "SessionApprovalTimedOut1",
            session = %self.session_id,
            client_ip = %self.client_ip_for_logging(),
            user_id = %self.user_info.id,
            username = %self.user_info.username,
            protocol = %self.protocol,
            target = %self.target_name,
            related_users = %format_related_ids(&[self.user_info.id]),
            "Session approval timed out",
        );
    }

    fn emit_bypassed_event(&self) {
        info!(
            target: "audit",
            _type = "AdminApprovalBypassed1",
            session = %self.session_id,
            client_ip = %self.client_ip_for_logging(),
            user_id = %self.user_info.id,
            username = %self.user_info.username,
            protocol = %self.protocol,
            target = %self.target_name,
            related_users = %format_related_ids(&[self.user_info.id]),
            "Administrator approval bypassed within grace period",
        );
    }
}

/// The request row an administrator gate is waiting on, removed when the wait
/// ends however it ends — resolved, timed out, cancelled, or the future dropped.
///
/// The guard names the target its question was about, and only touches the row
/// while it still says so: a slot taken over by a later question — the same
/// session gating for another target — is that question's row now, and a
/// straggling close from this guard must not end it.
struct PendingApproval {
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
    async fn begin(
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
    const fn timed_out(&mut self) {
        self.close_as = Some(SessionApprovalRequest::ApprovalRequestStatus::TimedOut);
    }

    /// A decision was read off the row and acted on, so the row keeps it and is
    /// only stamped as picked up.
    const fn decided(&mut self) {
        self.close_as = None;
    }
}

/// Writes (idempotently) the request row an administrator gate advertises. Kept
/// beside [`PendingApproval::begin`], its only caller, so the row a guard owns
/// and the row this writes stay in step.
async fn advertise_admin_request(
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
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// How a wait on a request row ended.
enum RowOutcome {
    Decided(ApprovalDecision, ApprovalActor),
    /// The row stopped being a live question underneath the wait — the session
    /// ended, or it was reaped because this node looked dead. Nothing approved
    /// the connection.
    Ended,
    TimedOut,
    Cancelled,
}

/// What a request row currently says.
///
/// Three states, not an `Option`: "nobody has answered yet" and "this will never
/// be answered" both carry no decision but mean opposite things to a waiter, and
/// an `Option` makes them the same value with the difference left on the row for
/// each caller to re-derive.
enum RowState {
    /// Still a live question.
    Pending,
    Decided(ApprovalDecision, ApprovalActor),
    /// Terminal with no decision — nobody answered in time, or nobody was left
    /// to answer for.
    Ended,
}

fn row_state(row: &SessionApprovalRequest::Model) -> RowState {
    use SessionApprovalRequest::{ApprovalRequestScope, ApprovalRequestStatus};

    let decision = match row.status {
        ApprovalRequestStatus::Pending => return RowState::Pending,
        ApprovalRequestStatus::TimedOut | ApprovalRequestStatus::Abandoned => {
            return RowState::Ended;
        }
        ApprovalRequestStatus::Rejected => ApprovalDecision::Rejected,
        ApprovalRequestStatus::Approved => ApprovalDecision::Approved(match row.scope {
            Some(ApprovalRequestScope::Target) => ApprovalScope::Target,
            Some(ApprovalRequestScope::AllTargets) => ApprovalScope::AllTargets,
            // Grant this connection only, which is also the safe reading of an
            // approval that somehow recorded no scope.
            Some(ApprovalRequestScope::Once) | None => ApprovalScope::Once,
        }),
    };
    let actor = ApprovalActor {
        username: row
            .resolved_by_username
            .clone()
            .unwrap_or_else(|| "<unknown>".to_string()),
        user_id: row.resolved_by_user_id,
    };
    RowState::Decided(decision, actor)
}

/// Waits for a decision to be written to this question's row, giving up at
/// `timeout` or when `cancel` fires.
///
/// The wait reads its row by question — session, kind, *and target* — not by
/// key alone: the slot can be taken over by a later question on the same
/// session, and an answer written after that is the successor's, not this
/// one's. To this wait a taken-over slot reads as the row being gone.
///
/// A read failure keeps the wait going rather than ending it: a database blip
/// must not deny a connection an administrator is in the middle of approving,
/// and the timeout still bounds the wait.
async fn await_row_decision(
    db: &DatabaseConnection,
    session_id: UserSessionId,
    kind: ApprovalKind,
    target: &str,
    timeout: Duration,
    cancel: impl Future<Output = ()> + Send,
) -> RowOutcome {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut ticker = tokio::time::interval(POLL_INTERVAL);
    tokio::pin!(cancel);

    loop {
        tokio::select! {
            () = &mut cancel => return RowOutcome::Cancelled,
            () = tokio::time::sleep_until(deadline) => return RowOutcome::TimedOut,
            // The first tick is immediate, catching a decision that landed
            // between advertising the row and starting the wait.
            _ = ticker.tick() => {
                match find_question(db, session_id, kind, target).await {
                    Ok(Some(row)) => match row_state(&row) {
                        RowState::Pending => {}
                        RowState::Decided(decision, actor) => {
                            return RowOutcome::Decided(decision, actor);
                        }
                        // Something else ended this wait, so there is nothing
                        // left to wait for.
                        RowState::Ended => return RowOutcome::Ended,
                    },
                    // The row is gone (retention never prunes one this young)
                    // or the slot now carries a different question — either
                    // way, this one is no longer being asked.
                    Ok(None) => return RowOutcome::Ended,
                    Err(error) => {
                        warn!(%error, "Failed to read a session approval request");
                    }
                }
            }
        }
    }
}

/// The request of one kind on a session, where only one can exist: a login has
/// a single target name fixed when its auth state is built, so its own approval
/// is unambiguous. Administrator gates name their target — see
/// [`find_question`].
async fn find_request(
    db: &DatabaseConnection,
    session_id: UserSessionId,
    kind: ApprovalKind,
) -> Result<Option<SessionApprovalRequest::Model>, WarpgateError> {
    Ok(SessionApprovalRequest::Entity::find()
        .filter(one_request(session_id, kind))
        .one(db)
        .await?)
}

/// [`find_request`], narrowed to one question: `None` also when the slot has
/// been taken over by a question about a different target.
async fn find_question(
    db: &DatabaseConnection,
    session_id: UserSessionId,
    kind: ApprovalKind,
    target: &str,
) -> Result<Option<SessionApprovalRequest::Model>, WarpgateError> {
    Ok(SessionApprovalRequest::Entity::find()
        .filter(one_question(session_id, kind, target))
        .one(db)
        .await?)
}

/// A status change on request rows, and the only thing in this module that
/// writes [`SessionApprovalRequest::Column::Status`].
///
/// There is no constructor that doesn't name the states it may leave. That is
/// the whole point: every write here is a close of some kind, and a close that
/// forgot to exclude `Approved`/`Rejected` would erase an answer an
/// administrator had already given — the session would then wait out its window
/// while the inbox kept offering it again. Making the guard part of building the
/// statement means a new close site cannot be written without one.
///
/// The one status write that doesn't go through this is the row takeover in
/// [`upsert_request`], which rewrites every column and so builds its statement
/// from the model; it names its source states with [`question_is_over`].
struct StatusTransition {
    to: SessionApprovalRequest::ApprovalRequestStatus,
    /// Which rows this transition is allowed to leave.
    from: Condition,
    /// Columns written alongside the status.
    columns: Vec<(SessionApprovalRequest::Column, SimpleExpr)>,
}

impl StatusTransition {
    /// The ordinary case: a request still waiting on an answer. Every way out
    /// of `Pending` goes through here, so the transition also stamps when the
    /// question was resolved — for an approval, that is what anchors the
    /// grace-period window.
    fn from_pending(to: SessionApprovalRequest::ApprovalRequestStatus) -> Self {
        Self {
            to,
            from: SessionApprovalRequest::Column::Status
                .eq(SessionApprovalRequest::ApprovalRequestStatus::Pending)
                .into_condition(),
            columns: vec![(
                SessionApprovalRequest::Column::ResolvedAt,
                OffsetDateTime::now_utc().into(),
            )],
        }
    }

    fn set(mut self, column: SessionApprovalRequest::Column, value: impl Into<SimpleExpr>) -> Self {
        self.columns.push((column, value.into()));
        self
    }

    /// Applies to every row matching `which` that is also in an allowed source
    /// state. Returns how many rows moved.
    async fn apply(self, db: &DatabaseConnection, which: Condition) -> Result<u64, WarpgateError> {
        let mut query = SessionApprovalRequest::Entity::update_many()
            .col_expr(SessionApprovalRequest::Column::Status, self.to.into())
            .filter(which)
            .filter(self.from);
        for (column, value) in self.columns {
            query = query.col_expr(column, value);
        }
        Ok(query.exec(db).await?.rows_affected)
    }
}

/// Rows whose question is over: they ended without an answer, or the owning node
/// has already taken the one they had. Nothing is waiting on either, so a later
/// gate on the same session may take the row over.
///
/// The counterpart to [`StatusTransition::from_pending`]. Together with the
/// different-target takeover in [`upsert_request`], these name every source
/// state any write in this module is allowed to leave.
fn question_is_over() -> Condition {
    SessionApprovalRequest::Column::Status
        .is_in(SessionApprovalRequest::ApprovalRequestStatus::UNANSWERED)
        .or(SessionApprovalRequest::Column::ConsumedAt.is_not_null())
        .into_condition()
}

/// The rows of one request slot: a session's approval of a given kind.
fn one_request(session_id: UserSessionId, kind: ApprovalKind) -> Condition {
    SessionApprovalRequest::Column::SessionId
        .eq(session_id)
        .and(
            SessionApprovalRequest::Column::Kind
                .eq(SessionApprovalRequest::ApprovalRequestKind::from(kind)),
        )
        .into_condition()
}

/// The rows of one *question*: [`one_request`] narrowed to the target it asks
/// about. The key alone names the slot; the same slot can be reused by a later
/// question when the session gates for another target, and everything that
/// answers, consumes or closes a question must say which one it means.
fn one_question(session_id: UserSessionId, kind: ApprovalKind, target: &str) -> Condition {
    one_request(session_id, kind).add(SessionApprovalRequest::Column::Target.eq(target))
}

/// Records a decision against a pending request, from whichever node the
/// approver happens to be talking to. `Ok(false)` when there is no longer a
/// pending request to decide — already resolved, or the waiter gave up and
/// closed it.
///
/// `target` is the question the approver believes they are answering — what
/// their screen said, or what the row said when it was looked up. A request
/// that has since been reopened for a different target is not moved, so a
/// stale click can never resolve a question nobody was shown.
pub async fn record_decision(
    db: &DatabaseConnection,
    session_id: UserSessionId,
    kind: ApprovalKind,
    target: &str,
    decision: ApprovalDecision,
    actor: &ApprovalActor,
) -> Result<bool, WarpgateError> {
    use SessionApprovalRequest::{ApprovalRequestScope, ApprovalRequestStatus, Column};

    let (status, scope) = match decision {
        ApprovalDecision::Approved(scope) => (
            ApprovalRequestStatus::Approved,
            Some(match scope {
                ApprovalScope::Once => ApprovalRequestScope::Once,
                ApprovalScope::Target => ApprovalRequestScope::Target,
                ApprovalScope::AllTargets => ApprovalRequestScope::AllTargets,
            }),
        ),
        ApprovalDecision::Rejected => (ApprovalRequestStatus::Rejected, None),
    };

    // Read ahead of the transition: the columns are stable while the row is
    // pending, and only the pending row this call itself moves is acted on.
    let consumes_ticket_id = if matches!(decision, ApprovalDecision::Approved(_)) {
        find_question(db, session_id, kind, target)
            .await?
            .and_then(|row| row.consumes_ticket_id)
    } else {
        None
    };

    let moved = StatusTransition::from_pending(status)
        .set(Column::Scope, scope)
        .set(Column::ResolvedByUsername, actor.username.clone())
        .set(Column::ResolvedByUserId, actor.user_id)
        .apply(db, one_question(session_id, kind, target))
        .await?;

    // The pending→approved transition is one-shot, so whichever node records
    // the approval consumes the deferred ticket exactly once — however many
    // gates across the cluster are watching the row.
    if moved > 0
        && let Some(ticket_id) = consumes_ticket_id
        && let Err(error) = consume_ticket(db, &ticket_id).await
    {
        warn!(%error, %ticket_id, "Failed to consume the ticket for an approved session");
    }

    Ok(moved > 0)
}

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
/// the one-wait-per-session rule and the only-while-the-session-lives rule
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
) -> Result<(TargetSessionId, ApprovedTarget<O>), WarpgateError> {
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
            std::future::pending(),
            || async { Ok::<_, WarpgateError>(()) },
        )
        .await?;

    let Some(approved) = outcome.approved() else {
        warn!(%session_id, "Session was not approved by an administrator");
        return Err(WarpgateError::SessionNotApproved);
    };

    let target_session_id = handle
        .lock()
        .await
        .register_approved_target_session(&approved)
        .await?;
    Ok((target_session_id, approved))
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
    /// `cancel` ends the wait early when the client goes away. It is a
    /// promptness measure, not a correctness one — session teardown closes the
    /// row regardless — so protocols that can't cheaply observe a disconnect
    /// may pass `std::future::pending()`.
    pub async fn require_admin_approval<E, F, Fut, O>(
        &self,
        authorization: TargetAuthorization<O>,
        context: AdminApprovalContext,
        cancel: impl Future<Output = ()> + Send,
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
            .hold_at_admin_gate(authorization, subject, cancel, notify_waiting)
            .await;

        // A refusal — the administrator's, an expired window, or a gate that
        // failed outright — is not the user's doing, so the ticket gets its
        // use back through the guard's drop. Only an approval keeps the spend.
        if let Some(mut guard) = held_ticket
            && matches!(result, Ok(GateOutcome::Approved(_)))
        {
            guard.disarm();
        }

        result
    }

    /// The wait itself, factored out so [`Self::require_admin_approval`] can
    /// settle the ticket stake on every way out, error paths included.
    async fn hold_at_admin_gate<E, F, Fut, O>(
        &self,
        authorization: TargetAuthorization<O>,
        subject: ApprovalSubject,
        cancel: impl Future<Output = ()> + Send,
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
        let (decision, actor) = match await_row_decision(
            &self.db,
            session_id,
            ApprovalKind::Admin,
            &subject.target_name,
            timeout,
            cancel,
        )
        .await
        {
            RowOutcome::Decided(decision, actor) => {
                guard.decided();
                (decision, actor)
            }
            RowOutcome::TimedOut => {
                guard.timed_out();
                subject.emit_timed_out_event();
                return Ok(GateOutcome::Expired);
            }
            RowOutcome::Ended | RowOutcome::Cancelled => return Ok(GateOutcome::Expired),
        };

        subject.emit_resolved_event(&actor, matches!(decision, ApprovalDecision::Approved(_)));

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
    /// A session has one request slot, so its gates run one at a time: a
    /// request for a second gated target while another target's wait runs is
    /// told to come back, and starts its own wait once the slot frees up.
    /// Settled outcomes are kept per target for the life of the session.
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
                .require_admin_approval(authorization, context, std::future::pending(), || async {
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

    /// Applies a decision already recorded for this session's own approval, if
    /// one is waiting on its row.
    ///
    /// The background sweep delivers these within a tick anyway; an auth flow
    /// that answers the client per message calls this before reporting "still
    /// waiting", so a decision the user just made takes effect on that very
    /// round. SSH clients with no TTY answer the web-approval prompt instantly
    /// and burn through their retry budget in well under a sweep interval, so
    /// for them this is correctness, not just latency.
    pub async fn apply_recorded_user_decision(
        &self,
        session_id: &UserSessionId,
    ) -> Result<(), WarpgateError> {
        let Some(row) = find_request(&self.db, *session_id, ApprovalKind::User).await? else {
            return Ok(());
        };
        // A row that has been picked up is the record of a decision already
        // delivered, not one waiting to be.
        if row.consumed_at.is_some() {
            return Ok(());
        }
        let RowState::Decided(decision, actor) = row_state(&row) else {
            return Ok(());
        };
        self.apply_user_approval(row.session_id, decision, &actor)
            .await?;
        Ok(())
    }

    /// Applies decisions recorded elsewhere to the auth states this node holds.
    ///
    /// A self approval satisfies a credential on an in-memory auth state, so
    /// only the node holding that state can act on the decision — wherever the
    /// user happened to click. Administrator gates need no sweep: each polls its
    /// own row while it holds the connection.
    pub(crate) async fn apply_decided_user_approvals(&self) -> Result<(), WarpgateError> {
        use SessionApprovalRequest::{ApprovalRequestKind, ApprovalRequestStatus, Column};

        // Decided and not yet picked up. Rows stay behind as audit records once
        // they are, so the stamp — not the row's absence — is what stops this
        // delivering the same decision every tick.
        let rows = SessionApprovalRequest::Entity::find()
            .filter(Column::Kind.eq(ApprovalRequestKind::User))
            .filter(Column::NodeId.eq(self.cluster.node_id))
            .filter(Column::Status.is_in([
                ApprovalRequestStatus::Approved,
                ApprovalRequestStatus::Rejected,
            ]))
            .filter(Column::ConsumedAt.is_null())
            .all(&self.db)
            .await?;

        for row in rows {
            let RowState::Decided(decision, actor) = row_state(&row) else {
                continue;
            };
            self.apply_user_approval(row.session_id, decision, &actor)
                .await?;
        }
        Ok(())
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

    /// Advertises that an auth state is waiting for the user's own in-browser
    /// approval: creates the request row, idempotently, so a login driven
    /// through several credential submissions ends up with one request.
    ///
    /// Applies a user's own approval to the locally-owned auth state: adds or
    /// withholds the approval credential through the pending gate, records the
    /// grace key, audits, and stamps the row as picked up. `Ok(false)` when the state is
    /// gone or no longer pending an approval (resolved concurrently, expired,
    /// or never asked).
    ///
    /// The store hands out auth states by session id, so the row's key is also
    /// the key of the state it resolves against.
    pub async fn apply_user_approval(
        &self,
        session_id: UserSessionId,
        decision: ApprovalDecision,
        actor: &ApprovalActor,
    ) -> Result<bool, WarpgateError> {
        let Some(state_arc) = self.auth_state_store.lock().await.get(&session_id) else {
            // The state is gone (vacuumed or node restarted) — nothing can act
            // on the decision, so the row is stamped picked up to stop the
            // sweep re-offering it. It keeps who decided what; that the login
            // never heard is in its own audit trail.
            mark_consumed(&self.db, one_request(session_id, ApprovalKind::User)).await?;
            return Ok(false);
        };

        // All the in-memory work under one lock — it's synchronous, and this
        // path runs at most once per session.
        let target_name = {
            let mut state = state_arc.lock().await;
            let subject = ApprovalSubject::from_auth_state(&state);

            // Only resolve a request the state is actually still waiting on —
            // not already accepted, rejected, or resolved concurrently.
            if !matches!(
                state.verify(),
                AuthResult::Need(ref kinds) if kinds.contains(&CredentialKind::WebUserApproval)
            ) {
                // A state that no longer wants it means the row is stale
                // (satisfied by a grace bypass, or resolved concurrently) —
                // close it rather than leave it advertising a request nobody
                // can fulfil.
                drop(state);
                mark_consumed(&self.db, one_request(session_id, ApprovalKind::User)).await?;
                return Ok(false);
            }

            match decision {
                ApprovalDecision::Approved(_) => {
                    state.add_web_user_approval();
                    subject.emit_resolved_event(actor, true);
                }
                ApprovalDecision::Rejected => {
                    state.reject();
                    subject.emit_resolved_event(actor, false);
                    // A denied login is a failed authentication too — alerting
                    // keys off this event, and a user explicitly denying an
                    // out-of-band request is its highest-value instance.
                    state.emit_authentication_failed_event(
                        Some(&AuthCredential::WebUserApproval),
                        "rejected by user",
                    );
                }
            }
            subject.target_name
        };

        // The row is the durable record of who answered — and, scope and all,
        // the remembered approval later attempts bypass on. A decision the
        // sweep read off the row already stands there, and the pending-only
        // transition makes this a no-op; one applied straight off the click —
        // the user answered on the node holding the state — reaches the row
        // only here.
        let _ = record_decision(
            &self.db,
            session_id,
            ApprovalKind::User,
            &target_name,
            decision,
            actor,
        )
        .await?;
        mark_consumed(&self.db, one_request(session_id, ApprovalKind::User)).await?;
        Ok(true)
    }
}

/// Whether a stored approval within `grace` matches `key` — the grace-period
/// bypass, answered from the request rows themselves, so a grant given while
/// talking to one node bypasses the gate on every node.
///
/// A row matches on kind, protocol, scope, user, origin and the credentials
/// digest. The scope condition covers the exact ask and an all-targets grant,
/// which is strictly broader; an untargeted ask (empty target name) is its own
/// bucket, so a grant for a real target never stands in for it, nor the other
/// way round. The candidate set is narrowed in SQL and pinned down in Rust,
/// where username comparison follows the same rule as the rest of the auth
/// stack rather than the database's collation.
pub(crate) async fn approval_is_remembered(
    db: &DatabaseConnection,
    key: &WebApprovalMatchKey,
    grace: Duration,
    salt: &CredentialDigestSalt,
) -> Result<bool, WarpgateError> {
    use SessionApprovalRequest::{ApprovalRequestScope, ApprovalRequestStatus, Column};

    #[allow(clippy::cast_possible_wrap)]
    let cutoff = OffsetDateTime::now_utc() - time::Duration::seconds(grace.as_secs() as i64);

    let asked_target = match &key.scope {
        WebApprovalScopeKey::Target(name) => name.as_str(),
        // An untargeted flow stores an empty target name on its rows.
        WebApprovalScopeKey::Untargeted => "",
    };
    let scope_matches = Condition::any()
        .add(
            Column::Scope
                .eq(ApprovalRequestScope::Target)
                .and(Column::Target.eq(asked_target)),
        )
        .add(Column::Scope.eq(ApprovalRequestScope::AllTargets));

    let rows = SessionApprovalRequest::Entity::find()
        .filter(Column::Kind.eq(SessionApprovalRequest::ApprovalRequestKind::from(key.kind)))
        .filter(Column::Status.eq(ApprovalRequestStatus::Approved))
        .filter(Column::ResolvedAt.gte(cutoff))
        .filter(scope_matches)
        .all(db)
        .await?;

    let digest = key.other_credentials.digest(salt);
    let protocol = key.protocol.to_string();
    Ok(rows.into_iter().any(|row| {
        row.protocol == protocol
            && username_eq_ci(&row.username, &key.username)
            && row.credentials_digest.as_deref() == Some(digest.as_str())
            && row
                .remote_address
                .as_deref()
                .and_then(|address| address.parse::<IpAddr>().ok())
                == Some(key.remote_ip)
    }))
}

/// Records a self-approval request, so it is visible to every node.
///
/// Written *before* the user is told a request is waiting: the notification and
/// the record would otherwise race, and a user acting on the notification the
/// instant it arrives could find nothing to act on.
pub(crate) async fn advertise_user_request(
    db: &DatabaseConnection,
    node_id: NodeId,
    salt: &CredentialDigestSalt,
    state_arc: &Arc<Mutex<AuthState>>,
) -> Result<(), WarpgateError> {
    // Snapshot under the state lock and release it before the insert, so
    // database IO never runs while a login's state is held.
    let row = {
        let state = state_arc.lock().await;
        let session_id = *state.session_id();
        SessionApprovalRequest::ActiveModel {
            session_id: Set(session_id),
            kind: Set(ApprovalKind::User.into()),
            node_id: Set(node_id),
            protocol: Set(state.protocol().to_string()),
            username: Set(state.user_info().username.clone()),
            target: Set(state.target_name().to_string()),
            remote_address: Set(state.remote_ip().map(|ip| ip.to_string())),
            identification_string: Set(Some(state.identification_string().to_owned())),
            credentials_digest: Set(state
                .remembered_by()
                .credentials()
                .map(|credentials| credentials.digest(salt))),
            consumes_ticket_id: Set(None),
            started: Set(*state.started()),
            status: Set(SessionApprovalRequest::ApprovalRequestStatus::Pending),
            scope: Set(None),
            resolved_by_username: Set(None),
            resolved_by_user_id: Set(None),
            resolved_at: Set(None),
            consumed_at: Set(None),
        }
    };

    upsert_request(db, row).await
}

/// Rows are keyed by `(session_id, kind, target)`, so a wait site that runs
/// twice for the same question updates its own row instead of queueing a
/// duplicate, and a question about another target is simply another row.
///
/// A decision nobody has picked up yet is deliberately left alone.
/// Re-advertising is the same session asking the same question again — a
/// request/response protocol re-enters its gate on every request — and an
/// answer given between two of those is the answer to *this* question.
/// Rewriting it would silently discard a decision an administrator has already
/// made.
///
/// A row whose gate has *finished* is a previous asking of the same question,
/// and is reopened: the session is asking again about the same target, and the
/// stale answer must not be read as this asking's.
async fn upsert_request(
    db: &DatabaseConnection,
    row: SessionApprovalRequest::ActiveModel,
) -> Result<(), WarpgateError> {
    use SessionApprovalRequest::ApprovalRequestStatus as Status;

    // The whole row is rewritten, so this writes its status through
    // `Entity::update` rather than a `StatusTransition` — but under the same
    // rule: the states it may leave are named, not assumed.
    let mut reopened = row.clone();
    reopened.status = Set(Status::Pending);
    reopened.scope = Set(None);
    reopened.resolved_by_username = Set(None);
    reopened.resolved_by_user_id = Set(None);
    reopened.resolved_at = Set(None);
    reopened.consumed_at = Set(None);

    match SessionApprovalRequest::Entity::update(reopened)
        .filter(question_is_over())
        .exec(db)
        .await
    {
        Ok(_) => return Ok(()),
        // No row at all, or one that is still this question's live request.
        Err(DbErr::RecordNotUpdated) => {}
        Err(error) => return Err(error.into()),
    }

    SessionApprovalRequest::Entity::insert(row)
        .on_conflict(
            OnConflict::columns([
                SessionApprovalRequest::Column::SessionId,
                SessionApprovalRequest::Column::Kind,
                SessionApprovalRequest::Column::Target,
            ])
            .update_columns(SessionApprovalRequest::Column::IDENTITY)
            .to_owned(),
        )
        .exec(db)
        .await?;
    Ok(())
}

/// The configured administrator-approval window, or the default auth-state
/// timeout when unset.
pub(crate) async fn admin_approval_timeout(
    db: &DatabaseConnection,
) -> Result<Duration, WarpgateError> {
    Ok(Parameters::Entity::get(db)
        .await?
        .admin_approval_timeout_seconds
        .filter(|s| *s > 0)
        .and_then(|s| u64::try_from(s).ok())
        .map_or(*TIMEOUT, Duration::from_secs))
}

/// Ends a request that is still waiting, leaving the row as the record of how.
///
/// Only a pending request can be closed this way: a decision already written to
/// the row is the answer, and outranks whatever the waiting side went on to do.
/// `target` names the question being closed, so a straggling close cannot end a
/// successor question that has since taken the slot over.
pub async fn close_request(
    db: &DatabaseConnection,
    session_id: UserSessionId,
    kind: ApprovalKind,
    target: &str,
    status: SessionApprovalRequest::ApprovalRequestStatus,
) -> Result<(), WarpgateError> {
    StatusTransition::from_pending(status)
        .apply(db, one_question(session_id, kind, target))
        .await?;
    Ok(())
}

/// Records that the owning node has read a decision off the row and acted on
/// it. The row stays as the audit record; the stamp is what takes it out of the
/// sweep and marks it reusable by a later gate on the same session. `which`
/// names the rows — [`one_question`] where the caller knows which question it
/// delivered, [`one_request`] where the state, not the row, was the authority.
async fn mark_consumed(db: &DatabaseConnection, which: Condition) -> Result<(), WarpgateError> {
    use SessionApprovalRequest::Column;

    SessionApprovalRequest::Entity::update_many()
        .col_expr(Column::ConsumedAt, OffsetDateTime::now_utc().into())
        .filter(which)
        .filter(Column::ConsumedAt.is_null())
        .exec(db)
        .await?;
    Ok(())
}

/// Ends every request still waiting on a session, for when the session itself
/// ends — the waiting connection is gone, so nothing can consume them.
pub(crate) async fn abandon_requests_for_session(
    db: &DatabaseConnection,
    session_id: UserSessionId,
) -> Result<(), WarpgateError> {
    StatusTransition::from_pending(SessionApprovalRequest::ApprovalRequestStatus::Abandoned)
        .apply(
            db,
            SessionApprovalRequest::Column::SessionId
                .eq(session_id)
                .into_condition(),
        )
        .await?;
    Ok(())
}

/// How long approval requests must stay alive: the administrator-approval
/// window, never shorter than the auth-state [`TIMEOUT`].
///
/// A request legitimately outlives the auth state that may have preceded it, so
/// expiring it at the shorter interval would strand sessions still waiting.
pub(crate) async fn request_lifetime(db: &DatabaseConnection) -> Result<Duration, WarpgateError> {
    Ok(admin_approval_timeout(db).await?.max(*TIMEOUT))
}

/// Ends requests whose waiter is gone without having closed them (owning node
/// crashed, or a `Drop` that never got to run). Nothing can still be waiting on
/// a request older than the window it would have waited for.
pub(crate) async fn reap_stale(db: &DatabaseConnection) -> Result<(), WarpgateError> {
    use SessionApprovalRequest::{ApprovalRequestStatus, Column};

    let lifetime = request_lifetime(db).await?;
    #[allow(clippy::cast_possible_wrap)]
    let cutoff = OffsetDateTime::now_utc() - time::Duration::seconds(lifetime.as_secs() as i64);
    StatusTransition::from_pending(ApprovalRequestStatus::Abandoned)
        .apply(db, Column::Started.lt(cutoff).into_condition())
        .await?;
    Ok(())
}

/// Drops request rows past the audit retention. The only thing that deletes
/// one: everything else moves a request to a terminal status and leaves it as
/// the record of what was asked and who answered.
pub async fn prune_before(
    db: &DatabaseConnection,
    cutoff: OffsetDateTime,
) -> Result<(), WarpgateError> {
    SessionApprovalRequest::Entity::delete_many()
        .filter(SessionApprovalRequest::Column::Started.lt(cutoff))
        .exec(db)
        .await?;
    Ok(())
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::Database;
    use warpgate_common::auth::AuthCredentialFingerprint;
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_migrations::migrate_database;

    use super::*;

    /// The tests share one salt: a digest is only ever compared against another
    /// digest from the same installation, so the value is irrelevant — that it
    /// is the *same* one on both sides is the whole point.
    fn test_salt() -> CredentialDigestSalt {
        #[allow(clippy::expect_used)]
        CredentialDigestSalt::from_stored("test-salt").expect("non-empty")
    }

    async fn migrated_db() -> DatabaseConnection {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        db
    }

    async fn advertise_row(
        db: &DatabaseConnection,
        session_id: UserSessionId,
        subject: &ApprovalSubject,
    ) {
        upsert_request(
            db,
            SessionApprovalRequest::ActiveModel {
                session_id: Set(session_id),
                kind: Set(subject.kind.into()),
                node_id: Set(NodeId(Uuid::new_v4())),
                protocol: Set(subject.protocol.to_string()),
                username: Set(subject.user_info.username.clone()),
                target: Set(subject.target_name.clone()),
                remote_address: Set(subject.remote_ip.map(|ip| ip.to_string())),
                identification_string: Set(None),
                credentials_digest: Set(subject.credentials_digest(&test_salt())),
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
        .unwrap();
    }

    fn plain_subject(target: &str) -> ApprovalSubject {
        ApprovalSubject {
            kind: ApprovalKind::Admin,
            session_id: UserSessionId(Uuid::new_v4()),
            user_info: AuthStateUserInfo {
                id: Uuid::new_v4(),
                username: "someone".into(),
            },
            protocol: Protocol::Ssh,
            target_name: target.into(),
            remote_ip: None,
            credentials: RememberedBy::Nothing,
            consumes_ticket_id: None,
        }
    }

    async fn pending_row(db: &DatabaseConnection, session_id: UserSessionId, target: &str) {
        advertise_row(db, session_id, &plain_subject(target)).await;
    }

    fn admin_actor() -> ApprovalActor {
        ApprovalActor {
            username: "admin".into(),
            user_id: None,
        }
    }

    async fn approve(db: &DatabaseConnection, session_id: UserSessionId, target: &str) -> bool {
        approve_with_scope(db, session_id, target, ApprovalScope::Once).await
    }

    async fn approve_with_scope(
        db: &DatabaseConnection,
        session_id: UserSessionId,
        target: &str,
        scope: ApprovalScope,
    ) -> bool {
        record_decision(
            db,
            session_id,
            ApprovalKind::Admin,
            target,
            ApprovalDecision::Approved(scope),
            &admin_actor(),
        )
        .await
        .unwrap()
    }

    async fn status_of(
        db: &DatabaseConnection,
        session_id: UserSessionId,
        target: &str,
    ) -> SessionApprovalRequest::ApprovalRequestStatus {
        find_question(db, session_id, ApprovalKind::Admin, target)
            .await
            .unwrap()
            .expect("the request should still exist")
            .status
    }

    /// Moves a request's start time into the past, so the reaper sees it as
    /// older than the window anything could still be waiting for.
    async fn backdate(db: &DatabaseConnection, session_id: UserSessionId, by: Duration) {
        SessionApprovalRequest::Entity::update_many()
            .col_expr(
                SessionApprovalRequest::Column::Started,
                (OffsetDateTime::now_utc() - time::Duration::seconds(by.as_secs() as i64)).into(),
            )
            .filter(one_request(session_id, ApprovalKind::Admin))
            .exec(db)
            .await
            .unwrap();
    }

    /// Nothing else ends a request whose owning node died mid-hold: the guard's
    /// `Drop` never ran, and no waiter is left to time out. Without the reaper
    /// the row sits in the inbox forever, offering an administrator a session
    /// that no longer exists.
    #[tokio::test]
    async fn reaping_ends_requests_nobody_can_still_be_waiting_on() {
        use SessionApprovalRequest::ApprovalRequestStatus as Status;

        let db = migrated_db().await;
        let stale = UserSessionId(Uuid::new_v4());
        let recent = UserSessionId(Uuid::new_v4());
        pending_row(&db, stale, "a-target").await;
        pending_row(&db, recent, "a-target").await;
        // Past any window: the lifetime is the approval timeout, never shorter
        // than the auth-state timeout.
        backdate(&db, stale, Duration::from_secs(24 * 3600)).await;

        reap_stale(&db).await.unwrap();

        assert_eq!(status_of(&db, stale, "a-target").await, Status::Abandoned);
        assert_eq!(
            status_of(&db, recent, "a-target").await,
            Status::Pending,
            "a request still inside its window is still a live question",
        );
    }

    /// The reaper runs on a timer against every row in the table, so it meets
    /// answered ones too. An answer outranks the reaper: the owning node may
    /// not have picked it up yet, and overwriting it would deny a session an
    /// administrator approved.
    #[tokio::test]
    async fn reaping_never_erases_an_answer() {
        use SessionApprovalRequest::ApprovalRequestStatus as Status;

        let db = migrated_db().await;
        let session_id = UserSessionId(Uuid::new_v4());
        pending_row(&db, session_id, "a-target").await;
        assert!(approve(&db, session_id, "a-target").await);
        backdate(&db, session_id, Duration::from_secs(24 * 3600)).await;

        reap_stale(&db).await.unwrap();

        assert_eq!(
            status_of(&db, session_id, "a-target").await,
            Status::Approved
        );
    }

    /// A request/response protocol re-enters its gate on every request, so the
    /// same session re-advertises constantly. If that overwrote the decision
    /// columns it would erase an administrator's answer, and the session would
    /// wait forever while the inbox kept offering it again.
    #[tokio::test]
    async fn re_advertising_keeps_a_recorded_decision() {
        let db = migrated_db().await;
        let session_id = UserSessionId(Uuid::new_v4());
        pending_row(&db, session_id, "a-target").await;
        assert!(approve(&db, session_id, "a-target").await);

        pending_row(&db, session_id, "a-target").await;

        let row = find_request(&db, session_id, ApprovalKind::Admin)
            .await
            .unwrap()
            .expect("the request should still exist");
        assert!(
            matches!(row_state(&row), RowState::Decided(..)),
            "re-advertising must not erase the recorded decision",
        );
    }

    /// Rows outlive their gate now, so a session that gates again — a new
    /// target, or a retry after a timeout — would otherwise read the previous
    /// gate's answer as this one's and walk straight through.
    #[tokio::test]
    async fn re_advertising_reopens_a_finished_request() {
        let db = migrated_db().await;

        for finished in [
            SessionApprovalRequest::ApprovalRequestStatus::TimedOut,
            SessionApprovalRequest::ApprovalRequestStatus::Abandoned,
        ] {
            let session_id = UserSessionId(Uuid::new_v4());
            pending_row(&db, session_id, "a-target").await;
            close_request(&db, session_id, ApprovalKind::Admin, "a-target", finished)
                .await
                .unwrap();

            pending_row(&db, session_id, "a-target").await;

            assert_eq!(
                status_of(&db, session_id, "a-target").await,
                SessionApprovalRequest::ApprovalRequestStatus::Pending,
                "a request left {finished:?} must be reopened, not reused",
            );
        }
    }

    /// The same, for the decision that *was* delivered: once the owning node has
    /// picked it up, the question is over, and the next gate has to ask afresh.
    #[tokio::test]
    async fn re_advertising_reopens_a_consumed_request() {
        let db = migrated_db().await;
        let session_id = UserSessionId(Uuid::new_v4());
        pending_row(&db, session_id, "a-target").await;
        assert!(approve(&db, session_id, "a-target").await);
        mark_consumed(&db, one_request(session_id, ApprovalKind::Admin))
            .await
            .unwrap();

        pending_row(&db, session_id, "a-target").await;

        let row = find_request(&db, session_id, ApprovalKind::Admin)
            .await
            .unwrap()
            .expect("the request should still exist");
        assert_eq!(
            row.status,
            SessionApprovalRequest::ApprovalRequestStatus::Pending,
        );
        assert!(row.consumed_at.is_none(), "the stamp must be cleared too");
        assert!(row.scope.is_none(), "the previous answer must be cleared");
        assert!(
            row.resolved_by_username.is_none(),
            "the previous resolver must be cleared",
        );
    }

    /// A decision names the question it answers. A request reopened for a
    /// different target between the approver's screen and their click is a
    /// question they were never shown, and their answer must not land on it.
    #[tokio::test]
    async fn a_decision_names_its_question() {
        let db = migrated_db().await;
        let session_id = UserSessionId(Uuid::new_v4());
        pending_row(&db, session_id, "a-target").await;

        assert!(
            !approve(&db, session_id, "another-target").await,
            "a decision about a different target must not be recorded",
        );
        assert_eq!(
            status_of(&db, session_id, "a-target").await,
            SessionApprovalRequest::ApprovalRequestStatus::Pending,
        );
    }

    /// Gating for a second target asks a second question. It gets its own row,
    /// and the answer already given about the first stays exactly as the
    /// administrator left it — the record of who approved what is the table,
    /// and a session reaching two targets must not cost it one of them.
    #[tokio::test]
    async fn a_second_target_asks_alongside_the_first() {
        let db = migrated_db().await;
        let session_id = UserSessionId(Uuid::new_v4());
        pending_row(&db, session_id, "a-target").await;
        assert!(approve_with_scope(&db, session_id, "a-target", ApprovalScope::Target).await);

        pending_row(&db, session_id, "b-target").await;

        let first = find_question(&db, session_id, ApprovalKind::Admin, "a-target")
            .await
            .unwrap()
            .expect("the answered question must still be on record");
        assert_eq!(
            first.status,
            SessionApprovalRequest::ApprovalRequestStatus::Approved,
        );
        assert_eq!(
            first.scope,
            Some(SessionApprovalRequest::ApprovalRequestScope::Target),
            "the grant the administrator gave must survive the next question",
        );
        assert_eq!(first.resolved_by_username.as_deref(), Some("admin"));

        let second = find_question(&db, session_id, ApprovalKind::Admin, "b-target")
            .await
            .unwrap()
            .expect("the new question should exist");
        assert_eq!(
            second.status,
            SessionApprovalRequest::ApprovalRequestStatus::Pending,
        );
        assert!(second.scope.is_none());
        assert!(second.resolved_by_username.is_none());
    }

    /// A session's questions are answered one at a time and in any order, so a
    /// waiter must read only its own row: admitting a connection on the
    /// strength of an approval given for a different target would let one
    /// decision open two doors.
    #[tokio::test]
    async fn a_waiter_only_sees_answers_to_its_own_question() {
        let db = migrated_db().await;
        let session_id = UserSessionId(Uuid::new_v4());
        pending_row(&db, session_id, "a-target").await;
        pending_row(&db, session_id, "b-target").await;
        assert!(approve(&db, session_id, "b-target").await);

        let outcome = await_row_decision(
            &db,
            session_id,
            ApprovalKind::Admin,
            "a-target",
            Duration::from_millis(1500),
            std::future::pending(),
        )
        .await;
        assert!(
            matches!(outcome, RowOutcome::TimedOut),
            "a wait must not adopt an answer given about another target",
        );
    }

    /// Closing is what replaces deleting: a waiter that gives up must leave the
    /// row behind as the record, must not overwrite an answer that landed
    /// while it was giving up, and must not touch the session's other
    /// questions.
    #[tokio::test]
    async fn closing_keeps_the_row_and_never_overwrites_an_answer() {
        let db = migrated_db().await;

        let abandoned = UserSessionId(Uuid::new_v4());
        pending_row(&db, abandoned, "a-target").await;
        abandon_requests_for_session(&db, abandoned).await.unwrap();
        assert_eq!(
            status_of(&db, abandoned, "a-target").await,
            SessionApprovalRequest::ApprovalRequestStatus::Abandoned,
        );

        let answered = UserSessionId(Uuid::new_v4());
        pending_row(&db, answered, "a-target").await;
        assert!(approve(&db, answered, "a-target").await);
        close_request(
            &db,
            answered,
            ApprovalKind::Admin,
            "a-target",
            SessionApprovalRequest::ApprovalRequestStatus::TimedOut,
        )
        .await
        .unwrap();
        assert_eq!(
            status_of(&db, answered, "a-target").await,
            SessionApprovalRequest::ApprovalRequestStatus::Approved,
        );

        let two_targets = UserSessionId(Uuid::new_v4());
        pending_row(&db, two_targets, "a-target").await;
        pending_row(&db, two_targets, "b-target").await;
        close_request(
            &db,
            two_targets,
            ApprovalKind::Admin,
            "a-target",
            SessionApprovalRequest::ApprovalRequestStatus::TimedOut,
        )
        .await
        .unwrap();
        assert_eq!(
            status_of(&db, two_targets, "a-target").await,
            SessionApprovalRequest::ApprovalRequestStatus::TimedOut,
        );
        assert_eq!(
            status_of(&db, two_targets, "b-target").await,
            SessionApprovalRequest::ApprovalRequestStatus::Pending,
            "closing one question must not end the session's others",
        );
    }

    /// Every column belongs to the key, the question or the answer — the
    /// reopen path rewrites by these sets, so an unclassified column would
    /// silently keep stale data when a question is asked again.
    #[test]
    fn every_column_is_classified() {
        use std::collections::HashSet;

        use SessionApprovalRequest::Column;
        use sea_orm::Iterable;

        let classified: HashSet<String> = [Column::SessionId, Column::Kind, Column::Target]
            .iter()
            .chain(&Column::IDENTITY)
            .chain(&Column::DECISION)
            .map(|column| format!("{column:?}"))
            .collect();
        let all: HashSet<String> = Column::iter().map(|column| format!("{column:?}")).collect();
        assert_eq!(
            classified, all,
            "add the new column to Column::IDENTITY or Column::DECISION",
        );
    }

    /// The waiting side has to notice a decision written by *another* task —
    /// that hand-off is the whole substrate, and a wait that only ever reads the
    /// row once would hold the session open forever.
    #[tokio::test]
    async fn a_decision_written_later_is_picked_up() {
        let db = migrated_db().await;
        let session_id = UserSessionId(Uuid::new_v4());
        pending_row(&db, session_id, "a-target").await;

        let writer = {
            let db = db.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                record_decision(
                    &db,
                    session_id,
                    ApprovalKind::Admin,
                    "a-target",
                    ApprovalDecision::Approved(ApprovalScope::Once),
                    &ApprovalActor {
                        username: "admin".into(),
                        user_id: None,
                    },
                )
                .await
                .unwrap()
            })
        };

        let outcome = await_row_decision(
            &db,
            session_id,
            ApprovalKind::Admin,
            "a-target",
            Duration::from_secs(20),
            std::future::pending(),
        )
        .await;

        assert!(
            writer.await.unwrap(),
            "the decision should have been recorded"
        );
        assert!(
            matches!(
                outcome,
                RowOutcome::Decided(ApprovalDecision::Approved(ApprovalScope::Once), _)
            ),
            "the wait should have seen the recorded decision",
        );
    }

    fn password_credentials(hash: [u8; 32]) -> RememberedBy {
        RememberedBy::from_fingerprints(vec![AuthCredentialFingerprint::Password { hash }])
    }

    fn remembered_subject(target: &str, hash: [u8; 32]) -> ApprovalSubject {
        ApprovalSubject {
            remote_ip: Some("10.0.0.5".parse().unwrap()),
            credentials: password_credentials(hash),
            ..plain_subject(target)
        }
    }

    fn lookup_key(target: &str, hash: [u8; 32]) -> WebApprovalMatchKey {
        WebApprovalMatchKey::build(
            ApprovalKind::Admin,
            Some("10.0.0.5".parse().unwrap()),
            Protocol::Ssh,
            // Case differs from the stored row's "someone" on purpose:
            // usernames compare case-insensitively across the auth stack.
            "Someone",
            target,
            &password_credentials(hash),
        )
        .expect("a subject with an origin and credentials is keyable")
    }

    async fn remembered_approval(
        db: &DatabaseConnection,
        target: &str,
        hash: [u8; 32],
        scope: ApprovalScope,
    ) -> UserSessionId {
        let session_id = UserSessionId(Uuid::new_v4());
        advertise_row(db, session_id, &remembered_subject(target, hash)).await;
        assert!(approve_with_scope(db, session_id, target, scope).await);
        session_id
    }

    const GRACE: Duration = Duration::from_secs(3600);

    /// The bypass answers from the stored rows, so it must demand the full
    /// match: the kind, the target, the credentials, and a fresh resolution.
    #[tokio::test]
    async fn a_remembered_approval_requires_a_full_match() {
        let db = migrated_db().await;
        remembered_approval(&db, "prod", [7u8; 32], ApprovalScope::Target).await;

        assert!(
            approval_is_remembered(&db, &lookup_key("prod", [7u8; 32]), GRACE, &test_salt())
                .await
                .unwrap()
        );
        // Another target is not covered.
        assert!(
            !approval_is_remembered(&db, &lookup_key("staging", [7u8; 32]), GRACE, &test_salt())
                .await
                .unwrap()
        );
        // Different credentials are not covered.
        assert!(
            !approval_is_remembered(&db, &lookup_key("prod", [9u8; 32]), GRACE, &test_salt())
                .await
                .unwrap()
        );
        // A zero grace is never fresh, so approval is required again.
        assert!(
            !approval_is_remembered(
                &db,
                &lookup_key("prod", [7u8; 32]),
                Duration::ZERO,
                &test_salt()
            )
            .await
            .unwrap()
        );
        // The other approval kind is a different question entirely.
        let mut other_kind = lookup_key("prod", [7u8; 32]);
        other_kind.kind = ApprovalKind::User;
        assert!(
            !approval_is_remembered(&db, &other_kind, GRACE, &test_salt())
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn an_all_targets_grant_covers_every_target() {
        let db = migrated_db().await;
        remembered_approval(&db, "prod", [7u8; 32], ApprovalScope::AllTargets).await;

        assert!(
            approval_is_remembered(&db, &lookup_key("prod", [7u8; 32]), GRACE, &test_salt())
                .await
                .unwrap()
        );
        assert!(
            approval_is_remembered(&db, &lookup_key("staging", [7u8; 32]), GRACE, &test_salt())
                .await
                .unwrap()
        );
        // Approving every target is strictly broader than approving a portal
        // sign-in, so it subsumes an untargeted ask too.
        assert!(
            approval_is_remembered(&db, &lookup_key("", [7u8; 32]), GRACE, &test_salt())
                .await
                .unwrap()
        );
    }

    /// An HTTP sign-in / SSH menu login carries no target. A grant given to
    /// one must not stand in for approval of an actual target, nor a target's
    /// grant for it.
    #[tokio::test]
    async fn an_untargeted_grant_is_its_own_bucket() {
        let db = migrated_db().await;
        remembered_approval(&db, "", [7u8; 32], ApprovalScope::Target).await;

        assert!(
            approval_is_remembered(&db, &lookup_key("", [7u8; 32]), GRACE, &test_salt())
                .await
                .unwrap()
        );
        assert!(
            !approval_is_remembered(&db, &lookup_key("prod", [7u8; 32]), GRACE, &test_salt())
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn a_once_approval_is_not_remembered() {
        let db = migrated_db().await;
        remembered_approval(&db, "prod", [7u8; 32], ApprovalScope::Once).await;

        assert!(
            !approval_is_remembered(&db, &lookup_key("prod", [7u8; 32]), GRACE, &test_salt())
                .await
                .unwrap()
        );
    }

    /// Only an approval grants; a question still open, or one answered with a
    /// refusal, remembers nothing.
    #[tokio::test]
    async fn only_an_approval_is_remembered() {
        let db = migrated_db().await;

        let pending = UserSessionId(Uuid::new_v4());
        advertise_row(&db, pending, &remembered_subject("prod", [7u8; 32])).await;
        assert!(
            !approval_is_remembered(&db, &lookup_key("prod", [7u8; 32]), GRACE, &test_salt())
                .await
                .unwrap()
        );

        assert!(
            record_decision(
                &db,
                pending,
                ApprovalKind::Admin,
                "prod",
                ApprovalDecision::Rejected,
                &admin_actor(),
            )
            .await
            .unwrap()
        );
        assert!(
            !approval_is_remembered(&db, &lookup_key("prod", [7u8; 32]), GRACE, &test_salt())
                .await
                .unwrap()
        );
    }

    async fn ticket_with_uses(db: &DatabaseConnection, uses: i16) -> Uuid {
        use warpgate_db_entities::Target::TargetKind;
        use warpgate_db_entities::{Target, Ticket, User};

        let user_id = Uuid::new_v4();
        User::Entity::insert(User::ActiveModel {
            id: Set(user_id),
            username: Set(format!("user-{user_id}")),
            credential_policy: Set(serde_json::Value::Null),
            description: Set(String::new()),
            rate_limit_bytes_per_second: Set(None),
            ldap_server_id: Set(None),
            ldap_object_uuid: Set(None),
            allowed_ip_ranges: Set(serde_json::Value::Null),
        })
        .exec(db)
        .await
        .unwrap();

        let target_id = Uuid::new_v4();
        Target::Entity::insert(Target::ActiveModel {
            id: Set(target_id),
            name: Set(format!("target-{target_id}")),
            description: Set(String::new()),
            kind: Set(TargetKind::Ssh),
            options: Set(serde_json::Value::Null),
            rate_limit_bytes_per_second: Set(None),
            group_id: Set(None),
            ticket_max_duration_seconds: Set(None),
            ticket_requests_disabled: Set(false),
            ticket_require_approval: Set(false),
            ticket_max_uses: Set(None),
            require_approval: Set(true),
        })
        .exec(db)
        .await
        .unwrap();

        let id = Uuid::new_v4();
        Ticket::Entity::insert(Ticket::ActiveModel {
            id: Set(id),
            secret_hash: Set("hash".into()),
            user_id: Set(user_id),
            description: Set(String::new()),
            target_id: Set(target_id),
            uses_left: Set(Some(uses)),
            self_service: Set(false),
            expiry: Set(None),
            created: Set(OffsetDateTime::now_utc()),
        })
        .exec(db)
        .await
        .unwrap();
        id
    }

    async fn uses_left(db: &DatabaseConnection, id: Uuid) -> Option<i16> {
        use warpgate_db_entities::Ticket;

        Ticket::Entity::find_by_id(id)
            .one(db)
            .await
            .unwrap()
            .expect("the ticket should exist")
            .uses_left
    }

    /// A deferred ticket is spent by the pending→approved transition, which is
    /// one-shot — so however many gates across the cluster watch the row, an
    /// approval spends exactly one use, and nothing else spends any.
    #[tokio::test]
    async fn a_deferred_ticket_is_consumed_exactly_once_by_an_approval() {
        let db = migrated_db().await;
        let ticket_id = ticket_with_uses(&db, 2).await;

        let session_id = UserSessionId(Uuid::new_v4());
        let mut subject = plain_subject("a-target");
        subject.consumes_ticket_id = Some(ticket_id);
        advertise_row(&db, session_id, &subject).await;

        // A decision about a different target moves nothing and spends nothing.
        assert!(!approve(&db, session_id, "another-target").await);
        assert_eq!(uses_left(&db, ticket_id).await, Some(2));

        assert!(approve(&db, session_id, "a-target").await);
        assert_eq!(uses_left(&db, ticket_id).await, Some(1));

        // A second decision finds the question already answered.
        assert!(!approve(&db, session_id, "a-target").await);
        assert_eq!(uses_left(&db, ticket_id).await, Some(1));
    }

    /// A refusal is not the user's doing, so the ticket keeps its use.
    #[tokio::test]
    async fn a_refused_deferred_ticket_keeps_its_use() {
        let db = migrated_db().await;
        let ticket_id = ticket_with_uses(&db, 1).await;

        let session_id = UserSessionId(Uuid::new_v4());
        let mut subject = plain_subject("a-target");
        subject.consumes_ticket_id = Some(ticket_id);
        advertise_row(&db, session_id, &subject).await;

        assert!(
            record_decision(
                &db,
                session_id,
                ApprovalKind::Admin,
                "a-target",
                ApprovalDecision::Rejected,
                &admin_actor(),
            )
            .await
            .unwrap()
        );
        assert_eq!(uses_left(&db, ticket_id).await, Some(1));
    }
}
