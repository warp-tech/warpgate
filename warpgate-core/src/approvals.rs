//! Out-of-band approval requests: in-browser self approval, and administrator
//! just-in-time approval of a session.
//!
//! The two are deliberately different mechanisms. Self approval is a
//! *credential* — it satisfies a pending [`CredentialKind::WebUserApproval`] on
//! an in-memory auth state, so its request row carries the auth state it
//! resolves against. Administrator approval is a *gate on the connection*,
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
//! Rows are deleted once the owner has consumed the decision, when the waiter
//! gives up, when the session ends, and are aged out if the owner died.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::OnConflict;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use uuid::Uuid;
use warpgate_common::auth::{
    ApprovalKind, AuthCredential, AuthCredentialFingerprint, AuthResult, AuthState,
    AuthStateUserInfo, CredentialKind, WebApprovalMatchKey, WebApprovalScopeKey,
};
use warpgate_common::helpers::logging::format_related_ids;
use warpgate_common::{Protocol, SessionId, WarpgateError};
use warpgate_db_entities::{Parameters, SessionApprovalRequest};

use crate::auth_state_store::TIMEOUT;
use crate::services::Services;

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
    session_id: SessionId,
    user_info: AuthStateUserInfo,
    protocol: Protocol,
    target_name: String,
    remote_ip: Option<IpAddr>,
    /// Credentials this session authenticated with, keying the remembered
    /// approval. `None` where they aren't a stable fingerprint (ticket auth),
    /// which disables remembering rather than keying on less.
    credentials: Option<Vec<AuthCredentialFingerprint>>,
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
            credentials: Some(state.credential_fingerprints()),
        }
    }

    fn client_ip_for_logging(&self) -> String {
        self.remote_ip
            .map_or_else(|| "<unknown>".to_string(), |ip| ip.to_string())
    }

    /// The key this session's approval is remembered under. `None` without a
    /// remote IP or without known credentials, so a remembered approval is
    /// never replayed for a session that can't be pinned to the same origin
    /// and the same credentials.
    fn match_key(&self) -> Option<WebApprovalMatchKey> {
        let mut other_credentials = self.credentials.clone()?;
        other_credentials.sort_unstable();
        other_credentials.dedup();

        Some(WebApprovalMatchKey {
            kind: self.kind,
            remote_ip: self.remote_ip?,
            protocol: self.protocol,
            username: self.user_info.username.to_lowercase(),
            // An empty target name means the flow hasn't picked one, which is
            // not the same as an approval covering all targets.
            scope: if self.target_name.is_empty() {
                WebApprovalScopeKey::Untargeted
            } else {
                WebApprovalScopeKey::Target(self.target_name.clone())
            },
            other_credentials,
        })
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
/// A session waits on at most one administrator gate at a time (the row's key
/// says so), so the guard can drop the row without asking whose it is.
struct PendingApproval {
    session_id: SessionId,
    db: DatabaseConnection,
}

impl Drop for PendingApproval {
    fn drop(&mut self) {
        // Drop can't await. `reap_stale` and the session-teardown sweep both
        // cover a row this spawn never gets to delete.
        let session_id = self.session_id;
        let db = self.db.clone();
        tokio::spawn(async move {
            let _ = delete_request(&db, session_id, ApprovalKind::Admin).await;
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
        node_id: Uuid,
        subject: &ApprovalSubject,
    ) -> Result<Self, WarpgateError> {
        let guard = Self {
            session_id: subject.session_id,
            db,
        };
        advertise_admin_request(&guard.db, node_id, subject).await?;
        Ok(guard)
    }
}

/// Writes (idempotently) the request row an administrator gate advertises. Kept
/// beside [`PendingApproval::begin`], its only caller, so the row a guard owns
/// and the row this writes stay in step.
async fn advertise_admin_request(
    db: &DatabaseConnection,
    node_id: Uuid,
    subject: &ApprovalSubject,
) -> Result<(), WarpgateError> {
    upsert_request(
        db,
        SessionApprovalRequest::ActiveModel {
            session_id: Set(subject.session_id),
            kind: Set(ApprovalKind::Admin.into()),
            auth_state_id: Set(None),
            node_id: Set(node_id),
            protocol: Set(subject.protocol.to_string()),
            username: Set(subject.user_info.username.clone()),
            target: Set(subject.target_name.clone()),
            remote_address: Set(subject.remote_ip.map(|ip| ip.to_string())),
            identification_string: Set(None),
            started: Set(OffsetDateTime::now_utc()),
            status: Set(SessionApprovalRequest::ApprovalRequestStatus::Pending),
            scope: Set(None),
            resolved_by_username: Set(None),
            resolved_by_user_id: Set(None),
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
    /// The row went away underneath the wait — the session ended, or it was
    /// reaped because this node looked dead. Nothing approved the connection.
    Vanished,
    TimedOut,
    Cancelled,
}

/// The decision recorded on a row, or `None` while it is still pending.
fn decision_from_row(
    row: &SessionApprovalRequest::Model,
) -> Option<(ApprovalDecision, ApprovalActor)> {
    use SessionApprovalRequest::{ApprovalRequestScope, ApprovalRequestStatus};

    let decision = match row.status {
        ApprovalRequestStatus::Pending => return None,
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
    Some((decision, actor))
}

/// Waits for a decision to be written to this request's row, giving up at
/// `timeout` or when `cancel` fires.
///
/// A read failure keeps the wait going rather than ending it: a database blip
/// must not deny a connection an administrator is in the middle of approving,
/// and the timeout still bounds the wait.
async fn await_row_decision(
    db: &DatabaseConnection,
    session_id: SessionId,
    kind: ApprovalKind,
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
                match find_request(db, session_id, kind).await {
                    Ok(Some(row)) => {
                        if let Some((decision, actor)) = decision_from_row(&row) {
                            return RowOutcome::Decided(decision, actor);
                        }
                    }
                    Ok(None) => return RowOutcome::Vanished,
                    Err(error) => {
                        warn!(%error, "Failed to read a session approval request");
                    }
                }
            }
        }
    }
}

async fn find_request(
    db: &DatabaseConnection,
    session_id: SessionId,
    kind: ApprovalKind,
) -> Result<Option<SessionApprovalRequest::Model>, WarpgateError> {
    Ok(SessionApprovalRequest::Entity::find_by_id((
        session_id,
        SessionApprovalRequest::ApprovalRequestKind::from(kind),
    ))
    .one(db)
    .await?)
}

/// Records a decision against a pending request, from whichever node the
/// approver happens to be talking to. `Ok(false)` when there is no longer a
/// pending request to decide — already resolved, or the waiter gave up and took
/// the row with it.
pub async fn record_decision(
    db: &DatabaseConnection,
    session_id: SessionId,
    kind: ApprovalKind,
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

    let result = SessionApprovalRequest::Entity::update_many()
        .col_expr(Column::Status, status.into())
        .col_expr(Column::Scope, scope.into())
        .col_expr(Column::ResolvedByUsername, actor.username.clone().into())
        .col_expr(Column::ResolvedByUserId, actor.user_id.into())
        .filter(Column::SessionId.eq(session_id))
        .filter(Column::Kind.eq(SessionApprovalRequest::ApprovalRequestKind::from(kind)))
        // Only a request still waiting can be decided, so a decision already
        // recorded is never overwritten by a later click.
        .filter(Column::Status.eq(ApprovalRequestStatus::Pending))
        .exec(db)
        .await?;

    Ok(result.rows_affected > 0)
}

/// Where a session's administrator gate has got to.
///
/// Request/response protocols answer each request on its own rather than
/// holding a connection open, so they need to *observe* the gate instead of
/// awaiting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminApprovalStatus {
    Approved,
    Pending,
    Denied,
}

/// A session's current gate: which target it decided, and what it decided.
///
/// The target is part of the entry because a gate answers a question about one
/// target, and a session is not confined to one. Switching targets asks a new
/// question, so the previous answer is superseded rather than reused — without
/// this, approving a session for one gated target would walk it into every
/// other gated target it can reach.
#[derive(Debug, Clone)]
pub struct SessionGate {
    pub target_name: String,
    pub status: AdminApprovalStatus,
}

/// Per-session gate outcomes for the non-blocking path, owned by [`State`] so a
/// session's entry is dropped when the session ends.
///
/// [`State`]: crate::State
pub type AdminApprovalStatuses = Arc<Mutex<HashMap<SessionId, SessionGate>>>;

/// The session an administrator gate is being asked about.
pub struct AdminApprovalRequest<'a> {
    pub session_id: &'a SessionId,
    pub user_info: &'a AuthStateUserInfo,
    pub protocol: Protocol,
    pub target_name: &'a str,
    pub remote_ip: Option<IpAddr>,
    /// Fingerprints of the credentials that authenticated this session, keying
    /// the remembered-approval bypass. `None` disables remembering for this
    /// session — pass it wherever the authenticating credential has no stable
    /// fingerprint, such as ticket auth.
    pub credentials: Option<Vec<AuthCredentialFingerprint>>,
}

impl Services {
    /// Holds an authenticated connection until an administrator approves it,
    /// when the target requires approval. Returns whether it may proceed.
    ///
    /// Call this at the end of the authentication flow, once the target is
    /// known and before the client is told it is connected. For tickets, call
    /// it *before* consuming the ticket so a denied session doesn't burn a
    /// single-use one.
    ///
    /// The ordering here is the point of the function: a remembered approval
    /// short-circuits before anything is announced, the request is advertised
    /// before the wait begins (so it can never be resolved by an administrator
    /// who cannot see it), and only then does `notify_waiting` tell the client
    /// what is happening. Protocols with no in-band channel for that message
    /// pass a no-op.
    ///
    /// `cancel` ends the wait early when the client goes away. It is a
    /// promptness measure, not a correctness one — session teardown deletes the
    /// row regardless — so protocols that can't cheaply observe a disconnect
    /// may pass `std::future::pending()`.
    pub async fn require_admin_approval<E, F, Fut>(
        &self,
        request: AdminApprovalRequest<'_>,
        cancel: impl Future<Output = ()> + Send,
        notify_waiting: F,
    ) -> Result<bool, E>
    where
        E: From<WarpgateError>,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        if !self.target_requires_approval(request.target_name).await? {
            return Ok(true);
        }

        let session_id = request.session_id;
        let subject = ApprovalSubject {
            kind: ApprovalKind::Admin,
            session_id: *session_id,
            user_info: request.user_info.clone(),
            protocol: request.protocol,
            target_name: request.target_name.to_string(),
            remote_ip: request.remote_ip,
            credentials: request.credentials,
        };

        if self.admin_approval_is_remembered(&subject).await? {
            subject.emit_bypassed_event();
            return Ok(true);
        }

        let _guard =
            PendingApproval::begin(self.db.clone(), self.cluster.node_id, &subject).await?;

        subject.emit_requested_event();
        let _ = self.admin_approval_request_tx.send(*session_id);

        notify_waiting().await?;

        let timeout = self.admin_approval_timeout().await?;
        let (decision, actor) =
            match await_row_decision(&self.db, *session_id, ApprovalKind::Admin, timeout, cancel)
                .await
            {
                RowOutcome::Decided(decision, actor) => (decision, actor),
                RowOutcome::TimedOut => {
                    subject.emit_timed_out_event();
                    return Ok(false);
                }
                RowOutcome::Vanished | RowOutcome::Cancelled => return Ok(false),
            };

        subject.emit_resolved_event(&actor, matches!(decision, ApprovalDecision::Approved(_)));

        match decision {
            ApprovalDecision::Approved(scope) => {
                self.remember_admin_approval(&subject, scope).await;
                Ok(true)
            }
            ApprovalDecision::Rejected => Ok(false),
        }
    }

    /// Non-blocking form of [`Self::require_admin_approval`], for protocols
    /// that answer each request separately and so cannot park on the gate.
    ///
    /// The first call for a session starts the ordinary blocking wait on a
    /// background task; every call reports where that wait has got to. Routing
    /// it through the same wait means the grace bypass, timeout, audit trail
    /// and request-row lifecycle all behave identically to the
    /// connection-holding protocols — the only thing that differs is who does
    /// the waiting.
    ///
    /// The session's entry is dropped when the session ends, so a status is
    /// only ever reused for the connection it was decided for.
    pub async fn poll_admin_approval(
        &self,
        request: AdminApprovalRequest<'_>,
    ) -> Result<AdminApprovalStatus, WarpgateError> {
        let session_id = *request.session_id;
        let statuses = self.admin_approval_statuses().await;

        // Ahead of the target lookup: these protocols poll per request, so on a
        // decided gate this answers every request after the first without
        // touching the database at all.
        if let Some(status) = decided_gate(&statuses, &session_id, request.target_name).await {
            return Ok(status);
        }

        if !self.target_requires_approval(request.target_name).await? {
            return Ok(AdminApprovalStatus::Approved);
        }

        // Claim the slot under the same lock the lookup uses, so concurrent
        // requests for one session start exactly one wait between them. The
        // gate may have been decided while the target lookup was in flight, so
        // the check is repeated rather than assumed still false.
        {
            let mut gates = statuses.lock().await;
            if let Some(gate) = gates.get(&session_id)
                && gate.target_name == request.target_name
            {
                return Ok(gate.status);
            }
            gates.insert(
                session_id,
                SessionGate {
                    target_name: request.target_name.to_string(),
                    status: AdminApprovalStatus::Pending,
                },
            );
        }

        let services = self.clone();
        let user_info = request.user_info.clone();
        let protocol = request.protocol;
        let target_name = request.target_name.to_string();
        let remote_ip = request.remote_ip;
        let credentials = request.credentials;

        tokio::spawn(async move {
            let approved = services
                .require_admin_approval(
                    AdminApprovalRequest {
                        session_id: &session_id,
                        user_info: &user_info,
                        protocol,
                        target_name: &target_name,
                        remote_ip,
                        credentials,
                    },
                    std::future::pending(),
                    || async { Ok::<_, WarpgateError>(()) },
                )
                .await
                .unwrap_or_else(|error| {
                    error!(%error, "Failed to hold the session for administrator approval");
                    false
                });

            // Recorded only if this gate is still the session's current one.
            // A target switch or a session teardown drops the entry, and this
            // answer is about a question no longer being asked — reinstating it
            // would resurrect a decision for a dead session, which nothing ever
            // removes again.
            if let Some(gate) = statuses.lock().await.get_mut(&session_id)
                && gate.target_name == target_name
            {
                gate.status = if approved {
                    AdminApprovalStatus::Approved
                } else {
                    AdminApprovalStatus::Denied
                };
            }
        });

        Ok(AdminApprovalStatus::Pending)
    }

    /// Applies decisions recorded elsewhere to the auth states this node holds.
    ///
    /// A self approval satisfies a credential on an in-memory auth state, so
    /// only the node holding that state can act on the decision — wherever the
    /// user happened to click. Administrator gates need no sweep: each polls its
    /// own row while it holds the connection.
    pub(crate) async fn apply_decided_user_approvals(&self) -> Result<(), WarpgateError> {
        use SessionApprovalRequest::{ApprovalRequestKind, ApprovalRequestStatus, Column};

        let rows = SessionApprovalRequest::Entity::find()
            .filter(Column::Kind.eq(ApprovalRequestKind::User))
            .filter(Column::NodeId.eq(self.cluster.node_id))
            .filter(Column::Status.ne(ApprovalRequestStatus::Pending))
            .all(&self.db)
            .await?;

        for row in rows {
            let Some((decision, actor)) = decision_from_row(&row) else {
                continue;
            };
            match row.auth_state_id {
                Some(auth_state_id) => {
                    self.apply_user_approval(row.session_id, auth_state_id, decision, &actor)
                        .await?;
                }
                // Nothing to satisfy — drop it rather than sweep it forever.
                None => delete_request(&self.db, row.session_id, ApprovalKind::User).await?,
            }
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
        let store = self.auth_state_store.lock().await;
        // A remembered grant matches this exact scope, or one given for all
        // targets, which is strictly broader.
        Ok(store.recent_approval_is_fresh(&key, grace)
            || store.recent_approval_is_fresh(&key.for_all_targets(), grace))
    }

    async fn remember_admin_approval(&self, subject: &ApprovalSubject, scope: ApprovalScope) {
        let key = match scope {
            ApprovalScope::Once => None,
            ApprovalScope::Target => subject.match_key(),
            ApprovalScope::AllTargets => subject.match_key().map(|k| k.for_all_targets()),
        };
        if let Some(key) = key {
            self.auth_state_store.lock().await.record_web_approval(key);
        }
    }

    /// Advertises that an auth state is waiting for the user's own in-browser
    /// approval: creates the request row, idempotently, so a login driven
    /// through several credential submissions ends up with one request.
    ///
    /// The row is keyed by the session id, and so is the auth state it resolves
    /// against — the store hands out states by session id — so `auth_state_id`
    /// and `session_id` are the same value seen from the two sides.
    pub async fn request_approval(
        &self,
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
                auth_state_id: Set(Some(session_id)),
                node_id: Set(self.cluster.node_id),
                protocol: Set(state.protocol().to_string()),
                username: Set(state.user_info().username.clone()),
                target: Set(state.target_name().to_string()),
                remote_address: Set(state.remote_ip().map(|ip| ip.to_string())),
                identification_string: Set(Some(state.identification_string().to_owned())),
                started: Set(*state.started()),
                status: Set(SessionApprovalRequest::ApprovalRequestStatus::Pending),
                scope: Set(None),
                resolved_by_username: Set(None),
                resolved_by_user_id: Set(None),
            }
        };

        upsert_request(&self.db, row).await
    }

    /// Applies a user's own approval to the locally-owned auth state: adds or
    /// withholds the approval credential through the pending gate, records the
    /// grace key, audits, and deletes the row. `Ok(false)` when the state is
    /// gone or no longer pending an approval (resolved concurrently, expired,
    /// or never asked).
    pub async fn apply_user_approval(
        &self,
        session_id: SessionId,
        auth_state_id: Uuid,
        decision: ApprovalDecision,
        actor: &ApprovalActor,
    ) -> Result<bool, WarpgateError> {
        let Some(state_arc) = self.auth_state_store.lock().await.get(&auth_state_id) else {
            // The state is gone (vacuumed or node restarted) — the row is a ghost.
            delete_request(&self.db, session_id, ApprovalKind::User).await?;
            return Ok(false);
        };

        // All the in-memory work under one lock — it's synchronous, and this
        // path runs at most once per session.
        let grace_key = {
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
                // drop it rather than leave it advertising a request nobody can
                // fulfil.
                drop(state);
                delete_request(&self.db, session_id, ApprovalKind::User).await?;
                return Ok(false);
            }

            match decision {
                ApprovalDecision::Approved(scope) => {
                    state.add_web_user_approval();
                    subject.emit_resolved_event(actor, true);
                    match scope {
                        ApprovalScope::Once => None,
                        ApprovalScope::Target => state.web_approval_match_key(),
                        ApprovalScope::AllTargets => {
                            state.web_approval_match_key().map(|k| k.for_all_targets())
                        }
                    }
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
                    None
                }
            }
        };

        if let Some(key) = grace_key {
            self.auth_state_store.lock().await.record_web_approval(key);
        }
        delete_request(&self.db, session_id, ApprovalKind::User).await?;
        Ok(true)
    }
}

/// The gate's decision for `target_name`, if this session has one. `None` when
/// there is no gate, or when the one there decided another target.
async fn decided_gate(
    statuses: &AdminApprovalStatuses,
    session_id: &SessionId,
    target_name: &str,
) -> Option<AdminApprovalStatus> {
    statuses
        .lock()
        .await
        .get(session_id)
        .filter(|gate| gate.target_name == target_name)
        .map(|gate| gate.status)
}

/// Rows are keyed by `(session_id, kind)`, so a wait site that runs twice for
/// the same session updates its own request instead of queueing a duplicate.
/// The decision columns are rewritten too: re-advertising starts a fresh wait,
/// which must not inherit an answer given to the previous one.
async fn upsert_request(
    db: &DatabaseConnection,
    row: SessionApprovalRequest::ActiveModel,
) -> Result<(), WarpgateError> {
    SessionApprovalRequest::Entity::insert(row)
        .on_conflict(
            OnConflict::columns([
                SessionApprovalRequest::Column::SessionId,
                SessionApprovalRequest::Column::Kind,
            ])
            .update_columns([
                SessionApprovalRequest::Column::AuthStateId,
                SessionApprovalRequest::Column::NodeId,
                SessionApprovalRequest::Column::Protocol,
                SessionApprovalRequest::Column::Username,
                SessionApprovalRequest::Column::Target,
                SessionApprovalRequest::Column::RemoteAddress,
                SessionApprovalRequest::Column::IdentificationString,
                SessionApprovalRequest::Column::Started,
                SessionApprovalRequest::Column::Status,
                SessionApprovalRequest::Column::Scope,
                SessionApprovalRequest::Column::ResolvedByUsername,
                SessionApprovalRequest::Column::ResolvedByUserId,
            ])
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

pub(crate) async fn delete_request(
    db: &DatabaseConnection,
    session_id: SessionId,
    kind: ApprovalKind,
) -> Result<(), WarpgateError> {
    SessionApprovalRequest::Entity::delete_by_id((
        session_id,
        SessionApprovalRequest::ApprovalRequestKind::from(kind),
    ))
    .exec(db)
    .await?;
    Ok(())
}

/// Drops every approval request belonging to a session, for when the session
/// itself ends — the waiting connection is gone, so nothing can consume them.
pub(crate) async fn delete_requests_for_session(
    db: &DatabaseConnection,
    session_id: Uuid,
) -> Result<(), WarpgateError> {
    SessionApprovalRequest::Entity::delete_many()
        .filter(SessionApprovalRequest::Column::SessionId.eq(session_id))
        .exec(db)
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

/// Ages out request rows whose waiter is gone without having deleted them
/// (owning node crashed, or a `Drop` cleanup that never got to run).
pub(crate) async fn reap_stale(db: &DatabaseConnection) -> Result<(), WarpgateError> {
    let lifetime = request_lifetime(db).await?;
    #[allow(clippy::cast_possible_wrap)]
    let cutoff = OffsetDateTime::now_utc() - time::Duration::seconds(lifetime.as_secs() as i64);
    SessionApprovalRequest::Entity::delete_many()
        .filter(SessionApprovalRequest::Column::Started.lt(cutoff))
        .exec(db)
        .await?;
    Ok(())
}
