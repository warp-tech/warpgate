//! Out-of-band approval requests (in-browser self approval, administrator JIT
//! approval) as first-class records.
//!
//! A wait site on the owning node creates a `session_approval_requests` row
//! when an approval credential becomes needed; any node can list the rows. The
//! decision travels to the owning node (directly when local, via the internal
//! cluster RPC otherwise) and is applied here: the approval credential is added
//! to the in-memory auth state, the grace key recorded, the resolution audited,
//! the existing completion signal fired, and the row deleted. Rows are also
//! deleted when the waiter gives up, and aged out if the owning node died.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter,
};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::{SessionId, WarpgateError};
use warpgate_common::auth::{
    ApprovalKind, AuthCredential, AuthResult, AuthStateUserInfo, CredentialKind,
    PreauthenticatedPolicy, RequireApprovalPolicy,
};
use warpgate_db_entities::{Parameters, SessionApprovalRequest};

use crate::auth_state::AuthState;
use crate::auth_state_store::TIMEOUT;
use crate::services::Services;

/// How an approval should be remembered for later bypass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

/// Who resolved an approval. Travels with the decision (including across the
/// cluster RPC) so the owning node can attribute the audit entry to them.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApprovalActor {
    pub username: String,
    /// `None` when the resolver isn't a user — e.g. the admin API token.
    pub user_id: Option<Uuid>,
}

impl Services {
    /// Advertises that the auth state is waiting for an approval of `kind`:
    /// creates the request row (idempotent — at most one request per auth
    /// state) and, on actual creation, fires the request signal and audits.
    /// States without a session cannot be routed a decision, so they get no
    /// row; local subscribers are still signalled.
    pub async fn request_approval(
        &self,
        state_arc: &Arc<Mutex<AuthState>>,
        kind: ApprovalKind,
    ) -> Result<(), WarpgateError> {
        let signal = match kind {
            ApprovalKind::User => &self.web_auth_request_tx,
            ApprovalKind::Admin => &self.admin_approval_request_tx,
        };

        // Snapshot under the lock and release it before the insert: `complete()`
        // holds the *store* lock while awaiting this same state lock, so holding
        // it across database IO stalls every login on the node.
        let (id, row) = {
            let state = state_arc.lock().await;
            let id = *state.id();
            let Some(session_id) = state.session_id() else {
                // Without a session there is no node to route a decision to, so
                // no row; local subscribers are still woken.
                let _ = signal.send(id);
                return Ok(());
            };
            (
                id,
                SessionApprovalRequest::ActiveModel {
                    id: Set(id),
                    kind: Set(kind.into()),
                    session_id: Set(*session_id),
                    node_id: Set(self.cluster.node_id),
                    protocol: Set(state.protocol().to_string()),
                    username: Set(state.user_info().username.clone()),
                    target: Set(state.target_name().to_string()),
                    remote_address: Set(state.remote_ip().map(|ip| ip.to_string())),
                    identification_string: Set(state.identification_string().to_owned()),
                    started: Set(*state.started()),
                },
            )
        };

        // Callers re-request freely (SSH re-runs this on every
        // keyboard-interactive round), so only announce when this factor wasn't
        // already the pending one.
        let is_new_request = SessionApprovalRequest::Entity::find_by_id(id)
            .one(&self.db)
            .await?
            .is_none_or(|existing| existing.kind != kind.into());

        // Upsert rather than ignore the conflict: the row is keyed by auth-state
        // id, so a leftover request for the *other* factor (e.g. a user approval
        // that a grace-period bypass satisfied without consuming its row) would
        // otherwise silently survive here — leaving the new request advertised
        // under the wrong kind, invisible to whoever can resolve it.
        SessionApprovalRequest::Entity::insert(row)
            .on_conflict(
                OnConflict::column(SessionApprovalRequest::Column::Id)
                    .update_columns([
                        SessionApprovalRequest::Column::Kind,
                        SessionApprovalRequest::Column::SessionId,
                        SessionApprovalRequest::Column::NodeId,
                        SessionApprovalRequest::Column::Protocol,
                        SessionApprovalRequest::Column::Username,
                        SessionApprovalRequest::Column::Target,
                        SessionApprovalRequest::Column::RemoteAddress,
                        SessionApprovalRequest::Column::IdentificationString,
                        SessionApprovalRequest::Column::Started,
                    ])
                    .to_owned(),
            )
            .exec(&self.db)
            .await?;

        if is_new_request {
            let _ = signal.send(id);
            if kind == ApprovalKind::Admin {
                state_arc
                    .lock()
                    .await
                    .emit_session_approval_requested_event();
            }
        }

        Ok(())
    }

    /// Applies a resolution to the locally-owned auth state: adds/withholds the
    /// approval credential through the pending gate, records the grace key,
    /// audits, wakes waiters via the completion signal, and deletes the row.
    /// `Ok(false)` when the request is gone or the state no longer pends `kind`
    /// (resolved concurrently, expired, or never asked).
    pub async fn apply_approval_resolution(
        &self,
        id: Uuid,
        kind: ApprovalKind,
        decision: ApprovalDecision,
        actor: &ApprovalActor,
    ) -> Result<bool, WarpgateError> {
        let Some(state_arc) = self.auth_state_store.lock().await.get(&id) else {
            // The state is gone (vacuumed or node restarted) — the row is a ghost.
            delete_request(&self.db, id).await?;
            return Ok(false);
        };

        // All the in-memory work under one lock — it's synchronous, and this
        // path runs at most once per session. The lock must be released before
        // the store operations below, since `complete()` takes the store lock
        // and then this same state lock.
        let grace_key = {
            let mut state = state_arc.lock().await;

            // Only resolve a request the state is actually still waiting on
            // (not already accepted, rejected, or resolved by a concurrent
            // decision) — and only for the factor that was clicked.
            let needed = CredentialKind::from(kind);
            if !matches!(state.verify(), AuthResult::Need(ref kinds) if kinds.contains(&needed)) {
                // The caller already matched the row's kind, so a state that no
                // longer wants it means the row is stale (satisfied by a grace
                // bypass, or resolved concurrently) — drop it rather than leave
                // it advertising a request nobody can fulfil.
                drop(state);
                delete_request(&self.db, id).await?;
                return Ok(false);
            }

            match decision {
                ApprovalDecision::Approved(scope) => {
                    state.add_valid_credential(kind.into());
                    state.emit_session_approval_resolved_event(&actor.username, actor.user_id, true);
                    match scope {
                        ApprovalScope::Once => None,
                        ApprovalScope::Target => state.approval_match_key(kind),
                        ApprovalScope::AllTargets => {
                            state.approval_match_key(kind).map(|k| k.for_all_targets())
                        }
                    }
                }
                ApprovalDecision::Rejected => {
                    state.reject();
                    state.emit_session_approval_resolved_event(&actor.username, actor.user_id, false);
                    // A denied login is a failed authentication too — alerting
                    // keys off this event, and a user explicitly denying an
                    // out-of-band request is its highest-value instance.
                    state.emit_authentication_failed_event(
                        Some(&AuthCredential::from(kind)),
                        match kind {
                            ApprovalKind::User => "rejected by user",
                            ApprovalKind::Admin => "rejected by administrator",
                        },
                    );
                    None
                }
            }
        };

        if let Some(key) = grace_key {
            self.auth_state_store.lock().await.record_web_approval(key);
        }
        delete_request(&self.db, id).await?;
        self.auth_state_store.lock().await.complete(&id).await;
        Ok(true)
    }

    /// Holds an already-authenticated connection until an administrator
    /// approves it, when the target requires approval. Returns `true` when it
    /// may proceed.
    ///
    /// For connections whose target isn't known during the credential phase, so
    /// [`RequireApprovalPolicy`] never applied to them: a ticket (which carries
    /// its own authorization) and the SSH target menu (which picks a target
    /// after authenticating). No auth state exists for the approval to attach
    /// to, so one is created here purely to carry it, with the approval as its
    /// only outstanding factor. For tickets, call this *before* consuming the
    /// ticket so a denied session doesn't burn a single-use one.
    pub async fn hold_preauthenticated_for_admin_approval<E, F, Fut>(
        &self,
        session_id: &SessionId,
        user_info: &AuthStateUserInfo,
        protocol: &str,
        target_name: &str,
        remote_ip: Option<IpAddr>,
        notify_waiting: F,
    ) -> Result<bool, E>
    where
        E: From<WarpgateError>,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        if !self.target_requires_approval(target_name).await? {
            return Ok(true);
        }

        let (_, state_arc) = self.auth_state_store.lock().await.create(
            Some(session_id),
            user_info.clone(),
            protocol,
            target_name,
            Box::new(RequireApprovalPolicy {
                inner: Box::new(PreauthenticatedPolicy),
            }),
            remote_ip,
        );

        self.hold_for_admin_approval(&state_arc, notify_waiting).await
    }

    /// Holds the connection until an administrator resolves the session, and
    /// returns whether it may proceed.
    ///
    /// This owns the ordering every protocol needs: a remembered approval short
    /// circuits before anything is announced, the request is advertised before
    /// the wait begins (so it can never be resolved by an admin who cannot see
    /// it), and only then does `notify_waiting` tell the client what is
    /// happening. Protocols with no in-band channel for that message (MySQL)
    /// pass a no-op.
    pub async fn hold_for_admin_approval<E, F, Fut>(
        &self,
        state_arc: &Arc<Mutex<AuthState>>,
        notify_waiting: F,
    ) -> Result<bool, E>
    where
        E: From<WarpgateError>,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        if self.try_admin_approval_bypass(state_arc).await? {
            return Ok(true);
        }
        self.request_approval(state_arc, ApprovalKind::Admin).await?;
        notify_waiting().await?;
        Ok(self.wait_for_session_approval(state_arc).await?)
    }

    /// Blocks until an administrator resolves the pending approval, or the
    /// approval timeout elapses. On timeout the auth state is rejected (which
    /// also purges the request row), completed, and audited. Returns `true`
    /// if approved.
    ///
    /// Prefer [`Services::hold_for_admin_approval`], which sequences the bypass
    /// and the request record around this wait.
    pub async fn wait_for_session_approval(
        &self,
        state_arc: &Arc<Mutex<AuthState>>,
    ) -> Result<bool, WarpgateError> {
        let auth_state_id = *state_arc.lock().await.id();
        let mut event = self.auth_state_store.lock().await.subscribe(auth_state_id);

        // The resolution may have landed between the caller's last check and
        // the subscription above — the completion signal would be lost.
        match state_arc.lock().await.verify() {
            AuthResult::Accepted { .. } => return Ok(true),
            AuthResult::Rejected => return Ok(false),
            AuthResult::Need(kinds) if !kinds.contains(&CredentialKind::AdminApproval) => {
                return Ok(true);
            }
            AuthResult::Need(_) => {}
        }

        let timeout = self.admin_approval_timeout().await?;
        match tokio::time::timeout(timeout, event.recv()).await {
            Ok(Ok(AuthResult::Accepted { .. })) => Ok(true),
            Ok(_) => Ok(false),
            Err(_) => {
                self.expire_session_approval(state_arc).await?;
                Ok(false)
            }
        }
    }

    /// Gives up on a session held for administrator approval: audits the
    /// timeout, rejects the state (which purges its request row) and wakes any
    /// waiter. Used by every wait site that enforces the approval window.
    pub async fn expire_session_approval(
        &self,
        state_arc: &Arc<Mutex<AuthState>>,
    ) -> Result<(), WarpgateError> {
        let id = {
            let state = state_arc.lock().await;
            state.emit_session_approval_timed_out_event();
            *state.id()
        };
        self.reject_auth_state(state_arc).await?;
        self.auth_state_store.lock().await.complete(&id).await;
        Ok(())
    }
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

/// How long auth states, their completion signals and their approval requests
/// are kept alive.
///
/// Vacuuming measures from when the auth state was *created*, but the approval
/// window only starts once the client reaches the approval step — so the two
/// have to be added, not maxed: the credential phase is itself bounded by
/// [`TIMEOUT`], and the approval window runs on top of it. Taking the max
/// instead expires the state (and its request row) mid-wait, by exactly the
/// time the client spent authenticating — the admin's approval then 404s while
/// the client waits out the rest and is rejected.
pub(crate) async fn auth_state_lifetime(
    db: &DatabaseConnection,
) -> Result<Duration, WarpgateError> {
    Ok(*TIMEOUT + admin_approval_timeout(db).await?)
}

pub(crate) async fn delete_request(db: &DatabaseConnection, id: Uuid) -> Result<(), WarpgateError> {
    SessionApprovalRequest::Entity::delete_by_id(id)
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

/// Ages out request rows past the auth-state lifetime — the waiter that would
/// normally delete them is gone (owner crashed, or the state was vacuumed).
pub(crate) async fn reap_stale(
    db: &DatabaseConnection,
    lifetime: Duration,
) -> Result<(), WarpgateError> {
    #[allow(clippy::cast_possible_wrap)]
    let cutoff = OffsetDateTime::now_utc() - time::Duration::seconds(lifetime.as_secs() as i64);
    SessionApprovalRequest::Entity::delete_many()
        .filter(SessionApprovalRequest::Column::Started.lt(cutoff))
        .exec(db)
        .await?;
    Ok(())
}
