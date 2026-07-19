//! Out-of-band approval requests: in-browser self approval, and administrator
//! just-in-time approval of a session.
//!
//! The two are deliberately different mechanisms. Self approval is a
//! *credential* — it satisfies a pending [`CredentialKind::WebUserApproval`] on
//! an in-memory auth state, so its request row carries the auth state it
//! resolves against. Administrator approval is a *gate on the connection*,
//! decided once the target is known and after the credentials are settled; it
//! touches no auth state at all, and its waiter is a plain oneshot channel held
//! in [`Services::pending_admin_approvals`].
//!
//! What they share is the record: a `session_approval_requests` row keyed by
//! `(session_id, kind)` that advertises the request cluster-wide and names the
//! node to deliver the decision to. Any node can list the rows; the decision
//! travels to the owning node (directly when local, via the internal cluster
//! RPC otherwise). Rows are deleted when the request is resolved, when the
//! waiter gives up, when the session ends, and are aged out if the owner died.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::OnConflict;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use time::OffsetDateTime;
use tokio::sync::{Mutex, oneshot};
use tracing::info;
use uuid::Uuid;
use warpgate_common::auth::{
    ApprovalKind, AuthCredential, AuthResult, AuthStateUserInfo, CredentialKind,
};
use warpgate_common::helpers::logging::format_related_ids;
use warpgate_common::{SessionId, WarpgateError};
use warpgate_db_entities::{Parameters, SessionApprovalRequest};

use crate::auth_state::{ApprovalMatchKey, AuthState, generate_identification_string};
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

/// The session an approval is about, and the single source for its request row,
/// audit events and grace key.
///
/// The administrator gate owns one directly — that is the point of the gate, no
/// auth state need exist. The self-approval path builds one from its auth state
/// via [`ApprovalSubject::from_auth_state`], so both kinds audit through the
/// same code.
#[derive(Debug, Clone)]
struct ApprovalSubject {
    session_id: SessionId,
    user_info: AuthStateUserInfo,
    protocol: String,
    target_name: String,
    remote_ip: Option<IpAddr>,
    /// Short code shown to both parties so the administrator can confirm they
    /// are approving the session the user is actually looking at.
    identification_string: String,
}

impl ApprovalSubject {
    /// `None` for a state with no session — nothing to attribute the events to.
    fn from_auth_state(state: &AuthState) -> Option<Self> {
        Some(Self {
            session_id: *state.session_id()?,
            user_info: state.user_info().clone(),
            protocol: state.protocol().to_string(),
            target_name: state.target_name().to_string(),
            remote_ip: state.remote_ip(),
            identification_string: state.identification_string().to_owned(),
        })
    }

    fn client_ip_for_logging(&self) -> String {
        self.remote_ip
            .map_or_else(|| "<unknown>".to_string(), |ip| ip.to_string())
    }

    /// The key this session's approval is remembered under. `None` without a
    /// remote IP — an approval that can't be pinned to an origin isn't safe to
    /// replay.
    fn match_key(&self) -> Option<ApprovalMatchKey> {
        Some(ApprovalMatchKey {
            approval_kind: ApprovalKind::Admin,
            remote_ip: self.remote_ip?,
            protocol: self.protocol.clone(),
            username: self.user_info.username.to_lowercase(),
            target_name: Some(self.target_name.clone()),
            other_credentials: vec![],
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

/// The waiter's registry entry and its row, removed together when the wait ends
/// however it ends — resolved, timed out, cancelled, or the future dropped.
struct PendingApproval {
    session_id: SessionId,
    registry: Arc<Mutex<HashMap<SessionId, oneshot::Sender<(ApprovalDecision, ApprovalActor)>>>>,
    db: DatabaseConnection,
}

impl Drop for PendingApproval {
    fn drop(&mut self) {
        // Drop can't await. `reap_stale` and the session-teardown sweep both
        // cover a row this spawn never gets to delete.
        let session_id = self.session_id;
        let registry = self.registry.clone();
        let db = self.db.clone();
        tokio::spawn(async move {
            registry.lock().await.remove(&session_id);
            let _ = delete_request(&db, session_id, ApprovalKind::Admin).await;
        });
    }
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
    /// what is happening — it receives the session's identification string, the
    /// code the administrator sees alongside the request. Protocols with no
    /// in-band channel for that message (MySQL) pass a no-op.
    ///
    /// `cancel` ends the wait early when the client goes away. It is a
    /// promptness measure, not a correctness one — session teardown deletes the
    /// row regardless — so protocols that can't cheaply observe a disconnect
    /// may pass `std::future::pending()`.
    #[allow(clippy::too_many_arguments)]
    pub async fn require_admin_approval<E, F, Fut>(
        &self,
        session_id: &SessionId,
        user_info: &AuthStateUserInfo,
        protocol: &str,
        target_name: &str,
        remote_ip: Option<IpAddr>,
        cancel: impl Future<Output = ()> + Send,
        notify_waiting: F,
    ) -> Result<bool, E>
    where
        E: From<WarpgateError>,
        F: FnOnce(&str) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        if !self.target_requires_approval(target_name).await? {
            return Ok(true);
        }

        let subject = ApprovalSubject {
            session_id: *session_id,
            user_info: user_info.clone(),
            protocol: protocol.to_string(),
            target_name: target_name.to_string(),
            remote_ip,
            identification_string: generate_identification_string(),
        };

        if self.admin_approval_is_remembered(&subject).await? {
            subject.emit_bypassed_event();
            return Ok(true);
        }

        let (tx, rx) = oneshot::channel();
        // Registered before the row exists, so a decision can never arrive for
        // a request with nowhere to deliver it.
        self.pending_admin_approvals
            .lock()
            .await
            .insert(*session_id, tx);
        let _guard = PendingApproval {
            session_id: *session_id,
            registry: self.pending_admin_approvals.clone(),
            db: self.db.clone(),
        };

        self.advertise_admin_approval(&subject).await?;
        subject.emit_requested_event();
        let _ = self.admin_approval_request_tx.send(*session_id);

        notify_waiting(&subject.identification_string).await?;

        let timeout = self.admin_approval_timeout().await?;
        let decision = tokio::select! {
            received = rx => received.ok(),
            () = cancel => return Ok(false),
            () = tokio::time::sleep(timeout) => {
                subject.emit_timed_out_event();
                return Ok(false);
            }
        };

        // The sender was dropped without a decision — treat as not approved.
        let Some((decision, actor)) = decision else {
            return Ok(false);
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

    /// Delivers a decision to a session waiting on this node. `Ok(false)` when
    /// nobody is waiting — the connection dropped, timed out, or was resolved
    /// by a concurrent decision.
    pub async fn deliver_admin_approval(
        &self,
        session_id: SessionId,
        decision: ApprovalDecision,
        actor: &ApprovalActor,
    ) -> Result<bool, WarpgateError> {
        let Some(tx) = self
            .pending_admin_approvals
            .lock()
            .await
            .remove(&session_id)
        else {
            // A row with no waiter is a ghost (owner restarted, or the waiter
            // gave up before the decision landed).
            delete_request(&self.db, session_id, ApprovalKind::Admin).await?;
            return Ok(false);
        };
        Ok(tx.send((decision, actor.clone())).is_ok())
    }

    async fn advertise_admin_approval(
        &self,
        subject: &ApprovalSubject,
    ) -> Result<(), WarpgateError> {
        upsert_request(
            &self.db,
            SessionApprovalRequest::ActiveModel {
                session_id: Set(subject.session_id),
                kind: Set(ApprovalKind::Admin.into()),
                auth_state_id: Set(None),
                node_id: Set(self.cluster.node_id),
                protocol: Set(subject.protocol.clone()),
                username: Set(subject.user_info.username.clone()),
                target: Set(subject.target_name.clone()),
                remote_address: Set(subject.remote_ip.map(|ip| ip.to_string())),
                identification_string: Set(subject.identification_string.clone()),
                started: Set(OffsetDateTime::now_utc()),
            },
        )
        .await
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
        Ok(self
            .auth_state_store
            .lock()
            .await
            .matching_approval_is_fresh(&key, grace))
    }

    async fn remember_admin_approval(&self, subject: &ApprovalSubject, scope: ApprovalScope) {
        let key = match scope {
            ApprovalScope::Once => None,
            ApprovalScope::Target => subject.match_key(),
            ApprovalScope::AllTargets => subject.match_key().map(|k| k.for_all_targets()),
        };
        if let Some(key) = key {
            self.auth_state_store.lock().await.record_approval(key);
        }
    }

    /// Advertises that an auth state is waiting for the user's own in-browser
    /// approval: creates the request row (idempotent — one per session) and, on
    /// actual creation, fires the request signal. States without a session
    /// cannot be routed a decision, so they get no row; local subscribers are
    /// still signalled.
    pub async fn request_approval(
        &self,
        state_arc: &Arc<Mutex<AuthState>>,
    ) -> Result<(), WarpgateError> {
        // Snapshot under the lock and release it before the insert: `complete()`
        // holds the *store* lock while awaiting this same state lock, so holding
        // it across database IO stalls every login on the node.
        let (id, row) = {
            let state = state_arc.lock().await;
            let id = *state.id();
            let Some(session_id) = state.session_id() else {
                // Without a session there is no node to route a decision to, so
                // no row; local subscribers are still woken.
                let _ = self.web_auth_request_tx.send(id);
                return Ok(());
            };
            (
                id,
                SessionApprovalRequest::ActiveModel {
                    session_id: Set(*session_id),
                    kind: Set(ApprovalKind::User.into()),
                    auth_state_id: Set(Some(id)),
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

        upsert_request(&self.db, row).await?;
        let _ = self.web_auth_request_tx.send(id);
        Ok(())
    }

    /// Applies a user's own approval to the locally-owned auth state: adds or
    /// withholds the approval credential through the pending gate, records the
    /// grace key, audits, wakes waiters via the completion signal, and deletes
    /// the row. `Ok(false)` when the state is gone or no longer pending an
    /// approval (resolved concurrently, expired, or never asked).
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
        // path runs at most once per session. The lock must be released before
        // the store operations below, since `complete()` takes the store lock
        // and then this same state lock.
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
                    state.add_valid_credential(AuthCredential::WebUserApproval);
                    if let Some(subject) = &subject {
                        subject.emit_resolved_event(actor, true);
                    }
                    match scope {
                        ApprovalScope::Once => None,
                        ApprovalScope::Target => state.approval_match_key(),
                        ApprovalScope::AllTargets => {
                            state.approval_match_key().map(|k| k.for_all_targets())
                        }
                    }
                }
                ApprovalDecision::Rejected => {
                    state.reject();
                    if let Some(subject) = &subject {
                        subject.emit_resolved_event(actor, false);
                    }
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
            self.auth_state_store.lock().await.record_approval(key);
        }
        delete_request(&self.db, session_id, ApprovalKind::User).await?;
        self.auth_state_store
            .lock()
            .await
            .complete(&auth_state_id)
            .await;
        Ok(true)
    }
}

/// Rows are keyed by `(session_id, kind)`, so a wait site that runs twice for
/// the same session updates its own request instead of queueing a duplicate.
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

/// Ages out request rows whose waiter is gone without having deleted them
/// (owning node crashed, or a `Drop` cleanup that never got to run).
///
/// Keyed to the administrator-approval window rather than the auth-state
/// [`TIMEOUT`]: a request legitimately outlives the auth state that may have
/// preceded it, and reaping at the shorter interval would delete live requests
/// out from under sessions still waiting on them.
pub(crate) async fn reap_stale(db: &DatabaseConnection) -> Result<(), WarpgateError> {
    let lifetime = admin_approval_timeout(db).await?.max(*TIMEOUT);
    #[allow(clippy::cast_possible_wrap)]
    let cutoff = OffsetDateTime::now_utc() - time::Duration::seconds(lifetime.as_secs() as i64);
    SessionApprovalRequest::Entity::delete_many()
        .filter(SessionApprovalRequest::Column::Started.lt(cutoff))
        .exec(db)
        .await?;
    Ok(())
}
