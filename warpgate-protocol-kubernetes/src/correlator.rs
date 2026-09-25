use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use poem::Request;
use tokio::sync::Mutex;
use tokio_util::sync::{CancellationToken, DropGuard};
use uuid::Uuid;
use warpgate_common::auth::{AuthResult, AuthStateUserInfo, RememberApprovalBy};
use warpgate_common::{TargetKubernetesOptions, UserSessionId, WarpgateError};
use warpgate_common_http::logging::get_client_ip;
use warpgate_core::approvals::{GatedConnection, admit_target_session};
use warpgate_core::{
    AdmittedTarget, Services, State, TargetAuthorization, UserSessionStateInit,
    WarpgateServerHandle,
};

use crate::server::auth::{KubernetesIdentity, authorize_kubernetes_target, unauthorized};
use crate::session_handle::KubernetesSessionHandle;

#[derive(Clone, PartialEq, Eq, Hash)]
struct CorrelationKey {
    user_id: Uuid,
    target_name: String,
    ip: Option<String>,
    // Ticket sessions must never share admission with another ticket or a
    // normal login by the same user.
    ticket_id: Option<Uuid>,
}

impl CorrelationKey {
    async fn for_request(
        request: &Request,
        identity: &KubernetesIdentity,
        services: &Services,
        target_name: String,
    ) -> Self {
        Self {
            user_id: identity.user_info().id,
            target_name,
            ip: get_client_ip(request, services).await,
            ticket_id: identity.ticket_id(),
        }
    }
}

/// Approval refusale are remembered because otherwise every API request would trigger a new one
/// This is just long enough to cover a burst of API requests from a single kubectl
const REFUSAL_MEMORY: Duration = Duration::from_secs(5);

pub type AdmittedSession = Arc<AdmittedTarget<TargetKubernetesOptions>>;

/// The outcome of the request that opened one correlated session. Requests that
/// join a session in flight wait on the mutex, so a `kubectl` command's fan-out
/// of concurrent requests shares one web approval instead of each raising its
/// own.
#[derive(Clone, Default)]
enum Authorization {
    /// Still resolving — or, once the mutex is free again, abandoned by an
    /// opening request that was dropped mid-approval.
    #[default]
    Pending,
    Authorized(AdmittedSession),
    Denied,
}

type SharedAuthorization = Arc<Mutex<Authorization>>;

/// One correlated Kubernetes session. The `authorization` is resolved once (which
/// is what runs the credential policy / web approval) and reused for every request
/// in the session, so a single approval covers a whole `kubectl` command.
struct SessionEntry {
    handle: Arc<Mutex<WarpgateServerHandle>>,
    created: Instant,
    authorization: SharedAuthorization,
    /// Cancelled when the session's handle is closed (admin close, or a
    /// user's deletion) -- raced against in-flight requests in
    /// `server::handlers`, since a correlated session's fan-out of requests
    /// otherwise only gets re-admitted at its *next* `kubectl` call.
    closed: CancellationToken,
    /// Cancels the evictor task's own `stop` token on drop, so that task ends
    /// instead of leaking when the entry is instead removed some other way (a
    /// denial, a vacuum).
    _stop_evictor: DropGuard,
}

/// Whether a correlator entry is still usable: not aged out, and not
/// cancelled by a session close reaching it first. Shared by `entry` (an
/// on-demand check at lookup) and `vacuum` (the periodic sweep) so both
/// enforce the exact same rule.
fn entry_is_live(created: Instant, closed: &CancellationToken, max_age: Duration) -> bool {
    created.elapsed() < max_age && !closed.is_cancelled()
}

pub struct RequestCorrelator {
    handles: HashMap<CorrelationKey, SessionEntry>,
    // Refused sessions are dropped from `handles` immediately and kept here
    refusals: HashMap<CorrelationKey, Instant>,
    services: Services,
}

/// The correlated session for this request and its authorization, opening the
/// session if this is the first request of a `kubectl` command.
///
/// The session is correlated *before* its authorization is known, so the rest of
/// the command's fan-out joins this attempt and waits for its single web
/// approval. The session is registered up front for the same reason: a cluster
/// peer can then resolve this node as the session's owner (via `user_sessions`
/// table) and route a pending approval back here.
pub async fn correlated_authorization(
    correlator: &Arc<Mutex<RequestCorrelator>>,
    request: &Request,
    identity: KubernetesIdentity,
    target_name: &str,
    services: &Services,
) -> poem::Result<(
    Arc<Mutex<WarpgateServerHandle>>,
    AdmittedSession,
    CancellationToken,
)> {
    let user_info = identity.user_info();
    let key = CorrelationKey::for_request(request, &identity, services, target_name.into()).await;
    let max_age = services
        .config
        .lock()
        .await
        .store
        .kubernetes
        .session_max_age;

    loop {
        if correlator.lock().await.was_refused(&key) {
            return Err(unauthorized());
        }

        // Bound to its own `let` so the correlator lock is released before
        // joining: joining waits for the opening request's approval, which can
        // take minutes, and that request needs the correlator lock to clean up
        // after a denial.
        let existing = correlator.lock().await.entry(&key, max_age);
        if let Some((handle, slot, closed)) = existing
            && let Some(joined) =
                join_session(correlator, &key, handle, slot, closed, services).await?
        {
            return Ok(joined);
        }

        // Registered outside the correlator lock so that concurrent first
        // requests don't serialise on its database insert. A handle that then
        // loses the race below is dropped, deleting the session it just opened.
        let (handle, closed) = register_pending_session(services, request, &user_info).await?;
        let session_id = handle.lock().await.user_session_id();

        let slot = SharedAuthorization::default();
        let claimed = {
            let mut correlator_state = correlator.lock().await;
            if correlator_state.entry(&key, max_age).is_some() {
                None
            } else {
                // Locked before the correlator lock is released, so a request
                // joining this session can't reach the pending slot ahead of us.
                let guard = slot.clone().lock_owned().await;
                // Evicts the entry the moment its session closes (admin close,
                // or a user's deletion), instead of leaving it to the periodic
                // vacuum: the DB row is already ended by then (the admin
                // endpoint revokes it before calling close()), but the
                // correlator's own reference to the entry would otherwise
                // linger and keep handing out the closed session.
                let stop = CancellationToken::new();
                tokio::spawn({
                    let correlator = correlator.clone();
                    let key = key.clone();
                    let slot = slot.clone();
                    let closed = closed.clone();
                    let stop = stop.clone();
                    async move {
                        tokio::select! {
                            () = closed.cancelled() => {
                                correlator.lock().await.evict(&key, &slot);
                            }
                            () = stop.cancelled() => {}
                        }
                    }
                });
                correlator_state.handles.insert(
                    key.clone(),
                    SessionEntry {
                        handle: handle.clone(),
                        created: Instant::now(),
                        authorization: slot.clone(),
                        closed: closed.clone(),
                        _stop_evictor: stop.drop_guard(),
                    },
                );
                Some(guard)
            }
        };
        // Another request opened the session first; join it on the next pass.
        let Some(mut authorization) = claimed else {
            continue;
        };

        // Raced against a close so a request held here -- including a user's
        // WebUserApproval credential-policy prompt, which can block for up to
        // ten minutes -- (and every request joined to it) ends when the
        // session is closed, instead of only the admission step below.
        // Cancellation falls into the `Err` arm below the same way a real
        // denial would, which is what settles the attempt and drops its
        // pending auth state.
        let resolved = tokio::select! {
            biased;
            () = closed.cancelled() => Err(unauthorized()),
            resolved = async move {
                match identity {
                    KubernetesIdentity::User(user) => {
                        authorize_kubernetes_target(request, &user, target_name, session_id, services).await
                    }
                    KubernetesIdentity::Ticket(ticket) => ticket
                        .spend(&services.db)
                        .await
                        .map_err(poem::Error::from)
                        .and_then(|authorization| authorization.ok_or_else(unauthorized))
                        .and_then(|authorization| authorization.narrow().map_err(Into::into)),
                }
            } => resolved,
        };
        return match resolved {
            Ok(resolved) => {
                // Raced against a close so a request held for admin approval
                // (and every request joined to it) ends when the session is
                // closed; dropping the admission withdraws its approval request.
                let admission = tokio::select! {
                    biased;
                    () = closed.cancelled() => Err(WarpgateError::UserSessionEnded),
                    admission = admit_kubernetes_session(request, services, &handle, resolved) => admission,
                };
                let admitted = match admission {
                    Ok(admitted) => Arc::new(admitted),
                    Err(error) => {
                        *authorization = Authorization::Denied;
                        {
                            let mut correlator = correlator.lock().await;
                            correlator.evict(&key, &slot);
                            if matches!(error, WarpgateError::SessionNotApproved) {
                                correlator.refusals.insert(key.clone(), Instant::now());
                            }
                        }
                        settle_failed_attempt(services, &handle, session_id).await;
                        return Err(match error {
                            WarpgateError::UserSessionEnded => unauthorized(),
                            error => error.into(),
                        });
                    }
                };
                handle.lock().await.confirm();
                *authorization = Authorization::Authorized(admitted.clone());
                Ok((handle, admitted, closed))
            }
            Err(error) => {
                // A denied attempt is not cached: the requests waiting on this
                // one fail with it, and the entry goes so that the next request
                // can prompt again. A close that cancelled the wait above lands
                // here too, so every joined request gets `unauthorized()` instead
                // of waiting out the rest of the ten-minute approval timeout. The
                // credential-policy prompt's own pending-approval row isn't
                // necessarily gone yet -- it's inserted by a separate task that
                // can still be mid-flight -- but it no longer blocks anything here.
                *authorization = Authorization::Denied;
                correlator.lock().await.evict(&key, &slot);
                settle_failed_attempt(services, &handle, session_id).await;
                Err(error)
            }
        };
    }
}

/// Start the target session, waiting for approval if needed
async fn admit_kubernetes_session(
    request: &Request,
    services: &Services,
    handle: &Arc<Mutex<WarpgateServerHandle>>,
    resolved: TargetAuthorization<TargetKubernetesOptions>,
) -> Result<AdmittedTarget<TargetKubernetesOptions>, WarpgateError> {
    admit_target_session(
        services,
        handle,
        resolved,
        GatedConnection {
            remote_ip: get_client_ip(request, services)
                .await
                .and_then(|ip| ip.parse().ok()),
            // k8s has no AuthState
            credentials: RememberApprovalBy::Nothing,
        },
        || async { Ok(()) },
    )
    .await
}

/// Waits for the request that opened this session to resolve its authorization.
///
/// `None` means there is nothing to join and the caller should open a session of
/// its own: the opening request was dropped mid-approval — a cancelled `kubectl`
/// — so its entry is evicted here rather than left to fail every later request
/// until the vacuum, and its auth state is dropped so the dead attempt is no
/// longer reachable by session id. This is best-effort, not a guarantee: the
/// credential-policy prompt's pending-approval row is written by a separate task
/// (see `AuthStateStore::open` in `warpgate-core`) that can still be mid-flight
/// when the state is dropped here, in which case the row lands afterward and
/// stays visible and approvable until `reap_stale` clears it out. This is a
/// pre-existing race, not something this change introduces or fixes.
async fn join_session(
    correlator: &Arc<Mutex<RequestCorrelator>>,
    key: &CorrelationKey,
    handle: Arc<Mutex<WarpgateServerHandle>>,
    slot: SharedAuthorization,
    closed: CancellationToken,
    services: &Services,
) -> poem::Result<
    Option<(
        Arc<Mutex<WarpgateServerHandle>>,
        AdmittedSession,
        CancellationToken,
    )>,
> {
    // Cloned out so the slot lock is not held while taking the correlator lock.
    let outcome = slot.lock().await.clone();
    match outcome {
        Authorization::Authorized(admitted) => Ok(Some((handle, admitted, closed))),
        Authorization::Denied => Err(unauthorized()),
        Authorization::Pending => {
            correlator.lock().await.evict(key, &slot);
            let session_id = handle.lock().await.user_session_id();
            services.auth_state_store.lock().await.remove(&session_id);
            Ok(None)
        }
    }
}

/// Settles the session of an attempt that failed.
///
/// A terminal auth outcome — a rejection, or an approval whose target lookup
/// then failed — is recorded in the audit log against the session, so that
/// session has to outlive the attempt and is confirmed. An approval that merely
/// timed out leaves no trace to keep: the session stays provisional and is
/// discarded along with the handle. Either way nothing will come back to the
/// attempt, so its auth state is dropped here rather than left reachable by
/// session id. As noted on [`join_session`], this can't guarantee the
/// credential-policy prompt's pending-approval row is gone too, since that row
/// is written by a separate, possibly still in-flight task; a pre-existing race,
/// unrelated to this change.
async fn settle_failed_attempt(
    services: &Services,
    handle: &Arc<Mutex<WarpgateServerHandle>>,
    session_id: UserSessionId,
) {
    let state = {
        let mut store = services.auth_state_store.lock().await;
        let state = store.get(&session_id);
        store.remove(&session_id);
        state
    };
    if let Some(state) = state
        && matches!(
            state.lock().await.verify(),
            AuthResult::Rejected | AuthResult::Accepted { .. }
        )
    {
        handle.lock().await.confirm();
    }
}

/// Opens a session for an attempt whose authorization is still pending. It stays
/// provisional until [`correlated_authorization`] confirms it, so an attempt
/// that never became a session — one denied, or one that lost the correlation
/// race — leaves nothing behind.
async fn register_pending_session(
    services: &Services,
    request: &Request,
    user_info: &AuthStateUserInfo,
) -> Result<(Arc<Mutex<WarpgateServerHandle>>, CancellationToken), WarpgateError> {
    let ip = get_client_ip(request, services).await;
    let (session_handle, closed) = KubernetesSessionHandle::new();
    let handle = State::register_node_local_user_session(
        &services.state,
        crate::PROTOCOL_NAME,
        UserSessionStateInit {
            remote_address: ip.and_then(|x| x.parse().ok()),
            handle: Box::new(session_handle),
        },
    )
    .await?;
    {
        let mut handle = handle.lock().await;
        handle.mark_provisional();
        // The transport credential is already authenticated, so a session
        // waiting for approval is attributable while it waits.
        handle.set_user_info(user_info.clone()).await?;
    }
    Ok((handle, closed))
}

impl RequestCorrelator {
    pub fn new(services: &Services) -> Arc<Mutex<Self>> {
        let this = Arc::new(Mutex::new(Self {
            handles: HashMap::new(),
            refusals: HashMap::new(),
            services: services.clone(),
        }));
        Self::spawn_vacuum_task(this.clone());
        this
    }

    /// The correlated session for this key, if one is already open — its
    /// authorization may still be resolving.
    fn entry(
        &self,
        key: &CorrelationKey,
        max_age: Duration,
    ) -> Option<(
        Arc<Mutex<WarpgateServerHandle>>,
        SharedAuthorization,
        CancellationToken,
    )> {
        self.handles
            .get(key)
            // Enforce the bound at lookup, not just on the periodic vacuum.
            .filter(|entry| entry_is_live(entry.created, &entry.closed, max_age))
            .map(|entry| {
                (
                    entry.handle.clone(),
                    entry.authorization.clone(),
                    entry.closed.clone(),
                )
            })
    }

    fn was_refused(&self, key: &CorrelationKey) -> bool {
        self.refusals
            .get(key)
            .is_some_and(|at| at.elapsed() < REFUSAL_MEMORY)
    }

    fn evict(&mut self, key: &CorrelationKey, slot: &SharedAuthorization) {
        if self
            .handles
            .get(key)
            .is_some_and(|entry| Arc::ptr_eq(&entry.authorization, slot))
        {
            self.handles.remove(key);
        }
    }

    /// Remove handles older than session_max_age
    pub async fn vacuum(&mut self) {
        let max_age = self
            .services
            .config
            .lock()
            .await
            .store
            .kubernetes
            .session_max_age;
        let now = Instant::now();
        self.handles
            .retain(|_, entry| entry_is_live(entry.created, &entry.closed, max_age));
        self.refusals
            .retain(|_, at| now.duration_since(*at) < REFUSAL_MEMORY);
    }

    /// Spawns a background task to periodically call vacuum
    fn spawn_vacuum_task(this: Arc<Mutex<Self>>) {
        let interval = Duration::from_secs(60);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let mut guard = this.lock().await;
                guard.vacuum().await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `entry` and `vacuum` are exercised through `entry_is_live` rather than a
    // full `RequestCorrelator`: a real entry needs a `WarpgateServerHandle`,
    // which drags in a database and the rest of `State`.

    #[test]
    fn a_cancelled_entry_is_not_live() {
        let closed = CancellationToken::new();
        assert!(entry_is_live(
            Instant::now(),
            &closed,
            Duration::from_secs(60)
        ));
        closed.cancel();
        assert!(!entry_is_live(
            Instant::now(),
            &closed,
            Duration::from_secs(60)
        ));
    }

    #[test]
    fn an_aged_out_entry_is_not_live() {
        let closed = CancellationToken::new();
        let created = Instant::now() - Duration::from_secs(120);
        assert!(!entry_is_live(created, &closed, Duration::from_secs(60)));
    }
}
