use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use poem::Request;
use time::OffsetDateTime;
use tokio::sync::{Mutex, OwnedMutexGuard};
use tokio_util::sync::CancellationToken;
use tracing::warn;
use uuid::Uuid;
use warpgate_common::auth::{AuthResult, AuthStateUserInfo, RememberApprovalBy};
use warpgate_common::{
    Target, TargetKubernetesOptions, TargetSessionId, UserSessionId, WarpgateError,
};
use warpgate_common_http::logging::get_client_ip;
use warpgate_core::approvals::{Admission, GatedConnection, admit_target_session};
use warpgate_core::{
    AdmittedTarget, AuthStateStore, Services, State, TargetAuthorization, TargetSessionStart,
    UserSessionStateInit, WarpgateServerHandle,
};
use warpgate_db_entities::KubernetesSession::{self, Claim};

use crate::server::auth::{
    KubernetesIdentity, authorize_kubernetes_join, authorize_kubernetes_target,
    resolve_kubernetes_target, unauthorized,
};
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

    /// Needs the resolved target id, so it is only built on a local cache miss.
    fn db_key(&self, target: &Target) -> String {
        KubernetesSession::key(self.user_id, target.id, self.ip.as_deref(), self.ticket_id)
    }
}

/// Approval refusals are remembered because otherwise every API request would trigger a new one
/// This is just long enough to cover a burst of API requests from a single kubectl
const REFUSAL_MEMORY: Duration = Duration::from_secs(5);

/// Each retry follows progress by another request, so a few suffice.
const MAX_PASSES: usize = 5;

/// Backoff while another node's admission is pending. Starts short because most
/// admissions need no approval.
const CLAIM_POLL_INITIAL: Duration = Duration::from_millis(50);
const CLAIM_POLL_MAX: Duration = Duration::from_secs(1);

pub type AdmittedSession = Arc<AdmittedTarget<TargetKubernetesOptions>>;

type CorrelatedSession = (
    Arc<Mutex<WarpgateServerHandle>>,
    AdmittedSession,
    CancellationToken,
);

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

/// The `authorization` is resolved once and reused for every request, so one
/// approval covers a whole `kubectl` command.
///
/// `handle` owns the session if this node opened it, otherwise it is a
/// detached view.
struct SessionEntry {
    handle: Arc<Mutex<WarpgateServerHandle>>,
    /// Taken from the claim row, so all nodes expire the session together.
    created: OffsetDateTime,
    authorization: SharedAuthorization,
    /// Stops in-flight requests and prevents new requests from joining the session.
    closed: CancellationToken,
}

/// Closed or expired entries are rejected on lookup and removed by the vacuum.
fn entry_is_live(created: OffsetDateTime, closed: &CancellationToken, max_age: Duration) -> bool {
    OffsetDateTime::now_utc() - created < max_age && !closed.is_cancelled()
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
/// The session is claimed in `kubernetes_sessions`, so requests landing on
/// other nodes join it instead of opening their own. The local map caches the
/// claim, so only a node's first request per session queries the table.
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
) -> poem::Result<CorrelatedSession> {
    let user_info = identity.user_info();
    let key = CorrelationKey::for_request(request, &identity, services, target_name.into()).await;
    let max_age = session_max_age(services).await;

    if let Some(joined) = local_session(correlator, &key, max_age, services).await? {
        return Ok(joined);
    }

    let target = match &identity {
        KubernetesIdentity::Ticket(ticket) => ticket.target().clone(),
        KubernetesIdentity::User(_) => resolve_kubernetes_target(services, target_name).await?,
    };
    let db_key = key.db_key(&target);

    for _ in 0..MAX_PASSES {
        if let Some(joined) = local_session(correlator, &key, max_age, services).await? {
            return Ok(joined);
        }

        let replacing = match ClaimState::load(services, &db_key, user_info.id, max_age).await? {
            ClaimState::Absent => None,
            ClaimState::Stale { claimant } | ClaimState::Ended { claimant } => Some(claimant),
            ClaimState::Pending { claimant } => {
                wait_for_claim(services, &db_key, claimant, user_info.id, max_age).await?;
                continue;
            }
            ClaimState::Admitted {
                claimant,
                target_session_id,
                created,
            } => {
                let Some(local) = adopt_locally(
                    correlator, &key, request, services, claimant, created, max_age,
                )
                .await
                else {
                    continue;
                };
                return join_admitted(
                    correlator,
                    &key,
                    services,
                    identity,
                    target,
                    target_session_id,
                    local,
                )
                .await;
            }
        };

        // Registered outside the correlator lock so that concurrent first
        // requests don't serialise on its database insert. A handle that then
        // loses the race below is dropped, deleting the session it just opened.
        let (handle, closed) = register_pending_session(services, request, &user_info).await?;
        let session_id = handle.lock().await.user_session_id();
        let created = OffsetDateTime::now_utc();

        let Some(local) = claim_locally(correlator, &key, handle, closed, created, max_age).await
        else {
            // Lost to a concurrent local request; join it on the next pass.
            continue;
        };
        let mut abandoned = AbandonGuard::new(correlator, &key, &local.slot, session_id, services);

        let claim =
            KubernetesSession::claim(&services.db, &db_key, session_id, created, replacing).await;
        if !matches!(claim, Ok(Claim::Won)) {
            // Local waiters see the slot abandoned and retry.
            correlator.lock().await.evict(&key, &local.slot);
            abandoned.disarm();
            if let Err(error) = claim {
                return Err(error.into());
            }
            // Lost to another node; join it on the next pass.
            continue;
        }

        let result = open_session(
            correlator, &key, request, services, identity, target, &db_key, local,
        )
        .await;
        abandoned.disarm();
        return result;
    }

    warn!(user_id = %user_info.id, %target_name, "Kubernetes session correlation did not settle");
    Err(poem::Error::from_status(
        poem::http::StatusCode::SERVICE_UNAVAILABLE,
    ))
}

/// `Ok(None)` if nothing usable is cached for `key`.
async fn local_session(
    correlator: &Arc<Mutex<RequestCorrelator>>,
    key: &CorrelationKey,
    max_age: Duration,
    services: &Services,
) -> poem::Result<Option<CorrelatedSession>> {
    // Bound to its own `let` so the correlator lock is released before
    // joining: joining waits for the opening request's approval, which can
    // take minutes, and that request needs the correlator lock to clean up
    // after a denial.
    let existing = {
        let correlator = correlator.lock().await;
        if correlator.was_refused(key) {
            return Err(unauthorized());
        }
        correlator.entry(key, max_age)
    };
    match existing {
        Some((handle, slot, closed)) => {
            join_session(
                correlator,
                key,
                handle,
                slot,
                closed,
                &services.auth_state_store,
            )
            .await
        }
        None => Ok(None),
    }
}

enum ClaimState {
    Absent,
    Pending {
        claimant: UserSessionId,
    },
    Admitted {
        claimant: UserSessionId,
        target_session_id: TargetSessionId,
        created: OffsetDateTime,
    },
    /// Refused, or closed after admission.
    Ended {
        claimant: UserSessionId,
    },
    /// Aged out, abandoned before admission, or not this user's session.
    Stale {
        claimant: UserSessionId,
    },
}

impl ClaimState {
    async fn load(
        services: &Services,
        db_key: &str,
        user_id: Uuid,
        max_age: Duration,
    ) -> Result<Self, WarpgateError> {
        let Some((row, parent)) = KubernetesSession::find_with_parent(&services.db, db_key).await?
        else {
            return Ok(Self::Absent);
        };
        let claimant = row.user_session_id;
        let Some(parent) = parent.filter(|parent| {
            parent.protocol == crate::PROTOCOL_NAME.name() && parent.user_id == Some(user_id)
        }) else {
            return Ok(Self::Stale { claimant });
        };
        if parent.ended.is_some() {
            return Ok(Self::Ended { claimant });
        }
        if OffsetDateTime::now_utc() - row.created >= max_age {
            return Ok(Self::Stale { claimant });
        }
        Ok(match row.target_session_id {
            Some(target_session_id) => Self::Admitted {
                claimant,
                target_session_id,
                created: row.created,
            },
            None => Self::Pending { claimant },
        })
    }
}

/// Waits until `claimant`'s pending claim changes. `Ok` means look again.
async fn wait_for_claim(
    services: &Services,
    db_key: &str,
    claimant: UserSessionId,
    user_id: Uuid,
    max_age: Duration,
) -> poem::Result<()> {
    let mut delay = CLAIM_POLL_INITIAL;
    loop {
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(CLAIM_POLL_MAX);
        match ClaimState::load(services, db_key, user_id, max_age).await? {
            ClaimState::Pending { claimant: current } if current == claimant => {}
            ClaimState::Ended { claimant: current } if current == claimant => {
                return Err(unauthorized());
            }
            _ => return Ok(()),
        }
    }
}

/// Other local requests for the key wait on `authorization` until it is set.
struct LocalClaim {
    handle: Arc<Mutex<WarpgateServerHandle>>,
    closed: CancellationToken,
    slot: SharedAuthorization,
    authorization: OwnedMutexGuard<Authorization>,
}

/// `None` if a live entry already exists.
async fn claim_locally(
    correlator: &Arc<Mutex<RequestCorrelator>>,
    key: &CorrelationKey,
    handle: Arc<Mutex<WarpgateServerHandle>>,
    closed: CancellationToken,
    created: OffsetDateTime,
    max_age: Duration,
) -> Option<LocalClaim> {
    let mut correlator = correlator.lock().await;
    if correlator.entry(key, max_age).is_some() {
        return None;
    }
    Some(correlator.insert_claim(key, handle, closed, created).await)
}

/// The view is created under the correlator lock: with two views of one
/// session on a node, a close would reach only the last one.
async fn adopt_locally(
    correlator: &Arc<Mutex<RequestCorrelator>>,
    key: &CorrelationKey,
    request: &Request,
    services: &Services,
    claimant: UserSessionId,
    created: OffsetDateTime,
    max_age: Duration,
) -> Option<LocalClaim> {
    let (init, closed) = session_init(request, services).await;
    let mut correlator = correlator.lock().await;
    if correlator.entry(key, max_age).is_some() {
        return None;
    }
    let handle =
        State::adopt_user_session(&services.state, claimant, crate::PROTOCOL_NAME, init).await;
    Some(correlator.insert_claim(key, handle, closed, created).await)
}

/// Re-mints the authorization locally and reuses the opener's target session,
/// so joining raises no approval and spends no ticket use.
async fn join_admitted(
    correlator: &Arc<Mutex<RequestCorrelator>>,
    key: &CorrelationKey,
    services: &Services,
    identity: KubernetesIdentity,
    target: Target,
    target_session_id: TargetSessionId,
    local: LocalClaim,
) -> poem::Result<CorrelatedSession> {
    let LocalClaim {
        handle,
        closed,
        slot,
        mut authorization,
    } = local;

    let joined = async {
        let resolved = match identity {
            KubernetesIdentity::User(user) => {
                authorize_kubernetes_join(&user, target, services).await?
            }
            KubernetesIdentity::Ticket(ticket) => ticket.join().narrow()?,
        };
        let started = handle.lock().await.start_target_session(resolved).await;
        match started {
            Ok(TargetSessionStart::Started(admitted)) if admitted.id() == target_session_id => {
                Ok(Arc::new(admitted))
            }
            Err(WarpgateError::UserSessionEnded) => Err(unauthorized()),
            Err(error) => Err(error.into()),
            Ok(_) => {
                warn!(%target_session_id, "Joined Kubernetes session has no open target session");
                Err(unauthorized())
            }
        }
    }
    .await;

    match joined {
        Ok(admitted) => {
            *authorization = Authorization::Authorized(admitted.clone());
            Ok((handle, admitted, closed))
        }
        Err(error) => {
            *authorization = Authorization::Denied;
            correlator.lock().await.evict(key, &slot);
            Err(error)
        }
    }
}

/// Records the admission in the claim so other nodes can join.
#[allow(clippy::too_many_arguments)]
async fn open_session(
    correlator: &Arc<Mutex<RequestCorrelator>>,
    key: &CorrelationKey,
    request: &Request,
    services: &Services,
    identity: KubernetesIdentity,
    target: Target,
    db_key: &str,
    local: LocalClaim,
) -> poem::Result<CorrelatedSession> {
    let LocalClaim {
        handle,
        closed,
        slot,
        mut authorization,
    } = local;
    let session_id = handle.lock().await.user_session_id();

    let resolved = match identity {
        // Closing the session cancels a pending web approval.
        KubernetesIdentity::User(user) => closed
            .run_until_cancelled(authorize_kubernetes_target(
                request, &user, target, session_id, services,
            ))
            .await
            .unwrap_or_else(|| Err(unauthorized())),
        // Doesn't block, so closing is only checked around admission below.
        KubernetesIdentity::Ticket(ticket) => ticket
            .spend(&services.db)
            .await
            .map_err(poem::Error::from)
            .and_then(|authorization| authorization.ok_or_else(unauthorized))
            .and_then(|authorization| authorization.narrow().map_err(Into::into)),
    };
    match resolved {
        Ok(resolved) => {
            // Closing the session also cancels an admin-approval wait.
            let admission = tokio::select! {
                biased;
                () = closed.cancelled() => Err(WarpgateError::UserSessionEnded),
                admission = admit_kubernetes_session(request, services, &handle, resolved) => admission,
            };
            let admission = match admission {
                Ok(Admission::Admitted(admitted)) => {
                    KubernetesSession::admit(&services.db, db_key, session_id, admitted.id())
                        .await
                        .map(|()| admitted)
                }
                Ok(Admission::Refused) => {
                    // End the session instead of discarding it: waiters on other
                    // nodes read an ended session as refused, but a deleted one
                    // as abandoned, and would ask again.
                    handle.lock().await.confirm();
                    correlator
                        .lock()
                        .await
                        .refusals
                        .insert(key.clone(), Instant::now());
                    Err(WarpgateError::SessionNotApproved)
                }
                Ok(Admission::Expired) => Err(WarpgateError::SessionNotApproved),
                Err(error) => Err(error),
            };
            match admission {
                Ok(admitted) => {
                    let admitted = Arc::new(admitted);
                    *authorization = Authorization::Authorized(admitted.clone());
                    Ok((handle, admitted, closed))
                }
                Err(error) => {
                    *authorization = Authorization::Denied;
                    correlator.lock().await.evict(key, &slot);
                    settle_failed_attempt(services, &handle, session_id).await;
                    Err(match error {
                        WarpgateError::UserSessionEnded => unauthorized(),
                        error => error.into(),
                    })
                }
            }
        }
        Err(error) => {
            // A denied attempt is not cached: the requests waiting on this
            // one fail with it, and the entry goes so that the next request
            // can prompt again.
            *authorization = Authorization::Denied;
            correlator.lock().await.evict(key, &slot);
            settle_failed_attempt(services, &handle, session_id).await;
            Err(error)
        }
    }
}

/// Start the target session, waiting for approval if needed
async fn admit_kubernetes_session(
    request: &Request,
    services: &Services,
    handle: &Arc<Mutex<WarpgateServerHandle>>,
    resolved: TargetAuthorization<TargetKubernetesOptions>,
) -> Result<Admission<TargetKubernetesOptions>, WarpgateError> {
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

/// Evicts the local entry if the opening request is dropped before it resolves,
/// e.g. a cancelled `kubectl`. The entry would otherwise keep the provisional
/// session alive, and other nodes would wait on a dead claim. Evicting discards
/// the session, which is how they notice.
struct AbandonGuard {
    correlator: Arc<Mutex<RequestCorrelator>>,
    key: CorrelationKey,
    slot: SharedAuthorization,
    session_id: UserSessionId,
    auth_state_store: Arc<Mutex<AuthStateStore>>,
    armed: bool,
}

impl AbandonGuard {
    fn new(
        correlator: &Arc<Mutex<RequestCorrelator>>,
        key: &CorrelationKey,
        slot: &SharedAuthorization,
        session_id: UserSessionId,
        services: &Services,
    ) -> Self {
        Self {
            correlator: correlator.clone(),
            key: key.clone(),
            slot: slot.clone(),
            session_id,
            auth_state_store: services.auth_state_store.clone(),
            armed: true,
        }
    }

    const fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for AbandonGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let correlator = self.correlator.clone();
        let key = self.key.clone();
        let slot = self.slot.clone();
        let session_id = self.session_id;
        let auth_state_store = self.auth_state_store.clone();
        tokio::spawn(async move {
            correlator.lock().await.evict(&key, &slot);
            auth_state_store.lock().await.remove(&session_id);
        });
    }
}

/// Waits for the request that opened this session to resolve its authorization.
///
/// `None` means there is nothing to join and the caller should open a session of
/// its own: the opening request was dropped mid-approval — a cancelled `kubectl`
/// — so its entry is evicted here rather than left to fail every later request
/// until the vacuum, and its auth state is dropped so the dead attempt does not
/// linger as an approvable orphan in the pending-approvals UI. An in-flight
/// `AuthStateStore::open` can still insert a pending-approval row after this
/// cleanup; the stale-request reaper handles those rows.
async fn join_session(
    correlator: &Arc<Mutex<RequestCorrelator>>,
    key: &CorrelationKey,
    handle: Arc<Mutex<WarpgateServerHandle>>,
    slot: SharedAuthorization,
    closed: CancellationToken,
    auth_state_store: &Arc<Mutex<AuthStateStore>>,
) -> poem::Result<Option<CorrelatedSession>> {
    // Cloned out so the slot lock is not held while taking the correlator lock.
    let outcome = slot.lock().await.clone();
    match outcome {
        Authorization::Authorized(admitted) => Ok(Some((handle, admitted, closed))),
        Authorization::Denied => Err(unauthorized()),
        Authorization::Pending => {
            correlator.lock().await.evict(key, &slot);
            let session_id = handle.lock().await.user_session_id();
            auth_state_store.lock().await.remove(&session_id);
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
/// attempt, so its auth state must not outlive it as an approvable orphan (see
/// [`join_session`] for the pending-approval insertion race).
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

async fn session_init(
    request: &Request,
    services: &Services,
) -> (UserSessionStateInit, CancellationToken) {
    let ip = get_client_ip(request, services).await;
    let (session_handle, closed) = KubernetesSessionHandle::new();
    (
        UserSessionStateInit {
            remote_address: ip.and_then(|x| x.parse().ok()),
            handle: Box::new(session_handle),
        },
        closed,
    )
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
    let (init, closed) = session_init(request, services).await;
    let handle =
        State::register_node_local_user_session(&services.state, crate::PROTOCOL_NAME, init)
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

async fn session_max_age(services: &Services) -> Duration {
    services
        .config
        .lock()
        .await
        .store
        .kubernetes
        .session_max_age
}

impl RequestCorrelator {
    pub fn new(services: &Services) -> Arc<Mutex<Self>> {
        let this = Arc::new(Mutex::new(Self {
            handles: HashMap::new(),
            refusals: HashMap::new(),
            services: services.clone(),
        }));
        Self::spawn_vacuum_task(this.clone(), services.clone());
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

    /// The slot is locked before insertion: an unlocked `Pending` slot reads
    /// as abandoned to joiners.
    async fn insert_claim(
        &mut self,
        key: &CorrelationKey,
        handle: Arc<Mutex<WarpgateServerHandle>>,
        closed: CancellationToken,
        created: OffsetDateTime,
    ) -> LocalClaim {
        let slot = SharedAuthorization::default();
        let authorization = slot.clone().lock_owned().await;
        self.handles.insert(
            key.clone(),
            SessionEntry {
                handle: handle.clone(),
                created,
                authorization: slot.clone(),
                closed: closed.clone(),
            },
        );
        LocalClaim {
            handle,
            closed,
            slot,
            authorization,
        }
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
        let max_age = session_max_age(&self.services).await;
        let now = Instant::now();
        self.handles
            .retain(|_, entry| entry_is_live(entry.created, &entry.closed, max_age));
        self.refusals
            .retain(|_, at| now.duration_since(*at) < REFUSAL_MEMORY);
    }

    /// The DB sweep runs outside the correlator lock so it doesn't stall requests.
    fn spawn_vacuum_task(this: Arc<Mutex<Self>>, services: Services) {
        let interval = Duration::from_secs(60);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                this.lock().await.vacuum().await;
                let cutoff = OffsetDateTime::now_utc() - session_max_age(&services).await;
                if let Err(error) = KubernetesSession::sweep(&services.db, cutoff).await {
                    warn!(%error, "Failed to sweep expired Kubernetes session claims");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cancelled_entry_is_not_live() {
        let closed = CancellationToken::new();
        assert!(entry_is_live(
            OffsetDateTime::now_utc(),
            &closed,
            Duration::from_secs(60)
        ));
        closed.cancel();
        assert!(!entry_is_live(
            OffsetDateTime::now_utc(),
            &closed,
            Duration::from_secs(60)
        ));
    }

    #[test]
    fn an_aged_out_entry_is_not_live() {
        let closed = CancellationToken::new();
        let created = OffsetDateTime::now_utc() - Duration::from_secs(120);
        assert!(!entry_is_live(created, &closed, Duration::from_secs(60)));
    }
}
