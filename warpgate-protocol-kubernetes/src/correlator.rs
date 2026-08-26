use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use poem::Request;
use tokio::sync::Mutex;
use warpgate_common::auth::{AuthResult, AuthStateUserInfo};
use warpgate_common::{
    TargetKubernetesOptions, TargetSessionId, User, UserSessionId, WarpgateError,
};
use warpgate_common_http::logging::get_client_ip;
use warpgate_core::{
    ApprovedTarget, Services, State, TargetSessionStart, UserSessionStateInit, WarpgateServerHandle,
};

use crate::server::auth::{authorize_kubernetes_target, unauthorized};
use crate::session_handle::KubernetesSessionHandle;

type CorrelationKey = (String, String, Option<String>); // (username, target_name, ip)

#[derive(Clone)]
pub struct AdmittedSession {
    pub target_session_id: TargetSessionId,
    pub approved: Arc<ApprovedTarget<TargetKubernetesOptions>>,
}

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
}

pub struct RequestCorrelator {
    handles: HashMap<CorrelationKey, SessionEntry>,
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
    user: &User,
    target_name: &str,
    services: &Services,
) -> poem::Result<(Arc<Mutex<WarpgateServerHandle>>, AdmittedSession)> {
    let user_info: AuthStateUserInfo = user.into();
    let key = correlation_key_for_request(request, services, &user_info, target_name).await?;

    loop {
        // Bound to its own `let` so the correlator lock is released before
        // joining: joining waits for the opening request's approval, which can
        // take minutes, and that request needs the correlator lock to clean up
        // after a denial.
        let existing = correlator.lock().await.entry(&key);
        if let Some((handle, slot)) = existing
            && let Some(joined) = join_session(correlator, &key, handle, slot, services).await?
        {
            return Ok(joined);
        }

        // Registered outside the correlator lock so that concurrent first
        // requests don't serialise on its database insert. A handle that then
        // loses the race below is dropped, deleting the session it just opened.
        let handle = register_pending_session(services, request, &user_info).await?;
        let session_id = handle.lock().await.user_session_id();

        let slot = SharedAuthorization::default();
        let claimed = {
            let mut correlator = correlator.lock().await;
            if correlator.entry(&key).is_some() {
                None
            } else {
                // Locked before the correlator lock is released, so a request
                // joining this session can't reach the pending slot ahead of us.
                let guard = slot.clone().lock_owned().await;
                correlator.handles.insert(
                    key.clone(),
                    SessionEntry {
                        handle: handle.clone(),
                        created: Instant::now(),
                        authorization: slot.clone(),
                    },
                );
                Some(guard)
            }
        };
        // Another request opened the session first; join it on the next pass.
        let Some(mut authorization) = claimed else {
            continue;
        };

        return match authorize_kubernetes_target(request, user, target_name, session_id, services)
            .await
        {
            Ok(resolved) => {
                let admitted = match handle
                    .lock()
                    .await
                    .start_target_session(resolved)
                    .await
                    .and_then(TargetSessionStart::admitted)
                {
                    Ok((target_session_id, approved)) => AdmittedSession {
                        target_session_id,
                        approved: Arc::new(approved),
                    },
                    Err(error) => {
                        *authorization = Authorization::Denied;
                        correlator.lock().await.evict(&key, &slot);
                        settle_failed_attempt(services, &handle, session_id).await;
                        return Err(error.into());
                    }
                };
                handle.lock().await.confirm();
                *authorization = Authorization::Authorized(admitted.clone());
                Ok((handle, admitted))
            }
            Err(error) => {
                // A denied attempt is not cached: the requests waiting on this
                // one fail with it, and the entry goes so that the next request
                // can prompt again.
                *authorization = Authorization::Denied;
                correlator.lock().await.evict(&key, &slot);
                settle_failed_attempt(services, &handle, session_id).await;
                Err(error)
            }
        };
    }
}

/// Waits for the request that opened this session to resolve its authorization.
///
/// `None` means there is nothing to join and the caller should open a session of
/// its own: the opening request was dropped mid-approval — a cancelled `kubectl`
/// — so its entry is evicted here rather than left to fail every later request
/// until the vacuum, and its auth state is dropped so the dead attempt does not
/// linger as an approvable orphan in the pending-approvals UI.
async fn join_session(
    correlator: &Arc<Mutex<RequestCorrelator>>,
    key: &CorrelationKey,
    handle: Arc<Mutex<WarpgateServerHandle>>,
    slot: SharedAuthorization,
    services: &Services,
) -> poem::Result<Option<(Arc<Mutex<WarpgateServerHandle>>, AdmittedSession)>> {
    // Cloned out so the slot lock is not held while taking the correlator lock.
    let outcome = slot.lock().await.clone();
    match outcome {
        Authorization::Authorized(admitted) => Ok(Some((handle, admitted))),
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
/// attempt, so its auth state must not outlive it as an approvable orphan.
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
) -> Result<Arc<Mutex<WarpgateServerHandle>>, WarpgateError> {
    let ip = get_client_ip(request, services).await;
    let handle = State::register_node_local_user_session(
        &services.state,
        crate::PROTOCOL_NAME,
        UserSessionStateInit {
            remote_address: ip.and_then(|x| x.parse().ok()),
            handle: Box::new(KubernetesSessionHandle),
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
    Ok(handle)
}

async fn correlation_key_for_request(
    request: &Request,
    services: &Services,
    user_info: &AuthStateUserInfo,
    target_name: &str,
) -> Result<CorrelationKey, WarpgateError> {
    let ip = get_client_ip(request, services).await;
    Ok((user_info.username.clone(), target_name.into(), ip))
}

impl RequestCorrelator {
    pub fn new(services: &Services) -> Arc<Mutex<Self>> {
        let this = Arc::new(Mutex::new(Self {
            handles: HashMap::new(),
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
    ) -> Option<(Arc<Mutex<WarpgateServerHandle>>, SharedAuthorization)> {
        self.handles
            .get(key)
            .map(|entry| (entry.handle.clone(), entry.authorization.clone()))
    }

    /// Drops this session's entry unless it has already been replaced — an
    /// attempt long enough to have been vacuumed meanwhile must not evict
    /// whatever took its place.
    fn evict(&mut self, key: &CorrelationKey, slot: &SharedAuthorization) {
        if self
            .entry(key)
            .is_some_and(|(_, current)| Arc::ptr_eq(&current, slot))
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
            .retain(|_, entry| now.duration_since(entry.created) < max_age);
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
