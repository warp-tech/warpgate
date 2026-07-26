use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use poem::Request;
use tokio::sync::Mutex;
use warpgate_common::WarpgateError;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common_http::logging::get_client_ip;
use warpgate_core::{Services, SessionStateInit, State, TargetAuthorization, WarpgateServerHandle};

use crate::session_handle::KubernetesSessionHandle;

type CorrelationKey = (String, String, Option<String>); // (username, target_name, ip)

/// One correlated Kubernetes session. The `authorization` is resolved once (which
/// is what runs the credential policy / web approval) and reused for every request
/// in the session, so a single approval covers a whole `kubectl` command.
struct SessionEntry {
    handle: Arc<Mutex<WarpgateServerHandle>>,
    created: Instant,
    authorization: TargetAuthorization,
}

pub struct RequestCorrelator {
    handles: HashMap<CorrelationKey, SessionEntry>,
    services: Services,
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

    /// The existing correlated session for this request, with its cached
    /// authorization, if one is already open. A `Some` result lets the caller skip
    /// re-authorizing (and so skip the web-approval prompt) for the rest of the
    /// session.
    pub async fn existing_session(
        &self,
        request: &Request,
        user_info: &AuthStateUserInfo,
        target_name: &str,
    ) -> Result<Option<(Arc<Mutex<WarpgateServerHandle>>, TargetAuthorization)>, WarpgateError>
    {
        let key = self
            .correlation_key_for_request(request, user_info, target_name)
            .await?;
        Ok(self
            .handles
            .get(&key)
            .map(|entry| (entry.handle.clone(), entry.authorization.clone())))
    }

    /// Open a session for a freshly-authorized request, caching the authorization
    /// so subsequent requests reuse it. If a concurrent request already opened the
    /// session (a rare first-request race), its handle is returned instead — both
    /// authorized the same user for the same target, so either is correct.
    pub async fn register_authorized_session(
        &mut self,
        request: &Request,
        user_info: &AuthStateUserInfo,
        target_name: &str,
        authorization: TargetAuthorization,
    ) -> Result<Arc<Mutex<WarpgateServerHandle>>, WarpgateError> {
        let key = self
            .correlation_key_for_request(request, user_info, target_name)
            .await?;
        if let Some(entry) = self.handles.get(&key) {
            return Ok(entry.handle.clone());
        }

        let ip = get_client_ip(request, &self.services).await;

        let handle = State::register_session(
            &self.services.state,
            crate::PROTOCOL_NAME,
            SessionStateInit {
                remote_address: ip.and_then(|x| x.parse().ok()),
                handle: Box::new(KubernetesSessionHandle),
            },
        )
        .await?;
        self.handles.insert(
            key,
            SessionEntry {
                handle: handle.clone(),
                created: Instant::now(),
                authorization,
            },
        );
        Ok(handle)
    }

    async fn correlation_key_for_request(
        &self,
        request: &Request,
        user_info: &AuthStateUserInfo,
        target_name: &str,
    ) -> Result<CorrelationKey, WarpgateError> {
        let ip = get_client_ip(request, &self.services).await;
        Ok((user_info.username.clone(), target_name.into(), ip))
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
