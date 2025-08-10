use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use poem::Request;
use tokio::sync::Mutex;
use warpgate_common::WarpgateError;
use warpgate_core::helpers::extract_client_ip;
use warpgate_core::{Services, SessionStateInit, State, WarpgateServerHandle};

use crate::session_handle::KubernetesSessionHandle;

type CorrelationKey = (String, String, String); // (username, target_name, ip)

pub struct RequestCorrelator {
    handles: HashMap<CorrelationKey, (Arc<Mutex<WarpgateServerHandle>>, Instant)>,
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

    pub async fn session_for_request(
        &mut self,
        request: &Request,
        target_name: &str,
    ) -> Result<Arc<Mutex<WarpgateServerHandle>>, WarpgateError> {
        let key = self
            .correlation_key_for_request(request, target_name)
            .await?;
        let now = Instant::now();
        if let Some((handle, _created)) = self.handles.get(&key) {
            // Optionally, could update timestamp for LRU
            return Ok(handle.clone());
        }

        let ip = extract_client_ip(request, &self.services).await;

        let handle = State::register_session(
            &self.services.state,
            &crate::PROTOCOL_NAME,
            SessionStateInit {
                remote_address: ip.parse().ok(),
                handle: Box::new(KubernetesSessionHandle),
            },
        )
        .await?;
        self.handles.insert(key, (handle.clone(), now));
        Ok(handle)
    }

    async fn correlation_key_for_request(
        &self,
        request: &Request,
        target_name: &str,
    ) -> Result<CorrelationKey, WarpgateError> {
        let username = self.extract_username(request)?;
        let ip = extract_client_ip(request, &self.services).await;
        Ok((username, target_name.into(), ip))
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
            .retain(|_, (_, created)| now.duration_since(*created) < max_age);
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

    // Placeholder: fill in with your username extraction logic
    fn extract_username(&self, _request: &Request) -> Result<String, WarpgateError> {
        return Ok("TODO".into());
        // TODO: Extract username from request/session/auth
    }
}
