use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use tokio::sync::{broadcast, Mutex};
use uuid::Uuid;
use warpgate_common::auth::{AuthResult, AuthState, CredentialKind};
use warpgate_common::{SessionId, WarpgateError};

use crate::{ConfigProvider, ConfigProviderEnum};

#[allow(clippy::unwrap_used)]
pub static TIMEOUT: Lazy<Duration> = Lazy::new(|| Duration::from_secs(60 * 10));

struct AuthCompletionSignal {
    sender: broadcast::Sender<AuthResult>,
    created_at: Instant,
}

impl AuthCompletionSignal {
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > *TIMEOUT
    }
}

pub struct AuthStateStore {
    config_provider: Arc<Mutex<ConfigProviderEnum>>,
    store: HashMap<Uuid, (Arc<Mutex<AuthState>>, Instant)>,
    completion_signals: HashMap<Uuid, AuthCompletionSignal>,
    web_auth_request_signal: broadcast::Sender<Uuid>,
}

impl AuthStateStore {
    pub fn new(config_provider: Arc<Mutex<ConfigProviderEnum>>) -> Self {
        Self {
            store: HashMap::new(),
            config_provider,
            completion_signals: HashMap::new(),
            web_auth_request_signal: broadcast::channel(100).0,
        }
    }

    pub fn contains_key(&self, id: &Uuid) -> bool {
        self.store.contains_key(id)
    }

    pub async fn all_pending_web_auths_for_user(
        &self,
        username: &str,
    ) -> Vec<Arc<Mutex<AuthState>>> {
        let mut results = vec![];
        for auth in self.store.values() {
            {
                let inner = auth.0.lock().await;
                if inner.username() != username {
                    continue;
                }
                let AuthResult::Need(need) = inner.verify() else {
                    continue;
                };
                if !need.contains(&CredentialKind::WebUserApproval) {
                    continue;
                }
            }
            results.push(auth.0.clone())
        }
        results
    }

    pub fn get(&self, id: &Uuid) -> Option<Arc<Mutex<AuthState>>> {
        self.store.get(id).map(|x| x.0.clone())
    }

    pub fn subscribe_web_auth_request(&self) -> broadcast::Receiver<Uuid> {
        self.web_auth_request_signal.subscribe()
    }

    pub async fn create(
        &mut self,
        session_id: Option<&SessionId>,
        username: &str,
        protocol: &str,
        supported_credential_types: &[CredentialKind],
    ) -> Result<(Uuid, Arc<Mutex<AuthState>>), WarpgateError> {
        let id = Uuid::new_v4();
        let policy = self
            .config_provider
            .lock()
            .await
            .get_credential_policy(username, supported_credential_types)
            .await?;
        let Some(policy) = policy else {
            return Err(WarpgateError::UserNotFound(username.into()));
        };

        let (state_change_tx, mut state_change_rx) = broadcast::channel(1);
        let web_auth_request_signal = self.web_auth_request_signal.clone();
        tokio::spawn(async move {
            while let Ok(AuthResult::Need(result)) = state_change_rx.recv().await {
                if result.contains(&CredentialKind::WebUserApproval) {
                    let _ = web_auth_request_signal.send(id);
                }
            }
        });

        let state = AuthState::new(
            id,
            session_id.copied(),
            username.to_string(),
            protocol.to_string(),
            policy,
            state_change_tx,
        );
        self.store
            .insert(id, (Arc::new(Mutex::new(state)), Instant::now()));

        #[allow(clippy::unwrap_used)]
        Ok((id, self.get(&id).unwrap()))
    }

    pub fn subscribe(&mut self, id: Uuid) -> broadcast::Receiver<AuthResult> {
        let signal = self.completion_signals.entry(id).or_insert_with(|| {
            let (sender, _) = broadcast::channel(1);
            AuthCompletionSignal {
                sender,
                created_at: Instant::now(),
            }
        });

        signal.sender.subscribe()
    }

    pub async fn complete(&mut self, id: &Uuid) {
        let Some((state, _)) = self.store.get(id) else {
            return;
        };
        if let Some(sig) = self.completion_signals.remove(id) {
            let _ = sig.sender.send(state.lock().await.verify());
        }
    }

    pub async fn vacuum(&mut self) {
        self.store
            .retain(|_, (_, started_at)| started_at.elapsed() < *TIMEOUT);

        self.completion_signals
            .retain(|_, signal| !signal.is_expired());
    }
}
