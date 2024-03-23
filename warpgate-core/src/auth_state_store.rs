use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use tokio::sync::{broadcast, Mutex};
use uuid::Uuid;
use warpgate_common::auth::{AuthResult, AuthState, CredentialKind};
use warpgate_common::{SessionId, WarpgateError};

use crate::ConfigProvider;

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
    config_provider: Arc<Mutex<dyn ConfigProvider + Send + 'static>>,
    store: HashMap<Uuid, (Arc<Mutex<AuthState>>, Instant)>,
    completion_signals: HashMap<Uuid, AuthCompletionSignal>,
}

impl AuthStateStore {
    pub fn new(config_provider: Arc<Mutex<dyn ConfigProvider + Send + 'static>>) -> Self {
        Self {
            store: HashMap::new(),
            config_provider,
            completion_signals: HashMap::new(),
        }
    }

    pub fn contains_key(&self, id: &Uuid) -> bool {
        self.store.contains_key(id)
    }

    pub fn get(&self, id: &Uuid) -> Option<Arc<Mutex<AuthState>>> {
        self.store.get(id).map(|x| x.0.clone())
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
            return Err(WarpgateError::UserNotFound(username.into()))
        };

        let state = AuthState::new(
            id,
            session_id.copied(),
            username.to_string(),
            protocol.to_string(),
            policy,
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
