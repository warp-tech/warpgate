use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;
use uuid::Uuid;

use super::AuthState;
use crate::{ConfigProvider, WarpgateError};

pub struct AuthStateStore {
    config_provider: Arc<Mutex<dyn ConfigProvider + Send + 'static>>,
    store: HashMap<Uuid, AuthState>,
}

impl AuthStateStore {
    pub fn new(config_provider: Arc<Mutex<dyn ConfigProvider + Send + 'static>>) -> Self {
        Self {
            store: HashMap::new(),
            config_provider,
        }
    }

    pub fn contains_key(&mut self, id: &Uuid) -> bool {
        self.store.contains_key(id)
    }

    pub fn get_mut(&mut self, id: &Uuid) -> Option<&mut AuthState> {
        self.store.get_mut(id)
    }

    pub async fn create(
        &mut self,
        username: &str,
        protocol: &str,
    ) -> Result<(Uuid, &mut AuthState), WarpgateError> {
        let id = Uuid::new_v4();
        let state = AuthState::new(
            username.to_string(),
            protocol.to_string(),
            self.config_provider
                .lock()
                .await
                .get_credential_policy(username)
                .await?,
        );
        self.store.insert(id.clone(), state);

        #[allow(clippy::unwrap_used)]
        Ok((id, self.store.get_mut(&id).unwrap()))
    }

    pub async fn vacuum(&mut self) {
        let mut to_remove = vec![];
        for (id, state) in self.store.iter() {
            if state.is_expired() {
                to_remove.push(*id);
            }
        }
        for id in to_remove {
            self.store.remove(&id);
        }
    }
}
