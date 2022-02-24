use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{WarpgateConfig, Target, User, SessionHandle, SessionId};

pub struct State {
    pub sessions: HashMap<SessionId, Arc<Mutex<SessionState>>>,
    pub config: WarpgateConfig,
}

impl State {
    pub fn new(config: WarpgateConfig) -> Self {
        State {
            sessions:HashMap::new(),
            config,
        }
    }

    pub fn register_session(&mut self, session: &Arc<Mutex<SessionState>>) -> SessionId {
        let id = uuid::Uuid::new_v4();
        self.sessions.insert(id, session.clone());
        id
    }

    pub fn remove_session(&mut self, id: SessionId) {
        self.sessions.remove(&id);
    }
}

pub struct SessionState {
    pub remote_address: SocketAddr,
    pub user: Option<User>,
    pub target: Option<Target>,
    pub handle: Box<dyn SessionHandle + Send>,
}

impl SessionState {
    pub fn new(remote_address: SocketAddr, handle: Box<dyn SessionHandle + Send>) -> Self {
        SessionState {
            remote_address,
            user: None,
            target: None,
            handle,
        }
    }
}
