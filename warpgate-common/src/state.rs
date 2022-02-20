use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::Wrapping;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{WarpgateConfig, Target, User, SessionHandle};

pub struct State {
    pub sessions: HashMap<u64, Arc<Mutex<SessionState>>>,
    pub config: WarpgateConfig,
    last_id: Wrapping<u64>,
}

impl State {
    pub fn new(config: WarpgateConfig) -> Self {
        State {
            sessions:HashMap::new(),
            config,
            last_id: Wrapping(0),
        }
    }

    pub fn register_session(&mut self, session: &Arc<Mutex<SessionState>>) -> u64 {
        let id = self.alloc_id();
        self.sessions.insert(id, session.clone());
        id
    }

    pub fn remove_session(&mut self, id: u64) {
        self.sessions.remove(&id);
    }

    fn alloc_id(&mut self) -> u64 {
        self.last_id += 1;
        self.last_id.0
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
