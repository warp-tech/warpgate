use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::Wrapping;
use std::sync::Arc;

use tokio::sync::Mutex;

pub struct State {
    pub sessions: HashMap<u64, Arc<Mutex<SessionState>>>,
    last_id: Wrapping<u64>,
}

impl State {
    pub fn new() -> Self {
        State {
            sessions:HashMap::new(),
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

#[derive(Clone)]
pub struct TargetSnapshot {
    pub hostname: String,
    pub port: u16,
}

pub struct SessionState {
    pub remote_address: SocketAddr,
    pub username: Option<String>,
    pub target: Option<TargetSnapshot>,
}

impl SessionState {
    pub fn new(remote_address: SocketAddr) -> Self {
        SessionState {
            remote_address,
            username: None,
            target: None,
        }
    }
}
