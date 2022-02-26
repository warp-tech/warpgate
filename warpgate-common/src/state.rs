use crate::db::{connect_to_db, models, DatabasePool};
use crate::recorder::SessionRecordings;
use crate::{SessionHandle, SessionId, Target, User, WarpgateConfig};
use anyhow::{Context, Result};
use tokio_diesel::*;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct State {
    pub sessions: HashMap<SessionId, Arc<Mutex<SessionState>>>,
    pub config: WarpgateConfig,
    pub recordings: Arc<Mutex<SessionRecordings>>,
    pub db: DatabasePool,
}

impl State {
    pub fn new(config: WarpgateConfig) -> Result<Self> {
        let recordings = Arc::new(Mutex::new(SessionRecordings::new(
            config.recordings_path.clone(),
        )?));
        let db = connect_to_db(&config)?;
        Ok(State {
            sessions: HashMap::new(),
            config,
            recordings,
            db,
        })
    }

    pub async fn register_session(
        &mut self,
        session: &Arc<Mutex<SessionState>>,
    ) -> Result<SessionId> {
        let id = uuid::Uuid::new_v4().into();
        self.sessions.insert(id, session.clone());
        {
            use super::db::schema::sessions::dsl::sessions;
            let values = models::Session {
                id: id.clone(),
                started: chrono::Utc::now().naive_utc(),
                ended: None,
                remote_address: session.lock().await.remote_address.to_string(),
                target_snapshot: None,
                user_snapshot: None,
            };
            diesel::insert_into(sessions)
                .values(values)
                .execute_async(&self.db).await
                .context("Error inserting session")?;
        }
        Ok(id)
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
