use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait};
use tokio::sync::{broadcast, Mutex};
use tracing::*;
use uuid::Uuid;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{ProtocolName, SessionId, Target, WarpgateError};
use warpgate_db_entities::Session;

use crate::rate_limiting::{RateLimiterRegistry, RateLimiterStackHandle};
use crate::{SessionHandle, WarpgateServerHandle};

pub struct State {
    pub sessions: HashMap<SessionId, Arc<Mutex<SessionState>>>,
    db: Arc<Mutex<DatabaseConnection>>,
    rate_limiter_registry: Arc<Mutex<RateLimiterRegistry>>,
    change_sender: broadcast::Sender<()>,
}

impl State {
    pub fn new(
        db: &Arc<Mutex<DatabaseConnection>>,
        rate_limiter_registry: &Arc<Mutex<RateLimiterRegistry>>,
    ) -> Result<Arc<Mutex<Self>>, WarpgateError> {
        let sender = broadcast::channel(2).0;
        Ok(Arc::new(Mutex::new(Self {
            sessions: HashMap::new(),
            db: db.clone(),
            rate_limiter_registry: rate_limiter_registry.clone(),
            change_sender: sender,
        })))
    }

    pub async fn register_session(
        this: &Arc<Mutex<Self>>,
        protocol: &ProtocolName,
        state: SessionStateInit,
    ) -> Result<Arc<Mutex<WarpgateServerHandle>>, WarpgateError> {
        let this_copy = this.clone();
        let mut _self = this.lock().await;
        let id = uuid::Uuid::new_v4();

        let state = Arc::new(Mutex::new(SessionState::new(
            state,
            _self.change_sender.clone(),
        )));

        _self.sessions.insert(id, state.clone());

        {
            use sea_orm::ActiveValue::Set;

            let values = Session::ActiveModel {
                id: Set(id),
                started: Set(chrono::Utc::now()),
                remote_address: Set(state
                    .lock()
                    .await
                    .remote_address
                    .map(|x| x.to_string())
                    .unwrap_or_else(|| "".to_string())),
                protocol: Set(protocol.to_string()),
                ..Default::default()
            };

            let db = _self.db.lock().await;
            values
                .insert(&*db)
                .await
                .context("Error inserting session")
                .map_err(WarpgateError::from)?;
        }

        let _ = _self.change_sender.send(());

        Ok(Arc::new(Mutex::new(WarpgateServerHandle::new(
            id,
            _self.db.clone(),
            this_copy,
            state,
            _self.rate_limiter_registry.clone(),
        )?)))
    }

    pub fn subscribe(&mut self) -> broadcast::Receiver<()> {
        self.change_sender.subscribe()
    }

    pub async fn remove_session(&mut self, id: SessionId) {
        self.sessions.remove(&id);

        if let Err(error) = self.mark_session_complete(id).await {
            error!(%error, %id, "Could not update session in the DB");
        }

        let _ = self.change_sender.send(());
    }

    async fn mark_session_complete(&mut self, id: Uuid) -> Result<()> {
        use sea_orm::ActiveValue::Set;
        let db = self.db.lock().await;
        let session = Session::Entity::find_by_id(id)
            .one(&*db)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;
        let mut model: Session::ActiveModel = session.into();
        model.ended = Set(Some(chrono::Utc::now()));
        model.update(&*db).await?;
        Ok(())
    }
}

pub struct SessionState {
    pub remote_address: Option<SocketAddr>,
    pub user_info: Option<AuthStateUserInfo>,
    pub target: Option<Target>,
    pub handle: Box<dyn SessionHandle + Send + Sync>,
    change_sender: broadcast::Sender<()>,
    pub rate_limiter_handles: Vec<RateLimiterStackHandle>,
}

pub struct SessionStateInit {
    pub remote_address: Option<SocketAddr>,
    pub handle: Box<dyn SessionHandle + Send + Sync>,
}

impl SessionState {
    fn new(init: SessionStateInit, change_sender: broadcast::Sender<()>) -> Self {
        SessionState {
            remote_address: init.remote_address,
            user_info: None,
            target: None,
            handle: init.handle,
            change_sender,
            rate_limiter_handles: vec![],
        }
    }

    pub fn emit_change(&self) {
        let _ = self.change_sender.send(());
    }
}
