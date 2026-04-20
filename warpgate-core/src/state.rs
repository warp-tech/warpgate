use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait};
use time::OffsetDateTime;
use tokio::sync::{broadcast, Mutex};
use tracing::error;
use uuid::Uuid;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{ProtocolName, SessionId, Target, WarpgateError};
use warpgate_db_entities::Session;

use crate::logging::AuditEvent;
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
    ) -> Arc<Mutex<Self>> {
        let sender = broadcast::channel(2).0;
        Arc::new(Mutex::new(Self {
            sessions: HashMap::new(),
            db: db.clone(),
            rate_limiter_registry: rate_limiter_registry.clone(),
            change_sender: sender,
        }))
    }

    pub async fn register_session(
        this: &Arc<Mutex<Self>>,
        protocol: &ProtocolName,
        state: SessionStateInit,
    ) -> Result<Arc<Mutex<WarpgateServerHandle>>, WarpgateError> {
        let this_copy = this.clone();
        let mut self_ = this.lock().await;
        let id = uuid::Uuid::new_v4();

        let state = Arc::new(Mutex::new(SessionState::new(
            state,
            self_.change_sender.clone(),
        )));

        self_.sessions.insert(id, state.clone());

        {
            use sea_orm::ActiveValue::Set;

            let values = Session::ActiveModel {
                id: Set(id),
                started: Set(OffsetDateTime::now_utc()),
                remote_address: Set(state
                    .lock()
                    .await
                    .remote_address
                    .map_or_else(String::new, |x| x.to_string())),
                protocol: Set(protocol.to_string()),
                ..Default::default()
            };

            let db = self_.db.lock().await;
            values
                .insert(&*db)
                .await
                .context("Error inserting session")
                .map_err(WarpgateError::from)?;
        }

        let _ = self_.change_sender.send(());

        Ok(Arc::new(Mutex::new(WarpgateServerHandle::new(
            id,
            self_.db.clone(),
            this_copy,
            state,
            self_.rate_limiter_registry.clone(),
        ))))
    }

    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.change_sender.subscribe()
    }

    pub async fn remove_session(&mut self, id: SessionId) {
        if let Some(session_state) = self.sessions.remove(&id) {
            let state_guard = session_state.lock().await;
            if let (Some(user_info), Some(target)) = (&state_guard.user_info, &state_guard.target) {
                AuditEvent::TargetSessionEnded {
                    session_id: id,
                    target_id: target.id,
                    target_name: target.name.clone(),
                    user_id: user_info.id,
                    username: user_info.username.clone(),
                }
                .emit();
            }
        }

        if let Err(error) = self.mark_session_complete(id).await {
            error!(%error, %id, "Could not update session in the DB");
        }

        let _ = self.change_sender.send(());
    }

    async fn mark_session_complete(&self, id: Uuid) -> Result<()> {
        use sea_orm::ActiveValue::Set;
        let db = self.db.lock().await;
        let session = Session::Entity::find_by_id(id)
            .one(&*db)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;
        let mut model: Session::ActiveModel = session.into();
        model.ended = Set(Some(OffsetDateTime::now_utc()));
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
        Self {
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
