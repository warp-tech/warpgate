use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};

use anyhow::{anyhow, Context, Result};
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait};
use tokio::sync::{broadcast, Mutex};
use tracing::*;
use uuid::Uuid;
use warpgate_common::{ProtocolName, SessionId, Target, WarpgateError};
use warpgate_db_entities::Session;

use crate::{SessionHandle, WarpgateServerHandle};

pub struct State {
    pub sessions: HashMap<SessionId, Arc<Mutex<SessionState>>>,
    db: Arc<Mutex<DatabaseConnection>>,
    this: Weak<Mutex<Self>>,
    change_sender: broadcast::Sender<()>,
}

impl State {
    pub fn new(db: &Arc<Mutex<DatabaseConnection>>) -> Arc<Mutex<Self>> {
        let sender = broadcast::channel(2).0;
        Arc::<Mutex<Self>>::new_cyclic(|me| {
            Mutex::new(Self {
                sessions: HashMap::new(),
                db: db.clone(),
                this: me.clone(),
                change_sender: sender,
            })
        })
    }

    pub async fn register_session(
        &mut self,
        protocol: &ProtocolName,
        state: SessionStateInit,
    ) -> Result<Arc<Mutex<WarpgateServerHandle>>, WarpgateError> {
        let id = uuid::Uuid::new_v4();

        let state = Arc::new(Mutex::new(SessionState::new(
            state,
            self.change_sender.clone(),
        )));

        self.sessions.insert(id, state.clone());

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

            let db = self.db.lock().await;
            values
                .insert(&*db)
                .await
                .context("Error inserting session").map_err(WarpgateError::from)?;
        }

        let _ = self.change_sender.send(());

        match self.this.upgrade() {
            Some(this) => Ok(Arc::new(Mutex::new(WarpgateServerHandle::new(
                id,
                self.db.clone(),
                this,
                state,
            )))),
            None => Err(anyhow!("State is being detroyed").into()),
        }
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
    pub username: Option<String>,
    pub target: Option<Target>,
    pub handle: Box<dyn SessionHandle + Send>,
    change_sender: broadcast::Sender<()>,
}

pub struct SessionStateInit {
    pub remote_address: Option<SocketAddr>,
    pub handle: Box<dyn SessionHandle + Send>,
}

impl SessionState {
    fn new(init: SessionStateInit, change_sender: broadcast::Sender<()>) -> Self {
        SessionState {
            remote_address: init.remote_address,
            username: None,
            target: None,
            handle: init.handle,
            change_sender,
        }
    }

    pub fn emit_change(&self) {
        let _ = self.change_sender.send(());
    }
}
