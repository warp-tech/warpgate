use crate::{SessionHandle, SessionId, Target, WarpgateServerHandle};
use anyhow::{Context, Result};
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use tokio::sync::Mutex;
use tracing::*;
use uuid::Uuid;
use warpgate_db_entities::Session;

pub struct State {
    pub sessions: HashMap<SessionId, Arc<Mutex<SessionState>>>,
    pub db: Arc<Mutex<DatabaseConnection>>,
    this: Weak<Mutex<Self>>,
}

impl State {
    pub fn new(db: &Arc<Mutex<DatabaseConnection>>) -> Arc<Mutex<Self>> {
        Arc::<Mutex<Self>>::new_cyclic(|me| {
            Mutex::new(Self {
                sessions: HashMap::new(),
                db: db.clone(),
                this: me.clone(),
            })
        })
    }

    pub async fn register_session(
        &mut self,
        session: &Arc<Mutex<SessionState>>,
    ) -> Result<WarpgateServerHandle> {
        let id = uuid::Uuid::new_v4();
        self.sessions.insert(id, session.clone());

        {
            use sea_orm::ActiveValue::Set;

            let values = Session::ActiveModel {
                id: Set(id),
                started: Set(chrono::Utc::now()),
                remote_address: Set(session.lock().await.remote_address.to_string()),
                ..Default::default()
            };

            let db = self.db.lock().await;
            values
                .insert(&*db)
                .await
                .context("Error inserting session")?;
        }

        match self.this.upgrade() {
            Some(this) => Ok(WarpgateServerHandle::new(id, this, session.clone())),
            None => anyhow::bail!("State is being detroyed"),
        }
    }

    pub async fn remove_session(&mut self, id: SessionId) {
        self.sessions.remove(&id);

        if let Err(error) = self.mark_session_complete(id).await {
            error!(%error, %id, "Could not update session in the DB");
        }
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
    pub remote_address: SocketAddr,
    pub username: Option<String>,
    pub target: Option<Target>,
    pub handle: Box<dyn SessionHandle + Send>,
}

impl SessionState {
    pub fn new(remote_address: SocketAddr, handle: Box<dyn SessionHandle + Send>) -> Self {
        SessionState {
            remote_address,
            username: None,
            target: None,
            handle,
        }
    }
}
