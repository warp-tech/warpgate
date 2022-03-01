use crate::db::{connect_to_db, sanitize_db};
use crate::recorder::SessionRecordings;
use crate::{SessionHandle, SessionId, Target, User, WarpgateConfig};
use anyhow::{Context, Result};
use sea_orm::ActiveModelTrait;
use sea_orm::{DatabaseConnection, EntityTrait};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::*;
use uuid::Uuid;
use warpgate_db_entities::Session;

pub struct State {
    pub sessions: HashMap<SessionId, Arc<Mutex<SessionState>>>,
    pub config: WarpgateConfig,
    pub recordings: Arc<Mutex<SessionRecordings>>,
    pub db: Arc<Mutex<DatabaseConnection>>,
}

impl State {
    pub async fn new(config: WarpgateConfig) -> Result<Self> {
        let mut db = connect_to_db(&config).await?;
        sanitize_db(&mut db).await?;

        let db = Arc::new(Mutex::new(db));

        let recordings = Arc::new(Mutex::new(SessionRecordings::new(
            db.clone(),
            config.recordings_path.clone(),
        )?));

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
            use sea_orm::ActiveValue::Set;

            let values = Session::ActiveModel {
                id: Set(id.clone()),
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

        Ok(id)
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
            .ok_or(anyhow::anyhow!("Session not found"))?;
        let mut model: Session::ActiveModel = session.into();
        model.ended = Set(Some(chrono::Utc::now()));
        model.update(&*db).await?;
        Ok(())
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
