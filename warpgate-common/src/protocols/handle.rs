use std::sync::Arc;

use anyhow::{Context, Result};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use tokio::sync::Mutex;
use warpgate_db_entities::Session;

use crate::{SessionId, SessionState, State, Target};

pub trait SessionHandle {
    fn close(&mut self);
}

pub struct WarpgateServerHandle {
    id: SessionId,
    db: Arc<Mutex<DatabaseConnection>>,
    state: Arc<Mutex<State>>,
    session_state: Arc<Mutex<SessionState>>,
}

impl WarpgateServerHandle {
    pub fn new(
        id: SessionId,
        db: Arc<Mutex<DatabaseConnection>>,
        state: Arc<Mutex<State>>,
        session_state: Arc<Mutex<SessionState>>,
    ) -> Self {
        WarpgateServerHandle {
            id,
            db,
            state,
            session_state,
        }
    }

    pub fn id(&self) -> SessionId {
        self.id
    }

    pub fn session_state(&self) -> &Arc<Mutex<SessionState>> {
        &self.session_state
    }

    pub async fn set_username(&mut self, username: String) -> Result<()> {
        use sea_orm::ActiveValue::Set;

        {
            let mut state = self.session_state.lock().await;
            state.username = Some(username.clone());
            state.emit_change()
        }

        let db = self.db.lock().await;

        Session::Entity::update_many()
            .set(Session::ActiveModel {
                username: Set(Some(username)),
                ..Default::default()
            })
            .filter(Session::Column::Id.eq(self.id))
            .exec(&*db)
            .await?;

        Ok(())
    }

    pub async fn set_target(&self, target: &Target) -> Result<()> {
        use sea_orm::ActiveValue::Set;
        {
            let mut state = self.session_state.lock().await;
            state.target = Some(target.clone());
            state.emit_change()
        }

        let db = self.db.lock().await;

        Session::Entity::update_many()
            .set(Session::ActiveModel {
                target_snapshot: Set(Some(
                    serde_json::to_string(&target).context("Error serializing target")?,
                )),
                ..Default::default()
            })
            .filter(Session::Column::Id.eq(self.id))
            .exec(&*db)
            .await?;

        Ok(())
    }
}

impl Drop for WarpgateServerHandle {
    fn drop(&mut self) {
        let id = self.id;
        let state = self.state.clone();
        tokio::spawn(async move {
            state.lock().await.remove_session(id).await;
        });
    }
}
