use crate::{SessionId, SessionState, State, Target, TargetSnapshot, User, UserSnapshot};
use anyhow::{Context, Result};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use std::sync::Arc;
use tokio::sync::Mutex;
use warpgate_db_entities::Session;

pub trait SessionHandle {
    fn close(&mut self);
}

pub struct WarpgateServerHandle {
    id: SessionId,
    state: Arc<Mutex<State>>,
    session_state: Arc<Mutex<SessionState>>,
}

impl WarpgateServerHandle {
    pub fn new(
        id: SessionId,
        state: Arc<Mutex<State>>,
        session_state: Arc<Mutex<SessionState>>,
    ) -> Self {
        WarpgateServerHandle {
            id,
            state,
            session_state,
        }
    }

    pub fn id(&self) -> SessionId {
        self.id
    }

    pub async fn set_user(&mut self, user: &User) -> Result<()> {
        use sea_orm::ActiveValue::Set;

        {
            self.session_state.lock().await.user = Some(user.clone());
        }

        let state = self.state.lock().await;
        let db = state.db.lock().await;

        Session::Entity::update_many()
            .set(Session::ActiveModel {
                user_snapshot: Set(Some(
                    serde_json::to_string(&UserSnapshot::new(&user))
                        .context("Error serializing user")?,
                )),
                ..Default::default()
            })
            .filter(Session::Column::Id.eq(self.id))
            .exec(&*db)
            .await?;

        Ok(())
    }

    pub async fn set_target(&mut self, target: &Target) -> Result<()> {
        use sea_orm::ActiveValue::Set;
        {
            self.session_state.lock().await.target = Some(target.clone());
        }

        let state = self.state.lock().await;
        let db = state.db.lock().await;

        Session::Entity::update_many()
            .set(Session::ActiveModel {
                target_snapshot: Set(Some(
                    serde_json::to_string(&TargetSnapshot::new(&target))
                        .context("Error serializing target")?,
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
