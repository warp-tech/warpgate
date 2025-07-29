use std::num::NonZero;
use std::sync::Arc;

use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use warpgate_common::{SessionId, Target, WarpgateError};
use warpgate_db_entities::Session;

use crate::rate_limiting::{stack_rate_limiters, RateLimiterRegistry, RateLimiterStackHandle};
use crate::{SessionState, State};

pub trait SessionHandle {
    fn close(&mut self);
}

pub struct WarpgateServerHandle {
    id: SessionId,
    db: Arc<Mutex<DatabaseConnection>>,
    state: Arc<Mutex<State>>,
    session_state: Arc<Mutex<SessionState>>,
    rate_limiters_registry: Arc<Mutex<RateLimiterRegistry>>,
    rate_limiter_handles: Vec<RateLimiterStackHandle>,
}

impl WarpgateServerHandle {
    pub fn new(
        id: SessionId,
        db: Arc<Mutex<DatabaseConnection>>,
        state: Arc<Mutex<State>>,
        session_state: Arc<Mutex<SessionState>>,
        rate_limiters_registry: Arc<Mutex<RateLimiterRegistry>>,
    ) -> Result<Self, WarpgateError> {
        Ok(WarpgateServerHandle {
            id: id.clone(),
            db,
            state,
            session_state,
            rate_limiters_registry,
            rate_limiter_handles: vec![],
        })
    }

    pub fn id(&self) -> SessionId {
        self.id
    }

    pub fn session_state(&self) -> &Arc<Mutex<SessionState>> {
        &self.session_state
    }

    pub async fn set_username(&self, username: String) -> Result<(), WarpgateError> {
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

    pub async fn set_target(&self, target: &Target) -> Result<(), WarpgateError> {
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
                    serde_json::to_string(&target).map_err(WarpgateError::other)?,
                )),
                ..Default::default()
            })
            .filter(Session::Column::Id.eq(self.id))
            .exec(&*db)
            .await?;

        Ok(())
    }

    pub fn wrap_stream<S: AsyncRead + AsyncWrite + Unpin + Send>(
        &self,
        stream: S,
    ) -> impl AsyncRead + AsyncWrite + Unpin + Send {
        let rate_limiters_registry = self.rate_limiters_registry.clone();
        let session_id = self.id;

        let (stream, handle) = stack_rate_limiters(stream);
        // remember handle

        stream
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
