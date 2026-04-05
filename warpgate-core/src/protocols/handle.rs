use std::sync::Arc;

use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tracing::{info_span, Instrument};
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{SessionId, Target, WarpgateError};
use warpgate_db_entities::Session;

use crate::logging::AuditEvent;
use crate::rate_limiting::{stack_rate_limiters, RateLimiterRegistry};
use crate::{SessionState, State};

pub trait SessionHandle {
    fn close(&mut self);
}

#[derive(Clone)]
pub struct WarpgateServerHandle {
    id: SessionId,
    db: Arc<Mutex<DatabaseConnection>>,
    state: Arc<Mutex<State>>,
    session_state: Arc<Mutex<SessionState>>,
    rate_limiters_registry: Arc<Mutex<RateLimiterRegistry>>,
}

impl WarpgateServerHandle {
    pub const fn new(
        id: SessionId,
        db: Arc<Mutex<DatabaseConnection>>,
        state: Arc<Mutex<State>>,
        session_state: Arc<Mutex<SessionState>>,
        rate_limiters_registry: Arc<Mutex<RateLimiterRegistry>>,
    ) -> Self {
        Self {
            id,
            db,
            state,
            session_state,
            rate_limiters_registry,
        }
    }

    pub const fn id(&self) -> SessionId {
        self.id
    }

    pub const fn session_state(&self) -> &Arc<Mutex<SessionState>> {
        &self.session_state
    }

    pub async fn set_user_info(&self, user_info: AuthStateUserInfo) -> Result<(), WarpgateError> {
        use sea_orm::ActiveValue::Set;

        {
            let mut state = self.session_state.lock().await;
            state.user_info = Some(user_info.clone());
            state.emit_change();
        }

        let db = self.db.lock().await;

        Session::Entity::update_many()
            .set(Session::ActiveModel {
                username: Set(Some(user_info.username)),
                ..Default::default()
            })
            .filter(Session::Column::Id.eq(self.id))
            .exec(&*db)
            .await?;

        drop(db);

        self.update_rate_limiters().await?;

        Ok(())
    }

    pub async fn set_target(&self, target: &Target) -> Result<(), WarpgateError> {
        use sea_orm::ActiveValue::Set;
        let previous_target = {
            let mut state = self.session_state.lock().await;
            let previous_target = state.target.replace(target.clone());
            state.emit_change();
            previous_target
        };

        let Some(user_info) = self.session_state.lock().await.user_info.clone() else {
            return Err(WarpgateError::InconsistentState(
                "set_target called before set_user_info".into(),
            ));
        };

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

        drop(db);

        if previous_target.map(|x| x.id) != Some(target.id) {
            AuditEvent::TargetSessionStarted {
                session_id: self.id,
                target_id: target.id,
                target_name: target.name.clone(),
                user_id: user_info.id,
                username: user_info.username.clone(),
            }
            .emit();
        }

        self.update_rate_limiters().await?;

        Ok(())
    }

    pub async fn wrap_stream(
        &self,
        stream: impl AsyncRead + AsyncWrite + Unpin + Send,
    ) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send, WarpgateError> {
        let (stream, handle) = stack_rate_limiters(stream);
        let mut ss = self.session_state.lock().await;
        self.rate_limiters_registry
            .lock()
            .await
            .update_rate_limiters(&ss, &handle)
            .await?;
        ss.rate_limiter_handles.push(handle);
        Ok(stream)
    }

    async fn update_rate_limiters(&self) -> Result<(), WarpgateError> {
        let mut state = self.session_state.lock().await;
        let mut registry = self.rate_limiters_registry.lock().await;
        registry.update_all_rate_limiters(&mut state).await?;
        Ok(())
    }
}

impl Drop for WarpgateServerHandle {
    fn drop(&mut self) {
        let id = self.id;
        let state = self.state.clone();
        let session_state = self.session_state.clone();
        tokio::spawn(async move {
            // session ID from the span is needed for the audit log to get stored in the DB
            let username = session_state
                .lock()
                .await
                .user_info
                .as_ref()
                .map_or_else(String::new, |x| x.username.clone());
            let span = info_span!("SSH", session=%id, session_username=%username);
            state.lock().await.remove_session(id).instrument(span).await;
        });
    }
}
