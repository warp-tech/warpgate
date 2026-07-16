use std::sync::Arc;

use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tracing::{Instrument, info_span};
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{SessionId, Target, WarpgateError};
use warpgate_db_entities::Session;

use crate::logging::AuditEvent;
use crate::rate_limiting::{RateLimiterRegistry, stack_rate_limiters};
use crate::{SessionState, State};

pub trait SessionHandle {
    fn close(&mut self);
}

#[derive(Clone)]
pub struct WarpgateServerHandle {
    id: SessionId,
    db: DatabaseConnection,
    state: Arc<Mutex<State>>,
    session_state: Arc<Mutex<SessionState>>,
    rate_limiters_registry: Arc<Mutex<RateLimiterRegistry>>,
}

impl WarpgateServerHandle {
    pub const fn new(
        id: SessionId,
        db: DatabaseConnection,
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
            // Kubernetes reuses one session handle for many concurrent requests, so
            // most calls are no-ops, and the lock must span the no-op check and the
            // commit to keep the DB and in-memory state consistent.
            let mut state = self.session_state.lock().await;
            if state.user_info.as_ref() == Some(&user_info) {
                return Ok(());
            }

            Session::Entity::update_many()
                .set(Session::ActiveModel {
                    username: Set(Some(user_info.username.clone())),
                    ..Default::default()
                })
                .filter(Session::Column::Id.eq(self.id))
                .exec(&self.db)
                .await?;

            state.user_info = Some(user_info);
            state.emit_change();
        }

        self.update_rate_limiters().await
    }

    pub async fn set_target(&self, target: &Target) -> Result<(), WarpgateError> {
        use sea_orm::ActiveValue::Set;

        {
            let mut state = self.session_state.lock().await;
            if state.target.as_ref() == Some(target) {
                return Ok(());
            }

            let user_info = state.user_info.clone().ok_or_else(|| {
                WarpgateError::InconsistentState("set_target called before set_user_info".into())
            })?;

            Session::Entity::update_many()
                .set(Session::ActiveModel {
                    target_snapshot: Set(Some(
                        serde_json::to_string(&target).map_err(WarpgateError::other)?,
                    )),
                    ..Default::default()
                })
                .filter(Session::Column::Id.eq(self.id))
                .exec(&self.db)
                .await?;

            let previous_target = state.target.replace(target.clone());
            state.emit_change();

            if previous_target.map(|x| x.id) != Some(target.id) {
                AuditEvent::TargetSessionStarted {
                    session_id: self.id,
                    target_id: target.id,
                    target_name: target.name.clone(),
                    user_id: user_info.id,
                    username: user_info.username,
                }
                .emit();
            }
        }

        self.update_rate_limiters().await
    }

    pub async fn wrap_stream<S>(
        &self,
        stream: S,
    ) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send + use<S>, WarpgateError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
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
