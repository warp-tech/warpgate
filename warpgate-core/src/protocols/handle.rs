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
            let state = self.session_state.lock().await;
            // Kubernetes reuses one session handle for many requests. Avoid emitting a
            // change and writing the same username to the session row for every request.
            if state.user_info.as_ref() == Some(&user_info) {
                return Ok(());
            }
        }

        let db = &self.db;

        Session::Entity::update_many()
            .set(Session::ActiveModel {
                username: Set(Some(user_info.username.clone())),
                ..Default::default()
            })
            .filter(Session::Column::Id.eq(self.id))
            .exec(db)
            .await?;

        let previous_user_info = {
            let mut state = self.session_state.lock().await;
            state.user_info.replace(user_info)
        };

        if let Err(error) = self.update_rate_limiters().await {
            self.session_state.lock().await.user_info = previous_user_info;
            return Err(error);
        }
        self.session_state.lock().await.emit_change();

        Ok(())
    }

    pub async fn set_target(&self, target: &Target) -> Result<(), WarpgateError> {
        use sea_orm::ActiveValue::Set;

        let user_info = {
            let state = self.session_state.lock().await;
            // Do not emit a change if the target is the same as the previous one.
            if state.target.as_ref() == Some(target) {
                return Ok(());
            }

            state.user_info.clone().ok_or_else(|| {
                WarpgateError::InconsistentState("set_target called before set_user_info".into())
            })?
        };

        let db = &self.db;

        Session::Entity::update_many()
            .set(Session::ActiveModel {
                target_snapshot: Set(Some(
                    serde_json::to_string(&target).map_err(WarpgateError::other)?,
                )),
                ..Default::default()
            })
            .filter(Session::Column::Id.eq(self.id))
            .exec(db)
            .await?;

        let previous_target = {
            let mut state = self.session_state.lock().await;
            state.target.replace(target.clone())
        };

        if let Err(error) = self.update_rate_limiters().await {
            self.session_state.lock().await.target = previous_target;
            return Err(error);
        }
        self.session_state.lock().await.emit_change();

        if previous_target.as_ref().map(|x| x.id) != Some(target.id) {
            AuditEvent::TargetSessionStarted {
                session_id: self.id,
                target_id: target.id,
                target_name: target.name.clone(),
                user_id: user_info.id,
                username: user_info.username.clone(),
            }
            .emit();
        }

        Ok(())
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
