use std::num::NonZero;
use std::sync::Arc;

use governor::clock::{Clock, QuantaClock, QuantaInstant};
use governor::{DefaultDirectRateLimiter, NotUntil};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use tokio::sync::Mutex;
use warpgate_common::{SessionId, Target, WarpgateError};
use warpgate_db_entities::Session;

use crate::{SessionState, State};

pub trait SessionHandle {
    fn close(&mut self);
}

pub struct WarpgateRateLimiterHandle {
    rate_limiter: DefaultDirectRateLimiter,
}

impl WarpgateRateLimiterHandle {
    pub fn now() -> QuantaInstant {
        QuantaClock::default().now().into()
    }

    pub(crate) fn new(rate_limiter: DefaultDirectRateLimiter) -> Self {
        WarpgateRateLimiterHandle { rate_limiter }
    }

    pub fn check(&self) -> Result<(), NotUntil<QuantaInstant>> {
        self.rate_limiter.check()
    }

    pub async fn until_bytes_ready(&self, bytes: usize) -> Result<(), WarpgateError> {
        let bytes = match NonZero::new(bytes as u32) {
            Some(bytes) => bytes,
            None => return Ok(()),
        };
        self.rate_limiter.until_n_ready(bytes).await?;
        Ok(())
    }
}

pub struct WarpgateServerHandle {
    id: SessionId,
    db: Arc<Mutex<DatabaseConnection>>,
    state: Arc<Mutex<State>>,
    session_state: Arc<Mutex<SessionState>>,
    rate_limiter: Arc<WarpgateRateLimiterHandle>,
}

impl WarpgateServerHandle {
    pub fn new(
        id: SessionId,
        db: Arc<Mutex<DatabaseConnection>>,
        state: Arc<Mutex<State>>,
        session_state: Arc<Mutex<SessionState>>,
    ) -> Self {
        WarpgateServerHandle {
            id: id.clone(),
            db,
            state,
            session_state,
            rate_limiter: Arc::new(WarpgateRateLimiterHandle::new(
                DefaultDirectRateLimiter::direct(governor::Quota::per_second(
                    NonZero::try_from(50u32).unwrap(),
                )),
            )),
        }
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

    pub fn rate_limiter(&self) -> &Arc<WarpgateRateLimiterHandle> {
        &self.rate_limiter
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
