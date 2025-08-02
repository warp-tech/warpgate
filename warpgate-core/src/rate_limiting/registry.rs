use std::collections::HashMap;
use std::sync::Arc;

use sea_orm::{DatabaseConnection, EntityTrait};
use tokio::sync::Mutex;
use tracing::debug;
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_db_entities::{Parameters, Target, User};

use super::shared_limiter::SharedWarpgateRateLimiter;
use super::{RateLimiterStackHandle, WarpgateRateLimiter};
use crate::{SessionState, State};

pub struct RateLimiterRegistry {
    db: Arc<Mutex<DatabaseConnection>>,
    global_rate_limiter: SharedWarpgateRateLimiter,
    user_rate_limiters: HashMap<Uuid, SharedWarpgateRateLimiter>,
    target_rate_limiters: HashMap<Uuid, SharedWarpgateRateLimiter>,
}

impl RateLimiterRegistry {
    pub fn new(db: Arc<Mutex<DatabaseConnection>>) -> Self {
        Self {
            db,
            global_rate_limiter: WarpgateRateLimiter::unlimited(),
            user_rate_limiters: HashMap::new(),
            target_rate_limiters: HashMap::new(),
        }
    }

    // TODO granular refresh
    pub async fn refresh(&mut self) -> Result<(), WarpgateError> {
        let global_quota = self.global_quota().await?;
        self.global_rate_limiter.lock().replace(global_quota)?;

        for (user_id, limiter) in self.user_rate_limiters.iter() {
            let quota = self.quota_for_user(user_id).await?;
            limiter.lock().replace(quota)?;
        }
        for (target_id, limiter) in self.target_rate_limiters.iter() {
            let quota = self.quota_for_target(target_id).await?;
            limiter.lock().replace(quota)?;
        }
        Ok(())
    }

    pub fn global(&self) -> SharedWarpgateRateLimiter {
        self.global_rate_limiter.clone()
    }

    async fn global_quota(&mut self) -> Result<Option<u32>, WarpgateError> {
        let db = self.db.lock().await;
        let parameters = Parameters::Entity::get(&db).await?;
        Ok(parameters.rate_limit_bytes_per_second.map(|x| x as u32))
    }

    pub async fn user(
        &mut self,
        user_id: &Uuid,
    ) -> Result<SharedWarpgateRateLimiter, WarpgateError> {
        if !self.user_rate_limiters.contains_key(user_id) {
            let quota = self.quota_for_user(user_id).await?;
            let rate_limiter = WarpgateRateLimiter::new(quota)?;
            self.user_rate_limiters.insert(*user_id, rate_limiter);
        }
        Ok(self.user_rate_limiters.get(user_id).unwrap().clone())
    }

    async fn quota_for_user(&self, user_id: &Uuid) -> Result<Option<u32>, WarpgateError> {
        let db = self.db.lock().await;
        let user = User::Entity::find_by_id(*user_id).one(&*db).await?;
        Ok(user
            .and_then(|u| u.rate_limit_bytes_per_second)
            .map(|r| r as u32))
    }

    pub async fn target(
        &mut self,
        target_id: &Uuid,
    ) -> Result<SharedWarpgateRateLimiter, WarpgateError> {
        if !self.target_rate_limiters.contains_key(target_id) {
            let quota = self.quota_for_target(target_id).await?;
            let rate_limiter = WarpgateRateLimiter::new(quota)?;
            self.target_rate_limiters.insert(*target_id, rate_limiter);
        }
        Ok(self.target_rate_limiters.get(target_id).unwrap().clone())
    }

    async fn quota_for_target(&self, target_id: &Uuid) -> Result<Option<u32>, WarpgateError> {
        let db = self.db.lock().await;
        let target = Target::Entity::find_by_id(*target_id).one(&*db).await?;
        Ok(target
            .and_then(|t| t.rate_limit_bytes_per_second)
            .map(|r| r as u32))
    }

    pub async fn update_all_rate_limiters(
        &mut self,
        state: &mut SessionState,
    ) -> Result<(), WarpgateError> {
        // TODO figure something out so that handles do not get lost if update_rate_limiters fails for whatever reason
        let mut handles = std::mem::take(&mut state.rate_limiter_handles);
        for handle in handles.iter_mut() {
            self.update_rate_limiters(state, handle).await?;
        }
        state.rate_limiter_handles = handles;
        Ok(())
    }

    pub async fn update_rate_limiters(
        &mut self,
        state: &SessionState,
        handle: &mut RateLimiterStackHandle,
    ) -> Result<(), WarpgateError> {
        if let Some(user_info) = &state.user_info {
            let user_limiter = self.user(&user_info.id).await?;
            debug!("Setting user rate limit {user_limiter:?}");
            handle.user.replace(Some(user_limiter));
        } else {
            handle.user.replace(None);
        }

        if let Some(target) = &state.target {
            let target_limiter = self.target(&target.id).await?;
            debug!("Setting user rate limit {target_limiter:?}");
            handle.target.replace(Some(target_limiter));
        } else {
            handle.target.replace(None);
        }

        let global = self.global();
        debug!("Setting global rate limit {global:?}");
        handle.global.replace(Some(global));

        Ok(())
    }

    /// Force refresh all rate limiters in all sessions
    pub async fn apply_new_rate_limits(&mut self, state: &mut State) -> Result<(), WarpgateError> {
        // Refresh the global rate limiter
        self.refresh().await?;

        // Update all session rate limiters
        for session_state in state.sessions.values() {
            let mut session_state = session_state.lock().await;
            self.update_all_rate_limiters(&mut session_state).await?;
        }
        Ok(())
    }
}
