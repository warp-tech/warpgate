use std::collections::HashMap;
use std::sync::Arc;

use sea_orm::{DatabaseConnection, EntityTrait};
use tokio::sync::Mutex;
use tracing::debug;
use uuid::Uuid;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{Target as TargetConfig, WarpgateError};
use warpgate_db_entities::{Parameters, Target, User};

use super::shared_limiter::SharedWarpgateRateLimiter;
use super::{RateLimiterStackHandle, WarpgateRateLimiter};
use crate::{State, UserSessionState};

pub struct RateLimiterRegistry {
    db: DatabaseConnection,
    global_rate_limiter: SharedWarpgateRateLimiter,
    user_rate_limiters: HashMap<Uuid, SharedWarpgateRateLimiter>,
    target_rate_limiters: HashMap<Uuid, SharedWarpgateRateLimiter>,
}

impl RateLimiterRegistry {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            db,
            global_rate_limiter: WarpgateRateLimiter::unlimited(),
            user_rate_limiters: HashMap::new(),
            target_rate_limiters: HashMap::new(),
        }
    }

    // TODO granular refresh
    pub async fn refresh(&self) -> Result<(), WarpgateError> {
        let global_quota = self.global_quota().await?;
        self.global_rate_limiter.lock().replace(global_quota)?;

        for (user_id, limiter) in &self.user_rate_limiters {
            let quota = self.quota_for_user(user_id).await?;
            limiter.lock().replace(quota)?;
        }
        for (target_id, limiter) in &self.target_rate_limiters {
            let quota = self.quota_for_target(target_id).await?;
            limiter.lock().replace(quota)?;
        }
        Ok(())
    }

    pub fn global(&self) -> SharedWarpgateRateLimiter {
        self.global_rate_limiter.clone()
    }

    async fn global_quota(&self) -> Result<Option<u32>, WarpgateError> {
        let db = &self.db;
        let parameters = Parameters::Entity::get(db).await?;
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
        #[allow(clippy::unwrap_used, reason = "just inserted")]
        Ok(self.user_rate_limiters.get(user_id).unwrap().clone())
    }

    async fn quota_for_user(&self, user_id: &Uuid) -> Result<Option<u32>, WarpgateError> {
        let db = &self.db;
        let user = User::Entity::find_by_id(*user_id).one(db).await?;
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
        #[allow(clippy::unwrap_used, reason = "just inserted")]
        Ok(self.target_rate_limiters.get(target_id).unwrap().clone())
    }

    async fn quota_for_target(&self, target_id: &Uuid) -> Result<Option<u32>, WarpgateError> {
        let db = &self.db;
        let target = Target::Entity::find_by_id(*target_id).one(db).await?;
        Ok(target
            .and_then(|t| t.rate_limit_bytes_per_second)
            .map(|r| r as u32))
    }

    /// Re-derives the user, target, and global limits onto every stream of
    /// one session, from the session's own state — the target cell mirrors
    /// `state.target`, which is never unset once a target session starts.
    pub async fn update_session_rate_limiters(
        &mut self,
        state: &mut UserSessionState,
    ) -> Result<(), WarpgateError> {
        let handles = std::mem::take(&mut state.rate_limiter_handles);
        let result = async {
            for handle in &handles {
                self.update_user_rate_limiter(state.user_info.as_ref(), handle)
                    .await?;
                self.update_target_rate_limiter(state.target.as_ref(), handle)
                    .await?;
                self.update_global_rate_limiter(handle)?;
            }
            Ok(())
        }
        .await;
        state.rate_limiter_handles = handles;
        result
    }

    pub async fn update_user_rate_limiter(
        &mut self,
        user_info: Option<&AuthStateUserInfo>,
        handle: &RateLimiterStackHandle,
    ) -> Result<(), WarpgateError> {
        if let Some(user_info) = user_info {
            let user_limiter = self.user(&user_info.id).await?;
            debug!("Setting user rate limit {user_limiter:?}");
            handle.user.replace(Some(user_limiter));
        } else {
            handle.user.replace(None);
        }

        let global = self.global();
        debug!("Setting global rate limit {global:?}");
        handle.global.replace(Some(global));

        Ok(())
    }

    async fn update_target_rate_limiter(
        &mut self,
        target: Option<&TargetConfig>,
        handle: &RateLimiterStackHandle,
    ) -> Result<(), WarpgateError> {
        if let Some(target) = target {
            let target_limiter = self.target(&target.id).await?;
            debug!("Setting target rate limit {target_limiter:?}");
            handle.target.replace(Some(target_limiter));
        } else {
            handle.target.replace(None);
        }

        Ok(())
    }

    fn update_global_rate_limiter(
        &mut self,
        handle: &RateLimiterStackHandle,
    ) -> Result<(), WarpgateError> {
        let global = self.global();
        debug!("Setting global rate limit {global:?}");
        handle.global.replace(Some(global));

        Ok(())
    }
}

/// Force refresh all rate limiters in all sessions.
///
/// Lock order within each session is session state first, then the registry —
/// the same order `WarpgateServerHandle::wrap_stream` uses on every new
/// stream; taking them in the reverse order here would deadlock. The global
/// `State` lock is released before any session is locked so a stuck session
/// can't block session registration.
pub async fn apply_new_rate_limits(
    registry: &Arc<Mutex<RateLimiterRegistry>>,
    state: &Arc<Mutex<State>>,
) -> Result<(), WarpgateError> {
    // Refresh the global rate limiter
    registry.lock().await.refresh().await?;

    let user_sessions: Vec<_> = {
        let state = state.lock().await;
        state.user_sessions.values().cloned().collect()
    };
    for session_state in user_sessions {
        let mut session_state = session_state.lock().await;
        registry
            .lock()
            .await
            .update_session_rate_limiters(&mut session_state)
            .await?;
    }
    Ok(())
}
