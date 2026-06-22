use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
    Set, TransactionTrait,
};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::{debug, info};
use uuid::Uuid;
use warpgate_common::{IpRateLimitConfig, LoginProtectionConfig, UserLockoutConfig, WarpgateError};
use warpgate_db_entities::{FailedLoginAttempt, IpBlock, Parameters, UserLockout};

use super::cache::{IpBlockInfo, LoginProtectionCache, UserLockInfo};

/// Information about a failed login attempt.
#[derive(Clone, Debug)]
pub struct FailedAttemptInfo {
    pub username: String,
    pub remote_ip: IpAddr,
    pub protocol: String,
    pub credential_type: String,
}

/// Security status for admin dashboard.
#[derive(Clone, Debug)]
pub struct SecurityStatus {
    pub blocked_ip_count: u64,
    pub locked_user_count: u64,
    pub failed_attempts_last_hour: u64,
    pub failed_attempts_last_24h: u64,
}

/// Statistics from cleanup operation.
#[derive(Clone, Debug)]
pub struct CleanupStats {
    pub expired_blocks_removed: u64,
    pub expired_lockouts_removed: u64,
    pub old_attempts_removed: u64,
}

/// Central service for login protection logic.
///
/// Config is **never cached** — every method that needs thresholds reads
/// `Parameters` from the DB directly, matching the same pattern used by every
/// other warpgate parameter (ssh_client_auth_*, ticket_*, record_scp, etc.).
/// This means an admin saving new LP settings in the UI takes effect on the
/// very next login attempt with zero restart required.
pub struct LoginProtectionService {
    db: Arc<Mutex<DatabaseConnection>>,
    cache: LoginProtectionCache,
}

impl LoginProtectionService {
    /// Build a `LoginProtectionConfig` from a `Parameters` DB row.
    fn config_from_params(params: &Parameters::Model) -> LoginProtectionConfig {
        LoginProtectionConfig {
            enabled: params.login_protection_enabled,
            retention_days: params.login_protection_retention_days as u32,
            ip_rate_limit: IpRateLimitConfig {
                max_attempts: params.lp_ip_max_attempts as u32,
                time_window_minutes: params.lp_ip_time_window_minutes as u32,
                base_block_duration_minutes: params.lp_ip_base_block_duration_minutes as u32,
                block_duration_multiplier: params.lp_ip_block_duration_multiplier as f32,
                max_block_duration_hours: params.lp_ip_max_block_duration_hours as u32,
                cooldown_reset_hours: params.lp_ip_cooldown_reset_hours as u32,
                blocked_message: params.lp_ip_blocked_message.clone(),
            },
            user_lockout: UserLockoutConfig {
                max_attempts: params.lp_user_max_attempts as u32,
                time_window_minutes: params.lp_user_time_window_minutes as u32,
                auto_unlock: params.lp_user_auto_unlock,
                lockout_duration_minutes: params.lp_user_lockout_duration_minutes as u32,
                locked_message: params.lp_user_locked_message.clone(),
            },
        }
    }

    /// Read current config from the DB (same approach as all other warpgate parameters).
    async fn read_config(
        db: &DatabaseConnection,
    ) -> Result<LoginProtectionConfig, WarpgateError> {
        let params = Parameters::Entity::get(db).await?;
        Ok(Self::config_from_params(&params))
    }

    /// Create service, warm the cache from DB state.
    pub async fn new(
        db: Arc<Mutex<DatabaseConnection>>,
    ) -> Result<Self, WarpgateError> {
        let cache = LoginProtectionCache::new();

        // Warm cache with any existing blocks/lockouts from a previous run.
        {
            let db_conn = db.lock().await;
            let config = Self::read_config(&*db_conn).await?;
            if config.enabled {
                let blocked_message = config
                    .ip_rate_limit
                    .blocked_message
                    .clone()
                    .unwrap_or_else(|| {
                        "Your IP has been temporarily blocked due to too many failed login attempts."
                            .to_string()
                    });
                let locked_message = config
                    .user_lockout
                    .locked_message
                    .clone()
                    .unwrap_or_else(|| {
                        "Your account has been locked due to too many failed login attempts."
                            .to_string()
                    });
                cache
                    .load_from_db(&*db_conn, &blocked_message, &locked_message)
                    .await?;
            }
        }

        Ok(Self { db, cache })
    }

    /// Check if IP is currently blocked; returns block info if blocked.
    pub async fn check_ip_blocked(&self, ip: &IpAddr) -> Result<Option<IpBlockInfo>, WarpgateError> {
        let db = self.db.lock().await;
        let config = Self::read_config(&*db).await?;
        if !config.enabled {
            return Ok(None);
        }

        // Cache-first; fall back to DB.
        if let Some(info) = self.cache.is_ip_blocked(ip).await {
            debug!(ip = %ip, expires_at = %info.expires_at, "IP is blocked (from cache)");
            return Ok(Some(info));
        }

        let now = OffsetDateTime::now_utc();
        let block = IpBlock::Entity::find()
            .filter(IpBlock::Column::IpAddress.eq(ip.to_string()))
            .filter(IpBlock::Column::ExpiresAt.gt(now))
            .one(&*db)
            .await?;

        if let Some(block) = block {
            let blocked_message = config
                .ip_rate_limit
                .blocked_message
                .clone()
                .unwrap_or_else(|| {
                    "Your IP has been temporarily blocked due to too many failed login attempts."
                        .to_string()
                });
            let info = IpBlockInfo {
                ip_address: *ip,
                blocked_at: block.blocked_at,
                expires_at: block.expires_at,
                block_count: block.block_count,
                reason: block.reason.clone(),
                message: blocked_message,
            };
            self.cache.block_ip(*ip, info.clone()).await;
            debug!(ip = %ip, expires_at = %info.expires_at, "IP is blocked (from DB)");
            return Ok(Some(info));
        }

        Ok(None)
    }

    /// Check if user account is locked; returns lock info if locked.
    pub async fn check_user_locked(
        &self,
        username: &str,
    ) -> Result<Option<UserLockInfo>, WarpgateError> {
        let db = self.db.lock().await;
        let config = Self::read_config(&*db).await?;
        if !config.enabled {
            return Ok(None);
        }

        if let Some(info) = self.cache.is_user_locked(username).await {
            debug!(username = %username, "User is locked (from cache)");
            return Ok(Some(info));
        }

        let db_conn = &*db;
        let now = OffsetDateTime::now_utc();
        let lockout = UserLockout::Entity::find()
            .filter(UserLockout::Column::Username.eq(username))
            .one(db_conn)
            .await?;

        if let Some(lockout) = lockout {
            let is_active = lockout.expires_at.is_none() || lockout.expires_at.unwrap() > now;
            if is_active {
                let locked_message = config
                    .user_lockout
                    .locked_message
                    .clone()
                    .unwrap_or_else(|| {
                        "Your account has been locked due to too many failed login attempts."
                            .to_string()
                    });
                let info = UserLockInfo {
                    username: lockout.username.clone(),
                    locked_at: lockout.locked_at,
                    expires_at: lockout.expires_at,
                    reason: lockout.reason.clone(),
                    message: locked_message,
                };
                self.cache.lock_user(username.to_string(), info.clone()).await;
                debug!(username = %username, "User is locked (from DB)");
                return Ok(Some(info));
            }
        }

        Ok(None)
    }

    /// Record a failed login attempt; may trigger IP block or user lockout.
    pub async fn record_failed_attempt(
        &self,
        attempt: FailedAttemptInfo,
    ) -> Result<(), WarpgateError> {
        let db = self.db.lock().await;
        // Read config once — consistent snapshot for this transaction.
        let config = Self::read_config(&*db).await?;
        if !config.enabled {
            return Ok(());
        }

        let txn = db.begin().await?;
        let now = OffsetDateTime::now_utc();

        // Insert failed attempt record.
        let record = FailedLoginAttempt::ActiveModel {
            id: Set(Uuid::new_v4()),
            username: Set(attempt.username.clone()),
            remote_ip: Set(attempt.remote_ip.to_string()),
            protocol: Set(attempt.protocol.clone()),
            credential_type: Set(attempt.credential_type.clone()),
            timestamp: Set(now),
        };
        record.insert(&txn).await?;

        // Check IP threshold.
        let ip_window_start =
            now - time::Duration::minutes(config.ip_rate_limit.time_window_minutes as i64);
        let ip_count: u64 = FailedLoginAttempt::Entity::find()
            .filter(FailedLoginAttempt::Column::RemoteIp.eq(attempt.remote_ip.to_string()))
            .filter(FailedLoginAttempt::Column::Timestamp.gte(ip_window_start))
            .count(&txn)
            .await?;

        if ip_count >= config.ip_rate_limit.max_attempts as u64 {
            Self::create_or_update_ip_block(&txn, &attempt.remote_ip, now, &config).await?;
        }

        // Check user threshold.
        let user_window_start =
            now - time::Duration::minutes(config.user_lockout.time_window_minutes as i64);
        let user_count: u64 = FailedLoginAttempt::Entity::find()
            .filter(FailedLoginAttempt::Column::Username.eq(&attempt.username))
            .filter(FailedLoginAttempt::Column::Timestamp.gte(user_window_start))
            .count(&txn)
            .await?;

        if user_count >= config.user_lockout.max_attempts as u64 {
            Self::create_user_lockout(&txn, &attempt.username, user_count as i32, now, &config)
                .await?;
        }

        txn.commit().await?;

        // Refresh cache after commit.
        drop(db);
        self.refresh_cache(&config).await?;

        info!(
            ip = %attempt.remote_ip,
            username = %attempt.username,
            protocol = %attempt.protocol,
            ip_attempt_count = ip_count,
            user_attempt_count = user_count,
            "Recorded failed login attempt"
        );

        Ok(())
    }

    async fn create_or_update_ip_block<C: sea_orm::ConnectionTrait>(
        db: &C,
        ip: &IpAddr,
        now: OffsetDateTime,
        config: &LoginProtectionConfig,
    ) -> Result<(), WarpgateError> {
        let ip_str = ip.to_string();

        let existing = IpBlock::Entity::find()
            .filter(IpBlock::Column::IpAddress.eq(&ip_str))
            .one(db)
            .await?;

        let (block_count, new_block) = if let Some(existing) = existing {
            let cooldown_duration =
                time::Duration::hours(config.ip_rate_limit.cooldown_reset_hours as i64);
            let block_count = if now - existing.last_attempt_at > cooldown_duration {
                1
            } else {
                existing.block_count + 1
            };
            (block_count, false)
        } else {
            (1, true)
        };

        let block_duration = calculate_block_duration(block_count as u32, &config.ip_rate_limit);
        let expires_at =
            now + time::Duration::try_from(block_duration).unwrap_or(time::Duration::ZERO);

        if new_block {
            let record = IpBlock::ActiveModel {
                id: Set(Uuid::new_v4()),
                ip_address: Set(ip_str),
                block_count: Set(block_count),
                blocked_at: Set(now),
                expires_at: Set(expires_at),
                reason: Set(format!(
                    "Exceeded {} failed login attempts",
                    config.ip_rate_limit.max_attempts
                )),
                last_attempt_at: Set(now),
            };
            record.insert(db).await?;
        } else {
            let record = IpBlock::ActiveModel {
                id: Set(
                    IpBlock::Entity::find()
                        .filter(IpBlock::Column::IpAddress.eq(&ip.to_string()))
                        .one(db)
                        .await?
                        .map(|b| b.id)
                        .unwrap_or_else(Uuid::new_v4),
                ),
                ip_address: Set(ip.to_string()),
                block_count: Set(block_count),
                blocked_at: Set(now),
                expires_at: Set(expires_at),
                reason: Set(format!(
                    "Exceeded {} failed login attempts (block #{})",
                    config.ip_rate_limit.max_attempts, block_count
                )),
                last_attempt_at: Set(now),
            };
            IpBlock::Entity::update(record).exec(db).await?;
        }

        info!(
            ip = %ip,
            block_count = block_count,
            duration_minutes = block_duration.as_secs() / 60,
            expires_at = %expires_at,
            "IP blocked"
        );

        Ok(())
    }

    async fn create_user_lockout<C: sea_orm::ConnectionTrait>(
        db: &C,
        username: &str,
        failed_count: i32,
        now: OffsetDateTime,
        config: &LoginProtectionConfig,
    ) -> Result<(), WarpgateError> {
        let existing = UserLockout::Entity::find()
            .filter(UserLockout::Column::Username.eq(username))
            .one(db)
            .await?;

        if existing.is_some() {
            return Ok(());
        }

        let expires_at = if config.user_lockout.auto_unlock {
            Some(
                now + time::Duration::minutes(
                    config.user_lockout.lockout_duration_minutes as i64,
                ),
            )
        } else {
            None
        };

        let record = UserLockout::ActiveModel {
            id: Set(Uuid::new_v4()),
            username: Set(username.to_string()),
            locked_at: Set(now),
            expires_at: Set(expires_at),
            reason: Set(format!(
                "Exceeded {} failed login attempts",
                config.user_lockout.max_attempts
            )),
            failed_attempt_count: Set(failed_count),
        };
        record.insert(db).await?;

        info!(
            username = %username,
            auto_unlock = config.user_lockout.auto_unlock,
            expires_at = ?expires_at,
            "User account locked"
        );

        Ok(())
    }

    /// Clear failed attempts after a successful login.
    pub async fn clear_failed_attempts(
        &self,
        ip: &IpAddr,
        username: &str,
    ) -> Result<(), WarpgateError> {
        let db = self.db.lock().await;
        let config = Self::read_config(&*db).await?;
        if !config.enabled {
            return Ok(());
        }
        drop(db);

        self.cache.clear_ip_attempts(ip).await;
        self.cache.clear_user_attempts(username).await;

        debug!(ip = %ip, username = %username, "Cleared failed attempt counters");
        Ok(())
    }

    /// Admin: Unblock an IP; also removes attempt records so it gets a clean counter.
    pub async fn unblock_ip(&self, ip: &IpAddr) -> Result<(), WarpgateError> {
        let db = self.db.lock().await;

        IpBlock::Entity::delete_many()
            .filter(IpBlock::Column::IpAddress.eq(ip.to_string()))
            .exec(&*db)
            .await?;

        FailedLoginAttempt::Entity::delete_many()
            .filter(FailedLoginAttempt::Column::RemoteIp.eq(ip.to_string()))
            .exec(&*db)
            .await?;

        drop(db);

        self.cache.unblock_ip(ip).await;
        self.cache.clear_ip_attempts(ip).await;

        info!(ip = %ip, "IP unblocked by admin (attempt records cleared)");
        Ok(())
    }

    /// Admin: Unlock a user account; also removes attempt records.
    pub async fn unlock_user(&self, username: &str) -> Result<(), WarpgateError> {
        let db = self.db.lock().await;

        UserLockout::Entity::delete_many()
            .filter(UserLockout::Column::Username.eq(username))
            .exec(&*db)
            .await?;

        FailedLoginAttempt::Entity::delete_many()
            .filter(FailedLoginAttempt::Column::Username.eq(username))
            .exec(&*db)
            .await?;

        drop(db);

        self.cache.unlock_user(username).await;
        self.cache.clear_user_attempts(username).await;

        info!(username = %username, "User unlocked by admin (attempt records cleared)");
        Ok(())
    }

    /// Security status for the admin dashboard.
    pub async fn get_security_status(&self) -> Result<SecurityStatus, WarpgateError> {
        let db = self.db.lock().await;
        let now = OffsetDateTime::now_utc();

        let blocked_ip_count = IpBlock::Entity::find()
            .filter(IpBlock::Column::ExpiresAt.gt(now))
            .count(&*db)
            .await?;

        let locked_user_count = UserLockout::Entity::find()
            .filter(
                UserLockout::Column::ExpiresAt
                    .is_null()
                    .or(UserLockout::Column::ExpiresAt.gt(now)),
            )
            .count(&*db)
            .await?;

        let one_hour_ago = now - time::Duration::hours(1);
        let failed_attempts_last_hour = FailedLoginAttempt::Entity::find()
            .filter(FailedLoginAttempt::Column::Timestamp.gte(one_hour_ago))
            .count(&*db)
            .await?;

        let one_day_ago = now - time::Duration::hours(24);
        let failed_attempts_last_24h = FailedLoginAttempt::Entity::find()
            .filter(FailedLoginAttempt::Column::Timestamp.gte(one_day_ago))
            .count(&*db)
            .await?;

        Ok(SecurityStatus {
            blocked_ip_count,
            locked_user_count,
            failed_attempts_last_hour,
            failed_attempts_last_24h,
        })
    }

    /// List all currently blocked IPs.
    pub async fn list_blocked_ips(&self) -> Result<Vec<IpBlockInfo>, WarpgateError> {
        let db = self.db.lock().await;
        let config = Self::read_config(&*db).await?;
        let now = OffsetDateTime::now_utc();

        let blocks = IpBlock::Entity::find()
            .filter(IpBlock::Column::ExpiresAt.gt(now))
            .all(&*db)
            .await?;

        let blocked_message = config
            .ip_rate_limit
            .blocked_message
            .clone()
            .unwrap_or_else(|| {
                "Your IP has been temporarily blocked due to too many failed login attempts."
                    .to_string()
            });

        let mut result = Vec::new();
        for block in blocks {
            if let Ok(ip) = block.ip_address.parse::<IpAddr>() {
                result.push(IpBlockInfo {
                    ip_address: ip,
                    blocked_at: block.blocked_at,
                    expires_at: block.expires_at,
                    block_count: block.block_count,
                    reason: block.reason,
                    message: blocked_message.clone(),
                });
            }
        }

        Ok(result)
    }

    /// List all currently locked users.
    pub async fn list_locked_users(&self) -> Result<Vec<UserLockInfo>, WarpgateError> {
        let db = self.db.lock().await;
        let config = Self::read_config(&*db).await?;
        let now = OffsetDateTime::now_utc();

        let lockouts = UserLockout::Entity::find()
            .filter(
                UserLockout::Column::ExpiresAt
                    .is_null()
                    .or(UserLockout::Column::ExpiresAt.gt(now)),
            )
            .all(&*db)
            .await?;

        let locked_message = config
            .user_lockout
            .locked_message
            .clone()
            .unwrap_or_else(|| {
                "Your account has been locked due to too many failed login attempts.".to_string()
            });

        Ok(lockouts
            .into_iter()
            .map(|l| UserLockInfo {
                username: l.username,
                locked_at: l.locked_at,
                expires_at: l.expires_at,
                reason: l.reason,
                message: locked_message.clone(),
            })
            .collect())
    }

    /// Background cleanup: remove expired blocks, lockouts, and old attempt records.
    /// Reads LP enabled flag from DB each time, so it honours runtime config changes.
    pub async fn cleanup_expired(&self) -> Result<CleanupStats, WarpgateError> {
        let db = self.db.lock().await;
        let config = Self::read_config(&*db).await?;
        if !config.enabled {
            return Ok(CleanupStats {
                expired_blocks_removed: 0,
                expired_lockouts_removed: 0,
                old_attempts_removed: 0,
            });
        }

        let now = OffsetDateTime::now_utc();

        let expired_blocks = IpBlock::Entity::delete_many()
            .filter(IpBlock::Column::ExpiresAt.lt(now))
            .exec(&*db)
            .await?;

        let expired_lockouts = UserLockout::Entity::delete_many()
            .filter(UserLockout::Column::ExpiresAt.is_not_null())
            .filter(UserLockout::Column::ExpiresAt.lt(now))
            .exec(&*db)
            .await?;

        let retention_cutoff = now - time::Duration::days(config.retention_days as i64);
        let old_attempts = FailedLoginAttempt::Entity::delete_many()
            .filter(FailedLoginAttempt::Column::Timestamp.lt(retention_cutoff))
            .exec(&*db)
            .await?;

        drop(db);
        self.cache.clear_expired().await;

        let stats = CleanupStats {
            expired_blocks_removed: expired_blocks.rows_affected,
            expired_lockouts_removed: expired_lockouts.rows_affected,
            old_attempts_removed: old_attempts.rows_affected,
        };

        if stats.expired_blocks_removed > 0
            || stats.expired_lockouts_removed > 0
            || stats.old_attempts_removed > 0
        {
            info!(
                expired_blocks = stats.expired_blocks_removed,
                expired_lockouts = stats.expired_lockouts_removed,
                old_attempts = stats.old_attempts_removed,
                "Login protection cleanup completed"
            );
        }

        Ok(stats)
    }

    async fn refresh_cache(&self, config: &LoginProtectionConfig) -> Result<(), WarpgateError> {
        let db = self.db.lock().await;
        let blocked_message = config
            .ip_rate_limit
            .blocked_message
            .clone()
            .unwrap_or_else(|| {
                "Your IP has been temporarily blocked due to too many failed login attempts."
                    .to_string()
            });
        let locked_message = config
            .user_lockout
            .locked_message
            .clone()
            .unwrap_or_else(|| {
                "Your account has been locked due to too many failed login attempts.".to_string()
            });
        self.cache
            .refresh_from_db(&*db, &blocked_message, &locked_message)
            .await
    }
}

/// Calculate block duration with exponential backoff.
/// Formula: base * multiplier^(block_count - 1), capped at max.
pub fn calculate_block_duration(
    block_count: u32,
    config: &warpgate_common::IpRateLimitConfig,
) -> Duration {
    let base_secs = config.base_block_duration_minutes as u64 * 60;
    let max_secs = config.max_block_duration_hours as u64 * 3600;

    if block_count == 0 {
        return Duration::from_secs(base_secs);
    }

    let factor = config.block_duration_multiplier.powi((block_count - 1) as i32);
    let duration_secs = (base_secs as f32 * factor) as u64;

    Duration::from_secs(std::cmp::min(duration_secs, max_secs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use warpgate_common::IpRateLimitConfig;

    fn default_config() -> IpRateLimitConfig {
        IpRateLimitConfig {
            max_attempts: 5,
            time_window_minutes: 15,
            base_block_duration_minutes: 30,
            block_duration_multiplier: 2.0,
            max_block_duration_hours: 24,
            cooldown_reset_hours: 24,
            blocked_message: None,
        }
    }

    #[test]
    fn test_calculate_block_duration_first_block() {
        let config = default_config();
        assert_eq!(calculate_block_duration(1, &config).as_secs(), 1800);
    }

    #[test]
    fn test_calculate_block_duration_second_block() {
        let config = default_config();
        assert_eq!(calculate_block_duration(2, &config).as_secs(), 3600);
    }

    #[test]
    fn test_calculate_block_duration_third_block() {
        let config = default_config();
        assert_eq!(calculate_block_duration(3, &config).as_secs(), 7200);
    }

    #[test]
    fn test_calculate_block_duration_fifth_block() {
        let config = default_config();
        assert_eq!(calculate_block_duration(5, &config).as_secs(), 28800);
    }

    #[test]
    fn test_calculate_block_duration_capped_at_max() {
        let config = default_config();
        assert_eq!(calculate_block_duration(10, &config).as_secs(), 86400);
    }

    #[test]
    fn test_calculate_block_duration_with_different_multiplier() {
        let mut config = default_config();
        config.block_duration_multiplier = 1.5;
        assert_eq!(calculate_block_duration(3, &config).as_secs(), 4050);
    }

    #[test]
    fn test_calculate_block_duration_zero_block_count() {
        let config = default_config();
        assert_eq!(calculate_block_duration(0, &config).as_secs(), 1800);
    }
}
