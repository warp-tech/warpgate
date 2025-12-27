use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
    Set, TransactionTrait,
};
use tokio::sync::Mutex;
use tracing::{debug, info};
use uuid::Uuid;
use warpgate_common::{LoginProtectionConfig, WarpgateError};
use warpgate_db_entities::{FailedLoginAttempt, IpBlock, UserLockout};

use super::cache::{IpBlockInfo, LoginProtectionCache, UserLockInfo};

/// Information about a failed login attempt
#[derive(Clone, Debug)]
pub struct FailedAttemptInfo {
    pub username: String,
    pub remote_ip: IpAddr,
    pub protocol: String,
    pub credential_type: String,
}

/// Security status for admin dashboard
#[derive(Clone, Debug)]
pub struct SecurityStatus {
    pub blocked_ip_count: u64,
    pub locked_user_count: u64,
    pub failed_attempts_last_hour: u64,
    pub failed_attempts_last_24h: u64,
}

/// Statistics from cleanup operation
#[derive(Clone, Debug)]
pub struct CleanupStats {
    pub expired_blocks_removed: u64,
    pub expired_lockouts_removed: u64,
    pub old_attempts_removed: u64,
}

/// Central service for login protection logic
pub struct LoginProtectionService {
    config: LoginProtectionConfig,
    db: Arc<Mutex<DatabaseConnection>>,
    cache: LoginProtectionCache,
}

impl LoginProtectionService {
    /// Create service with config and database, initializes cache from DB
    pub async fn new(
        config: LoginProtectionConfig,
        db: Arc<Mutex<DatabaseConnection>>,
    ) -> Result<Self, WarpgateError> {
        let cache = LoginProtectionCache::new();

        if config.enabled {
            let db_conn = db.lock().await;
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

        Ok(Self { config, db, cache })
    }

    /// Check if login protection is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Check if IP is currently blocked, returns block info if blocked
    pub async fn check_ip_blocked(&self, ip: &IpAddr) -> Result<Option<IpBlockInfo>, WarpgateError> {
        if !self.config.enabled {
            return Ok(None);
        }

        // Check cache first
        if let Some(info) = self.cache.is_ip_blocked(ip).await {
            debug!(ip = %ip, expires_at = %info.expires_at, "IP is blocked (from cache)");
            return Ok(Some(info));
        }

        // Check database as fallback (cache might be stale)
        let db = self.db.lock().await;
        let now = Utc::now();
        let block = IpBlock::Entity::find()
            .filter(IpBlock::Column::IpAddress.eq(ip.to_string()))
            .filter(IpBlock::Column::ExpiresAt.gt(now))
            .one(&*db)
            .await?;

        if let Some(block) = block {
            let blocked_message = self
                .config
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
            // Update cache
            self.cache.block_ip(*ip, info.clone()).await;
            debug!(ip = %ip, expires_at = %info.expires_at, "IP is blocked (from DB)");
            return Ok(Some(info));
        }

        Ok(None)
    }

    /// Check if user account is locked, returns lock info if locked
    pub async fn check_user_locked(
        &self,
        username: &str,
    ) -> Result<Option<UserLockInfo>, WarpgateError> {
        if !self.config.enabled {
            return Ok(None);
        }

        // Check cache first
        if let Some(info) = self.cache.is_user_locked(username).await {
            debug!(username = %username, "User is locked (from cache)");
            return Ok(Some(info));
        }

        // Check database as fallback
        let db = self.db.lock().await;
        let now = Utc::now();
        let lockout = UserLockout::Entity::find()
            .filter(UserLockout::Column::Username.eq(username))
            .one(&*db)
            .await?;

        if let Some(lockout) = lockout {
            // Check if lockout is still active
            let is_active = lockout.expires_at.is_none() || lockout.expires_at.unwrap() > now;
            if is_active {
                let locked_message = self
                    .config
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
                // Update cache
                self.cache.lock_user(username.to_string(), info.clone()).await;
                debug!(username = %username, "User is locked (from DB)");
                return Ok(Some(info));
            }
        }

        Ok(None)
    }

    /// Record a failed login attempt, may trigger block/lockout
    pub async fn record_failed_attempt(
        &self,
        attempt: FailedAttemptInfo,
    ) -> Result<(), WarpgateError> {
        if !self.config.enabled {
            return Ok(());
        }

        let db = self.db.lock().await;
        let txn = db.begin().await?;
        let now = Utc::now();

        // 1. Insert failed attempt record
        let record = FailedLoginAttempt::ActiveModel {
            id: Set(Uuid::new_v4()),
            username: Set(attempt.username.clone()),
            remote_ip: Set(attempt.remote_ip.to_string()),
            protocol: Set(attempt.protocol.clone()),
            credential_type: Set(attempt.credential_type.clone()),
            timestamp: Set(now),
        };
        record.insert(&txn).await?;

        // 2. Check IP threshold
        let ip_window_start =
            now - chrono::Duration::minutes(self.config.ip_rate_limit.time_window_minutes as i64);
        let ip_count: u64 = FailedLoginAttempt::Entity::find()
            .filter(FailedLoginAttempt::Column::RemoteIp.eq(attempt.remote_ip.to_string()))
            .filter(FailedLoginAttempt::Column::Timestamp.gte(ip_window_start))
            .count(&txn)
            .await?;

        if ip_count >= self.config.ip_rate_limit.max_attempts as u64 {
            self.create_or_update_ip_block(&txn, &attempt.remote_ip, now)
                .await?;
        }

        // 3. Check user threshold
        let user_window_start =
            now - chrono::Duration::minutes(self.config.user_lockout.time_window_minutes as i64);
        let user_count: u64 = FailedLoginAttempt::Entity::find()
            .filter(FailedLoginAttempt::Column::Username.eq(&attempt.username))
            .filter(FailedLoginAttempt::Column::Timestamp.gte(user_window_start))
            .count(&txn)
            .await?;

        if user_count >= self.config.user_lockout.max_attempts as u64 {
            self.create_user_lockout(&txn, &attempt.username, user_count as i32, now)
                .await?;
        }

        // 4. Commit transaction
        txn.commit().await?;

        // 5. Update cache after successful commit
        drop(db); // Release lock before refreshing cache
        self.refresh_cache().await?;

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

    /// Create or update an IP block with exponential backoff
    async fn create_or_update_ip_block<C: sea_orm::ConnectionTrait>(
        &self,
        db: &C,
        ip: &IpAddr,
        now: DateTime<Utc>,
    ) -> Result<(), WarpgateError> {
        let ip_str = ip.to_string();

        // Check for existing block
        let existing = IpBlock::Entity::find()
            .filter(IpBlock::Column::IpAddress.eq(&ip_str))
            .one(db)
            .await?;

        let (block_count, new_block) = if let Some(existing) = existing {
            // Check if cooldown period has passed - reset block count
            let cooldown_duration =
                chrono::Duration::hours(self.config.ip_rate_limit.cooldown_reset_hours as i64);
            let block_count = if now - existing.last_attempt_at > cooldown_duration {
                1 // Reset to first block
            } else {
                existing.block_count + 1
            };
            (block_count, false)
        } else {
            (1, true)
        };

        let block_duration = calculate_block_duration(block_count as u32, &self.config.ip_rate_limit);
        let expires_at = now + block_duration;

        if new_block {
            let record = IpBlock::ActiveModel {
                id: Set(Uuid::new_v4()),
                ip_address: Set(ip_str),
                block_count: Set(block_count),
                blocked_at: Set(now),
                expires_at: Set(expires_at),
                reason: Set(format!(
                    "Exceeded {} failed login attempts",
                    self.config.ip_rate_limit.max_attempts
                )),
                last_attempt_at: Set(now),
            };
            record.insert(db).await?;
        } else {
            // Update existing block
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
                    self.config.ip_rate_limit.max_attempts, block_count
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

    /// Create a user lockout record
    async fn create_user_lockout<C: sea_orm::ConnectionTrait>(
        &self,
        db: &C,
        username: &str,
        failed_count: i32,
        now: DateTime<Utc>,
    ) -> Result<(), WarpgateError> {
        // Check for existing lockout
        let existing = UserLockout::Entity::find()
            .filter(UserLockout::Column::Username.eq(username))
            .one(db)
            .await?;

        if existing.is_some() {
            // Already locked, don't create another
            return Ok(());
        }

        let expires_at = if self.config.user_lockout.auto_unlock {
            Some(
                now + chrono::Duration::minutes(
                    self.config.user_lockout.lockout_duration_minutes as i64,
                ),
            )
        } else {
            None // Manual unlock required
        };

        let record = UserLockout::ActiveModel {
            id: Set(Uuid::new_v4()),
            username: Set(username.to_string()),
            locked_at: Set(now),
            expires_at: Set(expires_at),
            reason: Set(format!(
                "Exceeded {} failed login attempts",
                self.config.user_lockout.max_attempts
            )),
            failed_attempt_count: Set(failed_count),
        };
        record.insert(db).await?;

        info!(
            username = %username,
            auto_unlock = self.config.user_lockout.auto_unlock,
            expires_at = ?expires_at,
            "User account locked"
        );

        Ok(())
    }

    /// Clear failed attempts after successful login
    pub async fn clear_failed_attempts(
        &self,
        ip: &IpAddr,
        username: &str,
    ) -> Result<(), WarpgateError> {
        if !self.config.enabled {
            return Ok(());
        }

        // Clear attempt counters in cache
        self.cache.clear_ip_attempts(ip).await;
        self.cache.clear_user_attempts(username).await;

        debug!(ip = %ip, username = %username, "Cleared failed attempt counters");
        Ok(())
    }

    /// Admin: Unblock an IP address
    /// Also deletes associated failed login attempts to prevent immediate re-blocking
    pub async fn unblock_ip(&self, ip: &IpAddr) -> Result<(), WarpgateError> {
        let db = self.db.lock().await;

        // Delete block from database
        IpBlock::Entity::delete_many()
            .filter(IpBlock::Column::IpAddress.eq(ip.to_string()))
            .exec(&*db)
            .await?;

        // Delete failed login attempts for this IP so they don't count toward next block
        FailedLoginAttempt::Entity::delete_many()
            .filter(FailedLoginAttempt::Column::RemoteIp.eq(ip.to_string()))
            .exec(&*db)
            .await?;

        drop(db);

        // Remove from cache and clear attempt counter
        self.cache.unblock_ip(ip).await;
        self.cache.clear_ip_attempts(ip).await;

        info!(ip = %ip, "IP unblocked by admin (attempt records cleared)");
        Ok(())
    }

    /// Admin: Unlock a user account
    /// Also deletes associated failed login attempts to prevent immediate re-locking
    pub async fn unlock_user(&self, username: &str) -> Result<(), WarpgateError> {
        let db = self.db.lock().await;

        // Delete lockout from database
        UserLockout::Entity::delete_many()
            .filter(UserLockout::Column::Username.eq(username))
            .exec(&*db)
            .await?;

        // Delete failed login attempts for this user so they don't count toward next lockout
        FailedLoginAttempt::Entity::delete_many()
            .filter(FailedLoginAttempt::Column::Username.eq(username))
            .exec(&*db)
            .await?;

        drop(db);

        // Remove from cache and clear attempt counter
        self.cache.unlock_user(username).await;
        self.cache.clear_user_attempts(username).await;

        info!(username = %username, "User unlocked by admin (attempt records cleared)");
        Ok(())
    }

    /// Get current security status for admin UI
    pub async fn get_security_status(&self) -> Result<SecurityStatus, WarpgateError> {
        let db = self.db.lock().await;
        let now = Utc::now();

        // Count active blocked IPs
        let blocked_ip_count = IpBlock::Entity::find()
            .filter(IpBlock::Column::ExpiresAt.gt(now))
            .count(&*db)
            .await?;

        // Count active locked users
        let locked_user_count = UserLockout::Entity::find()
            .filter(
                UserLockout::Column::ExpiresAt
                    .is_null()
                    .or(UserLockout::Column::ExpiresAt.gt(now)),
            )
            .count(&*db)
            .await?;

        // Count failed attempts in last hour
        let one_hour_ago = now - chrono::Duration::hours(1);
        let failed_attempts_last_hour = FailedLoginAttempt::Entity::find()
            .filter(FailedLoginAttempt::Column::Timestamp.gte(one_hour_ago))
            .count(&*db)
            .await?;

        // Count failed attempts in last 24 hours
        let one_day_ago = now - chrono::Duration::hours(24);
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

    /// List all currently blocked IPs
    pub async fn list_blocked_ips(&self) -> Result<Vec<IpBlockInfo>, WarpgateError> {
        let db = self.db.lock().await;
        let now = Utc::now();

        let blocks = IpBlock::Entity::find()
            .filter(IpBlock::Column::ExpiresAt.gt(now))
            .all(&*db)
            .await?;

        let blocked_message = self
            .config
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

    /// List all currently locked users
    pub async fn list_locked_users(&self) -> Result<Vec<UserLockInfo>, WarpgateError> {
        let db = self.db.lock().await;
        let now = Utc::now();

        let lockouts = UserLockout::Entity::find()
            .filter(
                UserLockout::Column::ExpiresAt
                    .is_null()
                    .or(UserLockout::Column::ExpiresAt.gt(now)),
            )
            .all(&*db)
            .await?;

        let locked_message = self
            .config
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

    /// Background task: cleanup expired records
    pub async fn cleanup_expired(&self) -> Result<CleanupStats, WarpgateError> {
        if !self.config.enabled {
            return Ok(CleanupStats {
                expired_blocks_removed: 0,
                expired_lockouts_removed: 0,
                old_attempts_removed: 0,
            });
        }

        let db = self.db.lock().await;
        let now = Utc::now();

        // Delete expired IP blocks
        let expired_blocks = IpBlock::Entity::delete_many()
            .filter(IpBlock::Column::ExpiresAt.lt(now))
            .exec(&*db)
            .await?;

        // Delete expired user lockouts (only those with expiry set)
        let expired_lockouts = UserLockout::Entity::delete_many()
            .filter(UserLockout::Column::ExpiresAt.is_not_null())
            .filter(UserLockout::Column::ExpiresAt.lt(now))
            .exec(&*db)
            .await?;

        // Delete old failed login attempts beyond retention period
        let retention_cutoff =
            now - chrono::Duration::days(self.config.retention_days as i64);
        let old_attempts = FailedLoginAttempt::Entity::delete_many()
            .filter(FailedLoginAttempt::Column::Timestamp.lt(retention_cutoff))
            .exec(&*db)
            .await?;

        drop(db);

        // Clear expired entries from cache
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

    /// Refresh cache from database
    async fn refresh_cache(&self) -> Result<(), WarpgateError> {
        let db = self.db.lock().await;
        let blocked_message = self
            .config
            .ip_rate_limit
            .blocked_message
            .clone()
            .unwrap_or_else(|| {
                "Your IP has been temporarily blocked due to too many failed login attempts."
                    .to_string()
            });
        let locked_message = self
            .config
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

/// Calculate block duration with exponential backoff
/// Formula: base * multiplier^(block_count - 1), capped at max
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
        let duration = calculate_block_duration(1, &config);
        // First block: 30 min * 2^0 = 30 min = 1800 sec
        assert_eq!(duration.as_secs(), 1800);
    }

    #[test]
    fn test_calculate_block_duration_second_block() {
        let config = default_config();
        let duration = calculate_block_duration(2, &config);
        // Second block: 30 min * 2^1 = 60 min = 3600 sec
        assert_eq!(duration.as_secs(), 3600);
    }

    #[test]
    fn test_calculate_block_duration_third_block() {
        let config = default_config();
        let duration = calculate_block_duration(3, &config);
        // Third block: 30 min * 2^2 = 120 min = 7200 sec
        assert_eq!(duration.as_secs(), 7200);
    }

    #[test]
    fn test_calculate_block_duration_fifth_block() {
        let config = default_config();
        let duration = calculate_block_duration(5, &config);
        // Fifth block: 30 min * 2^4 = 480 min = 8 hours = 28800 sec
        assert_eq!(duration.as_secs(), 28800);
    }

    #[test]
    fn test_calculate_block_duration_capped_at_max() {
        let config = default_config();
        let duration = calculate_block_duration(10, &config);
        // 10th block would be: 30 min * 2^9 = 15360 min = 256 hours
        // But max is 24 hours = 86400 sec
        assert_eq!(duration.as_secs(), 86400);
    }

    #[test]
    fn test_calculate_block_duration_with_different_multiplier() {
        let mut config = default_config();
        config.block_duration_multiplier = 1.5;
        let duration = calculate_block_duration(3, &config);
        // Third block: 30 min * 1.5^2 = 30 * 2.25 = 67.5 min = 4050 sec
        assert_eq!(duration.as_secs(), 4050);
    }

    #[test]
    fn test_calculate_block_duration_zero_block_count() {
        let config = default_config();
        let duration = calculate_block_duration(0, &config);
        // Zero defaults to base duration
        assert_eq!(duration.as_secs(), 1800);
    }
}
