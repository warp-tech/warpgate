use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait,
    PaginatorTrait, QueryFilter, Set, TransactionTrait,
};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::{debug, info};
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_db_entities::{
    FailedLoginAttempt, IpBlock, Parameters, User, UserAdminRoleAssignment, UserLockout,
};

use super::cache::{IpBlockInfo, LoginProtectionCache, UserLockInfo};

/// IP rate-limiting thresholds, read from the `parameters` table.
#[derive(Clone, Debug)]
struct IpRateLimitConfig {
    max_attempts: u32,
    time_window_minutes: u32,
    base_block_duration_minutes: u32,
    block_duration_multiplier: f32,
    max_block_duration_hours: u32,
    cooldown_reset_hours: u32,
}

/// User-lockout thresholds, read from the `parameters` table.
#[derive(Clone, Debug)]
struct UserLockoutConfig {
    max_attempts: u32,
    time_window_minutes: u32,
    auto_unlock: bool,
    lockout_duration_minutes: u32,
    /// When set, users holding an admin role are never locked out (so an
    /// attacker can't lock an admin out by spamming their username).
    exempt_admins: bool,
}

/// Snapshot of login-protection settings, read fresh from the DB per call.
#[derive(Clone, Debug)]
struct LoginProtectionConfig {
    enabled: bool,
    retention_days: u32,
    ip_rate_limit: IpRateLimitConfig,
    user_lockout: UserLockoutConfig,
}

/// Information about a failed login attempt.
#[derive(Clone, Debug)]
pub struct FailedAttemptInfo {
    pub username: String,
    pub remote_ip: IpAddr,
    pub protocol: String,
    pub credential_type: String,
}

/// Security status for the admin dashboard.
#[derive(Clone, Debug)]
pub struct SecurityStatus {
    pub blocked_ip_count: u64,
    pub locked_user_count: u64,
    pub failed_attempts_last_hour: u64,
    pub failed_attempts_last_24h: u64,
}

/// Statistics from a cleanup run.
#[derive(Clone, Debug)]
pub struct CleanupStats {
    pub expired_blocks_removed: u64,
    pub expired_lockouts_removed: u64,
    pub old_attempts_removed: u64,
}

/// Central service for login protection logic.
///
/// Thresholds are **never cached** — every method reads `Parameters` from the
/// DB directly, matching the pattern used by every other warpgate parameter
/// (ssh_client_auth_*, ticket_*, record_scp, …). An admin saving new settings
/// takes effect on the very next login attempt with no restart.
///
/// Active blocks/lockouts are mirrored in an in-memory [`LoginProtectionCache`]
/// for the read path; the cache is warmed on startup and updated incrementally
/// as blocks/lockouts are created or cleared.
pub struct LoginProtectionService {
    db: Arc<Mutex<DatabaseConnection>>,
    cache: LoginProtectionCache,
}

impl LoginProtectionService {
    /// Build a [`LoginProtectionConfig`] from a `Parameters` DB row.
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
            },
            user_lockout: UserLockoutConfig {
                max_attempts: params.lp_user_max_attempts as u32,
                time_window_minutes: params.lp_user_time_window_minutes as u32,
                auto_unlock: params.lp_user_auto_unlock,
                lockout_duration_minutes: params.lp_user_lockout_duration_minutes as u32,
                exempt_admins: params.lp_user_exempt_admins,
            },
        }
    }

    /// Read the current config from the DB.
    async fn read_config(db: &DatabaseConnection) -> Result<LoginProtectionConfig, WarpgateError> {
        Ok(Self::config_from_params(
            &Parameters::Entity::get(db).await?,
        ))
    }

    /// Admin status of `username`: `None` if no such user exists, otherwise
    /// `Some(is_admin)`. Used to keep account lockout limited to real, non-admin
    /// accounts — locking a non-existent username is pointless, and admins must
    /// never be lockable by an attacker spamming their username.
    async fn user_admin_status<C: ConnectionTrait>(
        db: &C,
        username: &str,
    ) -> Result<Option<bool>, WarpgateError> {
        let Some(user) = User::Entity::find()
            .filter(User::Entity::username_eq_ci(username))
            .one(db)
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(
            UserAdminRoleAssignment::Entity::find()
                .filter(UserAdminRoleAssignment::Column::UserId.eq(user.id))
                .exists(db)
                .await?,
        ))
    }

    /// Create the service and warm the cache from DB state.
    pub async fn new(db: Arc<Mutex<DatabaseConnection>>) -> Result<Self, WarpgateError> {
        let cache = LoginProtectionCache::new();
        {
            let db_conn = db.lock().await;
            if Self::read_config(&db_conn).await?.enabled {
                cache.load_from_db(&db_conn).await?;
            }
        }
        Ok(Self { db, cache })
    }

    /// Check whether `ip` is currently blocked.
    pub async fn check_ip_blocked(
        &self,
        ip: &IpAddr,
    ) -> Result<Option<IpBlockInfo>, WarpgateError> {
        let db = self.db.lock().await;
        if !Self::read_config(&db).await?.enabled {
            return Ok(None);
        }

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

        let Some(block) = block else {
            return Ok(None);
        };
        let info = IpBlockInfo {
            ip_address: *ip,
            blocked_at: block.blocked_at,
            expires_at: block.expires_at,
            block_count: block.block_count,
            reason: block.reason,
        };
        self.cache.block_ip(*ip, info.clone()).await;
        debug!(ip = %ip, expires_at = %info.expires_at, "IP is blocked (from DB)");
        Ok(Some(info))
    }

    /// Check whether `username` is currently locked. When admin exemption is
    /// enabled, admins are never reported as locked.
    pub async fn check_user_locked(
        &self,
        username: &str,
    ) -> Result<Option<UserLockInfo>, WarpgateError> {
        let db = self.db.lock().await;
        let config = Self::read_config(&db).await?;
        if !config.enabled {
            return Ok(None);
        }

        let info = match self.cache.is_user_locked(username).await {
            Some(info) => Some(info),
            None => {
                let now = OffsetDateTime::now_utc();
                let lockout = UserLockout::Entity::find()
                    .filter(UserLockout::Column::Username.eq(username))
                    .one(&*db)
                    .await?
                    .filter(|l| l.expires_at.is_none_or(|e| e > now));
                match lockout {
                    Some(lockout) => {
                        let info = UserLockInfo {
                            username: lockout.username,
                            locked_at: lockout.locked_at,
                            expires_at: lockout.expires_at,
                            reason: lockout.reason,
                        };
                        self.cache
                            .lock_user(username.to_string(), info.clone())
                            .await;
                        Some(info)
                    }
                    None => None,
                }
            }
        };

        // When exemption is enabled, never report an admin as locked.
        if info.is_some()
            && config.user_lockout.exempt_admins
            && Self::user_admin_status(&*db, username).await? == Some(true)
        {
            return Ok(None);
        }

        if info.is_some() {
            debug!(username = %username, "User is locked");
        }
        Ok(info)
    }

    /// Record a failed login attempt; may trigger an IP block or user lockout.
    pub async fn record_failed_attempt(
        &self,
        attempt: FailedAttemptInfo,
    ) -> Result<(), WarpgateError> {
        let db = self.db.lock().await;
        let config = Self::read_config(&db).await?;
        if !config.enabled {
            return Ok(());
        }

        let txn = db.begin().await?;
        let now = OffsetDateTime::now_utc();

        FailedLoginAttempt::ActiveModel {
            id: Set(Uuid::new_v4()),
            username: Set(attempt.username.clone()),
            remote_ip: Set(attempt.remote_ip.to_string()),
            protocol: Set(attempt.protocol.clone()),
            credential_type: Set(attempt.credential_type.clone()),
            timestamp: Set(now),
        }
        .insert(&txn)
        .await?;

        let ip_window_start =
            now - time::Duration::minutes(config.ip_rate_limit.time_window_minutes as i64);
        let ip_count = FailedLoginAttempt::Entity::find()
            .filter(FailedLoginAttempt::Column::RemoteIp.eq(attempt.remote_ip.to_string()))
            .filter(FailedLoginAttempt::Column::Timestamp.gte(ip_window_start))
            .count(&txn)
            .await?;
        let new_block = if ip_count >= config.ip_rate_limit.max_attempts as u64 {
            Some(Self::create_or_update_ip_block(&txn, &attempt.remote_ip, now, &config).await?)
        } else {
            None
        };

        let user_window_start =
            now - time::Duration::minutes(config.user_lockout.time_window_minutes as i64);
        let user_count = FailedLoginAttempt::Entity::find()
            .filter(FailedLoginAttempt::Column::Username.eq(&attempt.username))
            .filter(FailedLoginAttempt::Column::Timestamp.gte(user_window_start))
            .count(&txn)
            .await?;
        // Lock real accounts over the threshold; skip non-existent usernames and
        // (unless exemption is disabled) admins.
        let new_lock = if user_count >= config.user_lockout.max_attempts as u64 {
            match Self::user_admin_status(&txn, &attempt.username).await? {
                None => None,
                Some(true) if config.user_lockout.exempt_admins => None,
                Some(_) => {
                    Self::create_user_lockout(
                        &txn,
                        &attempt.username,
                        user_count as i32,
                        now,
                        &config,
                    )
                    .await?
                }
            }
        } else {
            None
        };

        txn.commit().await?;
        drop(db);

        // Reflect the new state in the cache without a full reload.
        if let Some(info) = new_block {
            self.cache.block_ip(attempt.remote_ip, info).await;
        }
        if let Some(info) = new_lock {
            self.cache.lock_user(attempt.username.clone(), info).await;
        }

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

    async fn create_or_update_ip_block<C: ConnectionTrait>(
        db: &C,
        ip: &IpAddr,
        now: OffsetDateTime,
        config: &LoginProtectionConfig,
    ) -> Result<IpBlockInfo, WarpgateError> {
        let ip_str = ip.to_string();
        let existing = IpBlock::Entity::find()
            .filter(IpBlock::Column::IpAddress.eq(&ip_str))
            .one(db)
            .await?;

        // Escalate the block count unless the IP has been quiet long enough.
        let cooldown = time::Duration::hours(config.ip_rate_limit.cooldown_reset_hours as i64);
        let block_count = match &existing {
            Some(e) if now - e.last_attempt_at <= cooldown => e.block_count + 1,
            _ => 1,
        };

        let block_duration = calculate_block_duration(block_count as u32, &config.ip_rate_limit);
        let expires_at =
            now + time::Duration::try_from(block_duration).unwrap_or(time::Duration::ZERO);
        let reason = format!(
            "Exceeded {} failed login attempts (block #{block_count})",
            config.ip_rate_limit.max_attempts
        );

        let model = IpBlock::ActiveModel {
            id: Set(existing.as_ref().map_or_else(Uuid::new_v4, |e| e.id)),
            ip_address: Set(ip_str),
            block_count: Set(block_count),
            blocked_at: Set(now),
            expires_at: Set(expires_at),
            reason: Set(reason.clone()),
            last_attempt_at: Set(now),
        };
        if existing.is_some() {
            IpBlock::Entity::update(model).exec(db).await?;
        } else {
            model.insert(db).await?;
        }

        info!(
            ip = %ip,
            block_count,
            duration_minutes = block_duration.as_secs() / 60,
            expires_at = %expires_at,
            "IP blocked"
        );

        Ok(IpBlockInfo {
            ip_address: *ip,
            blocked_at: now,
            expires_at,
            block_count,
            reason,
        })
    }

    async fn create_user_lockout<C: ConnectionTrait>(
        db: &C,
        username: &str,
        failed_count: i32,
        now: OffsetDateTime,
        config: &LoginProtectionConfig,
    ) -> Result<Option<UserLockInfo>, WarpgateError> {
        let already_locked = UserLockout::Entity::find()
            .filter(UserLockout::Column::Username.eq(username))
            .one(db)
            .await?
            .is_some();
        if already_locked {
            return Ok(None);
        }

        let expires_at = config.user_lockout.auto_unlock.then(|| {
            now + time::Duration::minutes(config.user_lockout.lockout_duration_minutes as i64)
        });
        let reason = format!(
            "Exceeded {} failed login attempts",
            config.user_lockout.max_attempts
        );

        UserLockout::ActiveModel {
            id: Set(Uuid::new_v4()),
            username: Set(username.to_string()),
            locked_at: Set(now),
            expires_at: Set(expires_at),
            reason: Set(reason.clone()),
            failed_attempt_count: Set(failed_count),
        }
        .insert(db)
        .await?;

        info!(
            username = %username,
            auto_unlock = config.user_lockout.auto_unlock,
            expires_at = ?expires_at,
            "User account locked"
        );

        Ok(Some(UserLockInfo {
            username: username.to_string(),
            locked_at: now,
            expires_at,
            reason,
        }))
    }

    /// Clear recorded failed attempts after a successful login, so a user who
    /// fumbled their password a few times isn't progressively penalised.
    pub async fn clear_failed_attempts(
        &self,
        ip: &IpAddr,
        username: &str,
    ) -> Result<(), WarpgateError> {
        let db = self.db.lock().await;
        if !Self::read_config(&db).await?.enabled {
            return Ok(());
        }

        FailedLoginAttempt::Entity::delete_many()
            .filter(
                FailedLoginAttempt::Column::RemoteIp
                    .eq(ip.to_string())
                    .or(FailedLoginAttempt::Column::Username.eq(username)),
            )
            .exec(&*db)
            .await?;

        debug!(ip = %ip, username = %username, "Cleared failed attempts after successful login");
        Ok(())
    }

    /// Admin: unblock an IP and clear its attempt history.
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
        info!(ip = %ip, "IP unblocked by admin");
        Ok(())
    }

    /// Admin: unlock a user account and clear its attempt history.
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
        info!(username = %username, "User unlocked by admin");
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

        let failed_attempts_last_hour = FailedLoginAttempt::Entity::find()
            .filter(FailedLoginAttempt::Column::Timestamp.gte(now - time::Duration::hours(1)))
            .count(&*db)
            .await?;

        let failed_attempts_last_24h = FailedLoginAttempt::Entity::find()
            .filter(FailedLoginAttempt::Column::Timestamp.gte(now - time::Duration::hours(24)))
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
        let now = OffsetDateTime::now_utc();
        let blocks = IpBlock::Entity::find()
            .filter(IpBlock::Column::ExpiresAt.gt(now))
            .all(&*db)
            .await?;

        Ok(blocks
            .into_iter()
            .filter_map(|block| {
                let ip = block.ip_address.parse::<IpAddr>().ok()?;
                Some(IpBlockInfo {
                    ip_address: ip,
                    blocked_at: block.blocked_at,
                    expires_at: block.expires_at,
                    block_count: block.block_count,
                    reason: block.reason,
                })
            })
            .collect())
    }

    /// List all currently locked users.
    pub async fn list_locked_users(&self) -> Result<Vec<UserLockInfo>, WarpgateError> {
        let db = self.db.lock().await;
        let now = OffsetDateTime::now_utc();
        let lockouts = UserLockout::Entity::find()
            .filter(
                UserLockout::Column::ExpiresAt
                    .is_null()
                    .or(UserLockout::Column::ExpiresAt.gt(now)),
            )
            .all(&*db)
            .await?;

        Ok(lockouts
            .into_iter()
            .map(|l| UserLockInfo {
                username: l.username,
                locked_at: l.locked_at,
                expires_at: l.expires_at,
                reason: l.reason,
            })
            .collect())
    }

    /// Background cleanup: remove expired blocks, lockouts, and old attempts.
    /// Reads the enabled flag from the DB so it honours runtime config changes.
    pub async fn cleanup_expired(&self) -> Result<CleanupStats, WarpgateError> {
        let db = self.db.lock().await;
        let config = Self::read_config(&db).await?;
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
}

/// Block duration with exponential backoff:
/// `base * multiplier^(block_count - 1)`, capped at the configured maximum.
fn calculate_block_duration(block_count: u32, config: &IpRateLimitConfig) -> Duration {
    let base_secs = config.base_block_duration_minutes as u64 * 60;
    let max_secs = config.max_block_duration_hours as u64 * 3600;
    let factor = config
        .block_duration_multiplier
        .powi(block_count.saturating_sub(1) as i32);
    let duration_secs = (base_secs as f32 * factor) as u64;
    Duration::from_secs(duration_secs.min(max_secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> IpRateLimitConfig {
        IpRateLimitConfig {
            max_attempts: 5,
            time_window_minutes: 15,
            base_block_duration_minutes: 30,
            block_duration_multiplier: 2.0,
            max_block_duration_hours: 24,
            cooldown_reset_hours: 24,
        }
    }

    #[test]
    fn test_calculate_block_duration_first_block() {
        assert_eq!(
            calculate_block_duration(1, &default_config()).as_secs(),
            1800
        );
    }

    #[test]
    fn test_calculate_block_duration_second_block() {
        assert_eq!(
            calculate_block_duration(2, &default_config()).as_secs(),
            3600
        );
    }

    #[test]
    fn test_calculate_block_duration_third_block() {
        assert_eq!(
            calculate_block_duration(3, &default_config()).as_secs(),
            7200
        );
    }

    #[test]
    fn test_calculate_block_duration_fifth_block() {
        assert_eq!(
            calculate_block_duration(5, &default_config()).as_secs(),
            28800
        );
    }

    #[test]
    fn test_calculate_block_duration_capped_at_max() {
        assert_eq!(
            calculate_block_duration(10, &default_config()).as_secs(),
            86400
        );
    }

    #[test]
    fn test_calculate_block_duration_with_different_multiplier() {
        let mut config = default_config();
        config.block_duration_multiplier = 1.5;
        assert_eq!(calculate_block_duration(3, &config).as_secs(), 4050);
    }

    #[test]
    fn test_calculate_block_duration_zero_block_count() {
        assert_eq!(
            calculate_block_duration(0, &default_config()).as_secs(),
            1800
        );
    }
}
