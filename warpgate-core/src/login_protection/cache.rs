use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use tokio::sync::RwLock;
use warpgate_common::WarpgateError;
use warpgate_db_entities::{IpBlock, UserLockout};

/// Information about a blocked IP
#[derive(Clone, Debug)]
pub struct IpBlockInfo {
    pub ip_address: IpAddr,
    pub blocked_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub block_count: i32,
    pub reason: String,
    pub message: String,
}

/// Information about a locked user
#[derive(Clone, Debug)]
pub struct UserLockInfo {
    pub username: String,
    pub locked_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub reason: String,
    pub message: String,
}

/// Counter for tracking attempts within a time window
#[derive(Clone, Debug, Default)]
pub struct AttemptCounter {
    pub count: u32,
    pub window_start: Option<DateTime<Utc>>,
}

/// In-memory cache for fast lookups during attacks
pub struct LoginProtectionCache {
    blocked_ips: RwLock<HashMap<IpAddr, IpBlockInfo>>,
    locked_users: RwLock<HashMap<String, UserLockInfo>>,
    ip_attempt_counts: RwLock<HashMap<IpAddr, AttemptCounter>>,
    user_attempt_counts: RwLock<HashMap<String, AttemptCounter>>,
}

impl LoginProtectionCache {
    pub fn new() -> Self {
        Self {
            blocked_ips: RwLock::new(HashMap::new()),
            locked_users: RwLock::new(HashMap::new()),
            ip_attempt_counts: RwLock::new(HashMap::new()),
            user_attempt_counts: RwLock::new(HashMap::new()),
        }
    }

    /// Load active blocks and lockouts from database on startup
    pub async fn load_from_db(
        &self,
        db: &DatabaseConnection,
        default_blocked_message: &str,
        default_locked_message: &str,
    ) -> Result<(), WarpgateError> {
        let now = Utc::now();

        // Load active IP blocks
        let blocks = IpBlock::Entity::find()
            .filter(IpBlock::Column::ExpiresAt.gt(now))
            .all(db)
            .await?;

        let mut blocked_ips = self.blocked_ips.write().await;
        blocked_ips.clear();
        for block in blocks {
            if let Ok(ip) = block.ip_address.parse::<IpAddr>() {
                blocked_ips.insert(
                    ip,
                    IpBlockInfo {
                        ip_address: ip,
                        blocked_at: block.blocked_at,
                        expires_at: block.expires_at,
                        block_count: block.block_count,
                        reason: block.reason.clone(),
                        message: default_blocked_message.to_string(),
                    },
                );
            }
        }

        // Load active user lockouts
        let lockouts = UserLockout::Entity::find().all(db).await?;

        let mut locked_users = self.locked_users.write().await;
        locked_users.clear();
        for lockout in lockouts {
            // Only include if no expiry or expiry is in the future
            if lockout.expires_at.is_none() || lockout.expires_at.unwrap() > now {
                locked_users.insert(
                    lockout.username.clone(),
                    UserLockInfo {
                        username: lockout.username.clone(),
                        locked_at: lockout.locked_at,
                        expires_at: lockout.expires_at,
                        reason: lockout.reason.clone(),
                        message: default_locked_message.to_string(),
                    },
                );
            }
        }

        Ok(())
    }

    /// Refresh cache after database changes
    pub async fn refresh_from_db(
        &self,
        db: &DatabaseConnection,
        default_blocked_message: &str,
        default_locked_message: &str,
    ) -> Result<(), WarpgateError> {
        self.load_from_db(db, default_blocked_message, default_locked_message)
            .await
    }

    /// Check if an IP is blocked, returning None if not blocked or expired
    pub async fn is_ip_blocked(&self, ip: &IpAddr) -> Option<IpBlockInfo> {
        let blocked_ips = self.blocked_ips.read().await;
        if let Some(info) = blocked_ips.get(ip) {
            if info.expires_at > Utc::now() {
                return Some(info.clone());
            }
        }
        None
    }

    /// Check if a user is locked, returning None if not locked or expired
    pub async fn is_user_locked(&self, username: &str) -> Option<UserLockInfo> {
        let locked_users = self.locked_users.read().await;
        if let Some(info) = locked_users.get(username) {
            // If no expiry, it's a permanent lock (until admin unlocks)
            if info.expires_at.is_none() {
                return Some(info.clone());
            }
            // If expiry is in the future, still locked
            if info.expires_at.unwrap() > Utc::now() {
                return Some(info.clone());
            }
        }
        None
    }

    /// Increment IP attempt counter within time window, returns new count
    pub async fn increment_ip_attempts(
        &self,
        ip: &IpAddr,
        time_window_minutes: u32,
    ) -> u32 {
        let mut counts = self.ip_attempt_counts.write().await;
        let counter = counts.entry(*ip).or_default();
        let now = Utc::now();

        // Reset counter if window has expired
        if let Some(window_start) = counter.window_start {
            let window_duration = chrono::Duration::minutes(time_window_minutes as i64);
            if now - window_start > window_duration {
                counter.count = 0;
                counter.window_start = Some(now);
            }
        } else {
            counter.window_start = Some(now);
        }

        counter.count += 1;
        counter.count
    }

    /// Increment user attempt counter within time window, returns new count
    pub async fn increment_user_attempts(
        &self,
        username: &str,
        time_window_minutes: u32,
    ) -> u32 {
        let mut counts = self.user_attempt_counts.write().await;
        let counter = counts.entry(username.to_string()).or_default();
        let now = Utc::now();

        // Reset counter if window has expired
        if let Some(window_start) = counter.window_start {
            let window_duration = chrono::Duration::minutes(time_window_minutes as i64);
            if now - window_start > window_duration {
                counter.count = 0;
                counter.window_start = Some(now);
            }
        } else {
            counter.window_start = Some(now);
        }

        counter.count += 1;
        counter.count
    }

    /// Add an IP to the blocked list
    pub async fn block_ip(&self, ip: IpAddr, info: IpBlockInfo) {
        let mut blocked_ips = self.blocked_ips.write().await;
        blocked_ips.insert(ip, info);
    }

    /// Add a user to the locked list
    pub async fn lock_user(&self, username: String, info: UserLockInfo) {
        let mut locked_users = self.locked_users.write().await;
        locked_users.insert(username, info);
    }

    /// Remove an IP from the blocked list
    pub async fn unblock_ip(&self, ip: &IpAddr) {
        let mut blocked_ips = self.blocked_ips.write().await;
        blocked_ips.remove(ip);
        // Also clear the attempt counter
        let mut counts = self.ip_attempt_counts.write().await;
        counts.remove(ip);
    }

    /// Remove a user from the locked list
    pub async fn unlock_user(&self, username: &str) {
        let mut locked_users = self.locked_users.write().await;
        locked_users.remove(username);
        // Also clear the attempt counter
        let mut counts = self.user_attempt_counts.write().await;
        counts.remove(username);
    }

    /// Clear expired entries from the cache
    pub async fn clear_expired(&self) {
        let now = Utc::now();

        // Clear expired IP blocks
        let mut blocked_ips = self.blocked_ips.write().await;
        blocked_ips.retain(|_, info| info.expires_at > now);

        // Clear expired user lockouts
        let mut locked_users = self.locked_users.write().await;
        locked_users.retain(|_, info| {
            info.expires_at.is_none() || info.expires_at.unwrap() > now
        });
    }

    /// Clear IP attempt counter after successful login
    pub async fn clear_ip_attempts(&self, ip: &IpAddr) {
        let mut counts = self.ip_attempt_counts.write().await;
        counts.remove(ip);
    }

    /// Clear user attempt counter after successful login
    pub async fn clear_user_attempts(&self, username: &str) {
        let mut counts = self.user_attempt_counts.write().await;
        counts.remove(username);
    }

    /// Get all currently blocked IPs
    pub async fn list_blocked_ips(&self) -> Vec<IpBlockInfo> {
        let now = Utc::now();
        let blocked_ips = self.blocked_ips.read().await;
        blocked_ips
            .values()
            .filter(|info| info.expires_at > now)
            .cloned()
            .collect()
    }

    /// Get all currently locked users
    pub async fn list_locked_users(&self) -> Vec<UserLockInfo> {
        let now = Utc::now();
        let locked_users = self.locked_users.read().await;
        locked_users
            .values()
            .filter(|info| info.expires_at.is_none() || info.expires_at.unwrap() > now)
            .cloned()
            .collect()
    }
}

impl Default for LoginProtectionCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_is_ip_blocked_returns_none_for_expired() {
        let cache = LoginProtectionCache::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Add an expired block
        let info = IpBlockInfo {
            ip_address: ip,
            blocked_at: Utc::now() - chrono::Duration::hours(2),
            expires_at: Utc::now() - chrono::Duration::hours(1),
            block_count: 1,
            reason: "test".to_string(),
            message: "test".to_string(),
        };
        cache.block_ip(ip, info).await;

        // Should return None because it's expired
        assert!(cache.is_ip_blocked(&ip).await.is_none());
    }

    #[tokio::test]
    async fn test_is_ip_blocked_returns_some_for_active() {
        let cache = LoginProtectionCache::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Add an active block
        let info = IpBlockInfo {
            ip_address: ip,
            blocked_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            block_count: 1,
            reason: "test".to_string(),
            message: "test".to_string(),
        };
        cache.block_ip(ip, info).await;

        // Should return Some because it's still active
        assert!(cache.is_ip_blocked(&ip).await.is_some());
    }

    #[tokio::test]
    async fn test_is_user_locked_returns_none_for_expired() {
        let cache = LoginProtectionCache::new();

        // Add an expired lockout
        let info = UserLockInfo {
            username: "testuser".to_string(),
            locked_at: Utc::now() - chrono::Duration::hours(2),
            expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
            reason: "test".to_string(),
            message: "test".to_string(),
        };
        cache.lock_user("testuser".to_string(), info).await;

        // Should return None because it's expired
        assert!(cache.is_user_locked("testuser").await.is_none());
    }

    #[tokio::test]
    async fn test_is_user_locked_returns_some_for_permanent() {
        let cache = LoginProtectionCache::new();

        // Add a permanent lockout (no expiry)
        let info = UserLockInfo {
            username: "testuser".to_string(),
            locked_at: Utc::now(),
            expires_at: None,
            reason: "test".to_string(),
            message: "test".to_string(),
        };
        cache.lock_user("testuser".to_string(), info).await;

        // Should return Some because it's permanent
        assert!(cache.is_user_locked("testuser").await.is_some());
    }

    #[tokio::test]
    async fn test_block_ip_and_unblock_ip() {
        let cache = LoginProtectionCache::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Block IP
        let info = IpBlockInfo {
            ip_address: ip,
            blocked_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            block_count: 1,
            reason: "test".to_string(),
            message: "test".to_string(),
        };
        cache.block_ip(ip, info).await;
        assert!(cache.is_ip_blocked(&ip).await.is_some());

        // Unblock IP
        cache.unblock_ip(&ip).await;
        assert!(cache.is_ip_blocked(&ip).await.is_none());
    }

    #[tokio::test]
    async fn test_increment_ip_attempts() {
        let cache = LoginProtectionCache::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // First attempt
        let count = cache.increment_ip_attempts(&ip, 15).await;
        assert_eq!(count, 1);

        // Second attempt
        let count = cache.increment_ip_attempts(&ip, 15).await;
        assert_eq!(count, 2);
    }
}
