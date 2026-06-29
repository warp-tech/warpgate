use std::collections::HashMap;
use std::net::IpAddr;

use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use time::OffsetDateTime;
use tokio::sync::RwLock;
use warpgate_common::WarpgateError;
use warpgate_db_entities::{IpBlock, UserLockout};

/// Information about a blocked IP.
#[derive(Clone, Debug)]
pub struct IpBlockInfo {
    pub ip_address: IpAddr,
    pub blocked_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub block_count: i32,
    pub reason: String,
}

/// Information about a locked user.
#[derive(Clone, Debug)]
pub struct UserLockInfo {
    pub username: String,
    pub locked_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
    pub reason: String,
}

/// In-memory cache of active blocks and lockouts for fast read-path checks.
///
/// The cache only mirrors the *currently active* blocks/lockouts so that the
/// common case (a check that finds nothing) never touches the database. It is
/// kept in sync incrementally: warmed once on startup, then updated in place
/// whenever a block/lockout is created or cleared — never reloaded wholesale.
#[derive(Default)]
pub struct LoginProtectionCache {
    blocked_ips: RwLock<HashMap<IpAddr, IpBlockInfo>>,
    locked_users: RwLock<HashMap<String, UserLockInfo>>,
}

impl LoginProtectionCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Warm the cache with active blocks and lockouts from the database.
    pub async fn load_from_db(&self, db: &DatabaseConnection) -> Result<(), WarpgateError> {
        let now = OffsetDateTime::now_utc();

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
                        reason: block.reason,
                    },
                );
            }
        }
        drop(blocked_ips);

        let lockouts = UserLockout::Entity::find().all(db).await?;

        let mut locked_users = self.locked_users.write().await;
        locked_users.clear();
        for lockout in lockouts {
            if lockout.expires_at.is_none_or(|e| e > now) {
                locked_users.insert(
                    lockout.username.clone(),
                    UserLockInfo {
                        username: lockout.username,
                        locked_at: lockout.locked_at,
                        expires_at: lockout.expires_at,
                        reason: lockout.reason,
                    },
                );
            }
        }

        Ok(())
    }

    /// Return the active block for `ip`, if any.
    pub async fn is_ip_blocked(&self, ip: &IpAddr) -> Option<IpBlockInfo> {
        let now = OffsetDateTime::now_utc();
        self.blocked_ips
            .read()
            .await
            .get(ip)
            .filter(|info| info.expires_at > now)
            .cloned()
    }

    /// Return the active lockout for `username`, if any.
    pub async fn is_user_locked(&self, username: &str) -> Option<UserLockInfo> {
        let now = OffsetDateTime::now_utc();
        self.locked_users
            .read()
            .await
            .get(username)
            .filter(|info| info.expires_at.is_none_or(|e| e > now))
            .cloned()
    }

    /// Record a block in the cache.
    pub async fn block_ip(&self, ip: IpAddr, info: IpBlockInfo) {
        self.blocked_ips.write().await.insert(ip, info);
    }

    /// Record a lockout in the cache.
    pub async fn lock_user(&self, username: String, info: UserLockInfo) {
        self.locked_users.write().await.insert(username, info);
    }

    /// Remove a block from the cache.
    pub async fn unblock_ip(&self, ip: &IpAddr) {
        self.blocked_ips.write().await.remove(ip);
    }

    /// Remove a lockout from the cache.
    pub async fn unlock_user(&self, username: &str) {
        self.locked_users.write().await.remove(username);
    }

    /// Drop expired entries from the cache.
    pub async fn clear_expired(&self) {
        let now = OffsetDateTime::now_utc();
        self.blocked_ips
            .write()
            .await
            .retain(|_, info| info.expires_at > now);
        self.locked_users
            .write()
            .await
            .retain(|_, info| info.expires_at.is_none_or(|e| e > now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip_block(expires_at: OffsetDateTime) -> IpBlockInfo {
        IpBlockInfo {
            ip_address: "192.168.1.1".parse().unwrap(),
            blocked_at: OffsetDateTime::now_utc(),
            expires_at,
            block_count: 1,
            reason: "test".to_string(),
        }
    }

    fn user_lock(expires_at: Option<OffsetDateTime>) -> UserLockInfo {
        UserLockInfo {
            username: "testuser".to_string(),
            locked_at: OffsetDateTime::now_utc(),
            expires_at,
            reason: "test".to_string(),
        }
    }

    #[tokio::test]
    async fn test_is_ip_blocked_returns_none_for_expired() {
        let cache = LoginProtectionCache::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        cache
            .block_ip(
                ip,
                ip_block(OffsetDateTime::now_utc() - time::Duration::hours(1)),
            )
            .await;
        assert!(cache.is_ip_blocked(&ip).await.is_none());
    }

    #[tokio::test]
    async fn test_is_ip_blocked_returns_some_for_active() {
        let cache = LoginProtectionCache::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        cache
            .block_ip(
                ip,
                ip_block(OffsetDateTime::now_utc() + time::Duration::hours(1)),
            )
            .await;
        assert!(cache.is_ip_blocked(&ip).await.is_some());
    }

    #[tokio::test]
    async fn test_is_user_locked_returns_none_for_expired() {
        let cache = LoginProtectionCache::new();
        cache
            .lock_user(
                "testuser".to_string(),
                user_lock(Some(OffsetDateTime::now_utc() - time::Duration::hours(1))),
            )
            .await;
        assert!(cache.is_user_locked("testuser").await.is_none());
    }

    #[tokio::test]
    async fn test_is_user_locked_returns_some_for_permanent() {
        let cache = LoginProtectionCache::new();
        cache
            .lock_user("testuser".to_string(), user_lock(None))
            .await;
        assert!(cache.is_user_locked("testuser").await.is_some());
    }

    #[tokio::test]
    async fn test_block_ip_and_unblock_ip() {
        let cache = LoginProtectionCache::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        cache
            .block_ip(
                ip,
                ip_block(OffsetDateTime::now_utc() + time::Duration::hours(1)),
            )
            .await;
        assert!(cache.is_ip_blocked(&ip).await.is_some());

        cache.unblock_ip(&ip).await;
        assert!(cache.is_ip_blocked(&ip).await.is_none());
    }
}
