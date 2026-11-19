use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use pgwire::messages::ProtocolVersion;
use pgwire::messages::startup::SecretKey;
use warpgate_common::TargetPostgresOptions;

/// Where a cancel key handed out to a client actually points to.
#[derive(Clone)]
pub struct CancelTarget {
    pub options: TargetPostgresOptions,
    pub pid: i32,
    pub secret_key: SecretKey,
}

/// Cancel keys issued to clients, shared by all PostgreSQL sessions.
///
/// A client cancels a running query by opening a new connection and sending
/// the pid and secret key from BackendKeyData. Warpgate never passes the
/// target's key through: it issues its own random key per session and
/// remembers which target backend it stands for.
#[derive(Clone, Default)]
pub struct CancelRegistry {
    keys: Arc<Mutex<HashMap<(i32, Bytes), CancelTarget>>>,
}

impl CancelRegistry {
    /// Replaces the target's key with a new random one in the format of the
    /// client's protocol version and registers the mapping.
    pub fn issue(&self, client_protocol: ProtocolVersion, target: CancelTarget) -> CancelKeyGuard {
        let secret_key = if client_protocol == ProtocolVersion::PROTOCOL3_0 {
            SecretKey::I32(rand::random::<i32>())
        } else {
            SecretKey::Bytes(Bytes::from_owner(rand::random::<[u8; 32]>()))
        };
        let pid = target.pid;
        let key = (pid, secret_key.to_bytes());
        if let Ok(mut keys) = self.keys.lock() {
            keys.insert(key.clone(), target);
        }
        CancelKeyGuard {
            registry: self.clone(),
            key,
            secret_key,
        }
    }

    pub fn lookup(&self, pid: i32, secret_key: &SecretKey) -> Option<CancelTarget> {
        self.keys
            .lock()
            .ok()?
            .get(&(pid, secret_key.to_bytes()))
            .cloned()
    }
}

/// Removes the issued key from the registry when the session ends.
pub struct CancelKeyGuard {
    registry: CancelRegistry,
    key: (i32, Bytes),
    pub secret_key: SecretKey,
}

impl Drop for CancelKeyGuard {
    fn drop(&mut self) {
        if let Ok(mut keys) = self.registry.keys.lock() {
            keys.remove(&self.key);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use warpgate_common::{DatabaseTargetAuth, PostgresProtocolVersion, Tls};

    use super::*;

    fn target(pid: i32) -> CancelTarget {
        CancelTarget {
            options: TargetPostgresOptions {
                host: "db".into(),
                port: 5432,
                username: "u".into(),
                default_database_name: None,
                auth: DatabaseTargetAuth::default(),
                tls: Tls::default(),
                idle_timeout: None,
                protocol_version: PostgresProtocolVersion::default(),
            },
            pid,
            secret_key: SecretKey::I32(42),
        }
    }

    #[test]
    fn issued_key_resolves_to_target_key() {
        let registry = CancelRegistry::default();
        let guard = registry.issue(ProtocolVersion::PROTOCOL3_2, target(7));
        assert_ne!(guard.secret_key, SecretKey::I32(42));
        let found = registry.lookup(7, &guard.secret_key).unwrap();
        assert_eq!(found.pid, 7);
        assert_eq!(found.secret_key, SecretKey::I32(42));
    }

    #[test]
    fn client_protocol_decides_key_format() {
        let registry = CancelRegistry::default();
        let old = registry.issue(ProtocolVersion::PROTOCOL3_0, target(1));
        assert!(matches!(old.secret_key, SecretKey::I32(_)));
        let new = registry.issue(ProtocolVersion::PROTOCOL3_2, target(2));
        assert!(matches!(new.secret_key, SecretKey::Bytes(ref b) if b.len() == 32));
    }

    #[test]
    fn target_key_and_unknown_key_are_rejected() {
        let registry = CancelRegistry::default();
        let guard = registry.issue(ProtocolVersion::PROTOCOL3_2, target(7));
        assert!(registry.lookup(7, &SecretKey::I32(42)).is_none());
        assert!(registry.lookup(8, &guard.secret_key).is_none());
    }

    #[test]
    fn key_is_removed_when_session_ends() {
        let registry = CancelRegistry::default();
        let guard = registry.issue(ProtocolVersion::PROTOCOL3_2, target(7));
        let key = guard.secret_key.clone();
        drop(guard);
        assert!(registry.lookup(7, &key).is_none());
    }
}
