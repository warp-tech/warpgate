use std::net::{IpAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::{Expr, IntoCondition, OnConflict};
use sea_orm::{ColumnTrait, Condition, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect};
use time::OffsetDateTime;
use tracing::{info, warn};
use uuid::Uuid;
use warpgate_ca::ClusterTlsIdentity;
use warpgate_common::{Protocol, WarpgateError};
use warpgate_db_entities::{Node, Parameters, TargetSession, UserSession};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
const REAP_INTERVAL: Duration = Duration::from_secs(15);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(30);

/// Cluster identity, registers our ephemeral identity in the node list
pub struct Cluster {
    pub node_id: Uuid,
    /// Peer auth certificate issued for this process
    pub tls_identity: ClusterTlsIdentity,
    db: DatabaseConnection,
    /// Peer address (host:port)
    address: String,
    hostname: String,
}

impl Cluster {
    pub async fn new(db: DatabaseConnection, http_port: u16) -> Result<Self, WarpgateError> {
        let params = Parameters::Entity::get(&db).await?;
        Ok(Self {
            node_id: Uuid::new_v4(),
            tls_identity: ClusterTlsIdentity::issue(
                &params.ca_certificate_pem,
                &params.ca_private_key_pem,
            )?,
            db,
            address: advertised_peer_address(http_port)?,
            hostname: std::net::hostname()?.to_string_lossy().to_string(),
        })
    }

    /// Register this node and spawn heartbeat + reaper tasks
    pub async fn start(self: &Arc<Self>) -> Result<(), WarpgateError> {
        self.heartbeat().await?;
        info!(node_id = %self.node_id, address = %self.address, "Joined cluster");

        tokio::spawn({
            let this = Arc::clone(self);
            async move {
                let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
                loop {
                    interval.tick().await;
                    if let Err(error) = this.heartbeat().await {
                        warn!(%error, "Node heartbeat failed");
                    }
                }
            }
        });

        tokio::spawn({
            let db = self.db.clone();
            async move {
                let mut interval = tokio::time::interval(REAP_INTERVAL);
                loop {
                    interval.tick().await;
                    if let Err(error) = reap(&db).await {
                        warn!(%error, "Node reaper failed");
                    }
                }
            }
        });

        Ok(())
    }

    async fn heartbeat(&self) -> Result<(), WarpgateError> {
        let model = Node::ActiveModel {
            id: Set(self.node_id),
            address: Set(self.address.clone()),
            hostname: Set(self.hostname.clone()),
            last_seen: Set(OffsetDateTime::now_utc()),
            tls_spki_sha256: Set(Some(self.tls_identity.spki_sha256_hex.clone())),
            encryption_key_fingerprint: Set(warpgate_common::encryption::env_keyring()
                .primary()
                .map(|key| key.fingerprint().to_owned())),
        };
        // Upsert: SeaORM emits `ON CONFLICT DO UPDATE` (Postgres/SQLite) or
        // `ON DUPLICATE KEY UPDATE` (MySQL). `exec_without_returning` avoids the
        // last-insert-id path, which is where MySQL upserts of a non-auto-increment
        // UUID PK misbehave — and we don't need the id anyway.
        Node::Entity::insert(model)
            .on_conflict(
                OnConflict::column(Node::Column::Id)
                    .update_columns([
                        Node::Column::Address,
                        Node::Column::Hostname,
                        Node::Column::LastSeen,
                        Node::Column::TlsSpkiSha256,
                        Node::Column::EncryptionKeyFingerprint,
                    ])
                    .to_owned(),
            )
            .exec_without_returning(&self.db)
            .await?;
        Ok(())
    }

    /// Graceful shutdown: end this node's still-open sessions and drop its row, so
    /// a scale-down deregisters immediately instead of waiting for the reaper.
    pub async fn shutdown(&self) -> Result<(), WarpgateError> {
        mark_target_sessions_ended(&self.db, TargetSession::Column::NodeId.eq(self.node_id))
            .await?;
        mark_user_sessions_ended(&self.db, UserSession::Column::NodeId.eq(self.node_id)).await?;
        Node::Entity::delete_by_id(self.node_id)
            .exec(&self.db)
            .await?;
        Ok(())
    }
}

/// Mark every still-open target session whose owner node matches `node_filter`
/// as ended.
async fn mark_target_sessions_ended(
    db: &DatabaseConnection,
    node_filter: impl IntoCondition,
) -> Result<(), WarpgateError> {
    TargetSession::Entity::update_many()
        .col_expr(
            TargetSession::Column::Ended,
            Expr::value(OffsetDateTime::now_utc()),
        )
        .filter(node_filter)
        .filter(TargetSession::Column::Ended.is_null())
        .exec(db)
        .await?;
    Ok(())
}

async fn mark_user_sessions_ended(
    db: &DatabaseConnection,
    node_filter: impl IntoCondition,
) -> Result<(), WarpgateError> {
    UserSession::Entity::update_many()
        .col_expr(
            UserSession::Column::Ended,
            Expr::value(OffsetDateTime::now_utc()),
        )
        .filter(node_filter)
        // An authenticated HTTP parent is backed by shared Poem session
        // storage and remains valid after the node that created it disappears.
        // Incomplete HTTP logins and every direct protocol remain node-bound.
        .filter(
            Condition::any()
                .add(UserSession::Column::Protocol.ne(Protocol::Http.name()))
                .add(UserSession::Column::UserId.is_null()),
        )
        .filter(UserSession::Column::Ended.is_null())
        .exec(db)
        .await?;
    Ok(())
}

pub async fn alive_nodes(db: &DatabaseConnection) -> Result<Vec<Node::Model>, WarpgateError> {
    let cutoff = OffsetDateTime::now_utc() - HEARTBEAT_TIMEOUT;
    Ok(Node::Entity::find()
        .filter(Node::Column::LastSeen.gte(cutoff))
        .all(db)
        .await?)
}

/// End the sessions of nodes whose heartbeat has gone stale, then drop their rows,
/// then end any session left without a live owner node.
async fn reap(db: &DatabaseConnection) -> Result<(), WarpgateError> {
    let cutoff = OffsetDateTime::now_utc() - HEARTBEAT_TIMEOUT;
    let dead: Vec<Uuid> = Node::Entity::find()
        .filter(Node::Column::LastSeen.lt(cutoff))
        .all(db)
        .await?
        .into_iter()
        .map(|n| n.id)
        .collect();
    if !dead.is_empty() {
        warn!(count = dead.len(), "Reaping dead cluster nodes");
        mark_target_sessions_ended(db, TargetSession::Column::NodeId.is_in(dead.iter().copied()))
            .await?;
        mark_user_sessions_ended(db, UserSession::Column::NodeId.is_in(dead.iter().copied()))
            .await?;
        Node::Entity::delete_many()
            .filter(Node::Column::Id.is_in(dead))
            .exec(db)
            .await?;
    }

    // An ungracefully killed (and now cleaned up) node's
    // sessions never get cleaned up otherwise
    let live: Vec<Uuid> = Node::Entity::find()
        .select_only()
        .column(Node::Column::Id)
        .into_tuple()
        .all(db)
        .await?;
    // At least the current node should have been present - bail
    // intead of ending all sessions
    if live.is_empty() {
        return Ok(());
    }
    mark_target_sessions_ended(
        db,
        TargetSession::Column::NodeId.is_not_in(live.iter().copied()),
    )
    .await?;
    mark_user_sessions_ended(
        db,
        UserSession::Column::NodeId.is_not_in(live.iter().copied()),
    )
    .await?;
    Ok(())
}

/// Fallback order
/// * WARPGATE_PEER_ADDRESS
/// * POD_IP (kubernetes)
/// * local outbound IP
fn advertised_peer_address(http_port: u16) -> std::io::Result<String> {
    if let Some(addr) = non_empty_env("WARPGATE_PEER_ADDRESS") {
        return Ok(addr);
    }
    if let Some(ip) = non_empty_env("POD_IP") {
        return Ok(format!("{ip}:{http_port}"));
    }

    let ip = local_ip()?;
    Ok(format!("{ip}:{http_port}"))
}

fn local_ip() -> std::io::Result<IpAddr> {
    let socket = UdpSocket::bind(("0.0.0.0", 0))?;
    socket.connect(("1.1.1.1", 80))?; // no traffic here yet, just a route resolve
    socket.local_addr().map(|a| a.ip())
}

/// An environment variable's value, trimmed, or `None` if unset or blank.
fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::ActiveValue::NotSet;
    use sea_orm::Database;
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_migrations::migrate_database;

    use super::*;

    async fn migrated_db() -> DatabaseConnection {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        db
    }

    async fn session(db: &DatabaseConnection, node_id: Uuid, ended: bool) -> Uuid {
        let id = Uuid::new_v4();
        TargetSession::Entity::insert(TargetSession::ActiveModel {
            id: Set(id),
            user_session_id: Set(Uuid::new_v4()),
            target_snapshot: Set(r#"{"name":"web"}"#.into()),
            target_id: Set(Uuid::new_v4()),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(ended.then(OffsetDateTime::now_utc)),
            ticket_id: Set(None),
            node_id: Set(node_id),
        })
        .exec_without_returning(db)
        .await
        .unwrap();
        id
    }

    async fn is_open(db: &DatabaseConnection, id: Uuid) -> bool {
        TargetSession::Entity::find_by_id(id)
            .one(db)
            .await
            .unwrap()
            .unwrap()
            .ended
            .is_none()
    }

    async fn user_session(
        db: &DatabaseConnection,
        node_id: Uuid,
        protocol: Protocol,
        authenticated: bool,
    ) -> Uuid {
        let id = Uuid::new_v4();
        UserSession::Entity::insert(UserSession::ActiveModel {
            id: Set(id),
            username: Set(authenticated.then(|| "alice".into())),
            user_id: Set(authenticated.then(Uuid::new_v4)),
            remote_address: Set("127.0.0.1:1".into()),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            protocol: Set(protocol.to_string()),
            node_id: Set(node_id),
        })
        .exec_without_returning(db)
        .await
        .unwrap();
        id
    }

    async fn is_user_session_open(db: &DatabaseConnection, id: Uuid) -> bool {
        UserSession::Entity::find_by_id(id)
            .one(db)
            .await
            .unwrap()
            .unwrap()
            .ended
            .is_none()
    }

    #[tokio::test]
    async fn reap_ends_sessions_without_a_live_owner() {
        let db = migrated_db().await;

        let live_node = Uuid::new_v4();
        Node::Entity::insert(Node::ActiveModel {
            id: Set(live_node),
            address: Set("127.0.0.1:8888".into()),
            hostname: Set("live".into()),
            last_seen: Set(OffsetDateTime::now_utc()),
            tls_spki_sha256: NotSet,
            encryption_key_fingerprint: NotSet,
        })
        .exec_without_returning(&db)
        .await
        .unwrap();

        let live = session(&db, live_node, false).await;
        let orphan = session(&db, Uuid::new_v4(), false).await;
        // What m00072 backfills onto pre-clustering sessions
        let legacy = session(&db, Uuid::nil(), false).await;

        reap(&db).await.unwrap();

        assert!(is_open(&db, live).await);
        assert!(!is_open(&db, orphan).await);
        assert!(!is_open(&db, legacy).await);
    }

    #[tokio::test]
    async fn reap_keeps_sessions_when_the_node_list_reads_empty() {
        let db = migrated_db().await;

        let id = session(&db, Uuid::new_v4(), false).await;
        reap(&db).await.unwrap();
        assert!(is_open(&db, id).await);
    }

    #[tokio::test]
    async fn authenticated_http_user_sessions_survive_owner_loss() {
        let db = migrated_db().await;
        let node_id = Uuid::new_v4();
        let direct = user_session(&db, node_id, Protocol::Ssh, true).await;
        let incomplete_http = user_session(&db, node_id, Protocol::Http, false).await;
        let shared_http = user_session(&db, node_id, Protocol::Http, true).await;

        mark_user_sessions_ended(&db, UserSession::Column::NodeId.eq(node_id))
            .await
            .unwrap();

        assert!(!is_user_session_open(&db, direct).await);
        assert!(!is_user_session_open(&db, incomplete_http).await);
        assert!(is_user_session_open(&db, shared_http).await);
    }
}
