use std::net::{IpAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::{Expr, IntoCondition, OnConflict};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect};
use time::OffsetDateTime;
use tracing::{info, warn};
use uuid::Uuid;
use warpgate_ca::ClusterTlsIdentity;
use warpgate_common::{NodeId, Protocol, WarpgateError};
use warpgate_db_entities::{HttpSession, Node, Parameters, TargetSession, UserSession};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
const REAP_INTERVAL: Duration = Duration::from_secs(15);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(30);

/// Cluster identity, registers our ephemeral identity in the node list
pub struct Cluster {
    pub node_id: NodeId,
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
            node_id: NodeId(Uuid::new_v4()),
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
    /// Shared sessions carry no node and pass through untouched.
    pub async fn shutdown(&self) -> Result<(), WarpgateError> {
        end_connection_bound_sessions(&self.db, UserSession::Column::NodeId.eq(self.node_id))
            .await?;
        end_children_of_ended_parents(&self.db).await?;
        Node::Entity::delete_by_id(self.node_id)
            .exec(&self.db)
            .await?;
        Ok(())
    }
}

/// A shared session's row is inserted before the first cookie-session write
/// lands at the end of that request; the grace keeps the orphan sweep from
/// ending a session mid-birth.
const SHARED_SESSION_ORPHAN_GRACE: time::Duration = time::Duration::minutes(5);

/// bound sessions reap 1/2: mark user sessions matching filter as ended
async fn end_connection_bound_sessions(
    db: &DatabaseConnection,
    node_filter: impl IntoCondition,
) -> Result<(), WarpgateError> {
    UserSession::Entity::update_many()
        .col_expr(
            UserSession::Column::Ended,
            Expr::value(OffsetDateTime::now_utc()),
        )
        .filter(node_filter)
        .filter(UserSession::Column::NodeId.is_not_null())
        .filter(UserSession::Column::Ended.is_null())
        .exec(db)
        .await?;
    Ok(())
}

/// End unowned (HTTP browser) sessions whose backing is gone: they are kept
/// alive by their stored cookie sessions, not by any node.
async fn end_sessions_without_cookie(db: &DatabaseConnection) -> Result<(), WarpgateError> {
    let grace_cutoff = OffsetDateTime::now_utc() - SHARED_SESSION_ORPHAN_GRACE;
    UserSession::Entity::update_many()
        .col_expr(
            UserSession::Column::Ended,
            Expr::value(OffsetDateTime::now_utc()),
        )
        .filter(UserSession::Column::Protocol.eq(Protocol::Http.name()))
        .filter(UserSession::Column::NodeId.is_null())
        .filter(UserSession::Column::Ended.is_null())
        .filter(UserSession::Column::Started.lt(grace_cutoff))
        .filter(
            UserSession::Column::Id.not_in_subquery(
                sea_orm::sea_query::Query::select()
                    .column(HttpSession::Column::UserSessionId)
                    .from(HttpSession::Entity)
                    .and_where(Expr::col(HttpSession::Column::UserSessionId).is_not_null())
                    .to_owned(),
            ),
        )
        .exec(db)
        .await?;
    Ok(())
}

/// Safety net: no target access may read as open past its parent. The normal
/// end paths close children with their parent in one statement; this catches
/// whatever a crash left behind.
async fn end_children_of_ended_parents(db: &DatabaseConnection) -> Result<(), WarpgateError> {
    TargetSession::Entity::update_many()
        .col_expr(
            TargetSession::Column::Ended,
            Expr::value(OffsetDateTime::now_utc()),
        )
        .filter(TargetSession::Column::Ended.is_null())
        .filter(
            TargetSession::Column::UserSessionId.in_subquery(
                sea_orm::sea_query::Query::select()
                    .column(UserSession::Column::Id)
                    .from(UserSession::Entity)
                    .and_where(Expr::col(UserSession::Column::Ended).is_not_null())
                    .to_owned(),
            ),
        )
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

async fn reap(db: &DatabaseConnection) -> Result<(), WarpgateError> {
    let cutoff = OffsetDateTime::now_utc() - HEARTBEAT_TIMEOUT;
    // reap dead nodes
    let dead = Node::Entity::delete_many()
        .filter(Node::Column::LastSeen.lt(cutoff))
        .exec(db)
        .await?
        .rows_affected;
    if dead > 0 {
        warn!(count = dead, "Reaping dead cluster nodes");
    }

    let live: Vec<NodeId> = Node::Entity::find()
        .select_only()
        .column(Node::Column::Id)
        .into_tuple()
        .all(db)
        .await?;

    // At least the current node should have been present - bail
    // intead of ending all sessions
    if !live.is_empty() {
        end_connection_bound_sessions(db, UserSession::Column::NodeId.is_not_in(live)).await?;
    }

    end_sessions_without_cookie(db).await?;
    end_children_of_ended_parents(db).await?;
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
    use warpgate_common::Protocol;
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_migrations::migrate_database;

    use super::*;

    async fn migrated_db() -> DatabaseConnection {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        db
    }

    async fn target_session(db: &DatabaseConnection, parent: Uuid, node_id: Option<Uuid>) -> Uuid {
        let id = Uuid::new_v4();
        TargetSession::Entity::insert(TargetSession::ActiveModel {
            id: Set(warpgate_common::TargetSessionId(id)),
            user_session_id: Set(warpgate_common::UserSessionId(parent)),
            target_snapshot: Set(r#"{"name":"web"}"#.into()),
            target_id: Set(Uuid::new_v4()),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            ticket_id: Set(None),
            node_id: Set(node_id.map(NodeId)),
        })
        .exec_without_returning(db)
        .await
        .unwrap();
        id
    }

    async fn is_open(db: &DatabaseConnection, id: Uuid) -> bool {
        TargetSession::Entity::find_by_id(warpgate_common::TargetSessionId(id))
            .one(db)
            .await
            .unwrap()
            .unwrap()
            .ended
            .is_none()
    }

    async fn user_session_started(
        db: &DatabaseConnection,
        node_id: Option<Uuid>,
        protocol: Protocol,
        started: OffsetDateTime,
    ) -> Uuid {
        let id = Uuid::new_v4();
        UserSession::Entity::insert(UserSession::ActiveModel {
            id: Set(warpgate_common::UserSessionId(id)),
            username: Set(Some("alice".into())),
            user_id: Set(Some(Uuid::new_v4())),
            remote_address: Set("127.0.0.1:1".into()),
            started: Set(started),
            ended: Set(None),
            protocol: Set(protocol.to_string()),
            node_id: Set(node_id.map(NodeId)),
            auth_state_node_id: Set(None),
        })
        .exec_without_returning(db)
        .await
        .unwrap();
        id
    }

    async fn user_session(
        db: &DatabaseConnection,
        node_id: Option<Uuid>,
        protocol: Protocol,
    ) -> Uuid {
        user_session_started(db, node_id, protocol, OffsetDateTime::now_utc()).await
    }

    async fn cookie_backing(db: &DatabaseConnection, user_session_id: Uuid) {
        HttpSession::Entity::insert(HttpSession::ActiveModel {
            id: Set(user_session_id.to_string()),
            expires: Set(None),
            data: Set("{}".into()),
            updated: Set(OffsetDateTime::now_utc()),
            user_session_id: Set(Some(warpgate_common::UserSessionId(user_session_id))),
        })
        .exec_without_returning(db)
        .await
        .unwrap();
    }

    async fn is_user_session_open(db: &DatabaseConnection, id: Uuid) -> bool {
        UserSession::Entity::find_by_id(warpgate_common::UserSessionId(id))
            .one(db)
            .await
            .unwrap()
            .unwrap()
            .ended
            .is_none()
    }

    async fn register_node(db: &DatabaseConnection) -> Uuid {
        let id = Uuid::new_v4();
        Node::Entity::insert(Node::ActiveModel {
            id: Set(NodeId(id)),
            address: Set("127.0.0.1:8888".into()),
            hostname: Set("live".into()),
            last_seen: Set(OffsetDateTime::now_utc()),
            tls_spki_sha256: NotSet,
            encryption_key_fingerprint: NotSet,
        })
        .exec_without_returning(db)
        .await
        .unwrap();
        id
    }

    #[tokio::test]
    async fn reap_ends_connection_bound_sessions_without_a_live_owner() {
        let db = migrated_db().await;
        let live_node = register_node(&db).await;

        let live = user_session(&db, Some(live_node), Protocol::Ssh).await;
        let dead = user_session(&db, Some(Uuid::new_v4()), Protocol::Ssh).await;
        let dead_child = target_session(&db, dead, Some(Uuid::new_v4())).await;
        // What m00072 backfills onto pre-clustering sessions
        let legacy = user_session(&db, Some(Uuid::nil()), Protocol::Ssh).await;
        let shared = user_session(&db, None, Protocol::Http).await;
        cookie_backing(&db, shared).await;
        let shared_child = target_session(&db, shared, None).await;

        reap(&db).await.unwrap();

        assert!(is_user_session_open(&db, live).await);
        assert!(!is_user_session_open(&db, dead).await);
        assert!(!is_open(&db, dead_child).await);
        assert!(!is_user_session_open(&db, legacy).await);
        assert!(is_user_session_open(&db, shared).await);
        assert!(is_open(&db, shared_child).await);
    }

    #[tokio::test]
    async fn reap_keeps_sessions_when_the_node_list_reads_empty() {
        let db = migrated_db().await;

        let id = user_session(&db, Some(Uuid::new_v4()), Protocol::Ssh).await;
        reap(&db).await.unwrap();
        assert!(is_user_session_open(&db, id).await);
    }

    #[tokio::test]
    async fn orphaned_shared_sessions_end_after_the_grace() {
        let db = migrated_db().await;
        register_node(&db).await;
        let stale = OffsetDateTime::now_utc() - SHARED_SESSION_ORPHAN_GRACE * 2;

        let orphan = user_session_started(&db, None, Protocol::Http, stale).await;
        let orphan_child = target_session(&db, orphan, None).await;
        let backed = user_session_started(&db, None, Protocol::Http, stale).await;
        cookie_backing(&db, backed).await;
        // Fresh row whose first cookie write has not landed yet
        let newborn = user_session(&db, None, Protocol::Http).await;

        reap(&db).await.unwrap();

        assert!(!is_user_session_open(&db, orphan).await);
        assert!(!is_open(&db, orphan_child).await);
        assert!(is_user_session_open(&db, backed).await);
        assert!(is_user_session_open(&db, newborn).await);
    }

    /// An HTTP session can be held open by a node-local handle instead of a
    /// stored cookie — a header-borne ticket's. It registers node-owned and so
    /// records an owner, which is what keeps the orphan sweep (whose only
    /// liveness test is a cookie row) from ending it mid-use.
    #[tokio::test]
    async fn node_owned_http_sessions_survive_the_orphan_sweep() {
        let db = migrated_db().await;
        let node = register_node(&db).await;
        let stale = OffsetDateTime::now_utc() - SHARED_SESSION_ORPHAN_GRACE * 2;

        let ticket_session = user_session_started(&db, Some(node), Protocol::Http, stale).await;
        let ticket_child = target_session(&db, ticket_session, Some(node)).await;

        reap(&db).await.unwrap();

        assert!(is_user_session_open(&db, ticket_session).await);
        assert!(is_open(&db, ticket_child).await);
    }
}
