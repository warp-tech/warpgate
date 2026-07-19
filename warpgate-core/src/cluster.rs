use std::net::{IpAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use time::OffsetDateTime;
use tracing::{info, warn};
use uuid::Uuid;
use warpgate_ca::ClusterTlsIdentity;
use warpgate_common::WarpgateError;
use warpgate_db_entities::{Node, Parameters, Session};

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
            tls_spki_sha256: Set(self.tls_identity.spki_sha256_hex.clone()),
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
        mark_sessions_ended(&self.db, &[self.node_id]).await?;
        Node::Entity::delete_by_id(self.node_id)
            .exec(&self.db)
            .await?;
        Ok(())
    }
}

/// Mark every still-open session owned by any of `node_ids` as ended.
async fn mark_sessions_ended(
    db: &DatabaseConnection,
    node_ids: &[Uuid],
) -> Result<(), WarpgateError> {
    if node_ids.is_empty() {
        return Ok(());
    }
    Session::Entity::update_many()
        .col_expr(
            Session::Column::Ended,
            Expr::value(OffsetDateTime::now_utc()),
        )
        .filter(Session::Column::NodeId.is_in(node_ids.iter().copied()))
        .filter(Session::Column::Ended.is_null())
        .exec(db)
        .await?;
    Ok(())
}

/// End the sessions of nodes whose heartbeat has gone stale, then drop their rows.
async fn reap(db: &DatabaseConnection) -> Result<(), WarpgateError> {
    let cutoff = OffsetDateTime::now_utc() - HEARTBEAT_TIMEOUT;
    let dead: Vec<Uuid> = Node::Entity::find()
        .filter(Node::Column::LastSeen.lt(cutoff))
        .all(db)
        .await?
        .into_iter()
        .map(|n| n.id)
        .collect();
    if dead.is_empty() {
        return Ok(());
    }
    warn!(count = dead.len(), "Reaping dead cluster nodes");
    mark_sessions_ended(db, &dead).await?;
    Node::Entity::delete_many()
        .filter(Node::Column::Id.is_in(dead))
        .exec(db)
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
    return Ok(format!("{ip}:{http_port}"));
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
