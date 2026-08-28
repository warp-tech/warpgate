use poem_openapi::Object;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::{NodeId, Target, TargetSessionId, UserSessionId, redact_target_secrets};
use warpgate_db_entities::{TargetSession, UserSession};

#[derive(Serialize, Deserialize, Object)]
pub struct UserSessionSnapshot {
    pub id: UserSessionId,
    pub username: Option<String>,
    pub user_id: Option<Uuid>,
    pub started: OffsetDateTime,
    pub ended: Option<OffsetDateTime>,
    pub protocol: String,
    /// The node this session's lifetime is bound to; `None` for shared
    /// sessions, which any node serves.
    pub node_id: Option<NodeId>,
    /// Hostname of the bound node, while registered.
    pub node_hostname: Option<String>,
    pub remote_address: String,
    pub target_sessions: Vec<TargetSessionSnapshot>,
}

impl From<UserSession::Model> for UserSessionSnapshot {
    fn from(model: UserSession::Model) -> Self {
        Self {
            id: model.id,
            username: model.username,
            user_id: model.user_id,
            started: model.started,
            ended: model.ended,
            protocol: model.protocol,
            node_id: model.node_id,
            node_hostname: None,
            remote_address: model.remote_address,
            target_sessions: vec![],
        }
    }
}

#[derive(Serialize, Deserialize, Object)]
pub struct TargetSessionSnapshot {
    pub id: TargetSessionId,
    /// `None` only when the stored snapshot fails to parse.
    pub target: Option<Target>,
    pub target_id: Uuid,
    pub started: OffsetDateTime,
    pub ended: Option<OffsetDateTime>,
    pub ticket_id: Option<Uuid>,
    /// The node serving this target connection; `None` for shared (HTTP)
    /// target sessions, which are access records any node serves.
    pub node_id: Option<NodeId>,
    /// Hostname of the serving node, while registered.
    pub node_hostname: Option<String>,
}

impl From<TargetSession::Model> for TargetSessionSnapshot {
    fn from(model: TargetSession::Model) -> Self {
        Self {
            id: model.id,
            // Redacted on read as well as on write: rows predating snapshot
            // redaction (m00073 handled them, but defense in depth) must never
            // surface a secret through the API.
            target: serde_json::from_str(&model.target_snapshot)
                .ok()
                .and_then(|mut value| {
                    redact_target_secrets(&mut value);
                    serde_json::from_value::<Target>(value).ok()
                }),
            target_id: model.target_id,
            started: model.started,
            ended: model.ended,
            ticket_id: model.ticket_id,
            node_id: model.node_id,
            node_hostname: None,
        }
    }
}
