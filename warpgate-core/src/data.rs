use poem_openapi::Object;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::{redact_target_secrets, NodeId, Target, TargetSessionId, UserSessionId};
use warpgate_db_entities::{SessionApprovalRequest, TargetSession, UserSession};

#[derive(Serialize, Object)]
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
    pub admin_approvals: Vec<SessionApprovalRequestSnapshot>,
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
            admin_approvals: vec![],
        }
    }
}

#[derive(Serialize, Object)]
pub struct SessionApprovalRequestSnapshot {
    pub resolved_by_username: Option<String>,
    pub resolved_by_user_id: Option<Uuid>,
    pub resolved_at: Option<OffsetDateTime>,
    pub target_id: Option<Uuid>,
    pub target: String,
    pub status: SessionApprovalRequest::ApprovalRequestStatus,
}

impl From<SessionApprovalRequest::Model> for SessionApprovalRequestSnapshot {
    fn from(value: SessionApprovalRequest::Model) -> Self {
        Self {
            resolved_by_username: value.resolved_by_username,
            resolved_by_user_id: value.resolved_by_user_id,
            resolved_at: value.resolved_at,
            target: value.target,
            target_id: None,
            status: value.status,
        }
    }
}

#[derive(Serialize, Object)]
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
