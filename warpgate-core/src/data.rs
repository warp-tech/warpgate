use poem_openapi::Object;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::{SessionId, Target, redact_target_secrets};
use warpgate_db_entities::Session;

#[derive(Serialize, Deserialize, Object)]
pub struct SessionSnapshot {
    pub id: SessionId,
    pub username: Option<String>,
    pub user_id: Option<Uuid>,
    pub target: Option<Target>,
    pub target_id: Option<Uuid>,
    pub started: OffsetDateTime,
    pub ended: Option<OffsetDateTime>,
    pub ticket_id: Option<Uuid>,
    pub protocol: String,
    pub node_id: Uuid,
    /// Hostname of the owning node; only filled in by the session detail
    /// endpoint, and only while the node is registered.
    pub node_hostname: Option<String>,
    pub remote_address: String,
}

impl From<Session::Model> for SessionSnapshot {
    fn from(model: Session::Model) -> Self {
        Self {
            id: model.id,
            username: model.username,
            user_id: model.user_id,
            // Unredacted snapshots can be written by an old node during a rolling upgrade
            target: model.target_snapshot.and_then(|s| {
                let mut value = serde_json::from_str(&s).ok()?;
                redact_target_secrets(&mut value);
                serde_json::from_value::<Target>(value).ok()
            }),
            target_id: model.target_id,
            started: model.started,
            ended: model.ended,
            ticket_id: model.ticket_id,
            protocol: model.protocol,
            node_id: model.node_id,
            node_hostname: None,
            remote_address: model.remote_address,
        }
    }
}
