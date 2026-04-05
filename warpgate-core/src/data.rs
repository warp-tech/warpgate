use poem_openapi::Object;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::{SessionId, Target};
use warpgate_db_entities::Session;

#[derive(Serialize, Deserialize, Object)]
pub struct SessionSnapshot {
    pub id: SessionId,
    pub username: Option<String>,
    pub target: Option<Target>,
    pub started: OffsetDateTime,
    pub ended: Option<OffsetDateTime>,
    pub ticket_id: Option<Uuid>,
    pub protocol: String,
}

impl From<Session::Model> for SessionSnapshot {
    fn from(model: Session::Model) -> Self {
        Self {
            id: model.id,
            username: model.username,
            target: model
                .target_snapshot
                .and_then(|s| serde_json::from_str(&s).ok()),
            started: model.started,
            ended: model.ended,
            ticket_id: model.ticket_id,
            protocol: model.protocol,
        }
    }
}
