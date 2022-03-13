use chrono::{DateTime, Utc};
use poem_openapi::Object;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warpgate_db_entities::{Session, Ticket};

use crate::{SessionId, Target, User};

#[derive(Serialize, Deserialize, Object)]
pub struct SessionSnapshot {
    pub id: SessionId,
    pub username: Option<String>,
    pub target: Option<TargetSnapshot>,
    pub started: DateTime<Utc>,
    pub ended: Option<DateTime<Utc>>,
    pub ticket_id: Option<Uuid>,
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
        }
    }
}

#[derive(Serialize, Deserialize, Object)]
pub struct TargetSnapshot {
    name: String,
    host: String,
    port: u16,
}

impl TargetSnapshot {
    pub fn new(target: &Target) -> Self {
        Self {
            name: target.name.clone(),
            host: target.host.clone(),
            port: target.port,
        }
    }
}

#[derive(Serialize, Deserialize, Object)]
pub struct UserSnapshot {
    pub username: String,
}

impl UserSnapshot {
    pub fn new(user: &User) -> Self {
        Self {
            username: user.username.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Object)]
pub struct TicketSnapshot {
    pub id: Uuid,
    pub target: String,
}

impl From<Ticket::Model> for TicketSnapshot {
    fn from(model: Ticket::Model) -> Self {
        Self {
            id: model.id,
            target: model.target,
        }
    }
}
