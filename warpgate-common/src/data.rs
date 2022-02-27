use chrono::{DateTime, Utc};
use poem_openapi::Object;
use serde::{Deserialize, Serialize};
use warpgate_db_entities::Session;

use crate::{SessionId, Target, User};

#[derive(Serialize, Deserialize, Object)]
pub struct SessionSnapshot {
    id: SessionId,
    user: Option<UserSnapshot>,
    target: Option<TargetSnapshot>,
    started: DateTime<Utc>,
    ended: Option<DateTime<Utc>>,
}

impl From<Session::Model> for SessionSnapshot {
    fn from(model: Session::Model) -> Self {
        Self {
            id: model.id,
            user: model
                .user_snapshot
                .and_then(|s| serde_json::from_str(&s).ok()),
            target: model
                .target_snapshot
                .and_then(|s| serde_json::from_str(&s).ok()),
            started: model.started,
            ended: model.ended,
        }
    }
}

#[derive(Serialize, Deserialize, Object)]
pub struct TargetSnapshot {
    host: String,
    port: u16,
}

impl TargetSnapshot {
    pub fn new(target: &Target) -> Self {
        Self {
            host: target.host.clone(),
            port: target.port.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Object)]
pub struct UserSnapshot {
    username: String,
}

impl UserSnapshot {
    pub fn new(user: &User) -> Self {
        Self {
            username: user.username.clone(),
        }
    }
}
