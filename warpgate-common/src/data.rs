use chrono::NaiveDateTime;
use rocket_okapi::JsonSchema;
use serde::{Serialize, Deserialize};
use warpgate_db_entities::Session;

use crate::{SessionId, Target, User};

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct SessionSnapshot {
    id: SessionId,
    user: Option<UserSnapshot>,
    target: Option<TargetSnapshot>,
    started: NaiveDateTime,
    ended: Option<NaiveDateTime>,
}

impl From<Session::Model> for SessionSnapshot {
    fn from(model: Session::Model) -> Self {
        Self {
            id: model.id,
            user: model.user_snapshot.and_then(|s| serde_json::from_str(&s).ok()),
            target: model.target_snapshot.and_then(|s| serde_json::from_str(&s).ok()),
            started: model.started,
            ended: model.ended,
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema)]
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

#[derive(Serialize, Deserialize, JsonSchema)]
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
