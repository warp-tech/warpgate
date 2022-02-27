use rocket_okapi::JsonSchema;
use serde::Serialize;

use crate::{SessionId, SessionState, Target, User};

#[derive(Serialize, JsonSchema)]
pub struct SessionSnapshot {
    id: SessionId,
    user: Option<UserSnapshot>,
    target: Option<TargetSnapshot>,
}

impl SessionSnapshot {
    pub fn new(id: SessionId, session: &SessionState) -> Self {
        Self {
            id,
            user: session.user.as_ref().map(UserSnapshot::new),
            target: session.target.as_ref().map(TargetSnapshot::new),
        }
    }
}

#[derive(Serialize, JsonSchema)]
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

#[derive(Serialize, JsonSchema)]
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
