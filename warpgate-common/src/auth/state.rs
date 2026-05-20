use std::collections::HashSet;
use std::fmt::Write;

use rand::RngExt;
use time::OffsetDateTime;
use tokio::sync::broadcast;
use tracing::{debug, info};
use url::Url;
use uuid::Uuid;

use super::{AuthCredential, CredentialKind, CredentialPolicy, CredentialPolicyResponse};
use crate::{SessionId, User};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthResult {
    Accepted { user_info: AuthStateUserInfo },
    Need(HashSet<CredentialKind>),
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthStateUserInfo {
    pub id: Uuid,
    pub username: String,
}

impl From<&User> for AuthStateUserInfo {
    fn from(user: &User) -> Self {
        Self {
            id: user.id,
            username: user.username.clone(),
        }
    }
}

pub struct AuthState {
    id: Uuid,
    user_info: AuthStateUserInfo,
    session_id: Option<Uuid>,
    protocol: String,
    force_rejected: bool,
    policy: Box<dyn CredentialPolicy + Sync + Send>,
    valid_credentials: Vec<AuthCredential>,
    started: OffsetDateTime,
    identification_string: String,
    last_result: Option<AuthResult>,
    state_change_signal: broadcast::Sender<AuthResult>,
}

fn generate_identification_string() -> String {
    let mut s = String::new();
    let mut rng = rand::rng();
    for _ in 0..4 {
        let _ = write!(&mut s, "{:X}", rng.random_range(0..16));
    }
    s
}

impl AuthState {
    pub fn new(
        id: Uuid,
        session_id: Option<SessionId>,
        user_info: AuthStateUserInfo,
        protocol: String,
        policy: Box<dyn CredentialPolicy + Sync + Send>,
        state_change_signal: broadcast::Sender<AuthResult>,
    ) -> Self {
        let mut this = Self {
            id,
            session_id,
            user_info,
            protocol,
            force_rejected: false,
            policy,
            valid_credentials: vec![],
            started: OffsetDateTime::now_utc(),
            identification_string: generate_identification_string(),
            last_result: None,
            state_change_signal,
        };
        this.maybe_update_verification_state();
        this
    }

    pub const fn id(&self) -> &Uuid {
        &self.id
    }

    pub const fn session_id(&self) -> Option<&SessionId> {
        self.session_id.as_ref()
    }

    pub const fn user_info(&self) -> &AuthStateUserInfo {
        &self.user_info
    }

    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    pub const fn started(&self) -> &OffsetDateTime {
        &self.started
    }

    pub fn identification_string(&self) -> &str {
        &self.identification_string
    }

    pub fn add_valid_credential(&mut self, credential: AuthCredential) {
        self.valid_credentials.push(credential);
        self.maybe_update_verification_state();
    }

    pub const fn reject(&mut self) {
        self.force_rejected = true;
    }

    pub fn verify(&self) -> AuthResult {
        self.current_verification_state()
    }

    fn current_verification_state(&self) -> AuthResult {
        if self.force_rejected {
            return AuthResult::Rejected;
        }
        match self
            .policy
            .is_sufficient(&self.protocol, &self.valid_credentials[..])
        {
            CredentialPolicyResponse::Ok => {
                info!(
                    username=%self.user_info.username,
                    credentials=%self.valid_credentials
                        .iter()
                        .map(AuthCredential::safe_description)
                        .collect::<Vec<_>>()
                        .join(", "),
                    "Authenticated",
                );
                AuthResult::Accepted {
                    user_info: self.user_info.clone(),
                }
            }
            CredentialPolicyResponse::Need(kinds) => AuthResult::Need(kinds),
        }
    }

    fn maybe_update_verification_state(&mut self) -> AuthResult {
        let new_result = self.current_verification_state();
        if self.last_result.as_ref() != Some(&new_result) {
            debug!(
                "Verification state changed for auth state {}: {:?} -> {:?}",
                self.id, self.last_result, &new_result
            );
            let _ = self.state_change_signal.send(new_result.clone());
            self.last_result = Some(new_result.clone());
        }

        new_result
    }

    pub fn construct_web_approval_url(&self, mut external_url: Url) -> url::Url {
        external_url.set_path("@warpgate");
        external_url.set_fragment(Some(&format!("/login/{}", self.id())));
        external_url
    }
}
