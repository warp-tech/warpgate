use std::collections::HashSet;

use chrono::{DateTime, Utc};
use rand::Rng;
use tokio::sync::broadcast;
use tracing::{debug, info};
use uuid::Uuid;

use super::{AuthCredential, CredentialKind, CredentialPolicy, CredentialPolicyResponse};
use crate::{SessionId, WarpgateConfig, WarpgateError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthResult {
    Accepted { username: String },
    Need(HashSet<CredentialKind>),
    Rejected,
}

pub struct AuthState {
    id: Uuid,
    session_id: Option<Uuid>,
    username: String,
    protocol: String,
    force_rejected: bool,
    policy: Box<dyn CredentialPolicy + Sync + Send>,
    valid_credentials: Vec<AuthCredential>,
    started: DateTime<Utc>,
    identification_string: String,
    last_result: Option<AuthResult>,
    state_change_signal: broadcast::Sender<AuthResult>,
}

fn generate_identification_string() -> String {
    let mut s = String::new();
    let mut rng = rand::thread_rng();
    for _ in 0..4 {
        s.push_str(&format!("{:X}", rng.gen_range(0..16)));
    }
    s
}

impl AuthState {
    pub fn new(
        id: Uuid,
        session_id: Option<SessionId>,
        username: String,
        protocol: String,
        policy: Box<dyn CredentialPolicy + Sync + Send>,
        state_change_signal: broadcast::Sender<AuthResult>,
    ) -> Self {
        let mut this = Self {
            id,
            session_id,
            username,
            protocol,
            force_rejected: false,
            policy,
            valid_credentials: vec![],
            started: Utc::now(),
            identification_string: generate_identification_string(),
            last_result: None,
            state_change_signal,
        };
        this.maybe_update_verification_state();
        this
    }

    pub fn id(&self) -> &Uuid {
        &self.id
    }

    pub fn session_id(&self) -> &Option<SessionId> {
        &self.session_id
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    pub fn started(&self) -> &DateTime<Utc> {
        &self.started
    }

    pub fn identification_string(&self) -> &str {
        &self.identification_string
    }

    pub fn add_valid_credential(&mut self, credential: AuthCredential) {
        self.valid_credentials.push(credential);
        self.maybe_update_verification_state();
    }

    pub fn reject(&mut self) {
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
                    username=%self.username,
                    credentials=%self.valid_credentials
                        .iter()
                        .map(|x| x.safe_description())
                        .collect::<Vec<_>>()
                        .join(", "),
                    "Authenticated",
                );
                AuthResult::Accepted {
                    username: self.username.clone(),
                }
            }
            CredentialPolicyResponse::Need(kinds) => AuthResult::Need(kinds),
        }
    }

    fn maybe_update_verification_state(&mut self) -> AuthResult {
        let new_result = self.current_verification_state();
        if Some(new_result.clone()) != self.last_result {
            debug!(
                "Verification state changed for auth state {}: {:?} -> {:?}",
                self.id, self.last_result, &new_result
            );
            let _ = self.state_change_signal.send(new_result.clone());
        }
        self.last_result = Some(new_result.clone());

        new_result
    }

    pub fn construct_web_approval_url(
        &self,
        config: &WarpgateConfig,
    ) -> Result<url::Url, WarpgateError> {
        let mut external_url = config.construct_external_url(None, None)?;
        external_url.set_path("@warpgate");
        external_url.set_fragment(Some(&format!("/login/{}", self.id())));
        Ok(external_url)
    }
}
