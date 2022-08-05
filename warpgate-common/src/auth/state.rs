use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use tracing::warn;

use super::{AuthCredential, CredentialPolicy, CredentialPolicyResponse};
use crate::AuthResult;

#[allow(clippy::unwrap_used)]
pub static TIMEOUT: Lazy<Duration> = Lazy::new(|| Duration::from_secs(60 * 10));

pub struct AuthState {
    username: String,
    protocol: String,
    policy: Option<Box<dyn CredentialPolicy + Sync + Send>>,
    valid_credentials: Vec<AuthCredential>,
    started_at: Instant,
}

impl AuthState {
    pub fn new(
        username: String,
        protocol: String,
        policy: Option<Box<dyn CredentialPolicy + Sync + Send>>,
    ) -> Self {
        Self {
            username,
            protocol,
            policy,
            valid_credentials: vec![],
            started_at: Instant::now(),
        }
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn add_valid_credential(&mut self, credential: AuthCredential) {
        self.valid_credentials.push(credential);
    }

    pub fn is_expired(&self) -> bool {
        self.started_at.elapsed() > *TIMEOUT
    }

    pub fn verify(&self) -> AuthResult {
        if self.valid_credentials.is_empty() {
            warn!(
                username=%self.username,
                "No matching valid credentials"
            );
            return AuthResult::Rejected;
        }

        if let Some(ref policy) = self.policy {
            match policy.is_sufficient(&self.protocol, &self.valid_credentials[..]) {
                CredentialPolicyResponse::Ok => {}
                CredentialPolicyResponse::Need(kind) => {
                    return AuthResult::Need(kind);
                }
                CredentialPolicyResponse::NeedMoreCredentials => {
                    return AuthResult::Rejected;
                }
            }
        }
        AuthResult::Accepted {
            username: self.username.clone(),
        }
    }
}
