use tracing::warn;
use uuid::Uuid;

use super::{AuthCredential, CredentialPolicy, CredentialPolicyResponse};
use crate::AuthResult;

pub struct AuthState {
    id: Uuid,
    username: String,
    protocol: String,
    policy: Option<Box<dyn CredentialPolicy + Sync + Send>>,
    valid_credentials: Vec<AuthCredential>,
}

impl AuthState {
    pub(crate) fn new(
        id: Uuid,
        username: String,
        protocol: String,
        policy: Option<Box<dyn CredentialPolicy + Sync + Send>>,
    ) -> Self {
        Self {
            id,
            username,
            protocol,
            policy,
            valid_credentials: vec![],
        }
    }

    pub fn id(&self) -> &Uuid {
        &self.id
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    pub fn add_valid_credential(&mut self, credential: AuthCredential) {
        self.valid_credentials.push(credential);
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
