use uuid::Uuid;

use super::{AuthCredential, CredentialPolicy, CredentialPolicyResponse};
use crate::AuthResult;

pub struct AuthState {
    id: Uuid,
    username: String,
    protocol: String,
    force_rejected: bool,
    policy: Box<dyn CredentialPolicy + Sync + Send>,
    valid_credentials: Vec<AuthCredential>,
}

impl AuthState {
    pub(crate) fn new(
        id: Uuid,
        username: String,
        protocol: String,
        policy: Box<dyn CredentialPolicy + Sync + Send>,
    ) -> Self {
        Self {
            id,
            username,
            protocol,
            force_rejected: false,
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

    pub fn reject(&mut self) {
        self.force_rejected = true;
    }

    pub fn verify(&self) -> AuthResult {
        if self.force_rejected {
            return AuthResult::Rejected;
        }
        match self
            .policy
            .is_sufficient(&self.protocol, &self.valid_credentials[..])
        {
            CredentialPolicyResponse::Ok => AuthResult::Accepted {
                username: self.username.clone(),
            },
            CredentialPolicyResponse::Need(kinds) => AuthResult::Need(kinds),
        }
    }
}
