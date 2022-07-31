use super::{AuthCredential, CredentialPolicy, CredentialPolicyResponse};
use crate::AuthResult;

pub struct AuthState {
    username: String,
    protocol: String,
    policy: Option<Box<dyn CredentialPolicy>>,
    valid_credentials: Vec<AuthCredential>,
}

impl AuthState {
    pub fn new<P: CredentialPolicy + Sized + 'static>(
        username: String,
        protocol: String,
        policy: Option<P>,
    ) -> Self {
        Self {
            username,
            protocol,
            policy: policy.map(|x| Box::new(x) as Box<dyn CredentialPolicy>),
            valid_credentials: vec![],
        }
    }

    pub fn add_valid_credential(&mut self, credential: AuthCredential) {
        self.valid_credentials.push(credential);
    }

    pub fn verify(&self) -> AuthResult {
        if self.valid_credentials.is_empty() {
            return AuthResult::Rejected;
        }

        if let Some(ref policy) = self.policy {
            match policy.is_sufficient(&self.protocol, &self.valid_credentials[..]) {
                CredentialPolicyResponse::Ok => {}
                CredentialPolicyResponse::Reject => return AuthResult::Rejected,
                CredentialPolicyResponse::Need(kind) => {
                    return AuthResult::Need(kind);
                }
            }
        }
        AuthResult::Accepted {
            username: self.username.clone(),
        }
    }
}
