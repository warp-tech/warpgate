use std::collections::{HashMap, HashSet};

use super::{AuthCredential, CredentialKind};

pub enum CredentialPolicyResponse {
    Ok,
    Need(HashSet<CredentialKind>),
}

pub trait CredentialPolicy {
    fn is_sufficient(
        &self,
        protocol: &str,
        valid_credentials: &[AuthCredential],
    ) -> CredentialPolicyResponse;
}

pub struct AnySingleCredentialPolicy {
    pub supported_credential_types: HashSet<CredentialKind>,
}

pub struct AllCredentialsPolicy {
    pub required_credential_types: HashSet<CredentialKind>,
    pub supported_credential_types: HashSet<CredentialKind>,
}

pub struct PerProtocolCredentialPolicy {
    pub protocols: HashMap<&'static str, Box<dyn CredentialPolicy + Send + Sync>>,
    pub default: Box<dyn CredentialPolicy + Send + Sync>,
}

impl CredentialPolicy for AnySingleCredentialPolicy {
    fn is_sufficient(
        &self,
        _protocol: &str,
        valid_credentials: &[AuthCredential],
    ) -> CredentialPolicyResponse {
        if valid_credentials.is_empty() {
            CredentialPolicyResponse::Need(
                self.supported_credential_types
                    .clone()
                    .into_iter()
                    .collect(),
            )
        } else {
            CredentialPolicyResponse::Ok
        }
    }
}

impl CredentialPolicy for AllCredentialsPolicy {
    fn is_sufficient(
        &self,
        _protocol: &str,
        valid_credentials: &[AuthCredential],
    ) -> CredentialPolicyResponse {
        let valid_credential_types: HashSet<CredentialKind> =
            valid_credentials.iter().map(|x| x.kind()).collect();

        if !valid_credential_types.is_empty()
            && valid_credential_types.is_superset(&self.required_credential_types)
        {
            CredentialPolicyResponse::Ok
        } else {
            CredentialPolicyResponse::Need(
                self.required_credential_types
                    .difference(&valid_credential_types)
                    .cloned()
                    .collect(),
            )
        }
    }
}

impl CredentialPolicy for PerProtocolCredentialPolicy {
    fn is_sufficient(
        &self,
        protocol: &str,
        valid_credentials: &[AuthCredential],
    ) -> CredentialPolicyResponse {
        if let Some(policy) = self.protocols.get(protocol) {
            policy.is_sufficient(protocol, valid_credentials)
        } else {
            self.default.is_sufficient(protocol, valid_credentials)
        }
    }
}
