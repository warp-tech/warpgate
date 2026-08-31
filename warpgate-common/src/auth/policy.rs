use std::collections::{HashMap, HashSet};

use super::CredentialKind;
use crate::Protocol;

pub enum CredentialPolicyResponse {
    Ok,
    Need(HashSet<CredentialKind>),
}

pub trait CredentialPolicy {
    /// `valid_credentials` is the *kinds* accepted so far, deliberately: no
    /// policy distinguishes which stored credential matched, and handing over
    /// the identities would let one start to.
    fn is_sufficient(
        &self,
        protocol: Protocol,
        valid_credentials: &HashSet<CredentialKind>,
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
    pub protocols: HashMap<Protocol, Box<dyn CredentialPolicy + Send + Sync>>,
    pub default: Box<dyn CredentialPolicy + Send + Sync>,
}

impl CredentialPolicy for AnySingleCredentialPolicy {
    fn is_sufficient(
        &self,
        _protocol: Protocol,
        valid_credentials: &HashSet<CredentialKind>,
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
        _protocol: Protocol,
        valid_credentials: &HashSet<CredentialKind>,
    ) -> CredentialPolicyResponse {
        if !valid_credentials.is_empty()
            && valid_credentials.is_superset(&self.required_credential_types)
        {
            CredentialPolicyResponse::Ok
        } else {
            CredentialPolicyResponse::Need(
                self.required_credential_types
                    .difference(valid_credentials)
                    .copied()
                    .collect(),
            )
        }
    }
}

impl CredentialPolicy for PerProtocolCredentialPolicy {
    fn is_sufficient(
        &self,
        protocol: Protocol,
        valid_credentials: &HashSet<CredentialKind>,
    ) -> CredentialPolicyResponse {
        // A protocol without a configured override intentionally falls back to
        // the default policy.
        self.protocols
            .get(&protocol)
            .unwrap_or(&self.default)
            .is_sufficient(protocol, valid_credentials)
    }
}
