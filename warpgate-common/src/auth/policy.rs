use std::collections::{HashMap, HashSet};

use super::CredentialKind;
use crate::Protocol;

pub enum CredentialPolicyResponse {
    Ok,
    Need(HashSet<CredentialKind>),
}

pub trait CredentialPolicy {
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

/// Wrapper policy that slaps a `required` MFA factor on top of another one
pub struct MfaEnforcementPolicy {
    pub inner: Box<dyn CredentialPolicy + Send + Sync>,
    pub required: HashMap<Protocol, CredentialKind>,
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

impl CredentialPolicy for MfaEnforcementPolicy {
    fn is_sufficient(
        &self,
        protocol: Protocol,
        valid_credentials: &HashSet<CredentialKind>,
    ) -> CredentialPolicyResponse {
        let response = self.inner.is_sufficient(protocol, valid_credentials);
        let Some(&factor) = self.required.get(&protocol) else {
            return response;
        };
        if valid_credentials.contains(&factor) {
            return response;
        }
        let mut needed = match response {
            CredentialPolicyResponse::Ok => HashSet::new(),
            CredentialPolicyResponse::Need(needed) => needed,
        };
        needed.insert(factor);
        CredentialPolicyResponse::Need(needed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrapper(
        inner: Box<dyn CredentialPolicy + Send + Sync>,
        required: &[(Protocol, CredentialKind)],
    ) -> MfaEnforcementPolicy {
        MfaEnforcementPolicy {
            inner,
            required: required.iter().copied().collect(),
        }
    }

    fn permissive_inner() -> Box<dyn CredentialPolicy + Send + Sync> {
        Box::new(AnySingleCredentialPolicy {
            supported_credential_types: [CredentialKind::Password].into_iter().collect(),
        })
    }

    fn kinds(kinds: &[CredentialKind]) -> HashSet<CredentialKind> {
        kinds.iter().copied().collect()
    }

    #[test]
    fn mfa_policy_passes_through_unlisted_protocols() {
        let policy = wrapper(permissive_inner(), &[(Protocol::Ssh, CredentialKind::Totp)]);
        assert!(matches!(
            policy.is_sufficient(Protocol::Http, &kinds(&[CredentialKind::Password])),
            CredentialPolicyResponse::Ok
        ));
    }

    #[test]
    fn mfa_policy_demands_missing_factor() {
        let policy = wrapper(permissive_inner(), &[(Protocol::Ssh, CredentialKind::Totp)]);
        let CredentialPolicyResponse::Need(needed) =
            policy.is_sufficient(Protocol::Ssh, &kinds(&[CredentialKind::Password]))
        else {
            panic!("expected Need");
        };
        assert_eq!(needed, [CredentialKind::Totp].into_iter().collect());
    }

    #[test]
    fn mfa_policy_accepts_presented_factor() {
        let policy = wrapper(permissive_inner(), &[(Protocol::Ssh, CredentialKind::Totp)]);
        assert!(matches!(
            policy.is_sufficient(
                Protocol::Ssh,
                &kinds(&[CredentialKind::Password, CredentialKind::Totp])
            ),
            CredentialPolicyResponse::Ok
        ));
    }

    #[test]
    fn mfa_policy_merges_with_inner_needs() {
        let inner = Box::new(AllCredentialsPolicy {
            required_credential_types: [CredentialKind::Password].into_iter().collect(),
            supported_credential_types: [CredentialKind::Password].into_iter().collect(),
        });
        let policy = wrapper(inner, &[(Protocol::Ssh, CredentialKind::Totp)]);
        let CredentialPolicyResponse::Need(needed) =
            policy.is_sufficient(Protocol::Ssh, &kinds(&[]))
        else {
            panic!("expected Need");
        };
        assert_eq!(
            needed,
            [CredentialKind::Password, CredentialKind::Totp]
                .into_iter()
                .collect()
        );
    }
}
