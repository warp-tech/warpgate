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

/// Wraps any policy to additionally require administrator (JIT) approval.
/// The approval is only demanded once the inner policy is otherwise satisfied,
/// so the user completes every real authentication factor before an
/// administrator is asked to approve — `AdminApproval` always comes last.
pub struct RequireApprovalPolicy {
    pub inner: Box<dyn CredentialPolicy + Send + Sync>,
}

impl CredentialPolicy for RequireApprovalPolicy {
    fn is_sufficient(
        &self,
        protocol: &str,
        valid_credentials: &[AuthCredential],
    ) -> CredentialPolicyResponse {
        match self.inner.is_sufficient(protocol, valid_credentials) {
            CredentialPolicyResponse::Need(kinds) => CredentialPolicyResponse::Need(kinds),
            CredentialPolicyResponse::Ok => {
                if valid_credentials
                    .iter()
                    .any(|c| c.kind() == CredentialKind::AdminApproval)
                {
                    CredentialPolicyResponse::Ok
                } else {
                    CredentialPolicyResponse::Need(HashSet::from([CredentialKind::AdminApproval]))
                }
            }
        }
    }
}

/// Satisfied without any credentials: the connection already authenticated by
/// other means (a ticket carries its own authorization). Used as the inner
/// policy of [`RequireApprovalPolicy`] so such a connection can still be held
/// for an out-of-band approval, with the approval as its only factor.
pub struct PreauthenticatedPolicy;

impl CredentialPolicy for PreauthenticatedPolicy {
    fn is_sufficient(
        &self,
        _protocol: &str,
        _valid_credentials: &[AuthCredential],
    ) -> CredentialPolicyResponse {
        CredentialPolicyResponse::Ok
    }
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
            valid_credentials.iter().map(AuthCredential::kind).collect();

        if !valid_credential_types.is_empty()
            && valid_credential_types.is_superset(&self.required_credential_types)
        {
            CredentialPolicyResponse::Ok
        } else {
            CredentialPolicyResponse::Need(
                self.required_credential_types
                    .difference(&valid_credential_types)
                    .copied()
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
        self.protocols
            .get(protocol)
            .unwrap_or(&self.default)
            .is_sufficient(protocol, valid_credentials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Secret;

    #[test]
    fn require_approval_demands_admin_approval_only_after_inner_satisfied() {
        let policy = RequireApprovalPolicy {
            inner: Box::new(AnySingleCredentialPolicy {
                supported_credential_types: HashSet::from([CredentialKind::Password]),
            }),
        };

        // Nothing presented: the inner policy still needs a password, so admin
        // approval is not requested yet (it must come last).
        match policy.is_sufficient("SSH", &[]) {
            CredentialPolicyResponse::Need(kinds) => {
                assert!(!kinds.contains(&CredentialKind::AdminApproval));
            }
            CredentialPolicyResponse::Ok => panic!("should still need a credential"),
        }

        // Password satisfied: now (and only now) admin approval is required.
        let creds = [AuthCredential::Password(Secret::new("pw".into()))];
        match policy.is_sufficient("SSH", &creds) {
            CredentialPolicyResponse::Need(kinds) => {
                assert_eq!(
                    kinds,
                    HashSet::from([CredentialKind::AdminApproval]),
                    "only admin approval should remain",
                );
            }
            CredentialPolicyResponse::Ok => panic!("must still require admin approval"),
        }

        // Both present: accepted.
        let creds = [
            AuthCredential::Password(Secret::new("pw".into())),
            AuthCredential::AdminApproval,
        ];
        assert!(matches!(
            policy.is_sufficient("SSH", &creds),
            CredentialPolicyResponse::Ok
        ));
    }
}
