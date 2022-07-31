use std::collections::HashSet;

use super::{AuthCredential, CredentialKind};
use crate::UserRequireCredentialsPolicy;

pub enum CredentialPolicyResponse {
    Ok,
    Need(CredentialKind),
}

pub trait CredentialPolicy {
    fn is_sufficient(
        &self,
        protocol: &str,
        valid_credentials: &[AuthCredential],
    ) -> CredentialPolicyResponse;
}

impl CredentialPolicy for UserRequireCredentialsPolicy {
    fn is_sufficient(
        &self,
        protocol: &str,
        valid_credentials: &[AuthCredential],
    ) -> CredentialPolicyResponse {
        let required_kinds = match protocol {
            "SSH" => &self.ssh,
            "HTTP" => &self.http,
            "MySQL" => &self.mysql,
            _ => unreachable!(),
        };
        if let Some(required_kinds) = required_kinds {
            let mut remaining_required_kinds = HashSet::<CredentialKind>::new();
            remaining_required_kinds.extend(required_kinds);
            for kind in required_kinds {
                if valid_credentials.iter().any(|x| x.kind() == *kind) {
                    remaining_required_kinds.remove(kind);
                }
            }

            if let Some(kind) = remaining_required_kinds.into_iter().next() {
                return CredentialPolicyResponse::Need(kind);
            }
        }
        CredentialPolicyResponse::Ok
    }
}
