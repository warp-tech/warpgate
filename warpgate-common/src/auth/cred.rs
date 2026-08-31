use bytes::Bytes;
use poem_openapi::Enum;
use russh::keys::Algorithm;
use sea_orm::entity::prelude::{DeriveActiveEnum, EnumIter};
use sea_orm::sea_query::StringLen;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{Secret, UserCertificateCredential};

#[derive(
    Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum,
)]
pub enum CredentialKind {
    #[serde(rename = "password")]
    Password,
    #[serde(rename = "publickey")]
    PublicKey,
    #[serde(rename = "certificate")]
    Certificate,
    #[serde(rename = "otp")]
    Totp,
    #[serde(rename = "sso")]
    Sso,
    #[serde(rename = "web")]
    WebUserApproval,
}

impl CredentialKind {
    pub const fn readable_description(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::PublicKey => "public key",
            Self::Certificate => "client certificate",
            Self::Totp => "one-time password",
            Self::Sso => "SSO",
            Self::WebUserApproval => "in-browser auth",
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, DeriveActiveEnum,
)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum ApprovalKind {
    /// User approval: is a credential and part of auth policy, approved by user themselves in their browser session, pre-auth
    #[sea_orm(string_value = "user")]
    User,
    /// Admin approval: a target property, not a credential, approved by an admin user, post-auth
    #[sea_orm(string_value = "admin")]
    Admin,
}

/// "Remember decision" scope for approvals
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Enum, EnumIter, DeriveActiveEnum,
)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum ApprovalScope {
    #[sea_orm(string_value = "once")]
    Once,
    #[sea_orm(string_value = "target")]
    Target,
    #[sea_orm(string_value = "all_targets")]
    AllTargets,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthCredential {
    Otp(Secret<String>),
    Password(Secret<String>),
    PublicKey {
        kind: Algorithm,
        public_key_bytes: Bytes,
    },
    Certificate {
        certificate_pem: Secret<String>,
    },
    Sso {
        provider: String,
        email: String,
    },
    WebUserApproval,
}

impl AuthCredential {
    pub const fn kind(&self) -> CredentialKind {
        match self {
            Self::Password { .. } => CredentialKind::Password,
            Self::PublicKey { .. } => CredentialKind::PublicKey,
            Self::Certificate { .. } => CredentialKind::Certificate,
            Self::Otp { .. } => CredentialKind::Totp,
            Self::Sso { .. } => CredentialKind::Sso,
            Self::WebUserApproval => CredentialKind::WebUserApproval,
        }
    }

    pub fn readable_description(&self) -> String {
        match self {
            Self::Sso { provider, .. } => format!("SSO ({provider})"),
            _ => self.kind().readable_description().to_string(),
        }
    }
}

/// An identifying representation of a credential
/// * does not contain secret material
/// * is stable
///
/// Used to remember and match against "remembered" approval decisions
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StoredCredentialFingerprint([u8; 32]);

impl StoredCredentialFingerprint {
    // never the actual secret
    #[must_use]
    pub fn of_stored_verifier(verifier: &[u8]) -> Self {
        Self(Sha256::digest(verifier).into())
    }

    const fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A subset of CredentialKind types that are stored in the DB
/// and are excplitily submissible by the user (i.e. not TLS certificates)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StoredCredentialKind {
    Password,
    PublicKey,
    Totp,
    Sso,
}

impl StoredCredentialKind {
    pub const fn kind(self) -> CredentialKind {
        match self {
            Self::Password => CredentialKind::Password,
            Self::PublicKey => CredentialKind::PublicKey,
            Self::Totp => CredentialKind::Totp,
            Self::Sso => CredentialKind::Sso,
        }
    }

    const fn readable_description(self) -> &'static str {
        self.kind().readable_description()
    }
}

/// A confirmation of an actual stored credential match from the auth backend, including the entry ID and verifiable fingerprint
///
///  The stored credential a submission was verified against: which row, and what
/// that row held at the time.
///
/// Both halves, because they answer different questions. The id distinguishes
/// two rows that hold identical material — two users enrolling the same public
/// key, or one user with two TOTP devices. The verifier notices when a row's
/// material is *replaced*: the admin endpoints for public keys and SSO update
/// in place, keeping the id, so an id-only identity would carry a remembered
/// approval across a key rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StoredCredential {
    kind: StoredCredentialKind,
    id: Uuid,
    fingerprint: StoredCredentialFingerprint,
}

impl StoredCredential {
    #[must_use]
    pub const fn new(
        kind: StoredCredentialKind,
        id: Uuid,
        fingerprint: StoredCredentialFingerprint,
    ) -> Self {
        Self {
            kind,
            id,
            fingerprint,
        }
    }

    pub const fn kind(&self) -> StoredCredentialKind {
        self.kind
    }

    /// serialize into a byte buffer for fingerprint generation of an entire credential set later
    pub(crate) fn write_canonical_bytes(&self, out: &mut Vec<u8>) {
        out.push(match self.kind {
            // stable ids
            StoredCredentialKind::Password => 1,
            StoredCredentialKind::PublicKey => 2,
            StoredCredentialKind::Totp => 3,
            StoredCredentialKind::Sso => 4,
        });
        out.extend_from_slice(self.id.as_bytes());
        out.extend_from_slice(self.fingerprint.bytes());
    }
}

/// A type tag for validated credential's identity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValidCredential {
    Stored(StoredCredential),
    WebUserApproval,
}

impl ValidCredential {
    #[must_use]
    pub const fn kind(&self) -> CredentialKind {
        match self {
            Self::Stored(credential) => credential.kind().kind(),
            Self::WebUserApproval => CredentialKind::WebUserApproval,
        }
    }

    #[must_use]
    pub const fn stored(&self) -> Option<&StoredCredential> {
        match self {
            Self::Stored(credential) => Some(credential),
            Self::WebUserApproval => None,
        }
    }

    #[must_use]
    pub fn readable_description(&self) -> String {
        match self {
            Self::Stored(credential) => {
                // TODO check verbosity
                format!(
                    "{} ({})",
                    credential.kind.readable_description(),
                    credential.id
                )
            }
            Self::WebUserApproval => "in-browser auth".to_string(),
        }
    }
}

impl From<UserCertificateCredential> for AuthCredential {
    fn from(cred: UserCertificateCredential) -> Self {
        Self::Certificate {
            certificate_pem: cred.certificate_pem,
        }
    }
}

impl From<AuthCredential> for Option<UserCertificateCredential> {
    fn from(cred: AuthCredential) -> Self {
        match cred {
            AuthCredential::Certificate { certificate_pem } => {
                Some(UserCertificateCredential { certificate_pem })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::StoredCredentials;

    fn digest(credential: StoredCredential) -> String {
        #[allow(clippy::expect_used)]
        StoredCredentials::new(vec![credential])
            .expect("non-empty")
            .digest()
    }

    fn base() -> StoredCredential {
        StoredCredential::new(
            StoredCredentialKind::Password,
            Uuid::from_u128(1),
            StoredCredentialFingerprint::of_stored_verifier(b"stored"),
        )
    }

    /// The digest *is* the comparison a remembered approval is matched by, so a
    /// part of a credential's identity that doesn't reach it is a part two
    /// different credentials may differ in and still share a grant.
    ///
    /// The destructuring is the point: adding a field to `StoredCredential`
    /// stops this compiling until someone says what it does to the digest.
    #[test]
    fn every_part_of_a_stored_credential_reaches_the_digest() {
        let StoredCredential {
            kind,
            id,
            fingerprint: verifier,
        } = base();
        let _ = (kind, id, verifier);

        for altered in [
            StoredCredential::new(StoredCredentialKind::Sso, id, verifier),
            StoredCredential::new(kind, Uuid::from_u128(2), verifier),
            StoredCredential::new(
                kind,
                id,
                StoredCredentialFingerprint::of_stored_verifier(b"replaced"),
            ),
        ] {
            assert_ne!(digest(base()), digest(altered), "{altered:?}");
        }
    }

    /// Every kind must encode distinctly, or two credentials of different kinds
    /// sharing an id and material would be one credential to the digest.
    #[test]
    fn every_stored_kind_encodes_distinctly() {
        use std::collections::HashSet;

        let kinds = [
            StoredCredentialKind::Password,
            StoredCredentialKind::PublicKey,
            StoredCredentialKind::Totp,
            StoredCredentialKind::Sso,
        ];
        // Exhaustive by construction: a new variant fails to compile here.
        for kind in kinds {
            let _: () = match kind {
                StoredCredentialKind::Password
                | StoredCredentialKind::PublicKey
                | StoredCredentialKind::Totp
                | StoredCredentialKind::Sso => (),
            };
        }

        let digests: HashSet<_> = kinds
            .into_iter()
            .map(|kind| {
                digest(StoredCredential::new(
                    kind,
                    Uuid::nil(),
                    StoredCredentialFingerprint::of_stored_verifier(b""),
                ))
            })
            .collect();
        assert_eq!(digests.len(), kinds.len());
    }
}
