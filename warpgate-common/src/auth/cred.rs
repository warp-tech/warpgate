use bytes::Bytes;
use poem_openapi::Enum;
use russh::keys::Algorithm;
use sea_orm::entity::prelude::{DeriveActiveEnum, EnumIter};
use sea_orm::sea_query::StringLen;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

    pub fn safe_description(&self) -> String {
        match self {
            Self::Password { .. } => "password".to_string(),
            Self::PublicKey { .. } => "public key".to_string(),
            Self::Certificate { .. } => "client certificate".to_string(),
            Self::Otp { .. } => "one-time password".to_string(),
            Self::Sso { provider, .. } => format!("SSO ({provider})"),
            Self::WebUserApproval => "in-browser auth".to_string(),
        }
    }
}

/// Identifies the *stored* credential that a submitted one matched, so a later
/// authentication can be recognised as having used the same one.
///
/// Built only from a credential's stored verifier — an Argon2 PHC string, an
/// OpenSSH public key — never from what the client submitted. That is the whole
/// point of the type: these identifiers end up in the approval rows, and a
/// digest of a submitted *password* would put a second, far cheaper
/// representation of it in the same database the Argon2 hash lives in. Anyone
/// holding a dump already has the verifier, so this tells them nothing new.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StoredCredentialId([u8; 32]);

impl StoredCredentialId {
    /// `verifier` must be the stored side of the credential, never the client's
    /// submission — see the type docs.
    #[must_use]
    pub fn of_stored_verifier(verifier: &[u8]) -> Self {
        Self(sha256(verifier))
    }

    const fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Which credentials an authentication was made with, by identity rather than
/// by value: enough to tell "the same credentials as last time", and nothing
/// more.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthCredentialFingerprint {
    // OTP is represented by kind only to avoid a mismatch every 30s,
    // also its key ID is not known at this time
    Otp,
    Password(StoredCredentialId),
    PublicKey {
        kind: String,
        id: StoredCredentialId,
    },
    Sso {
        provider: String,
        email: String,
    },
    WebUserApproval,
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

impl AuthCredentialFingerprint {
    /// Not necessarily a stable encoding!
    /// Pushes a byte encoding of this fingerprint, for hashing into a total
    /// fingerprint of an authentication.
    /// Variable-length parts are length-prefixed
    pub(crate) fn write_canonical_bytes(&self, out: &mut Vec<u8>) {
        fn push_str(out: &mut Vec<u8>, s: &str) {
            out.extend_from_slice(&(s.len() as u64).to_le_bytes());
            out.extend_from_slice(s.as_bytes());
        }

        match self {
            Self::Otp => out.push(1),
            Self::Password(id) => {
                out.push(2);
                out.extend_from_slice(id.bytes());
            }
            Self::PublicKey { kind, id } => {
                out.push(3);
                push_str(out, kind);
                out.extend_from_slice(id.bytes());
            }
            Self::Sso { provider, email } => {
                out.push(5);
                push_str(out, provider);
                push_str(out, email);
            }
            Self::WebUserApproval => out.push(6),
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
