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

/// Which kind of out-of-band approval a request or a remembered grant is for.
///
/// Only [`ApprovalKind::User`] is a credential; administrator approval is a
/// gate on the connection, decided after authentication. The two must never
/// cross-satisfy, so the kind is part of every request key and match key.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, DeriveActiveEnum,
)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum ApprovalKind {
    /// Self approval from the user's own browser session.
    #[sea_orm(string_value = "user")]
    User,
    /// JIT approval by an administrator.
    #[sea_orm(string_value = "admin")]
    Admin,
}

/// How widely an approval is remembered for later bypass.
///
/// Stored on the request row and taken by both approval endpoints, so it
/// derives its database and OpenAPI representations here rather than being
/// restated per layer with conversions between the copies.
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

/// A value-bound fingerprint of an [`AuthCredential`],
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthCredentialFingerprint {
    // OTP is represented by kind only to avoid a mismatch every 30s,
    // also its key ID is not known at this time
    Otp,
    Password { hash: [u8; 32] },
    PublicKey { kind: String, hash: [u8; 32] },
    Certificate { hash: [u8; 32] },
    Sso { provider: String, email: String },
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
            Self::Password { hash } => {
                out.push(2);
                out.extend_from_slice(hash);
            }
            Self::PublicKey { kind, hash } => {
                out.push(3);
                push_str(out, kind);
                out.extend_from_slice(hash);
            }
            Self::Certificate { hash } => {
                out.push(4);
                out.extend_from_slice(hash);
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

impl From<&AuthCredential> for AuthCredentialFingerprint {
    fn from(cred: &AuthCredential) -> Self {
        match cred {
            AuthCredential::Otp(_) => Self::Otp,
            AuthCredential::Password(secret) => Self::Password {
                hash: sha256(secret.expose_secret().as_bytes()),
            },
            AuthCredential::PublicKey {
                kind,
                public_key_bytes,
            } => Self::PublicKey {
                kind: kind.to_string(),
                hash: sha256(public_key_bytes),
            },
            AuthCredential::Certificate { certificate_pem } => Self::Certificate {
                hash: sha256(certificate_pem.expose_secret().as_bytes()),
            },
            AuthCredential::Sso { provider, email } => Self::Sso {
                provider: provider.clone(),
                email: email.clone(),
            },
            AuthCredential::WebUserApproval => Self::WebUserApproval,
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
