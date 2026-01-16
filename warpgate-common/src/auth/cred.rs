use bytes::Bytes;
use poem_openapi::Enum;
use russh::keys::Algorithm;
use serde::{Deserialize, Serialize};

use crate::{Secret, UserCertificateCredential};

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Hash, Enum)]
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
    pub fn kind(&self) -> CredentialKind {
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

impl From<UserCertificateCredential> for AuthCredential {
    fn from(cred: UserCertificateCredential) -> Self {
        AuthCredential::Certificate {
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
