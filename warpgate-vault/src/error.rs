use std::path::PathBuf;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, VaultError>;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Vault request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("Vault returned {status}: {body}")]
    Api {
        status: reqwest::StatusCode,
        body: String,
    },

    #[error("AWS: {0}")]
    Aws(#[from] warpgate_aws::AwsError),

    #[error("serialization: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid metadata service address: {0}")]
    MetadataAddress(#[from] url::ParseError),

    #[error("cannot read the Vault credential at {path}: {source}")]
    CredentialFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("Vault address must use HTTPS for non-localhost endpoints")]
    InsecureAddress,

    #[error("invalid Vault address: {0}")]
    InvalidAddress(String),

    #[error("invalid Vault role or mount name: {0}")]
    InvalidRole(String),

    #[error("invalid certificate principal: {0}")]
    InvalidPrincipal(String),

    #[error("invalid certificate key ID")]
    InvalidKeyId,

    #[error("Vault response is too large")]
    OversizedResponse,
}

impl VaultError {
    pub fn client_message(&self) -> &'static str {
        match self {
            VaultError::InsecureAddress | VaultError::InvalidAddress(_) => {
                "Vault endpoint configuration is invalid"
            }
            VaultError::InvalidRole(_) => "Invalid Vault role or mount configuration",
            VaultError::InvalidPrincipal(_) | VaultError::InvalidKeyId => {
                "Invalid certificate request parameters"
            }
            VaultError::Api { status, .. } => {
                if status.is_client_error() {
                    "Vault denied the certificate signing request"
                } else {
                    "Vault service error"
                }
            }
            VaultError::CredentialFile { .. } => "Failed to read Vault credentials",
            VaultError::Request(_) => "Vault is currently unavailable",
            VaultError::Json(_)
            | VaultError::MetadataAddress(_)
            | VaultError::OversizedResponse => "Invalid response from Vault",
            VaultError::Aws(e) => e.client_message(),
        }
    }
}
