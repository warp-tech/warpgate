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

    #[error("Vault reported an unusable token lease of {0} seconds")]
    InvalidLease(u64),

    #[error("the credential at {path} is {size} bytes, which is too large to be one")]
    CredentialTooLarge { path: PathBuf, size: u64 },

    #[error("certificate_ttl of {0:?} is less than a second, which no issuer accepts")]
    InvalidCertificateTtl(std::time::Duration),

    #[error("cannot use the CA bundle at {path}: {reason}")]
    CaBundle { path: PathBuf, reason: String },

    #[error(
        "cannot unwrap the AppRole secret ID at {path}: {source}. A wrapping token is single-use — whatever provisions this file has to write a fresh one, e.g. `vault write -f -wrap-ttl=<ttl> auth/approle/role/<role>/secret-id`"
    )]
    SecretIdUnwrap {
        path: PathBuf,
        source: Box<VaultError>,
    },

    /// Logging in took longer than `vault.timeout`.
    ///
    /// The HTTP call was always bounded by `reqwest`; assembling the request was
    /// not, and that is where the credential is read. A FIFO at `token_path`, a
    /// hung mount, or a stalled cloud credential chain therefore had no bound at
    /// all — while the token mutex is held across the login, so one blocked read
    /// stalls every session rather than one.
    #[error("authenticating to Vault took longer than the configured timeout")]
    LoginTimeout,
}

impl VaultError {
    pub fn client_message(&self) -> &'static str {
        match self {
            VaultError::InsecureAddress | VaultError::InvalidAddress(_) => {
                "Vault endpoint configuration is invalid"
            }
            VaultError::InvalidRole(_)
            | VaultError::InvalidCertificateTtl(_)
            | VaultError::CaBundle { .. } => "Invalid Vault role or mount configuration",
            VaultError::InvalidPrincipal(_) | VaultError::InvalidKeyId => {
                "Invalid certificate request parameters"
            }
            VaultError::Api { status, body } => {
                // Named rather than left generic: the role is one setting away
                // from working, and nothing else in the message would say so.
                if body.contains("setting key_id is not allowed by role") {
                    "The Vault role does not permit a key ID; set allow_user_key_ids=true on it"
                } else if status.is_client_error() {
                    "Vault denied the certificate signing request"
                } else {
                    "Vault service error"
                }
            }
            VaultError::CredentialFile { .. } | VaultError::CredentialTooLarge { .. } => {
                "Failed to read Vault credentials"
            }
            VaultError::SecretIdUnwrap { .. } => "Failed to unwrap the Vault AppRole secret ID",
            VaultError::Request(_) | VaultError::LoginTimeout => "Vault is currently unavailable",
            VaultError::Json(_)
            | VaultError::MetadataAddress(_)
            | VaultError::OversizedResponse
            | VaultError::InvalidLease(_) => "Invalid response from Vault",
            VaultError::Aws(e) => e.client_message(),
        }
    }
}
