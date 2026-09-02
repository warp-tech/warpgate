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

    #[error("the Vault address must use HTTPS; there is no exception for loopback")]
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

    /// Reported separately from `OversizedResponse`, which it used to borrow:
    /// a body that is not UTF-8 is not a body that is too long, and the log
    /// named a size problem that had not occurred.
    #[error("the response is not valid UTF-8")]
    NonUtf8Response,

    #[error("Vault reported an unusable token lease of {0} seconds")]
    InvalidLease(u64),

    #[error("the credential at {path} is {size} bytes, which is too large to be one")]
    CredentialTooLarge { path: PathBuf, size: u64 },

    #[error("certificate_ttl of {0:?} is outside the range an issuer accepts")]
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
            // Split rather than grouped: refusing plaintext is a rule of ours
            // that an operator may not know they have hit, and an unparseable
            // address is a typo. One message sent both to the same wrong place.
            VaultError::InsecureAddress => "The Vault address must use HTTPS",
            VaultError::InvalidAddress(_) => "The Vault address is not a valid URL",
            VaultError::InvalidRole(_) => "Invalid Vault role or mount configuration",
            // Its own message: grouped with the role, a certificate_ttl outside
            // the range sent the operator to a setting that was correct.
            VaultError::InvalidCertificateTtl(_) => {
                "certificate_ttl is outside the range the issuer accepts"
            }
            // Named separately because it is not a role or a mount at all: the
            // file at `ca_bundle` cannot be read or parsed. Grouped with the
            // role, it sent the reader to the one place that was fine.
            VaultError::CaBundle { .. } => "The Vault CA bundle cannot be read or parsed",
            VaultError::InvalidPrincipal(_) | VaultError::InvalidKeyId => {
                "Invalid certificate request parameters"
            }
            VaultError::Api { status, body } => {
                // Named rather than left generic: the role is one setting away
                // from working, and nothing else in the message would say so.
                if body.contains("setting key_id is not allowed by role") {
                    "The Vault role does not permit a key ID; set allow_user_key_ids=true on it"
                } else if *status == reqwest::StatusCode::UNAUTHORIZED
                    || *status == reqwest::StatusCode::FORBIDDEN
                {
                    // The credential, not the request: a policy that does not
                    // reach this path, or a token Vault no longer honours.
                    "Vault denied the certificate signing request"
                } else if *status == reqwest::StatusCode::NOT_FOUND {
                    "Vault has no signing role or mount at that path"
                } else if status.is_client_error() {
                    // Reported from the field, where a 400 cost a round trip to
                    // diagnose: at the sign endpoint it is the role refusing the
                    // request — a principal, key type, extension, critical
                    // option or TTL outside what the role allows. That is an
                    // operator's configuration to fix, and a message naming the
                    // role points at it; the previous wording sent the reader
                    // looking at the credential instead.
                    "Vault rejected the request as not permitted by the signing role"
                } else {
                    "Vault service error"
                }
            }
            VaultError::CredentialFile { .. } | VaultError::CredentialTooLarge { .. } => {
                "Failed to read Vault credentials"
            }
            VaultError::SecretIdUnwrap { .. } => "Failed to unwrap the Vault AppRole secret ID",
            VaultError::Request(_) => "Vault is currently unavailable",
            // Not the same as Vault being down, and the doc comment on the
            // variant says why: the bound covers reading the credential too, so
            // a FIFO, a hung mount or a stalled cloud chain lands here while
            // Vault is healthy.
            VaultError::LoginTimeout => {
                "Authenticating to Vault timed out; the credential source may be stalled"
            }
            // The metadata service, not Vault. Vault never answered, so calling
            // this a bad response from it named the wrong machine.
            VaultError::MetadataAddress(_) => "The cloud metadata service address is invalid",
            VaultError::Json(_)
            | VaultError::OversizedResponse
            | VaultError::NonUtf8Response
            | VaultError::InvalidLease(_) => {
                "Invalid response from Vault"
            }
            VaultError::Aws(e) => e.client_message(),
        }
    }
}
