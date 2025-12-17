use thiserror::Error;
use warpgate_tls::RustlsSetupError;

pub type Result<T> = std::result::Result<T, LdapError>;

#[derive(Error, Debug)]
pub enum LdapError {
    #[error("LDAP connection failed: {0}")]
    ConnectionFailed(String),

    #[error("LDAP authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("LDAP query failed: {0}")]
    QueryFailed(String),

    #[error("TLS error: {0}")]
    TlsError(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    #[error("LDAP error: {0}")]
    LdapClientError(#[from] ldap3::LdapError),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("rustls setup: {0}")]
    RustlSetup(#[from] RustlsSetupError),

    #[error("Other error: {0}")]
    Other(String),
}

impl From<String> for LdapError {
    fn from(s: String) -> Self {
        LdapError::Other(s)
    }
}
