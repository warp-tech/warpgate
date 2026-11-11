use warpgate_common::WarpgateError;
use warpgate_tls::{MaybeTlsStreamError, RustlsSetupError};

#[derive(thiserror::Error, Debug)]
pub enum OracleError {
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("authentication failed: {0}")]
    AuthFailed(String),
    #[error("invalid domain name")]
    InvalidDomainName,
    #[error("TNS: {0}")]
    Tns(#[from] warpgate_oracle_tns::error::Error),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("hex decode: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("TLS stream error: {0}")]
    Tls(#[from] MaybeTlsStreamError),
    #[error("TLS setup failed: {0}")]
    TlsSetup(#[from] RustlsSetupError),
    #[error(transparent)]
    Warpgate(#[from] WarpgateError),
}
