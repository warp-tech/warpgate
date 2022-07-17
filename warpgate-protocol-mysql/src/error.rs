use std::error::Error;

use sqlx_core_guts::error::Error as SqlxError;
use warpgate_common::WarpgateError;

use crate::stream::MySqlStreamError;
use crate::tls::{MaybeTlsStreamError, RustlsSetupError};

#[derive(thiserror::Error, Debug)]
pub enum MySqlError {
    #[error("invalid target config: {0}")]
    InvalidTargetConfig(#[from] InvalidMySqlTargetConfig),
    #[error("protocol error: {0}")]
    ProtocolError(String),
    #[error("sudden disconnection")]
    Eof,
    #[error("server doesn't offer TLS")]
    TlsNotSupported,
    #[error("client doesn't support TLS")]
    TlsNotSupportedByClient,
    #[error("TLS setup failed: {0}")]
    TlsSetup(#[from] RustlsSetupError),
    #[error("TLS stream error: {0}")]
    Tls(#[from] MaybeTlsStreamError),
    #[error("Invalid domain name")]
    InvalidDomainName,
    #[error("sqlx error: {0}")]
    Sqlx(#[from] SqlxError),
    #[error("MySQL stream error: {0}")]
    MySqlStream(#[from] MySqlStreamError),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("packet decode error: {0}")]
    Decode(Box<dyn Error + Send + Sync>),
    #[error(transparent)]
    Warpgate(#[from] WarpgateError),
    #[error(transparent)]
    Other(Box<dyn Error + Send + Sync>),
}

#[derive(thiserror::Error, Debug)]
pub enum InvalidMySqlTargetConfig {
    #[error("Password not set")]
    NoPassword,
    #[error("URI parse error: {0}")]
    UriParse(Box<dyn Error + Send + Sync>),
    #[error("Unkown")]
    Unknown,
}

impl MySqlError {
    pub fn other<E: Error + Send + Sync + 'static>(err: E) -> Self {
        Self::Other(Box::new(err))
    }

    pub fn decode(err: SqlxError) -> Self {
        match err {
            SqlxError::Decode(err) => Self::Decode(err),
            _ => Self::Sqlx(err),
        }
    }
}
