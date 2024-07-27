use std::error::Error;
use std::string::FromUtf8Error;

use pgwire::error::PgWireError;
use pgwire::messages::PgWireFrontendMessage;
use scram_rs::ScramRuntimeError;
use warpgate_common::{MaybeTlsStreamError, RustlsSetupError, WarpgateError};

use crate::stream::PostgresStreamError;

#[derive(thiserror::Error, Debug)]
pub enum PostgresError {
    #[error("protocol error: {0}")]
    ProtocolError(String),
    #[error("decode: {0}")]
    Decode(#[from] PgWireError),
    #[error("unexpected message: {0:?}")]
    UnexpectedMessage(PgWireFrontendMessage),
    #[error("sudden disconnection")]
    Eof,
    #[error("stream: {0}")]
    Stream(#[from] PostgresStreamError),
    // #[error("server doesn't offer TLS")]
    // TlsNotSupported,
    // #[error("client doesn't support TLS")]
    // TlsNotSupportedByClient,
    // #[error("TLS setup failed: {0}")]
    // TlsSetup(#[from] RustlsSetupError),
    #[error("TLS stream error: {0}")]
    Tls(#[from] MaybeTlsStreamError),
    // #[error("Invalid domain name")]
    // InvalidDomainName,
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("UTF-8: {0}")]
    Utf8(#[from] FromUtf8Error),
    #[error("SASL: {0}")]
    Sasl(ScramRuntimeError),
    // #[error("packet decode error: {0}")]
    // Decode(Box<dyn Error + Send + Sync>),
    #[error(transparent)]
    Warpgate(#[from] WarpgateError),
    #[error(transparent)]
    Other(Box<dyn Error + Send + Sync>),
}

impl PostgresError {
    pub fn other<E: Error + Send + Sync + 'static>(err: E) -> Self {
        Self::Other(Box::new(err))
    }
}
