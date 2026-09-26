use warpgate_common::WarpgateError;
use warpgate_tls::{MaybeTlsStreamError, RustlsSetupError};

#[derive(thiserror::Error, Debug)]
pub enum MongoError {
    #[error("protocol error: {0}")]
    ProtocolError(String),
    #[error("sudden disconnection")]
    Eof,
    #[error("invalid authentication payload: {0}")]
    InvalidAuthPayload(String),
    #[error("upstream authentication not supported: {0}")]
    UnsupportedUpstreamAuth(String),
    #[error("TLS setup failed: {0}")]
    TlsSetup(#[from] RustlsSetupError),
    #[error("TLS stream error: {0}")]
    Tls(#[from] MaybeTlsStreamError),
    #[error("Invalid domain name")]
    InvalidDomainName,
    #[error("wire protocol error: {0}")]
    WireProtocol(#[from] mongowire::ProtocolError),
    #[error("wire error: {0}")]
    Wire(#[from] mongowire::Error),
    #[error("authentication error: {0}")]
    Auth(#[from] mongo_common::auth::AuthError),
    #[error("BSON error: {0}")]
    Bson(#[from] wirebson::Error),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Warpgate(#[from] WarpgateError),
}
