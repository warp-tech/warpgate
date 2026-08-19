use redis_protocol::error::RedisProtocolError;
use warpgate_common::WarpgateError;
use warpgate_tls::{MaybeTlsStreamError, RustlsSetupError};

#[derive(thiserror::Error, Debug)]
pub enum RedisError {
    #[error("protocol error: {0}")]
    ProtocolError(String),
    #[error("remote error: {0}")]
    RemoteError(String),
    #[error("RESP: {0}")]
    Resp(#[from] RedisProtocolError),
    #[error("sudden disconnection")]
    Eof,
    #[error("TLS setup failed: {0}")]
    TlsSetup(#[from] RustlsSetupError),
    #[error("TLS stream error: {0}")]
    Tls(#[from] MaybeTlsStreamError),
    #[error("Invalid domain name")]
    InvalidDomainName,
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Warpgate(#[from] WarpgateError),
}
