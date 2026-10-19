use warpgate_common::WarpgateError;

#[derive(thiserror::Error, Debug)]
pub enum SocksError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("unsupported SOCKS version {0}")]
    UnsupportedVersion(u8),
    #[error("malformed message: {0}")]
    Malformed(&'static str),
    #[error("client offered no acceptable authentication method")]
    NoAcceptableMethod,
    #[error("timed out waiting for the client")]
    ClientTimeout,
    #[error(transparent)]
    Warpgate(#[from] WarpgateError),
}
