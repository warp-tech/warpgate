use thiserror::Error;

#[non_exhaustive]
#[derive(Debug, Error)]
pub enum VncError {
    #[error("Auth is required but no password provided")]
    NoPassword,
    #[error("No VNC encoding selected")]
    NoEncoding,
    #[error("Unknow VNC security type: {0}")]
    InvalidSecurityTyep(u8),
    #[error("Wrong password")]
    WrongPassword,
    #[error("Apple Remote Desktop authentication failed: {0}")]
    ArdAuthFailed(String),
    #[error("The server does not offer Apple Remote Desktop (ARD) authentication")]
    ArdNotOffered,
    #[error("Apple Remote Desktop requires RFB 3.8, but the client version is limited to {0:?}")]
    ArdVersionConflict(crate::VncVersion),
    #[error("Malformed Apple ARD handshake: {0}")]
    ArdProtocol(String),
    #[error("Connect error with unknown reason")]
    ConnectError,
    #[error("Unknown pixel format")]
    WrongPixelFormat,
    #[error("Unkonw server message")]
    WrongServerMessage,
    #[error("Image data cannot be decoded correctly")]
    InvalidImageData,
    #[error("The VNC client isn't started. Or it is already closed")]
    ClientNotRunning,
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error("VNC Error with message: {0}")]
    General(String),
}

impl<T> From<tokio::sync::mpsc::error::SendError<T>> for VncError {
    fn from(_value: tokio::sync::mpsc::error::SendError<T>) -> Self {
        VncError::General("Channel closed".to_string())
    }
}
