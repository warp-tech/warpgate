mod handle;
use anyhow::Result;
use async_trait::async_trait;
use std::net::SocketAddr;
use crate::Target;
pub use handle::{SessionHandle, WarpgateServerHandle};

#[derive(Debug, thiserror::Error)]
pub enum TargetTestError {
    #[error("unreachable")]
    Unreachable,
    #[error("authentication failed")]
    AuthenticationError,
    #[error("connection error")]
    ConnectionError(String),
    #[error("misconfigured")]
    Misconfigured(String),
    #[error("I/O")]
    Io(#[from] std::io::Error)
}

#[async_trait]
pub trait ProtocolServer {
    async fn run(self, address: SocketAddr) -> Result<()>;
    async fn test_target(self, target: Target) -> Result<(), TargetTestError>;
}
