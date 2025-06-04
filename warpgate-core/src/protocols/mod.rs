mod handle;

use std::future::Future;

use anyhow::Result;
pub use handle::{SessionHandle, WarpgateServerHandle};
use warpgate_common::{ListenEndpoint, Target};

#[derive(Debug, thiserror::Error)]
pub enum TargetTestError {
    #[error("unreachable")]
    Unreachable,
    #[error("authentication failed")]
    AuthenticationError,
    #[error("connection error: {0}")]
    ConnectionError(String),
    #[error("misconfigured: {0}")]
    Misconfigured(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("dialoguer: {0}")]
    Dialoguer(#[from] dialoguer::Error),
}

pub trait ProtocolServer {
    fn run(self, address: ListenEndpoint) -> impl Future<Output = Result<()>> + Send;
    fn test_target(
        &self,
        target: Target,
    ) -> impl Future<Output = Result<(), TargetTestError>> + Send;
}
