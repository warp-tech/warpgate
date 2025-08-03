use std::fmt::Debug;
use std::future::Future;

use anyhow::Result;
use warpgate_common::{ListenEndpoint, Target};

mod handle;

pub use handle::{SessionHandle, WarpgateServerHandle};

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
    fn name(&self) -> &'static str;
    fn run(self, address: ListenEndpoint) -> impl Future<Output = Result<()>> + Send;
    fn test_target(
        &self,
        target: Target,
    ) -> impl Future<Output = Result<(), TargetTestError>> + Send;
}
