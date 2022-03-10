use anyhow::Result;
use async_trait::async_trait;
use std::net::SocketAddr;

mod handle;
pub use handle::{SessionHandle, WarpgateServerHandle};

#[async_trait]
pub trait ProtocolServer {
    async fn run(self, address: SocketAddr) -> Result<()>;
}
