use std::fmt::Debug;
use std::future::Future;

use anyhow::Result;
use warpgate_common::ListenEndpoint;
use warpgate_tls::TlsCertificateAndPrivateKey;

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
    /// Run the listener on `address`. `tls` carries pre-loaded, validated TLS
    /// material: the first entry is the primary certificate, any further entries
    /// are SNI certificates (HTTP only). It is empty for protocols that do not
    /// use TLS (SSH) or when none is configured. Passing it in avoids re-reading
    /// the files and guarantees the server serves exactly the pair that was
    /// validated (cert and key matched).
    fn run(
        self,
        address: ListenEndpoint,
        tls: Vec<TlsCertificateAndPrivateKey>,
    ) -> impl Future<Output = Result<()>> + Send;
}
