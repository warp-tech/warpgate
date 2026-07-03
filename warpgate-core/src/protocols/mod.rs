use std::fmt::Debug;
use std::future::Future;

use anyhow::Result;
use futures::future::BoxFuture;
use warpgate_common::ListenEndpoint;
use warpgate_tls::TlsCertificateAndPrivateKey;

mod desktop;
mod handle;

pub use desktop::{
    DESKTOP_INPUT_CHANNEL_CAPACITY, DesktopEvent, DesktopInput, DesktopRect, DesktopState,
};
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

    /// Bind the listening socket(s) for `address`, returning a future that drives
    /// the accept loop. The two phases fail differently for the supervisor:
    ///
    /// * an error while binding (from *this* future) is non-fatal — the listener is
    ///   paused until the config or a certificate changes;
    /// * an error from the returned accept-loop future restarts the listener.
    ///
    /// `tls` is validated TLS pair(s): the main cert + maybe SNI certs.
    fn bind(
        self,
        address: ListenEndpoint,
        tls: Vec<TlsCertificateAndPrivateKey>,
    ) -> impl Future<Output = Result<BoxFuture<'static, Result<()>>>> + Send;
}
