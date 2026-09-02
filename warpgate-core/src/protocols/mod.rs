use std::fmt::Debug;
use std::future::Future;

use anyhow::Result;
use futures::future::BoxFuture;
use warpgate_common::ListenEndpoint;
use warpgate_tls::TlsCertificateAndPrivateKey;

mod desktop;
pub mod framebuffer;
mod handle;
mod terminal_screen;

pub use desktop::{
    DESKTOP_INPUT_CHANNEL_CAPACITY, DesktopClientHandles, DesktopEvent, DesktopInput, DesktopRect,
    DesktopState, LogonState, MAX_CLIPBOARD_BYTES, Scancode, truncate_clipboard_contents,
    truncate_clipboard_contents_in_place,
};
pub use framebuffer::{Framebuffer, PngEncodeError, Rect, decode_png_rgba};
pub use handle::{
    SessionHandle, TargetSessionStart, WarpgateServerHandle, target_session_needs_approval,
};
pub use terminal_screen::{TerminalScreen, sane_terminal_size};

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
        proxy_protocol: bool,
        tls: Vec<TlsCertificateAndPrivateKey>,
    ) -> impl Future<Output = Result<BoxFuture<'static, Result<()>>>> + Send;
}
