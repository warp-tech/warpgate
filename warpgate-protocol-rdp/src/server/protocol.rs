//! Messages exchanged between the viewer-facing RDP server task and the Warpgate
//! session that owns authentication, recording and the target connection.

use bytes::Bytes;
use tokio::sync::oneshot;
use warpgate_core::DesktopInput;

/// Warpgate's verdict on a viewer's credentials, returned through the
/// [`Event::AuthRequest`] reply channel.
pub enum AuthVerdict {
    /// The password check passed — let the RDP session start. Target authorization and any
    /// second factor may still be pending (collected on the hold screen); this only unblocks
    /// the NLA so the session can proceed to that point, and must not be read as "authorized".
    StartSession,
    /// Reject the credential; the session does not start.
    Deny,
}

/// Warpgate → RDP server: framebuffer updates (raw BGRA) and resize / shutdown control.
pub enum Input {
    Frame {
        x: u16,
        y: u16,
        width: u16,
        height: u16,
        data: Bytes,
    },
    Resize {
        width: u16,
        height: u16,
    },
    Shutdown,
}

/// RDP server → Warpgate: viewer credentials and input. The viewer's domain is discarded —
/// Warpgate resolves the target's domain from the auth selector.
///
/// The session ends by this channel closing; the server's own outcome comes back as the
/// result of [`super::rdp::run_on_thread`].
pub enum Event {
    AuthRequest {
        username: String,
        password: String,
        /// The credential validator awaits its verdict here. Carrying the reply channel in
        /// the request keeps request and response correlated by construction; dropping this
        /// sender — the control loop ending, or declining to answer a duplicate — resolves as
        /// a rejection rather than hanging the server on a reply that never comes.
        reply: oneshot::Sender<AuthVerdict>,
    },
    /// The desktop size settled with the viewer. Sent once the capability exchange
    /// completes, and again after every renegotiation, so Warpgate can paint and dial
    /// the target at the size the viewer is actually showing.
    Size {
        width: u16,
        height: u16,
    },
    Input(DesktopInput),
}
