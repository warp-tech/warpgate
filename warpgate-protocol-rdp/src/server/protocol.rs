//! Messages exchanged between the viewer-facing RDP server task and the Warpgate
//! session that owns authentication, recording and the target connection.

use bytes::Bytes;
use warpgate_core::DesktopInput;

/// Warpgate → RDP server: auth verdicts and framebuffer updates (raw BGRA).
pub enum Input {
    AuthResponse {
        accept: bool,
    },
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
