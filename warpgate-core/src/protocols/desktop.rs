//! Protocol-agnostic types for graphical (desktop) sessions such as VNC and RDP.
//!
//! Both the native proxy and the in-browser client paths normalise their backend
//! protocol into these events/inputs so that a single renderer and a single
//! recording format can serve every desktop protocol.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use tokio::sync::mpsc::{Receiver, Sender, UnboundedSender};

pub const DESKTOP_INPUT_CHANNEL_CAPACITY: usize = 256;

pub const MAX_CLIPBOARD_BYTES: usize = 10 * 1024 * 1024;

/// The longest prefix of `text` that fits in `max` bytes, cut on a char boundary.
pub fn truncate_clipboard_contents(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or("")
}

pub fn truncate_clipboard_contents_in_place(text: &mut String, max: usize) {
    let end = truncate_clipboard_contents(text, max).len();
    text.truncate(end);
}

// a simple Sync flip (but no flop) for interactive logon tracking
#[derive(Debug, Clone)]
pub struct LogonState(Arc<AtomicBool>);

impl LogonState {
    pub fn at_logon_screen() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }

    pub fn logged_on() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    pub fn mark_logged_on(&self) {
        self.0.store(false, Ordering::Relaxed);
    }

    pub fn still_at_logon_screen(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// Handles for driving a backend desktop client (RDP / VNC) running on its own task.
pub struct DesktopClientHandles {
    /// Normalised desktop events produced by the backend.
    pub event_rx: Receiver<DesktopEvent>,
    /// Inputs to forward to the backend.
    pub input_tx: Sender<DesktopInput>,
    /// Signal the backend task to disconnect and stop.
    pub abort_tx: UnboundedSender<()>,

    pub logon_state: LogonState,
}

/// A rectangular region of the remote framebuffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DesktopRect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
}

/// Connection lifecycle state of a desktop backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopState {
    Connecting,
    Connected,
    Disconnected,
}

/// An event produced by a desktop backend (server -> client direction).
///
/// Pixel data in [`DesktopEvent::RawImage`] is decoded server-side into 32-bit
/// BGRA, so the consumer (browser canvas or recorder) does not need protocol
/// knowledge.
#[derive(Debug, Clone)]
pub enum DesktopEvent {
    /// Connection state change.
    State(DesktopState),
    /// The remote desktop resolution changed.
    Resize { width: u16, height: u16 },
    /// A region updated with raw BGRA pixels (`width * height * 4` bytes).
    RawImage { rect: DesktopRect, data: Bytes },
    /// A region updated with a JPEG-encoded image.
    JpegImage { rect: DesktopRect, data: Bytes },
    /// A region updated with a lossless PNG.
    PngImage { rect: DesktopRect, data: Bytes },
    /// A region was copied from elsewhere in the framebuffer.
    CopyRect {
        dst: DesktopRect,
        src_x: u16,
        src_y: u16,
    },
    /// The mouse cursor shape changed (BGRA pixels for `rect`).
    Cursor { rect: DesktopRect, data: Bytes },
    /// The remote clipboard contents changed.
    Clipboard(String),
    /// The remote rang the bell.
    Bell,
    /// A non-fatal error message.
    Error(String),
}

/// A physical key position: a PC/AT set-1 "make" code, with `extended` marking the
/// `E0` prefix that distinguishes e.g. the nav cluster from the numeric keypad.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scancode {
    pub code: u8,
    pub extended: bool,
}

/// An input sent to a desktop backend (client -> server direction).
#[derive(Debug, Clone)]
pub enum DesktopInput {
    /// Pointer moved / button state changed. `buttons` is a button mask
    /// (bit 0 = left, bit 1 = middle, bit 2 = right, ...).
    Pointer { x: u16, y: u16, buttons: u8 },
    /// A key was pressed or released. Viewers report the key in whichever forms they
    /// know: `keysym` is the character the key produces under the *viewer's* keyboard
    /// layout, `scancode` is the layout-independent physical key position. Backends use
    /// the form their protocol speaks — RDP the scancode, so the *target's* layout
    /// decides the character; VNC the keysym, since RFB has no scancode input.
    Key {
        keysym: Option<u32>,
        scancode: Option<Scancode>,
        down: bool,
    },
    /// Mouse wheel scrolled at `(x, y)`. `delta` is a signed notch count
    /// (positive = up / right); `vertical` selects the axis.
    Wheel {
        x: u16,
        y: u16,
        vertical: bool,
        delta: i16,
    },
    /// Set the remote clipboard contents.
    Clipboard(String),
    /// Request a full framebuffer refresh.
    Refresh,
    /// The viewer's available display area changed; request the target resize its
    /// desktop to `width`×`height`. Backends without dynamic-resize support ignore it.
    Resize { width: u16, height: u16 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_in_is_one_way() {
        let state = LogonState::at_logon_screen();
        assert!(state.still_at_logon_screen());

        let observer = state.clone();
        state.mark_logged_on();
        assert!(!observer.still_at_logon_screen());

        // Nothing can put the session back at the sign-in screen.
        state.mark_logged_on();
        assert!(!observer.still_at_logon_screen());
    }

    #[test]
    fn a_backend_that_cannot_tell_never_suppresses() {
        assert!(!LogonState::logged_on().still_at_logon_screen());
    }
}
