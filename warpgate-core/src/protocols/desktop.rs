//! Protocol-agnostic types for graphical (desktop) sessions such as VNC and RDP.
//!
//! Both the native proxy and the in-browser client paths normalise their backend
//! protocol into these events/inputs so that a single renderer and a single
//! recording format can serve every desktop protocol.

use bytes::Bytes;

pub const DESKTOP_INPUT_CHANNEL_CAPACITY: usize = 256;

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

/// An input sent to a desktop backend (client -> server direction).
#[derive(Debug, Clone)]
pub enum DesktopInput {
    /// Pointer moved / button state changed. `buttons` is a button mask
    /// (bit 0 = left, bit 1 = middle, bit 2 = right, ...).
    Pointer { x: u16, y: u16, buttons: u8 },
    /// A key was pressed or released, identified by its X11 keysym.
    Key { keysym: u32, down: bool },
    /// A key was pressed or released, identified by its raw PC/AT scancode
    /// (set 1 "make" code). Emitted by native RDP viewers, which send scancodes
    /// rather than keysyms; protocols without scancode input (e.g. VNC) ignore it.
    Scancode { code: u8, extended: bool, down: bool },
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
}
