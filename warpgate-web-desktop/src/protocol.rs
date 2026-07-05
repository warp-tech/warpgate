use bytes::Bytes;
use serde::{Deserialize, Serialize};
use warpgate_core::{DesktopEvent, DesktopInput, DesktopRect, DesktopState};

#[derive(Debug, Clone, Copy, Serialize)]
pub struct WsRect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
}

impl From<DesktopRect> for WsRect {
    fn from(r: DesktopRect) -> Self {
        Self {
            x: r.x,
            y: r.y,
            width: r.width,
            height: r.height,
        }
    }
}

/// Messages sent from the browser to the server.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    PointerEvent {
        x: u16,
        y: u16,
        buttons: u8,
    },
    KeyEvent {
        keysym: u32,
        down: bool,
    },
    WheelEvent {
        x: u16,
        y: u16,
        vertical: bool,
        delta: i16,
    },
    Clipboard {
        text: String,
    },
    Refresh,
}

// avoid unbounded memory use from untrusted input
const MAX_CLIPBOARD_BYTES: usize = 10 * 1024 * 1024;

impl From<ClientMessage> for Option<DesktopInput> {
    fn from(msg: ClientMessage) -> Self {
        Some(match msg {
            ClientMessage::PointerEvent { x, y, buttons } => {
                DesktopInput::Pointer { x, y, buttons }
            }
            ClientMessage::KeyEvent { keysym, down } => DesktopInput::Key { keysym, down },
            ClientMessage::WheelEvent {
                x,
                y,
                vertical,
                delta,
            } => DesktopInput::Wheel {
                x,
                y,
                vertical,
                delta,
            },
            ClientMessage::Clipboard { mut text } => {
                if text.len() > MAX_CLIPBOARD_BYTES {
                    let mut end = MAX_CLIPBOARD_BYTES;
                    while end > 0 && !text.is_char_boundary(end) {
                        end -= 1;
                    }
                    text.truncate(end);
                }
                DesktopInput::Clipboard(text)
            }
            ClientMessage::Refresh => DesktopInput::Refresh,
        })
    }
}

/// Messages sent from the server to the browser.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    ConnectionState {
        state: &'static str,
    },
    Resize {
        width: u16,
        height: u16,
    },
    RawImage {
        rect: WsRect,
        #[serde(with = "warpgate_common::helpers::serde_base64")]
        data: Bytes,
    },
    JpegImage {
        rect: WsRect,
        #[serde(with = "warpgate_common::helpers::serde_base64")]
        data: Bytes,
    },
    CopyRect {
        dst: WsRect,
        src_x: u16,
        src_y: u16,
    },
    Cursor {
        rect: WsRect,
        #[serde(with = "warpgate_common::helpers::serde_base64")]
        data: Bytes,
    },
    Clipboard {
        text: String,
    },
    Bell,
    Error {
        message: String,
    },
}

impl ServerMessage {
    /// Whether this is an incremental framebuffer delta that may be dropped under
    /// output-buffer pressure, as opposed to a structural message (resize, clipboard,
    /// connection state) whose loss would corrupt or desync the client.
    pub fn is_incremental(&self) -> bool {
        matches!(
            self,
            Self::RawImage { .. }
                | Self::JpegImage { .. }
                | Self::CopyRect { .. }
                | Self::Cursor { .. }
        )
    }

    /// Encode for the WebSocket. Pixel-carrying frames are sent as compact **binary**
    /// (`[kind: u8][x,y,w,h: u16 LE][pixels…]`) so large buffers avoid the base64 +
    /// JSON-string cost that otherwise pins a core on the hot path; everything else stays
    /// small JSON text.
    pub fn ws_payload(&self) -> WsPayload {
        match self {
            Self::RawImage { rect, data } => WsPayload::Binary(encode_image(1, *rect, data)),
            Self::JpegImage { rect, data } => WsPayload::Binary(encode_image(2, *rect, data)),
            Self::Cursor { rect, data } => WsPayload::Binary(encode_image(3, *rect, data)),
            other => WsPayload::Text(serde_json::to_string(other).unwrap_or_default()),
        }
    }
}

/// A WebSocket payload: small control messages as JSON text, pixel frames as binary.
pub enum WsPayload {
    Text(String),
    Binary(Vec<u8>),
}

/// `[kind: u8][x: u16 LE][y: u16 LE][width: u16 LE][height: u16 LE][pixels…]`.
fn encode_image(kind: u8, rect: WsRect, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + data.len());
    out.push(kind);
    out.extend_from_slice(&rect.x.to_le_bytes());
    out.extend_from_slice(&rect.y.to_le_bytes());
    out.extend_from_slice(&rect.width.to_le_bytes());
    out.extend_from_slice(&rect.height.to_le_bytes());
    out.extend_from_slice(data);
    out
}

fn state_name(state: DesktopState) -> &'static str {
    match state {
        DesktopState::Connecting => "connecting",
        DesktopState::Connected => "connected",
        DesktopState::Disconnected => "disconnected",
    }
}

impl From<DesktopEvent> for ServerMessage {
    fn from(event: DesktopEvent) -> Self {
        match event {
            DesktopEvent::State(state) => ServerMessage::ConnectionState {
                state: state_name(state),
            },
            DesktopEvent::Resize { width, height } => ServerMessage::Resize { width, height },
            DesktopEvent::RawImage { rect, data } => ServerMessage::RawImage {
                rect: rect.into(),
                data,
            },
            DesktopEvent::JpegImage { rect, data } => ServerMessage::JpegImage {
                rect: rect.into(),
                data,
            },
            DesktopEvent::CopyRect { dst, src_x, src_y } => ServerMessage::CopyRect {
                dst: dst.into(),
                src_x,
                src_y,
            },
            DesktopEvent::Cursor { rect, data } => ServerMessage::Cursor {
                rect: rect.into(),
                data,
            },
            DesktopEvent::Clipboard(text) => ServerMessage::Clipboard { text },
            DesktopEvent::Bell => ServerMessage::Bell,
            DesktopEvent::Error(message) => ServerMessage::Error { message },
        }
    }
}
