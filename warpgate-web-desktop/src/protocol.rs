use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use warpgate_core::{DesktopEvent, DesktopInput, DesktopRect, DesktopState};

#[derive(Clone, Debug)]
pub struct Base64Bytes(pub Bytes);

impl Serialize for Base64Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Base64Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = STANDARD.decode(s).map_err(serde::de::Error::custom)?;
        Ok(Self(Bytes::from(bytes)))
    }
}

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
    PointerEvent { x: u16, y: u16, buttons: u8 },
    KeyEvent { keysym: u32, down: bool },
    Clipboard { text: String },
    Refresh,
}

impl From<ClientMessage> for Option<DesktopInput> {
    fn from(msg: ClientMessage) -> Self {
        Some(match msg {
            ClientMessage::PointerEvent { x, y, buttons } => {
                DesktopInput::Pointer { x, y, buttons }
            }
            ClientMessage::KeyEvent { keysym, down } => DesktopInput::Key { keysym, down },
            ClientMessage::Clipboard { text } => DesktopInput::Clipboard(text),
            ClientMessage::Refresh => DesktopInput::Refresh,
        })
    }
}

/// Messages sent from the server to the browser.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    ConnectionState { state: &'static str },
    Resize { width: u16, height: u16 },
    RawImage { rect: WsRect, data: Base64Bytes },
    JpegImage { rect: WsRect, data: Base64Bytes },
    CopyRect { dst: WsRect, src_x: u16, src_y: u16 },
    Cursor { rect: WsRect, data: Base64Bytes },
    Clipboard { text: String },
    Bell,
    Error { message: String },
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
                data: Base64Bytes(data),
            },
            DesktopEvent::JpegImage { rect, data } => ServerMessage::JpegImage {
                rect: rect.into(),
                data: Base64Bytes(data),
            },
            DesktopEvent::CopyRect { dst, src_x, src_y } => ServerMessage::CopyRect {
                dst: dst.into(),
                src_x,
                src_y,
            },
            DesktopEvent::Cursor { rect, data } => ServerMessage::Cursor {
                rect: rect.into(),
                data: Base64Bytes(data),
            },
            DesktopEvent::Clipboard(text) => ServerMessage::Clipboard { text },
            DesktopEvent::Bell => ServerMessage::Bell,
            DesktopEvent::Error(message) => ServerMessage::Error { message },
        }
    }
}
