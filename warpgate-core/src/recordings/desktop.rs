use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::time::Instant;
use warpgate_db_entities::Recording::RecordingKind;

use super::writer::RecordingWriter;
use super::{Error, Recorder, Result};
use crate::{DesktopEvent, DesktopInput, DesktopRect};

/// A rectangle as serialised in the recording stream. Matches the shape of the
/// `rect` field in the web-desktop WebSocket `ServerMessage`, so the browser can
/// reuse one canvas renderer for both live sessions and recording playback.
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct RecordingRect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
}

impl From<DesktopRect> for RecordingRect {
    fn from(r: DesktopRect) -> Self {
        Self {
            x: r.x,
            y: r.y,
            width: r.width,
            height: r.height,
        }
    }
}

/// One timestamped item in a desktop recording.
///
/// The JSON shape (tag + fields, minus `time`) intentionally mirrors the
/// web-desktop `ServerMessage` so the same browser-side canvas-apply function
/// drives both live viewing and playback.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DesktopRecordingItem {
    Resize {
        time: f32,
        width: u16,
        height: u16,
    },
    RawImage {
        time: f32,
        rect: RecordingRect,
        #[serde(with = "warpgate_common::helpers::serde_base64")]
        data: Bytes,
    },
    JpegImage {
        time: f32,
        rect: RecordingRect,
        #[serde(with = "warpgate_common::helpers::serde_base64")]
        data: Bytes,
    },
    CopyRect {
        time: f32,
        dst: RecordingRect,
        src_x: u16,
        src_y: u16,
    },
    Cursor {
        time: f32,
        rect: RecordingRect,
        #[serde(with = "warpgate_common::helpers::serde_base64")]
        data: Bytes,
    },
    /// A viewer key press/release (client -> server), captured for audit.
    KeyInput {
        time: f32,
        keysym: u32,
        down: bool,
    },
    /// A viewer pointer move / button-state change (client -> server), captured for audit.
    PointerInput {
        time: f32,
        x: u16,
        y: u16,
        buttons: u8,
    },
    /// A viewer clipboard update (client -> server), captured for audit.
    ClipboardInput {
        time: f32,
        text: String,
    },
    /// A viewer raw-scancode key press/release (client -> server), captured for audit.
    /// Emitted by native RDP viewers, which send PC/AT set-1 scancodes rather than keysyms.
    ScancodeInput {
        time: f32,
        code: u8,
        extended: bool,
        down: bool,
    },
    /// A viewer mouse-wheel scroll (client -> server), captured for audit.
    WheelInput {
        time: f32,
        x: u16,
        y: u16,
        vertical: bool,
        delta: i16,
    },
}

/// Recording metadata for a desktop session. Tagged like `SshRecordingMetadata`
/// so the frontend can discriminate on `type`.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DesktopRecordingMetadata {
    Desktop { protocol: String, target: String },
}

pub struct DesktopRecorder {
    writer: RecordingWriter,
    started_at: Instant,
}

impl DesktopRecorder {
    fn get_time(&self) -> f32 {
        self.started_at.elapsed().as_secs_f32()
    }

    async fn write_item(&self, item: &DesktopRecordingItem) -> Result<()> {
        let mut serialized = serde_json::to_vec(item).map_err(Error::Serialization)?;
        serialized.push(b'\n');
        self.writer.write(&serialized).await?;
        Ok(())
    }

    /// Record a renderable desktop event. Non-visual events
    /// (`State`/`Clipboard`/`Bell`/`Error`) are ignored.
    pub async fn write_event(&self, event: &DesktopEvent) -> Result<()> {
        let time = self.get_time();
        let item = match event {
            DesktopEvent::Resize { width, height } => DesktopRecordingItem::Resize {
                time,
                width: *width,
                height: *height,
            },
            DesktopEvent::RawImage { rect, data } => DesktopRecordingItem::RawImage {
                time,
                rect: (*rect).into(),
                data: data.clone(),
            },
            DesktopEvent::JpegImage { rect, data } => DesktopRecordingItem::JpegImage {
                time,
                rect: (*rect).into(),
                data: data.clone(),
            },
            DesktopEvent::CopyRect { dst, src_x, src_y } => DesktopRecordingItem::CopyRect {
                time,
                dst: (*dst).into(),
                src_x: *src_x,
                src_y: *src_y,
            },
            DesktopEvent::Cursor { rect, data } => DesktopRecordingItem::Cursor {
                time,
                rect: (*rect).into(),
                data: data.clone(),
            },
            DesktopEvent::State(_)
            | DesktopEvent::Clipboard(_)
            | DesktopEvent::Bell
            | DesktopEvent::Error(_) => return Ok(()),
        };
        self.write_item(&item).await
    }

    /// Record a viewer input (client -> server) for audit. Covers every viewer input
    /// kind across protocols — keysym (VNC) and scancode (native RDP) keys, pointer,
    /// wheel and clipboard. `Refresh` is a redraw request, not a user action, so it's
    /// ignored.
    pub async fn write_input(&self, input: &DesktopInput) -> Result<()> {
        let time = self.get_time();
        let item = match input {
            DesktopInput::Key { keysym, down } => DesktopRecordingItem::KeyInput {
                time,
                keysym: *keysym,
                down: *down,
            },
            DesktopInput::Scancode {
                code,
                extended,
                down,
            } => DesktopRecordingItem::ScancodeInput {
                time,
                code: *code,
                extended: *extended,
                down: *down,
            },
            DesktopInput::Pointer { x, y, buttons } => DesktopRecordingItem::PointerInput {
                time,
                x: *x,
                y: *y,
                buttons: *buttons,
            },
            DesktopInput::Wheel {
                x,
                y,
                vertical,
                delta,
            } => DesktopRecordingItem::WheelInput {
                time,
                x: *x,
                y: *y,
                vertical: *vertical,
                delta: *delta,
            },
            DesktopInput::Clipboard(text) => DesktopRecordingItem::ClipboardInput {
                time,
                text: text.clone(),
            },
            DesktopInput::Refresh => return Ok(()),
        };
        self.write_item(&item).await
    }
}

impl Recorder for DesktopRecorder {
    fn kind() -> RecordingKind {
        RecordingKind::Desktop
    }

    fn new(writer: RecordingWriter) -> Self {
        Self {
            writer,
            started_at: Instant::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_json_shape_matches_server_message() {
        // The recording item's JSON (minus `time`) must match the web-desktop
        // ServerMessage shape so the browser reuses one canvas renderer.
        let item = DesktopRecordingItem::RawImage {
            time: 1.5,
            rect: RecordingRect {
                x: 1,
                y: 2,
                width: 3,
                height: 4,
            },
            data: Bytes::from_static(&[0, 1, 2, 3]),
        };
        let value: serde_json::Value = serde_json::to_value(&item).unwrap();
        assert_eq!(value["type"], "raw_image");
        assert_eq!(value["time"], 1.5);
        assert_eq!(value["rect"]["width"], 3);
        assert!(value["data"].is_string()); // base64
    }

    #[test]
    fn item_roundtrip() {
        let item = DesktopRecordingItem::CopyRect {
            time: 0.25,
            dst: RecordingRect {
                x: 10,
                y: 20,
                width: 30,
                height: 40,
            },
            src_x: 5,
            src_y: 6,
        };
        let json = serde_json::to_string(&item).unwrap();
        let back: DesktopRecordingItem = serde_json::from_str(&json).unwrap();
        match back {
            DesktopRecordingItem::CopyRect {
                dst, src_x, src_y, ..
            } => {
                assert_eq!((dst.x, dst.y, dst.width, dst.height), (10, 20, 30, 40));
                assert_eq!((src_x, src_y), (5, 6));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn metadata_is_tagged() {
        let m = DesktopRecordingMetadata::Desktop {
            protocol: "vnc".into(),
            target: "host".into(),
        };
        let value: serde_json::Value = serde_json::to_value(&m).unwrap();
        assert_eq!(value["type"], "desktop");
        assert_eq!(value["protocol"], "vnc");
    }
}
