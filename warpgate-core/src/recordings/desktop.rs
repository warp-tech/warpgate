use std::path::PathBuf;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::time::Instant;
use warpgate_db_entities::Recording::RecordingKind;

use super::framebuffer::{Framebuffer, bgra_to_rgba, decode_jpeg_rgb, encode_png_rgba, write_atomic};
use super::writer::RecordingWriter;
use super::{Error, Recorder, RecorderInit, Result};
use crate::{DesktopEvent, DesktopInput, DesktopRect};

/// Emit a full-frame keyframe once this many delta bytes have accumulated since the last
/// one (bounds the work a seek must replay).
const KEYFRAME_BYTES: u64 = 2_000_000;
/// …or once this many seconds elapse with activity since the last keyframe.
const KEYFRAME_MAX_GAP_S: f32 = 10.0;
/// Rects at/above this encoded-input size are PNG-encoded on a blocking worker; smaller
/// ones inline (the handoff would cost more than the encode).
const OFFLOAD_ENCODE_BYTES: usize = 64 * 1024;

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
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DesktopRecordingItem {
    Resize {
        time: f32,
        width: u16,
        height: u16,
    },
    /// Legacy uncompressed BGRA rectangle (gen-1 recordings only; no longer emitted).
    RawImage {
        time: f32,
        rect: RecordingRect,
        #[serde(with = "warpgate_common::helpers::serde_base64")]
        data: Bytes,
    },
    /// A PNG-encoded rectangle. `keyframe` marks a full-canvas snapshot injected between
    /// packets (its `rect` covers the whole framebuffer) — a seek anchor.
    PngImage {
        time: f32,
        rect: RecordingRect,
        #[serde(default)]
        keyframe: bool,
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

/// A seek anchor: a keyframe's playback time and its byte offset in `data.ndjson`.
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct KeyframeCheckpoint {
    pub time: f32,
    pub offset: u64,
}

/// The `index.json` sidecar: total duration, keyframe seek anchors, and the (tiny) viewer
/// input track (so the player renders the click/key overlay without streaming pixels).
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct DesktopIndex {
    pub duration: f32,
    pub keyframes: Vec<KeyframeCheckpoint>,
    pub input: Vec<DesktopRecordingItem>,
}

/// Mutable recorder state, guarded by one mutex so event/input writes stay ordered and byte
/// offsets always match the file.
#[derive(Default)]
struct RecorderState {
    fb: Framebuffer,
    /// Current `data.ndjson` byte offset (== bytes written so far).
    offset: u64,
    bytes_since_keyframe: u64,
    last_keyframe_time: f32,
    duration: f32,
    keyframes: Vec<KeyframeCheckpoint>,
    input: Vec<DesktopRecordingItem>,
    dirty: bool,
    // reusable scratch buffers (cleared + refilled, never reallocated per frame)
    rgba_scratch: Vec<u8>,
    png_out: Vec<u8>,
    line_buf: Vec<u8>,
}

pub struct DesktopRecorder {
    writer: RecordingWriter,
    started_at: Instant,
    index_path: PathBuf,
    state: Mutex<RecorderState>,
}

impl DesktopRecorder {
    fn get_time(&self) -> f32 {
        self.started_at.elapsed().as_secs_f32()
    }

    /// Serialize + write one line, tracking the byte offset atomically (under the state
    /// lock held by the caller) so offsets stay aligned with the file even across the two
    /// writer tasks (events + input).
    async fn write_line(&self, st: &mut RecorderState, item: &DesktopRecordingItem) -> Result<()> {
        st.line_buf.clear();
        serde_json::to_writer(&mut st.line_buf, item).map_err(Error::Serialization)?;
        st.line_buf.push(b'\n');
        let len = st.line_buf.len() as u64;
        self.writer.write(&st.line_buf).await?;
        st.offset += len;
        st.bytes_since_keyframe += len;
        Ok(())
    }

    /// PNG-encode the RGBA already in `st.rgba_scratch` (a delta rect) or the full framebuffer,
    /// recycling `st.png_out`. Heavy encodes go to a blocking worker.
    async fn encode_scratch(&self, st: &mut RecorderState, w: u32, h: u32) -> Result<Bytes> {
        let rgba = std::mem::take(&mut st.rgba_scratch);
        let out = std::mem::take(&mut st.png_out);
        let (rgba, out, result) = Self::encode(w, h, rgba, out).await;
        st.rgba_scratch = rgba;
        let png = Bytes::copy_from_slice(&out);
        st.png_out = out;
        result?;
        Ok(png)
    }

    async fn encode(
        w: u32,
        h: u32,
        rgba: Vec<u8>,
        mut out: Vec<u8>,
    ) -> (Vec<u8>, Vec<u8>, Result<()>) {
        if rgba.len() >= OFFLOAD_ENCODE_BYTES {
            match tokio::task::spawn_blocking(move || {
                let r = encode_png_rgba(w, h, &rgba, &mut out);
                (rgba, out, r)
            })
            .await
            {
                Ok(t) => t,
                Err(e) => (Vec::new(), Vec::new(), Err(Error::Codec(e.to_string()))),
            }
        } else {
            let r = encode_png_rgba(w, h, &rgba, &mut out);
            (rgba, out, r)
        }
    }

    /// Record a renderable desktop event, compositing it into the framebuffer and
    /// (re-)compressing pixel rects to PNG. Non-visual events are ignored.
    pub async fn write_event(&self, event: &DesktopEvent) -> Result<()> {
        let time = self.get_time();
        let mut st = self.state.lock().await;
        st.duration = st.duration.max(time);

        match event {
            DesktopEvent::Resize { width, height } => {
                st.fb.resize(u32::from(*width), u32::from(*height));
                let item = DesktopRecordingItem::Resize {
                    time,
                    width: *width,
                    height: *height,
                };
                self.write_line(&mut st, &item).await?;
            }
            DesktopEvent::RawImage { rect, data } => {
                let rect: RecordingRect = (*rect).into();
                st.fb.blit_bgra(
                    u32::from(rect.x),
                    u32::from(rect.y),
                    u32::from(rect.width),
                    u32::from(rect.height),
                    data,
                );
                bgra_to_rgba(data, rect.width, rect.height, &mut st.rgba_scratch);
                let png = self
                    .encode_scratch(&mut st, u32::from(rect.width), u32::from(rect.height))
                    .await?;
                let item = DesktopRecordingItem::PngImage {
                    time,
                    rect,
                    keyframe: false,
                    data: png,
                };
                self.write_line(&mut st, &item).await?;
            }
            DesktopEvent::JpegImage { rect, data } => {
                let rect: RecordingRect = (*rect).into();
                // Composite into the framebuffer (best-effort) so keyframes stay accurate;
                // pass the already-compressed JPEG through to the stream unchanged.
                if let Some((_, _, rgb)) = decode_jpeg_rgb(data) {
                    st.fb.blit_rgb(
                        u32::from(rect.x),
                        u32::from(rect.y),
                        u32::from(rect.width),
                        u32::from(rect.height),
                        &rgb,
                    );
                }
                let item = DesktopRecordingItem::JpegImage {
                    time,
                    rect,
                    data: data.clone(),
                };
                self.write_line(&mut st, &item).await?;
            }
            DesktopEvent::CopyRect { dst, src_x, src_y } => {
                let dst: RecordingRect = (*dst).into();
                st.fb.copy_rect(
                    u32::from(dst.x),
                    u32::from(dst.y),
                    u32::from(dst.width),
                    u32::from(dst.height),
                    u32::from(*src_x),
                    u32::from(*src_y),
                );
                let item = DesktopRecordingItem::CopyRect {
                    time,
                    dst,
                    src_x: *src_x,
                    src_y: *src_y,
                };
                self.write_line(&mut st, &item).await?;
            }
            // Cursor isn't composited into the framebuffer (server renders the pointer into
            // it); non-visual events carry no pixels.
            DesktopEvent::Cursor { .. }
            | DesktopEvent::State(_)
            | DesktopEvent::Clipboard(_)
            | DesktopEvent::Bell
            | DesktopEvent::Error(_) => return Ok(()),
        }

        self.maybe_keyframe(&mut st, time).await?;
        Ok(())
    }

    /// Inject a full-frame keyframe between packets when enough has changed, and flush the
    /// index (keyframes are its only seek anchors, so flushing here bounds crash tail-loss).
    async fn maybe_keyframe(&self, st: &mut RecorderState, time: f32) -> Result<()> {
        if st.fb.is_empty() {
            return Ok(());
        }
        let due = st.bytes_since_keyframe >= KEYFRAME_BYTES
            || (time - st.last_keyframe_time) >= KEYFRAME_MAX_GAP_S;
        if !due {
            return Ok(());
        }

        let (w, h) = st.fb.size();
        st.rgba_scratch.clear();
        st.rgba_scratch.extend_from_slice(st.fb.rgba());
        let png = self.encode_scratch(st, w, h).await?;

        // Record the checkpoint at the offset where this keyframe line will start.
        st.keyframes.push(KeyframeCheckpoint {
            time,
            offset: st.offset,
        });
        let item = DesktopRecordingItem::PngImage {
            time,
            rect: RecordingRect {
                x: 0,
                y: 0,
                width: w as u16,
                height: h as u16,
            },
            keyframe: true,
            data: png,
        };
        self.write_line(st, &item).await?;
        st.bytes_since_keyframe = 0;
        st.last_keyframe_time = time;
        st.dirty = true;
        self.flush_index(st).await?;
        Ok(())
    }

    /// Record a viewer input (client -> server) for audit: written to the stream and added
    /// to the index input track. `Refresh` is a redraw request, not a user action.
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
        let mut st = self.state.lock().await;
        st.duration = st.duration.max(time);
        self.write_line(&mut st, &item).await?;
        st.input.push(item);
        st.dirty = true;
        Ok(())
    }

    /// Serialize the accumulated index to `index.json` atomically.
    async fn flush_index(&self, st: &mut RecorderState) -> Result<()> {
        if !st.dirty {
            return Ok(());
        }
        let index = DesktopIndex {
            duration: st.duration,
            keyframes: st.keyframes.clone(),
            input: st.input.clone(),
        };
        let bytes = serde_json::to_vec(&index).map_err(Error::Serialization)?;
        write_atomic(&self.index_path, &bytes).await?;
        st.dirty = false;
        Ok(())
    }
}

impl Recorder for DesktopRecorder {
    fn kind() -> RecordingKind {
        RecordingKind::Desktop
    }

    fn new(init: RecorderInit) -> Self {
        Self {
            writer: init.writer,
            started_at: Instant::now(),
            index_path: init.folder.join(super::INDEX_FILENAME),
            state: Mutex::new(RecorderState::default()),
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
