use std::sync::Arc;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::time::Instant;
use warpgate_db_entities::Recording::RecordingKind;

use super::framebuffer::{Framebuffer, Rect, decode_jpeg_rgb, encode_png_rgba};
use super::{Error, Recorder, Result};
use crate::recordings::RecordingWriterOpener;
use crate::recordings::writer::NDJsonRecordingWriter;
use crate::{DesktopEvent, DesktopInput, DesktopRect};

const MAX_GOP_BYTES: usize = 2_000_000;
const MAX_GOP_SECONDS: f32 = 10.0;
const PNG_OFFLOAD_ENCODING_ABOVE_SIZE: usize = 64 * 1024;
/// Minimum wall-clock gap between PNG-encoded delta frames. A busy target (e.g. a window
/// drag) emits hundreds of tiny rects per second; without a cap the recorder PNG-encodes
/// every one and pins a core. We instead composite them into the framebuffer and encode the
/// coalesced dirty region at most this often — a recording only needs a handful of fps.
const MIN_RECORD_FRAME_INTERVAL: f32 = 1.0 / 30.0;

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
#[serde(tag = "type")]
pub enum DesktopRecordingMetadata {
    #[serde(rename = "desktop")]
    Desktop,
}

/// One line in the append-only `index.ndjson` sidecar. The index is *metadata only* —
/// seek anchors, size changes, and viewer-input timestamps for the scrubber heatmap — so
/// it never grows per-event in the recorder's RAM. The full input events (and all pixels)
/// live in `data.ndjson`; the player sources its click/key overlay from that stream.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum IndexEntry {
    /// Seek anchor: a keyframe's playback time and byte offset into `data.ndjson`.
    Keyframe { time: f32, offset: usize },
    /// A desktop size change; the player uses the first one to size the canvas at t=0.
    Resize { time: f32, width: u16, height: u16 },
    /// A viewer input event — timestamp only (heatmap density; full data is in the stream).
    Input { time: f32 },
    /// Final line, written on finalize, carrying the true total duration.
    End { time: f32 },
}

/// Mutable recorder state, guarded by one mutex so event/input writes stay ordered and byte
/// offsets always match the file.
#[derive(Default)]
struct RecorderState {
    fb: Framebuffer,
    /// Current `data.ndjson` byte offset (== bytes written so far).
    offset: usize,
    bytes_since_keyframe: usize,
    last_keyframe_time: f32,
    duration: f32,
    /// Union of framebuffer pixels blitted but not yet PNG-encoded — deferred by
    /// `MIN_RECORD_FRAME_INTERVAL` and flushed as one rect.
    dirty: Option<Rect>,
    /// Time of the last encoded delta frame; gates the frame-rate cap.
    last_frame_time: f32,
    // reusable scratch buffers (cleared + refilled, never reallocated per frame)
    rgba_scratch: Vec<u8>,
    png_out: Vec<u8>,
}

impl RecorderState {
    /// Grow the pending dirty region to include `rect` (framebuffer coords).
    fn mark_dirty(&mut self, rect: Rect) {
        self.dirty = Some(match self.dirty {
            Some(existing) => existing.union(rect),
            None => rect,
        });
    }
}

/// Copy the pending dirty region out of the framebuffer into `out` (RGBA), clearing `dirty`.
/// Returns the clipped rect, or `None` if nothing is pending. Shared by the live
/// frame-rate-capped flush and the finalize (drop) flush.
fn take_dirty_region(st: &mut RecorderState, out: &mut Vec<u8>) -> Option<Rect> {
    let rect = st.dirty.take()?;
    st.fb.copy_region_rgba(rect, out)
}

pub struct DesktopRecorder {
    data_writer: NDJsonRecordingWriter,
    index_writer: NDJsonRecordingWriter,
    started_at: Instant,
    state: Arc<Mutex<RecorderState>>,
}

impl DesktopRecorder {
    fn get_time(&self) -> f32 {
        self.started_at.elapsed().as_secs_f32()
    }

    async fn write_index_item(&self, item: &IndexEntry) -> Result<()> {
        self.index_writer.write_json_line(item).await?;
        Ok(())
    }

    /// Serialize + write one line, tracking the byte offset atomically (under the state
    /// lock held by the caller) so offsets stay aligned with the file even across the two
    /// writer tasks (events + input).
    async fn write_data_item(
        &self,
        st: &mut RecorderState,
        item: &DesktopRecordingItem,
    ) -> Result<()> {
        let len = self.data_writer.write_json_line(item).await?;
        st.offset += len;
        st.bytes_since_keyframe += len;
        Ok(())
    }

    /// PNG-encode the RGBA already in `st.rgba_scratch` (a delta rect) or the full framebuffer,
    /// recycling `st.png_out`. Heavy encodes go to a blocking worker.
    async fn png_encode_scratch_rgba_buffer(
        &self,
        st: &mut RecorderState,
        w: u32,
        h: u32,
    ) -> Result<Bytes> {
        let rgba = std::mem::take(&mut st.rgba_scratch);
        let out = std::mem::take(&mut st.png_out);
        let (rgba, out, result) = Self::png_encode(w, h, rgba, out).await;
        st.rgba_scratch = rgba;
        let png = Bytes::copy_from_slice(&out);
        st.png_out = out;
        result?;
        Ok(png)
    }

    async fn png_encode(
        w: u32,
        h: u32,
        rgba: Vec<u8>,
        mut out: Vec<u8>,
    ) -> (Vec<u8>, Vec<u8>, Result<()>) {
        if rgba.len() >= PNG_OFFLOAD_ENCODING_ABOVE_SIZE {
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

    /// Encode the coalesced dirty region (deferred by the frame-rate cap) as one PNG delta
    /// and write it. No-op when nothing is pending.
    async fn flush_delta(&self, st: &mut RecorderState, time: f32) -> Result<()> {
        let mut rgba = std::mem::take(&mut st.rgba_scratch);
        let region = take_dirty_region(st, &mut rgba);
        st.rgba_scratch = rgba;
        let Some(r) = region else {
            return Ok(());
        };
        let png = self.png_encode_scratch_rgba_buffer(st, r.width, r.height).await?;
        let item = DesktopRecordingItem::PngImage {
            time,
            rect: RecordingRect {
                x: r.x as u16,
                y: r.y as u16,
                width: r.width as u16,
                height: r.height as u16,
            },
            keyframe: false,
            data: png,
        };
        self.write_data_item(st, &item).await?;
        st.last_frame_time = time;
        Ok(())
    }

    /// Record a renderable desktop event, compositing it into the framebuffer and
    /// (re-)compressing pixel rects to PNG. Non-visual events are ignored.
    pub async fn write_event(&self, event: &DesktopEvent) -> Result<()> {
        let time = self.get_time();
        let mut st = self.state.lock().await;
        st.duration = st.duration.max(time);

        match event {
            DesktopEvent::Resize { width, height } => {
                // Flush pending pixels first: they belong to the old size / earlier in the stream.
                self.flush_delta(&mut st, time).await?;
                st.fb.resize(u32::from(*width), u32::from(*height));
                let item = DesktopRecordingItem::Resize {
                    time,
                    width: *width,
                    height: *height,
                };
                self.write_data_item(&mut st, &item).await?;
                self.write_index_item(&IndexEntry::Resize {
                    time,
                    width: *width,
                    height: *height,
                })
                .await?;
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
                // Coalesce into the dirty region; encode at most once per frame interval.
                st.mark_dirty(Rect {
                    x: u32::from(rect.x),
                    y: u32::from(rect.y),
                    width: u32::from(rect.width),
                    height: u32::from(rect.height),
                });
                if time - st.last_frame_time >= MIN_RECORD_FRAME_INTERVAL {
                    self.flush_delta(&mut st, time).await?;
                }
            }
            DesktopEvent::JpegImage { rect, data } => {
                // Ordered before this JPEG in the stream: flush any pending raw pixels.
                self.flush_delta(&mut st, time).await?;
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
                self.write_data_item(&mut st, &item).await?;
            }
            DesktopEvent::CopyRect { dst, src_x, src_y } => {
                // The copy applies after the pixels it moves: flush them first.
                self.flush_delta(&mut st, time).await?;
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
                self.write_data_item(&mut st, &item).await?;
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

        let due = st.bytes_since_keyframe >= MAX_GOP_BYTES
            || (time - st.last_keyframe_time) >= MAX_GOP_SECONDS;
        if !due {
            return Ok(());
        }

        let (w, h) = st.fb.size();
        st.rgba_scratch.clear();
        st.rgba_scratch.extend_from_slice(st.fb.rgba());
        let png = self.png_encode_scratch_rgba_buffer(st, w, h).await?;

        // Index the checkpoint at the offset where this keyframe line will start.
        let offset = st.offset;
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
        self.write_data_item(st, &item).await?;
        st.bytes_since_keyframe = 0;
        st.last_keyframe_time = time;
        // The keyframe is the whole framebuffer, so any coalesced deltas are already in it.
        st.dirty = None;
        st.last_frame_time = time;
        self.write_index_item(&IndexEntry::Keyframe { time, offset })
            .await?;
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
        self.write_data_item(&mut st, &item).await?;
        self.write_index_item(&IndexEntry::Input { time }).await?;
        Ok(())
    }
}

impl Drop for DesktopRecorder {
    fn drop(&mut self) {
        let state = self.state.clone();
        let index_writer = self.index_writer.clone();
        let data_writer = self.data_writer.clone();

        tokio::spawn(async move {
            let mut state = state.lock().await;
            let time = state.duration;

            // Flush pixels the frame-rate cap deferred, so the final frame is recorded.
            let mut rgba = std::mem::take(&mut state.rgba_scratch);
            if let Some(r) = take_dirty_region(&mut state, &mut rgba) {
                let mut out = std::mem::take(&mut state.png_out);
                if encode_png_rgba(r.width, r.height, &rgba, &mut out).is_ok() {
                    let item = DesktopRecordingItem::PngImage {
                        time,
                        rect: RecordingRect {
                            x: r.x as u16,
                            y: r.y as u16,
                            width: r.width as u16,
                            height: r.height as u16,
                        },
                        keyframe: false,
                        data: Bytes::copy_from_slice(&out),
                    };
                    let _ = data_writer.write_json_line(&item).await;
                }
                state.png_out = out;
            }
            state.rgba_scratch = rgba;

            let entry = IndexEntry::End {
                time: state.duration,
            };
            index_writer.write_json_line(&entry).await?;
            Result::Ok(())
        });
    }
}

impl Recorder for DesktopRecorder {
    fn kind() -> RecordingKind {
        RecordingKind::Desktop
    }

    async fn new(opener: &RecordingWriterOpener) -> Result<Self> {
        Ok(Self {
            data_writer: opener.open_ndjson_data().await?,
            index_writer: opener.open_index().await?,
            started_at: Instant::now(),
            state: Arc::new(Mutex::new(RecorderState::default())),
        })
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
}
