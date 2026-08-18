use std::sync::Arc;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::error;
use warpgate_db_entities::Recording::RecordingKind;

use super::{Recorder, Result};
use crate::protocols::TerminalScreen;
use crate::recordings::RecordingWriterOpener;
use crate::recordings::writer::NDJsonRecordingWriter;

/// Bytes of data.ndjson between keyframes
const MAX_GOP_BYTES: usize = 256_000;
const MAX_GOP_SECONDS: f32 = 10.0;

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq)]
pub enum TerminalRecordingStreamId {
    Input,
    #[default]
    Output,
    Error,
}

impl TerminalRecordingStreamId {
    pub const fn from_usual_fd_number(fd: u8) -> Option<Self> {
        match fd {
            0 => Some(Self::Input),
            1 => Some(Self::Output),
            2 => Some(Self::Error),
            _ => None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum TerminalRecordingItem {
    Snapshot {
        time: f32,
        #[serde(with = "warpgate_common::helpers::serde_base64")]
        snapshot: Bytes,
    },
    Data {
        time: f32,
        #[serde(default)]
        stream: TerminalRecordingStreamId,
        #[serde(with = "warpgate_common::helpers::serde_base64")]
        data: Bytes,
    },
    PtyResize {
        time: f32,
        cols: u32,
        rows: u32,
    },
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum IndexEntry {
    /// Playback time and byte offset into `data.ndjson` of a snapshot item.
    Keyframe { time: f32, offset: usize },
    /// A terminal size change; the player restores a snapshot at the size it was taken.
    Resize { time: f32, cols: u32, rows: u32 },
    /// Final line, written on finalize, carrying the true total duration.
    End { time: f32 },
}

#[derive(Default)]
struct RecorderState {
    screen: TerminalScreen,
    /// Current data.ndjson writer position
    offset: usize,
    bytes_since_keyframe: usize,
    last_keyframe_time: f32,
    duration: f32,
    /// this channel has a PTY
    pty: bool,
}

pub struct TerminalRecorder {
    data_writer: Arc<NDJsonRecordingWriter>,
    index_writer: Arc<NDJsonRecordingWriter>,
    started_at: Instant,
    state: Arc<Mutex<RecorderState>>,
}

impl TerminalRecorder {
    fn get_time(&self) -> f32 {
        self.started_at.elapsed().as_secs_f32()
    }

    async fn write_data_item(
        &self,
        st: &mut RecorderState,
        item: &TerminalRecordingItem,
    ) -> Result<()> {
        let len = self.data_writer.write_json_line(item).await?;
        st.offset += len;
        st.bytes_since_keyframe += len;
        Ok(())
    }

    pub async fn write(&self, stream: TerminalRecordingStreamId, data: &[u8]) -> Result<()> {
        let mut st = self.state.lock().await;

        let time = self.get_time();
        st.duration = st.duration.max(time);

        if stream != TerminalRecordingStreamId::Input {
            st.screen.feed(data);
        }

        let item = TerminalRecordingItem::Data {
            time,
            stream,
            data: Bytes::from(data.to_vec()),
        };
        self.write_data_item(&mut st, &item).await?;
        self.maybe_keyframe(&mut st, time).await?;
        Ok(())
    }

    pub async fn write_pty_resize(&self, cols: u32, rows: u32) -> Result<()> {
        let mut st = self.state.lock().await;
        let time = self.get_time();
        st.duration = st.duration.max(time);
        st.pty = true;
        st.screen.resize(
            u16::try_from(cols).unwrap_or(u16::MAX),
            u16::try_from(rows).unwrap_or(u16::MAX),
        );

        let item = TerminalRecordingItem::PtyResize { time, rows, cols };
        self.write_data_item(&mut st, &item).await?;
        self.write_index_item(&IndexEntry::Resize { time, cols, rows })
            .await?;

        // Ensure the "previous" snapshot is alwats the current size
        self.write_keyframe(&mut st, time).await
    }

    async fn write_index_item(&self, item: &IndexEntry) -> Result<()> {
        self.index_writer.write_json_line(item).await?;
        Ok(())
    }

    async fn maybe_keyframe(&self, st: &mut RecorderState, time: f32) -> Result<()> {
        let due = st.bytes_since_keyframe >= MAX_GOP_BYTES
            || (time - st.last_keyframe_time) >= MAX_GOP_SECONDS;
        if !due {
            return Ok(());
        }
        self.write_keyframe(st, time).await
    }

    async fn write_keyframe(&self, st: &mut RecorderState, time: f32) -> Result<()> {
        if !st.pty {
            return Ok(());
        }

        // Index the checkpoint at the offset where this snapshot line will start
        let offset = st.offset;
        let item = TerminalRecordingItem::Snapshot {
            time,
            snapshot: Bytes::from(st.screen.snapshot()),
        };
        self.write_data_item(st, &item).await?;
        st.bytes_since_keyframe = 0;
        st.last_keyframe_time = time;
        self.write_index_item(&IndexEntry::Keyframe { time, offset })
            .await
    }
}

impl Drop for TerminalRecorder {
    fn drop(&mut self) {
        let state = self.state.clone();
        let index_writer = self.index_writer.clone();

        tokio::spawn(async move {
            let entry = IndexEntry::End {
                time: state.lock().await.duration,
            };
            if let Err(error) = index_writer.write_json_line(&entry).await {
                error!(%error, "Failed to write the recording index footer");
            }
        });
    }
}

impl Recorder for TerminalRecorder {
    fn kind() -> RecordingKind {
        RecordingKind::Terminal
    }

    async fn new(opener: &RecordingWriterOpener) -> Result<Self> {
        let index_writer = opener.open_index().await?;
        index_writer
            .write_json_line(&IndexEntry::Keyframe {
                time: 0.0,
                offset: 0,
            })
            .await?;
        Ok(Self {
            data_writer: Arc::new(opener.open_ndjson_data().await?),
            index_writer: Arc::new(index_writer),
            started_at: Instant::now(),
            state: Arc::new(Mutex::new(RecorderState::default())),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Untagged variants ignore unknown fields, so the item shapes must stay distinct
    /// enough that a line only ever matches the variant it was written as.
    #[test]
    fn items_do_not_match_each_others_shapes() {
        for item in [
            TerminalRecordingItem::Snapshot {
                time: 1.0,
                snapshot: Bytes::from_static(b"\x1b[2J"),
            },
            TerminalRecordingItem::Data {
                time: 2.0,
                stream: TerminalRecordingStreamId::Error,
                data: Bytes::from_static(b"boom"),
            },
            TerminalRecordingItem::PtyResize {
                time: 3.0,
                cols: 100,
                rows: 40,
            },
        ] {
            let json = serde_json::to_string(&item).expect("serialize");
            let parsed: TerminalRecordingItem = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(
                std::mem::discriminant(&item),
                std::mem::discriminant(&parsed),
                "{json} round-tripped into a different variant"
            );
        }
    }
}
