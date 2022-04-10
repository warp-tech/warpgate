use anyhow::Result;
use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;
use warpgate_db_entities::Recording::RecordingKind;

use super::writer::RecordingWriter;
use super::Recorder;

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum TerminalRecordingItem {
    Data {
        time: f32,
        #[serde(with = "crate::helpers::serde_base64")]
        data: Bytes,
    },
    PtyResize {
        time: f32,
        cols: u32,
        rows: u32,
    },
}

pub struct TerminalRecorder {
    writer: RecordingWriter,
    started_at: Instant,
}

impl TerminalRecorder {
    fn get_time(&self) -> f32 {
        self.started_at.elapsed().as_secs_f32()
    }

    async fn write_item(&mut self, item: &TerminalRecordingItem) -> Result<()> {
        let serialized_item = serde_json::to_vec(&item)?;
        self.writer.write(&serialized_item).await?;
        self.writer.write(b"\n").await?;
        Ok(())
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        self.write_item(&TerminalRecordingItem::Data {
            time: self.get_time(),
            data: BytesMut::from(data).freeze(),
        })
        .await
    }

    pub async fn write_pty_resize(&mut self, cols: u32, rows: u32) -> Result<()> {
        self.write_item(&TerminalRecordingItem::PtyResize {
            time: self.get_time(),
            rows,
            cols,
        })
        .await
    }
}

impl Recorder for TerminalRecorder {
    fn kind() -> RecordingKind {
        RecordingKind::Terminal
    }

    fn new(writer: RecordingWriter) -> Self {
        TerminalRecorder {
            writer,
            started_at: Instant::now(),
        }
    }
}
