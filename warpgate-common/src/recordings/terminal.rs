use anyhow::Result;
use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;
use warpgate_db_entities::Recording::RecordingKind;

use super::writer::RecordingWriter;
use super::Recorder;

#[derive(Serialize)]
#[serde(untagged)]
pub enum AsciiCast {
    Header {
        time: f32,
        version: u32,
        width: u32,
        height: u32,
        title: String,
    },
    Output(f32, String, String),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum TerminalRecordingStreamId {
    Input,
    Output,
    Error,
}

impl Default for TerminalRecordingStreamId {
    fn default() -> Self {
        TerminalRecordingStreamId::Output
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum TerminalRecordingItem {
    Data {
        time: f32,
        #[serde(default)]
        stream: TerminalRecordingStreamId,
        #[serde(with = "crate::helpers::serde_base64")]
        data: Bytes,
    },
    PtyResize {
        time: f32,
        cols: u32,
        rows: u32,
    },
}

impl From<TerminalRecordingItem> for AsciiCast {
    fn from(item: TerminalRecordingItem) -> Self {
        match item {
            TerminalRecordingItem::Data { time, stream, data } => AsciiCast::Output(
                time,
                match stream {
                    TerminalRecordingStreamId::Input => "i".to_string(),
                    TerminalRecordingStreamId::Output => "o".to_string(),
                    TerminalRecordingStreamId::Error => "e".to_string(),
                },
                String::from_utf8_lossy(&data[..]).to_string(),
            ),
            TerminalRecordingItem::PtyResize { time, cols, rows } => AsciiCast::Header {
                time,
                version: 2,
                width: cols,
                height: rows,
                title: "".to_string(),
            },
        }
    }
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
        let mut serialized_item = serde_json::to_vec(&item)?;
        serialized_item.push(b'\n');
        self.writer.write(&serialized_item).await?;
        Ok(())
    }

    pub async fn write(&mut self, stream: TerminalRecordingStreamId, data: &[u8]) -> Result<()> {
        self.write_item(&TerminalRecordingItem::Data {
            time: self.get_time(),
            stream,
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
