use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::time::Instant;
use warpgate_db_entities::Recording::RecordingKind;

use super::{Recorder, Result};
use crate::recordings::RecordingWriterOpener;
use crate::recordings::writer::NDJsonRecordingWriter;

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

#[derive(Serialize, Deserialize, Debug, Default)]
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

impl From<TerminalRecordingItem> for AsciiCast {
    fn from(item: TerminalRecordingItem) -> Self {
        match item {
            TerminalRecordingItem::Data { time, stream, data } => Self::Output(
                time,
                match stream {
                    TerminalRecordingStreamId::Input => "i".to_string(),
                    TerminalRecordingStreamId::Output => "o".to_string(),
                    TerminalRecordingStreamId::Error => "e".to_string(),
                },
                String::from_utf8_lossy(&data[..]).to_string(),
            ),
            TerminalRecordingItem::PtyResize { time, cols, rows } => Self::Header {
                time,
                version: 2,
                width: cols,
                height: rows,
                title: "".into(),
            },
        }
    }
}

pub struct TerminalRecorder {
    writer: NDJsonRecordingWriter,
    started_at: Instant,
}

impl TerminalRecorder {
    fn get_time(&self) -> f32 {
        self.started_at.elapsed().as_secs_f32()
    }

    pub async fn write(&self, stream: TerminalRecordingStreamId, data: &[u8]) -> Result<()> {
        self.writer
            .write_json_line(&TerminalRecordingItem::Data {
                time: self.get_time(),
                stream,
                data: Bytes::from(data.to_vec()),
            })
            .await?;
        Ok(())
    }

    pub async fn write_pty_resize(&self, cols: u32, rows: u32) -> Result<()> {
        self.writer
            .write_json_line(&TerminalRecordingItem::PtyResize {
                time: self.get_time(),
                rows,
                cols,
            })
            .await?;
        Ok(())
    }
}

impl Recorder for TerminalRecorder {
    fn kind() -> RecordingKind {
        RecordingKind::Terminal
    }

    async fn new(opener: &RecordingWriterOpener) -> Result<Self> {
        Ok(Self {
            writer: opener.open_ndjson_data().await?,
            started_at: Instant::now(),
        })
    }
}
