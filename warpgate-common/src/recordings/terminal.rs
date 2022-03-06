use anyhow::Result;
use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;
use warpgate_db_entities::Recording::RecordingKind;

use super::Recorder;
use super::writer::RecordingWriter;

#[derive(Serialize, Deserialize, Debug)]
pub struct TerminalRecordingItem {
    pub time: f32,
    #[serde(with = "crate::helpers::serde_base64")]
    pub data: Bytes,
}
pub struct TerminalRecorder {
    writer: RecordingWriter,
    started_at: Instant,
}

impl TerminalRecorder {
    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        let now = Instant::now();
        let record = TerminalRecordingItem {
            time: now.duration_since(self.started_at).as_secs_f32(),
            data: BytesMut::from(data).freeze(),
        };
        let serialized_record = serde_json::to_vec(&record)?;
        self.writer.write(&serialized_record).await?;
        self.writer.write(b"\n").await?;
        Ok(())
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
