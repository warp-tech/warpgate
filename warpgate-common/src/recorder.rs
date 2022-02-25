use anyhow::Result;
use bytes::BytesMut;
use serde::Serialize;
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::*;

use crate::SessionId;

mod serde_base64 {
    use data_encoding::BASE64;
    use serde::Serializer;

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64.encode(bytes))
    }
}

#[derive(Serialize, Debug)]
struct Record<'a> {
    pub time: f32,
    #[serde(with = "serde_base64")]
    pub data: &'a [u8],
}

pub struct SessionRecorder {
    sender: mpsc::Sender<BytesMut>,
}

impl SessionRecorder {
    async fn new(path: PathBuf) -> Result<Self> {
        let mut file = File::create(&path).await?;
        let started_at = Instant::now();
        let (sender, mut receiver) = mpsc::channel::<BytesMut>(1024);
        tokio::spawn(async move {
            if let Err(error) = async {
                while let Some(bytes) = receiver.recv().await {
                    let now = Instant::now();
                    let bytes = bytes.freeze();
                    let record = Record {
                        time: now.duration_since(started_at).as_secs_f32(),
                        data: &bytes,
                    };
                    let serialized_record = serde_yaml::to_vec(&record)?;
                    file.write_all(&serialized_record).await?;
                }
                Ok::<(), anyhow::Error>(())
            }
            .await
            {
                error!(%error, ?path, "Failed to write recording");
            }
        });
        Ok(SessionRecorder { sender })
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        self.sender.send(BytesMut::from(data)).await?;
        Ok(())
    }
}

pub struct SessionRecordings {
    path: PathBuf,
}

impl SessionRecordings {
    pub fn new(path: String) -> Result<Self> {
        std::fs::create_dir_all(&path)?;
        Ok(Self {
            path: PathBuf::from(path),
        })
    }

    pub async fn start(&self, id: &SessionId, name: String) -> Result<SessionRecorder> {
        let dir = self.path.join(id.to_string());
        tokio::fs::create_dir_all(&dir).await?;
        let path = dir.join(&name);
        info!(%name, path=?path, "Recording session {}", id);
        SessionRecorder::new(path).await
    }
}
