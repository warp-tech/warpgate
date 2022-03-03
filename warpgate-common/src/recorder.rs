use anyhow::{Context, Result};
use bytes::{BytesMut, Bytes};
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait};
use serde::{Serialize, Deserialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex};
use tokio::time::Instant;
use tracing::*;
use uuid::Uuid;
use warpgate_db_entities::Recording;

use crate::SessionId;

mod serde_base64 {
    use bytes::Bytes;
    use data_encoding::BASE64;
    use serde::{Serializer, Deserialize};

    pub fn serialize<S>(bytes: &Bytes, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(BASE64.decode(s.as_bytes()).map_err(serde::de::Error::custom)?.into())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Record {
    pub time: f32,
    #[serde(with = "serde_base64")]
    pub data: Bytes,
}

pub struct SessionRecorder {
    id: Uuid,
    db: Arc<Mutex<DatabaseConnection>>,
    sender: mpsc::Sender<BytesMut>,
}

impl SessionRecorder {
    async fn new(
        path: PathBuf,
        model: Recording::Model,
        db: Arc<Mutex<DatabaseConnection>>,
    ) -> Result<Self> {
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
                        data: bytes,
                    };
                    let serialized_record = serde_json::to_vec(&record)?;
                    file.write_all(&serialized_record).await?;
                    file.write_all(b"\n").await?;
                }
                Ok::<(), anyhow::Error>(())
            }
            .await
            {
                error!(%error, ?path, "Failed to write recording");
            }
        });

        Ok(SessionRecorder {
            id: model.id,
            db,
            sender,
        })
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        self.sender.send(BytesMut::from(data)).await?;
        Ok(())
    }
}

impl Drop for SessionRecorder {
    fn drop(&mut self) {
        use sea_orm::ActiveValue::Set;
        let id = self.id.clone();
        let db = self.db.clone();
        tokio::spawn(async move {
            if let Err(error) = async {
                let db = db.lock().await;
                let recording = Recording::Entity::find_by_id(id)
                    .one(&*db)
                    .await?
                    .ok_or(anyhow::anyhow!("Recording not found"))?;
                let mut model: Recording::ActiveModel = recording.into();
                model.ended = Set(Some(chrono::Utc::now()));
                model.update(&*db).await?;
                Ok::<(), anyhow::Error>(())
            }
            .await
            {
                error!(%error, ?id, "Failed to insert recording");
            }
        });
    }
}

pub struct SessionRecordings {
    db: Arc<Mutex<DatabaseConnection>>,
    path: PathBuf,
}

impl SessionRecordings {
    pub fn new(db: Arc<Mutex<DatabaseConnection>>, path: String) -> Result<Self> {
        std::fs::create_dir_all(&path)?;
        Ok(Self {
            db,
            path: PathBuf::from(path),
        })
    }

    pub async fn start(&self, id: &SessionId, name: String) -> Result<SessionRecorder> {
        let path = self.path_for(id, &name);
        tokio::fs::create_dir_all(&path.parent().unwrap()).await?;
        info!(%name, path=?path, "Recording session {}", id);

        let model = {
            use sea_orm::ActiveValue::Set;
            let values = Recording::ActiveModel {
                id: Set(Uuid::new_v4()),
                started: Set(chrono::Utc::now()),
                session_id: Set(id.clone()),
                name: Set(name),
                ..Default::default()
            };

            let db = self.db.lock().await;
            values
                .insert(&*db)
                .await
                .context("Error inserting recording")?
        };

        SessionRecorder::new(path, model, self.db.clone()).await
    }

    pub fn path_for(&self, session_id: &SessionId, name: &dyn AsRef<std::path::Path>) -> PathBuf {
        self.path.join(session_id.to_string()).join(&name)
    }
}
