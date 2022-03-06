use anyhow::Result;
use bytes::{Bytes, BytesMut};
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::{mpsc, Mutex};
use tracing::*;
use warpgate_db_entities::Recording;

#[derive(Clone)]
pub struct RecordingWriter {
    sender: mpsc::Sender<Bytes>,
}

impl RecordingWriter {
    pub(crate) async fn new(
        path: PathBuf,
        model: Recording::Model,
        db: Arc<Mutex<DatabaseConnection>>,
    ) -> Result<Self> {
        let file = File::create(&path).await?;
        let mut writer = BufWriter::new(file);
        let (sender, mut receiver) = mpsc::channel::<Bytes>(1024);
        tokio::spawn(async move {
            if let Err(error) = async {
                while let Some(bytes) = receiver.recv().await {
                    writer.write_all(&bytes).await?;
                }

                Ok::<(), anyhow::Error>(())
            }
            .await
            {
                error!(%error, ?path, "Failed to write recording");
            }

            if let Err(error) = async {
                writer.flush().await?;

                use sea_orm::ActiveValue::Set;
                let id = model.id.clone();
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
                error!(%error, ?path, "Failed to write recording");
            }
        });

        Ok(RecordingWriter {
            sender,
        })
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        self.sender.send(BytesMut::from(data).freeze()).await?;
        Ok(())
    }
}
