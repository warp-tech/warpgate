use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait};
use tokio::fs::File;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::{broadcast, mpsc, Mutex};
use tracing::*;
use uuid::Uuid;
use warpgate_db_entities::Recording;

use super::{Error, Result};
use crate::helpers::fs::secure_file;
use crate::try_block;

#[derive(Clone)]
pub struct RecordingWriter {
    sender: mpsc::Sender<Bytes>,
    live_sender: broadcast::Sender<Bytes>,
    drop_signal: mpsc::Sender<()>,
}

impl RecordingWriter {
    pub(crate) async fn new(
        path: PathBuf,
        model: Recording::Model,
        db: Arc<Mutex<DatabaseConnection>>,
        live: Arc<Mutex<HashMap<Uuid, broadcast::Sender<Bytes>>>>,
    ) -> Result<Self> {
        let file = File::create(&path).await?;
        secure_file(&path)?;
        let mut writer = BufWriter::new(file);
        let (sender, mut receiver) = mpsc::channel::<Bytes>(1024);
        let (drop_signal, mut drop_receiver) = mpsc::channel(1);

        let live_sender = broadcast::channel(128).0;
        {
            let mut live = live.lock().await;
            live.insert(model.id, live_sender.clone());
        }

        tokio::spawn({
            let live = live.clone();
            let id = model.id;
            async move {
                let _ = drop_receiver.recv().await;
                let mut live = live.lock().await;
                live.remove(&id);
            }
        });

        tokio::spawn(async move {
            try_block!(async {
                let mut last_flush = Instant::now();
                loop {
                    if Instant::now() - last_flush > Duration::from_secs(5) {
                        last_flush = Instant::now();
                        writer.flush().await?;
                    }
                    tokio::select! {
                        data = receiver.recv() => match data {
                            Some(bytes) => {
                                writer.write_all(&bytes).await?;
                            }
                            None => break,
                        },
                        _ = tokio::time::sleep(Duration::from_millis(5000)) => ()
                    }
                }
                Ok::<(), anyhow::Error>(())
            } catch (error: anyhow::Error) {
                error!(%error, ?path, "Failed to write recording");
            });

            try_block!(async {
                writer.flush().await?;

                use sea_orm::ActiveValue::Set;
                let id = model.id;
                let db = db.lock().await;
                let recording = Recording::Entity::find_by_id(id)
                    .one(&*db)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("Recording not found"))?;
                let mut model: Recording::ActiveModel = recording.into();
                model.ended = Set(Some(chrono::Utc::now()));
                model.update(&*db).await?;
                Ok::<(), anyhow::Error>(())
            } catch (error: anyhow::Error) {
                error!(%error, ?path, "Failed to write recording");
            });
        });

        Ok(RecordingWriter {
            sender,
            live_sender,
            drop_signal,
        })
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        let data = Bytes::from(data.to_vec());
        self.sender
            .send(data.clone())
            .await
            .map_err(|_| Error::Closed)?;
        let _ = self.live_sender.send(data);
        Ok(())
    }
}

impl Drop for RecordingWriter {
    fn drop(&mut self) {
        let _ = self.drop_signal.send(());
    }
}
