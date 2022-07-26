use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use sea_orm::{ActiveModelTrait, DatabaseConnection};
use tokio::sync::{broadcast, Mutex};
use tracing::*;
use uuid::Uuid;
use warpgate_db_entities::Recording::{self, RecordingKind};

use crate::{RecordingsConfig, SessionId, WarpgateConfig};
mod terminal;
mod traffic;
mod writer;
pub use terminal::*;
pub use traffic::*;
use writer::RecordingWriter;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    #[error("Database: {0}")]
    Database(#[from] sea_orm::DbErr),

    #[error("Failed to serialize a recording item: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Writer is closed")]
    Closed,

    #[error("Disabled")]
    Disabled,

    #[error("Invalid recording path")]
    InvalidPath,
}

pub type Result<T> = std::result::Result<T, Error>;

pub trait Recorder {
    fn kind() -> RecordingKind;
    fn new(writer: RecordingWriter) -> Self;
}

pub struct SessionRecordings {
    db: Arc<Mutex<DatabaseConnection>>,
    path: PathBuf,
    config: RecordingsConfig,
    live: Arc<Mutex<HashMap<Uuid, broadcast::Sender<Bytes>>>>,
}

impl SessionRecordings {
    pub fn new(db: Arc<Mutex<DatabaseConnection>>, config: &WarpgateConfig) -> Result<Self> {
        let mut path = config.paths_relative_to.clone();
        path.push(&config.store.recordings.path);
        if config.store.recordings.enable {
            std::fs::create_dir_all(&path)?;
            crate::helpers::fs::secure_directory(&path)?;
        }
        Ok(Self {
            db,
            config: config.store.recordings.clone(),
            path,
            live: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn start<T>(&mut self, id: &SessionId, name: String) -> Result<T>
    where
        T: Recorder,
    {
        if !self.config.enable {
            return Err(Error::Disabled);
        }

        let path = self.path_for(id, &name);
        tokio::fs::create_dir_all(&path.parent().ok_or(Error::InvalidPath)?).await?;
        info!(%name, path=?path, "Recording session {}", id);

        let model = {
            use sea_orm::ActiveValue::Set;
            let values = Recording::ActiveModel {
                id: Set(Uuid::new_v4()),
                started: Set(chrono::Utc::now()),
                session_id: Set(*id),
                name: Set(name),
                kind: Set(T::kind()),
                ..Default::default()
            };

            let db = self.db.lock().await;
            values.insert(&*db).await.map_err(Error::Database)?
        };

        let writer = RecordingWriter::new(path, model, self.db.clone(), self.live.clone()).await?;
        Ok(T::new(writer))
    }

    pub async fn subscribe_live(&self, id: &Uuid) -> Option<broadcast::Receiver<Bytes>> {
        let live = self.live.lock().await;
        live.get(id).map(|sender| sender.subscribe())
    }

    pub fn path_for(&self, session_id: &SessionId, name: &dyn AsRef<std::path::Path>) -> PathBuf {
        self.path.join(session_id.to_string()).join(&name)
    }
}
