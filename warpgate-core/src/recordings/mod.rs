use std::collections::HashMap;
use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use serde::Serialize;
use tokio::sync::{broadcast, Mutex};
use tracing::*;
use uuid::Uuid;
use warpgate_common::helpers::fs::secure_directory;
use warpgate_common::{GlobalParams, RecordingsConfig, SessionId, WarpgateConfig};
use warpgate_db_entities::Recording::{self, RecordingKind};
mod terminal;
mod traffic;
mod writer;
pub use terminal::*;
pub use traffic::*;
pub use writer::RecordingWriter;

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
    params: GlobalParams,
}

impl SessionRecordings {
    pub fn new(
        db: Arc<Mutex<DatabaseConnection>>,
        config: &WarpgateConfig,
        params: &GlobalParams,
    ) -> Result<Self> {
        let mut path = params.paths_relative_to().clone();
        path.push(&config.store.recordings.path);
        if config.store.recordings.enable {
            std::fs::create_dir_all(&path)?;
            if params.should_secure_files() {
                secure_directory(&path)?;
            }
        }
        Ok(Self {
            db,
            config: config.store.recordings.clone(),
            path,
            live: Arc::new(Mutex::new(HashMap::new())),
            params: params.clone(),
        })
    }

    /// Starting a recording with the same name again will append to it
    pub async fn start<T, M>(
        &mut self,
        id: &SessionId,
        name: Option<String>,
        metadata: M,
    ) -> Result<T>
    where
        T: Recorder,
        M: Serialize + Debug,
    {
        if !self.config.enable {
            return Err(Error::Disabled);
        }

        let name = name.unwrap_or_else(|| Uuid::new_v4().to_string());
        let path = self.path_for(id, &name);

        tokio::fs::create_dir_all(&path.parent().ok_or(Error::InvalidPath)?).await?;

        let model = {
            let db = self.db.lock().await;
            let existing = Recording::Entity::find()
                .filter(
                    Recording::Column::SessionId
                        .eq(*id)
                        .and(Recording::Column::Name.eq(name.clone()))
                        .and(Recording::Column::Kind.eq(T::kind())),
                )
                .one(&*db)
                .await?;
            match existing {
                Some(e) => e,
                None => {
                    info!(%name, ?metadata, path=?path, "Recording session {}", id);
                    use sea_orm::ActiveValue::Set;
                    let values = Recording::ActiveModel {
                        id: Set(Uuid::new_v4()),
                        started: Set(chrono::Utc::now()),
                        session_id: Set(*id),
                        name: Set(name.clone()),
                        kind: Set(T::kind()),
                        metadata: Set(serde_json::to_string(&metadata)?),
                        ..Default::default()
                    };
                    values.insert(&*db).await.map_err(Error::Database)?
                }
            }
        };

        let writer = RecordingWriter::new(
            path,
            model,
            self.db.clone(),
            self.live.clone(),
            &self.params,
        )
        .await?;
        Ok(T::new(writer))
    }

    pub async fn subscribe_live(&self, id: &Uuid) -> Option<broadcast::Receiver<Bytes>> {
        let live = self.live.lock().await;
        live.get(id).map(|sender| sender.subscribe())
    }

    pub async fn remove(&self, session_id: &SessionId, name: &str) -> Result<()> {
        let path = self.path_for(session_id, name);
        tokio::fs::remove_file(&path).await?;
        if let Some(parent) = path.parent() {
            if tokio::fs::read_dir(parent)
                .await?
                .next_entry()
                .await?
                .is_none()
            {
                tokio::fs::remove_dir(parent).await?;
            }
        }
        Ok(())
    }

    pub fn path_for<P: AsRef<Path>>(&self, session_id: &SessionId, name: P) -> PathBuf {
        self.path.join(session_id.to_string()).join(&name)
    }
}
