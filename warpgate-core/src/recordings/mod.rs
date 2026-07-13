use std::collections::HashMap;
use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use serde::Serialize;
use time::OffsetDateTime;
use tokio::sync::{Mutex, broadcast};
use tracing::info;
use uuid::Uuid;
use warpgate_common::helpers::fs::secure_directory;
use warpgate_common::{GlobalParams, RecordingsConfig, SessionId, WarpgateConfig};
use warpgate_db_entities::Recording::{self, RecordingKind};
mod desktop;
mod framebuffer;
mod terminal;
mod traffic;
mod writer;
pub use desktop::*;
pub use terminal::*;
pub use traffic::*;
pub use writer::{NDJsonRecordingWriter, RawRecordingWriter};

// The possible files that a recording can open
#[derive(Debug, Clone, Copy)]
pub enum RecordingFile {
    NDJsonData,
    TcpDumpData,
    Index,
}

impl RecordingFile {
    fn filename(&self) -> &'static str {
        match self {
            RecordingFile::NDJsonData => "data.ndjson",
            RecordingFile::TcpDumpData => "data.tcpdump",
            RecordingFile::Index => "index.ndjson",
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    #[error("Database: {0}")]
    Database(#[from] sea_orm::DbErr),

    #[error("Failed to serialize a recording item: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Image codec: {0}")]
    Codec(String),

    #[error("Writer is closed")]
    Closed,

    #[error("Disabled")]
    Disabled,

    #[error("Invalid recording path")]
    InvalidPath,
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct RecordingWriterOpener {
    folder: PathBuf,
    model: Recording::Model,
    db: DatabaseConnection,
    live: Arc<Mutex<HashMap<Uuid, broadcast::Sender<Bytes>>>>,
    params: GlobalParams,
}

impl RecordingWriterOpener {
    pub async fn open_ndjson_data(&self) -> Result<NDJsonRecordingWriter> {
        Ok(NDJsonRecordingWriter::new(
            self.open(RecordingFile::NDJsonData).await?,
        ))
    }

    pub async fn open_index(&self) -> Result<NDJsonRecordingWriter> {
        Ok(NDJsonRecordingWriter::new(
            self.open(RecordingFile::Index).await?,
        ))
    }

    pub async fn open_tcpdump_data(&self) -> Result<RawRecordingWriter> {
        self.open(RecordingFile::TcpDumpData).await
    }

    async fn open(&self, file: RecordingFile) -> Result<RawRecordingWriter> {
        // Only the primary data stream is live-broadcast (keyed by recording id). The index
        // and tcpdump sidecars must NOT register: they'd overwrite the data writer's entry
        // under the same id, and a live viewer would then receive the index (seek anchors,
        // no pixels) instead of the framebuffer.
        let live = matches!(file, RecordingFile::NDJsonData).then(|| self.live.clone());
        RawRecordingWriter::new(
            self.folder.join(file.filename()),
            self.model.clone(),
            self.db.clone(),
            live,
            &self.params,
        )
        .await
    }
}

pub trait Recorder
where
    Self: Sized,
{
    fn kind() -> RecordingKind;
    fn new(opener: &RecordingWriterOpener) -> impl Future<Output = Result<Self>> + Send;
}

pub struct SessionRecordings {
    db: DatabaseConnection,
    path: PathBuf,
    config: RecordingsConfig,
    live: Arc<Mutex<HashMap<Uuid, broadcast::Sender<Bytes>>>>,
    params: GlobalParams,
}

impl SessionRecordings {
    pub fn new(
        db: DatabaseConnection,
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
    pub async fn start<T, M>(&self, id: &SessionId, name: Option<String>, metadata: M) -> Result<T>
    where
        T: Recorder,
        M: Serialize + Debug,
    {
        if !self.config.enable {
            return Err(Error::Disabled);
        }

        let name = name.unwrap_or_else(|| Uuid::new_v4().to_string());
        // Gen-2 recordings are folders holding fixed-name files (`data.ndjson`, and a
        // desktop `index.json`), so the recording path is a directory we create here.
        let folder = self.path_for(id, &name);
        tokio::fs::create_dir_all(&folder).await?;
        if self.params.should_secure_files() {
            secure_directory(&folder)?;
        }

        let model = {
            let db = &self.db;
            let existing = Recording::Entity::find()
                .filter(
                    Recording::Column::SessionId
                        .eq(*id)
                        .and(Recording::Column::Name.eq(name.clone()))
                        .and(Recording::Column::Kind.eq(T::kind())),
                )
                .one(&*db)
                .await?;
            if let Some(e) = existing {
                e
            } else {
                use sea_orm::ActiveValue::Set;
                info!(%name, ?metadata, path=?folder, "Recording session {}", id);
                let values = Recording::ActiveModel {
                    id: Set(Uuid::new_v4()),
                    started: Set(OffsetDateTime::now_utc()),
                    session_id: Set(*id),
                    name: Set(name.clone()),
                    kind: Set(T::kind()),
                    metadata: Set(serde_json::to_string(&metadata)?),
                    generation: Set(2),
                    ..Default::default()
                };
                values.insert(&*db).await.map_err(Error::Database)?
            }
        };

        let opener = RecordingWriterOpener {
            folder: folder.clone(),
            model,
            db: self.db.clone(),
            live: self.live.clone(),
            params: self.params.clone(),
        };

        Ok(T::new(&opener).await?)
    }

    pub async fn subscribe_live(&self, id: &Uuid) -> Option<broadcast::Receiver<Bytes>> {
        let live = self.live.lock().await;
        live.get(id).map(broadcast::Sender::subscribe)
    }

    pub async fn remove(&self, session_id: &SessionId, name: &str) -> Result<()> {
        let path = self.path_for(session_id, name);
        // gen 2 is a folder, gen 1 a single file — pick by what's on disk.
        if tokio::fs::metadata(&path).await?.is_dir() {
            tokio::fs::remove_dir_all(&path).await?;
        } else {
            tokio::fs::remove_file(&path).await?;
        }
        if let Some(parent) = path.parent()
            && tokio::fs::read_dir(parent)
                .await?
                .next_entry()
                .await?
                .is_none()
        {
            tokio::fs::remove_dir(parent).await?;
        }
        Ok(())
    }

    pub fn path_for<P: AsRef<Path>>(&self, session_id: &SessionId, name: P) -> PathBuf {
        self.path.join(session_id.to_string()).join(&name)
    }

    /// On-disk path of a recording's primary data stream, generation-aware: gen 1 is a
    /// single file, gen 2 is multiple files inside the recording folder.
    pub fn file_path(&self, recording: &Recording::Model, file: RecordingFile) -> PathBuf {
        let base = self.path_for(&recording.session_id, &recording.name);
        if recording.generation >= 2 {
            base.join(file.filename())
        } else {
            base
        }
    }
}
