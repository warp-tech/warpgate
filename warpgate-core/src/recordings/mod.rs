use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use serde::Serialize;
use time::OffsetDateTime;
use tokio::sync::{Mutex, broadcast};
use tracing::info;
use uuid::Uuid;
use warpgate_common::helpers::fs::secure_directory;
use warpgate_common::{GlobalParams, SessionId};
use warpgate_db_entities::Parameters;
use warpgate_db_entities::Recording::{self, RecordingKind};
mod desktop;
mod framebuffer;
mod storage;
mod terminal;
mod traffic;
mod writer;
pub use desktop::*;
pub use storage::FileAccess;
use storage::Storage;
pub use terminal::*;
pub use traffic::*;
pub use writer::{LiveChunk, NDJsonRecordingWriter, RawRecordingWriter};

/// The live-broadcast channel for a recording's primary data stream, keyed by
/// recording id. Each item carries its end byte offset so a viewer can splice
/// the live tail onto a history snapshot without gaps (see [`LiveChunk`]).
type LiveMap = Arc<Mutex<HashMap<Uuid, broadcast::Sender<LiveChunk>>>>;

// The possible files that a recording can open
#[derive(Debug, Clone, Copy)]
pub enum RecordingFile {
    NDJsonData,
    TcpDumpData,
    Index,
}

impl RecordingFile {
    const fn filename(self) -> &'static str {
        match self {
            Self::NDJsonData => "data.ndjson",
            Self::TcpDumpData => "data.tcpdump",
            Self::Index => "index.ndjson",
        }
    }

    pub const fn mime_type(self) -> &'static str {
        match self {
            Self::NDJsonData | Self::Index => "application/x-ndjson",
            Self::TcpDumpData => "application/vnd.tcpdump.pcap",
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

    #[error("Storage backend: {0}")]
    Aws(#[from] warpgate_aws::AwsError),
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct RecordingWriterOpener {
    storage: Storage,
    model: Recording::Model,
    db: DatabaseConnection,
    live: LiveMap,
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
        let sink = self
            .storage
            .open_sink(&self.model, file, &self.params)
            .await?;
        RawRecordingWriter::new(sink, self.model.clone(), self.db.clone(), live).await
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
    live: LiveMap,
    params: GlobalParams,
}

impl SessionRecordings {
    pub fn new(db: DatabaseConnection, params: &GlobalParams) -> Self {
        Self {
            db,
            live: Arc::new(Mutex::new(HashMap::new())),
            params: params.clone(),
        }
    }

    async fn storage(&self) -> Result<Storage> {
        Storage::load(&self.db, &self.params).await
    }

    pub async fn is_enabled(&self) -> Result<bool> {
        Ok(Parameters::Entity::get(&self.db).await?.recordings_enable)
    }

    /// Starting a recording with the same name again will append to it
    pub async fn start<T, M>(&self, id: &SessionId, name: Option<String>, metadata: M) -> Result<T>
    where
        T: Recorder,
        M: Serialize + Debug,
    {
        let storage = self.storage().await?;
        if !storage.enabled() {
            return Err(Error::Disabled);
        }

        let name = name.unwrap_or_else(|| Uuid::new_v4().to_string());
        // Gen-2 recordings are folders holding fixed-name files (`data.ndjson`, and a
        // desktop `index.json`), so the recording path is a directory we create here.
        // On S3 this folder is a scratch copy, live-readable while the session runs and
        // dropped once each file finishes uploading.
        let folder = storage.recording_folder(id, &name);
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
                .one(db)
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
                values.insert(db).await.map_err(Error::Database)?
            }
        };

        let opener = RecordingWriterOpener {
            storage,
            model,
            db: self.db.clone(),
            live: self.live.clone(),
            params: self.params.clone(),
        };

        T::new(&opener).await
    }

    pub async fn subscribe_live(&self, id: &Uuid) -> Option<broadcast::Receiver<LiveChunk>> {
        let live = self.live.lock().await;
        live.get(id).map(broadcast::Sender::subscribe)
    }

    pub async fn remove(&self, session_id: &SessionId, name: &str) -> Result<()> {
        self.storage().await?.remove(session_id, name).await
    }

    /// Open a recording file as a streaming reader (local file or S3 object),
    /// without buffering the whole thing. Used by endpoints that transform the
    /// file server-side.
    pub async fn access(
        &self,
        recording: &Recording::Model,
        file: RecordingFile,
    ) -> Result<FileAccess> {
        Ok(self.storage().await?.access(recording, file))
    }
}
