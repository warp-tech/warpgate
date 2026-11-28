use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use sea_orm::{ActiveModelTrait, DatabaseConnection};
use serde::Serialize;
use time::OffsetDateTime;
use tokio::sync::{Mutex, broadcast};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{info, warn};
use uuid::Uuid;
use warpgate_common::helpers::fs::secure_directory;
use warpgate_common::{GlobalParams, NodeId, TargetSessionId};
use warpgate_db_entities::Parameters;
use warpgate_db_entities::Recording::{self, RecordingKind};
mod desktop;
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
use writer::{RecordingCompletion, WriterShutdown};

/// How long `SessionRecordings::shutdown` waits
/// (just under kubernetes default)
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(25);

const RECORDING_GENERATION: i32 = 3;

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

    #[error("Creating recording directory {}: {source}", path.display())]
    CreateDirectory {
        path: std::path::PathBuf,
        source: std::io::Error,
    },

    #[error("Database: {0}")]
    Database(#[from] sea_orm::DbErr),

    #[error("Failed to serialize a recording item: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Image codec: {0}")]
    Codec(String),

    #[error(transparent)]
    PngEncode(#[from] crate::protocols::PngEncodeError),

    #[error("Writer is closed")]
    Closed,

    #[error("Invalid recording path")]
    InvalidPath,

    #[error("Storage backend: {0}")]
    Aws(#[from] warpgate_aws::AwsError),

    #[error(transparent)]
    Azure(#[from] warpgate_azure::AzureError),
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct RecordingWriterOpener {
    storage: Storage,
    model: Recording::Model,
    db: DatabaseConnection,
    live: LiveMap,
    params: GlobalParams,
    shutdown: CancellationToken,
    shutdown_tracker: TaskTracker,
    completion: Arc<RecordingCompletion>,
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

        RawRecordingWriter::new(
            sink,
            live,
            WriterShutdown {
                token: self.shutdown.clone(),
                tracker: self.shutdown_tracker.clone(),
            },
            self.completion.register_writer().await,
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
    live: LiveMap,
    params: GlobalParams,
    node_id: NodeId,
    shutdown: CancellationToken,
    shutdown_tracker: TaskTracker,
}

impl SessionRecordings {
    pub fn new(db: DatabaseConnection, params: &GlobalParams, node_id: NodeId) -> Self {
        Self {
            db,
            node_id,
            live: Arc::new(Mutex::new(HashMap::new())),
            params: params.clone(),
            shutdown: CancellationToken::new(),
            shutdown_tracker: TaskTracker::new(),
        }
    }

    /// Signal every in-flight writer to finalize, then wait (bounded)
    pub async fn shutdown(&self) {
        self.shutdown.cancel();
        if !self.shutdown_tracker.is_empty() {
            info!(
                count = self.shutdown_tracker.len(),
                "Waiting for session recording uploads to finish..."
            );
        }
        self.shutdown_tracker.close();

        if tokio::time::timeout(SHUTDOWN_TIMEOUT, self.shutdown_tracker.wait())
            .await
            .is_err()
        {
            warn!("Timed out waiting for recording uploads to finish");
        }
    }

    async fn storage(&self) -> Result<Storage> {
        Storage::load(&self.db, &self.params).await
    }

    /// Whether [`Self::start`] would record
    pub async fn enabled(&self) -> Result<bool> {
        Ok(Parameters::Entity::get(&self.db).await?.recordings_enable)
    }

    /// `None` when recording is disabled.
    pub async fn start<T, M>(&self, id: &TargetSessionId, metadata: M) -> Result<Option<T>>
    where
        T: Recorder,
        M: Serialize + Debug,
    {
        if !self.enabled().await? {
            return Ok(None);
        }
        let storage = self.storage().await?;

        // A fresh name per start gives a recording's files a single writer
        let name = Uuid::new_v4().to_string();
        // Gen 2+ recordings are folders holding fixed-name files (`data.ndjson`, and an
        // index `index.json`), so the recording path is a directory we create here.
        // On S3 this folder is a scratch copy, live-readable while the session runs and
        // dropped once each file finishes uploading.
        let folder = storage.recording_folder(id, &name);
        tokio::fs::create_dir_all(&folder)
            .await
            .map_err(|source| Error::CreateDirectory {
                path: folder.clone(),
                source,
            })?;
        if self.params.should_secure_files() {
            secure_directory(&folder)?;
        }

        let model = {
            use sea_orm::ActiveValue::Set;
            info!(%name, ?metadata, path=?folder, "Recording session {}", id);
            Recording::ActiveModel {
                id: Set(Uuid::new_v4()),
                started: Set(OffsetDateTime::now_utc()),
                session_id: Set(*id),
                name: Set(name),
                kind: Set(T::kind()),
                metadata: Set(serde_json::to_string(&metadata)?),
                generation: Set(RECORDING_GENERATION),
                node_id: Set(Some(self.node_id)),
                ..Default::default()
            }
            .insert(&self.db)
            .await?
        };

        let opener = RecordingWriterOpener {
            storage,
            completion: RecordingCompletion::new(self.db.clone(), model.id),
            model,
            db: self.db.clone(),
            live: self.live.clone(),
            params: self.params.clone(),
            shutdown: self.shutdown.clone(),
            shutdown_tracker: self.shutdown_tracker.clone(),
        };

        // Held until every file is open, so a recorder that fails or is cancelled
        // half-way cannot let its first file end the recording.
        let construction = opener.completion.register_writer().await;
        let recorder = T::new(&opener).await?;
        construction.finished(None).await?;
        Ok(Some(recorder))
    }

    pub async fn subscribe_live(&self, id: &Uuid) -> Option<broadcast::Receiver<LiveChunk>> {
        let live = self.live.lock().await;
        live.get(id).map(broadcast::Sender::subscribe)
    }

    pub async fn remove(&self, session_id: &TargetSessionId, name: &str) -> Result<()> {
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

#[cfg(test)]
#[cfg(feature = "sqlite")]
mod tests;
