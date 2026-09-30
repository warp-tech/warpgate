use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use serde::Serialize;
use time::OffsetDateTime;
use tokio::sync::{Mutex, broadcast};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{info, warn};
use uuid::Uuid;
use warpgate_common::helpers::fs::secure_directory;
use warpgate_common::{GlobalParams, TargetSessionId};
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
use writer::{ConstructionHold, RecordingCompletion, WriterShutdown};
pub use writer::{LiveChunk, NDJsonRecordingWriter, RawRecordingWriter};

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
    shutdown: CancellationToken,
    shutdown_tracker: TaskTracker,
    completion: Arc<Mutex<RecordingCompletion>>,
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
            self.model.clone(),
            self.db.clone(),
            live,
            WriterShutdown {
                token: self.shutdown.clone(),
                tracker: self.shutdown_tracker.clone(),
            },
            self.completion.clone(),
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
    shutdown: CancellationToken,
    shutdown_tracker: TaskTracker,
}

impl SessionRecordings {
    pub fn new(db: DatabaseConnection, params: &GlobalParams) -> Self {
        Self {
            db,
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

    pub async fn is_enabled(&self) -> Result<bool> {
        Ok(Parameters::Entity::get(&self.db).await?.recordings_enable)
    }

    /// Starting a recording with the same name again will append to it. On S3
    /// storage this is not supported: each start completes its own upload of the
    /// same keys, and `ended` is not reset on append.
    pub async fn start<T, M>(
        &self,
        id: &TargetSessionId,
        name: Option<String>,
        metadata: M,
    ) -> Result<T>
    where
        T: Recorder,
        M: Serialize + Debug,
    {
        let storage = self.storage().await?;
        if !storage.enabled() {
            return Err(Error::Disabled);
        }

        let name = name.unwrap_or_else(|| Uuid::new_v4().to_string());
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
            let db = &self.db;
            let existing = Recording::Entity::find()
                .filter(
                    Recording::Column::SessionId
                        .eq(id.0)
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
                    generation: Set(RECORDING_GENERATION),
                    ..Default::default()
                };
                values.insert(db).await.map_err(Error::Database)?
            }
        };

        let id = model.id;
        let completion = Arc::<Mutex<RecordingCompletion>>::default();
        let hold = ConstructionHold::new(completion.clone()).await;
        let opener = RecordingWriterOpener {
            storage,
            model,
            db: self.db.clone(),
            live: self.live.clone(),
            params: self.params.clone(),
            shutdown: self.shutdown.clone(),
            shutdown_tracker: self.shutdown_tracker.clone(),
            completion: completion.clone(),
        };

        let recorder = T::new(&opener).await?;
        hold.open(&self.db, id).await;
        Ok(recorder)
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
mod tests {
    use std::path::{Path, PathBuf};

    use poem::http::{Method, StatusCode};
    use poem::listener::{Acceptor, Listener, TcpListener};
    use poem::{Request, Response};
    use sea_orm::ActiveValue::Set;
    use sea_orm::{Database, IntoActiveModel};
    use warpgate_aws::{S3Credentials, S3Storage, S3StorageConfig, StaticCredentials};
    use warpgate_db_entities::Parameters::{
        ConfigMigrationValues, RecordingsStorageConfig, set_config_migration_values,
    };
    use warpgate_db_migrations::migrate_database;

    use super::storage::RecordingSink;
    use super::*;

    /// A recording made of two files, like a terminal recording's data + index.
    struct TwoFiles {
        data: RawRecordingWriter,
        index: RawRecordingWriter,
    }

    impl Recorder for TwoFiles {
        fn kind() -> RecordingKind {
            RecordingKind::Terminal
        }

        async fn new(opener: &RecordingWriterOpener) -> Result<Self> {
            Ok(Self {
                data: opener.open(RecordingFile::NDJsonData).await?,
                index: opener.open(RecordingFile::Index).await?,
            })
        }
    }

    /// Just enough of the S3 multipart API, with a failure knob per call.
    #[derive(Default)]
    struct FakeS3 {
        fail_create: Option<&'static str>,
        fail_part: Option<(&'static str, u32)>,
        failed_parts: Vec<String>,
        completed: Vec<String>,
    }

    impl FakeS3 {
        fn handle(&mut self, method: &Method, path: &str, query: &str) -> Response {
            let part = query
                .split('&')
                .find_map(|pair| pair.strip_prefix("partNumber="))
                .and_then(|n| n.parse::<u32>().ok());
            let ok = |body: &str| Response::builder().body(body.to_string());
            let fail = || {
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body("<Error><Code>InvalidRequest</Code><Message>injected</Message></Error>")
            };
            match (method, part) {
                (&Method::POST, _) if query.split('&').any(|q| q.starts_with("uploads")) => {
                    if self.fail_create.is_some_and(|f| path.ends_with(f)) {
                        return fail();
                    }
                    ok(
                        "<InitiateMultipartUploadResult><UploadId>u</UploadId></InitiateMultipartUploadResult>",
                    )
                }
                (&Method::PUT, Some(n)) => {
                    if self
                        .fail_part
                        .is_some_and(|(f, fail_n)| path.ends_with(f) && n == fail_n)
                    {
                        self.failed_parts.push(path.into());
                        return fail();
                    }
                    Response::builder()
                        .header("ETag", format!("\"{n}\""))
                        .body("")
                }
                (&Method::POST, _) => {
                    self.completed.push(path.into());
                    ok(
                        "<CompleteMultipartUploadResult><ETag>\"e\"</ETag></CompleteMultipartUploadResult>",
                    )
                }
                (&Method::DELETE, _) => Response::builder().status(StatusCode::NO_CONTENT).body(""),
                _ => fail(),
            }
        }
    }

    struct Harness {
        db: DatabaseConnection,
        recordings: SessionRecordings,
        root: PathBuf,
        session_id: TargetSessionId,
        s3: Arc<std::sync::Mutex<FakeS3>>,
        s3_config: Option<S3StorageConfig>,
    }

    impl Harness {
        async fn new(s3: Option<FakeS3>) -> Self {
            set_config_migration_values(ConfigMigrationValues::default());
            let db = Database::connect("sqlite::memory:").await.unwrap();
            migrate_database(&db).await.unwrap();
            let root = std::env::temp_dir().join(format!("wg-recordings-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&root).unwrap();

            let use_s3 = s3.is_some();
            let s3 = Arc::new(std::sync::Mutex::new(s3.unwrap_or_default()));
            let s3_config = if use_s3 {
                Some(S3StorageConfig {
                    bucket: "recordings".into(),
                    region: "us-east-1".into(),
                    endpoint: Some(format!("http://{}", serve(s3.clone()).await)),
                    path_style: true,
                    prefix: String::new(),
                    credentials: S3Credentials::Static(StaticCredentials {
                        access_key_id: "test".into(),
                        secret_access_key: Some("test".into()),
                    }),
                    scratch_path: Some(root.join("scratch").to_string_lossy().into_owned()),
                })
            } else {
                None
            };

            let mut parameters = Parameters::Entity::get(&db)
                .await
                .unwrap()
                .into_active_model();
            parameters.recordings_enable = Set(true);
            if let Some(config) = &s3_config {
                parameters.recordings_storage = Set(serde_json::to_string(
                    &RecordingsStorageConfig::S3(config.clone()),
                )
                .unwrap());
            }
            parameters.update(&db).await.unwrap();

            let params = GlobalParams::new(root.join("warpgate.yaml"), false).unwrap();
            let recordings = SessionRecordings::new(db.clone(), &params);

            let session_id = TargetSessionId(Uuid::new_v4());
            warpgate_db_entities::TargetSession::ActiveModel {
                id: Set(session_id),
                user_session_id: Set(warpgate_common::UserSessionId(Uuid::new_v4())),
                target_snapshot: Set("{}".into()),
                target_id: Set(Uuid::new_v4()),
                started: Set(OffsetDateTime::now_utc()),
                ..Default::default()
            }
            .insert(&db)
            .await
            .unwrap();

            Self {
                db,
                recordings,
                root,
                session_id,
                s3,
                s3_config,
            }
        }

        async fn wait_for_writers(&self, remaining: usize) {
            tokio::time::timeout(Duration::from_secs(10), async {
                while self.recordings.shutdown_tracker.len() != remaining {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
        }

        async fn recording(&self) -> Recording::Model {
            Recording::Entity::find()
                .one(&self.db)
                .await
                .unwrap()
                .unwrap()
        }

        async fn ended(&self) -> Option<OffsetDateTime> {
            self.recording().await.ended
        }

        async fn scratch(&self, file: RecordingFile) -> PathBuf {
            let recording = self.recording().await;
            self.root
                .join("scratch")
                .join(recording.session_id.to_string())
                .join(recording.name)
                .join(file.filename())
        }

        fn s3(&self) -> std::sync::MutexGuard<'_, FakeS3> {
            self.s3.lock().unwrap()
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    async fn serve(s3: Arc<std::sync::Mutex<FakeS3>>) -> std::net::SocketAddr {
        let acceptor = TcpListener::bind("127.0.0.1:0")
            .into_acceptor()
            .await
            .unwrap();
        let address = acceptor
            .local_addr()
            .into_iter()
            .find_map(|address| address.0.as_socket_addr().copied())
            .unwrap();
        let app = poem::endpoint::make(move |mut request: Request| {
            let s3 = s3.clone();
            async move {
                let _ = request.take_body().into_vec().await;
                let uri = request.uri();
                s3.lock().unwrap().handle(
                    request.method(),
                    uri.path(),
                    uri.query().unwrap_or_default(),
                )
            }
        });
        tokio::spawn(poem::Server::new_with_acceptor(acceptor).run(app));
        address
    }

    fn exists(path: &Path) -> bool {
        path.try_exists().unwrap()
    }

    /// Readers switch a recording to S3 as soon as it is ended, so a file that
    /// finishes first must not end it while another is still uploading.
    #[tokio::test]
    async fn a_recording_ends_only_after_its_last_file_is_finalized() {
        let h = Harness::new(None).await;

        let recording: TwoFiles = h.recordings.start(&h.session_id, None, ()).await.unwrap();
        h.wait_for_writers(2).await;

        drop(recording.index);
        h.wait_for_writers(1).await;
        assert_eq!(h.ended().await, None, "ended while data.ndjson was open");

        drop(recording.data);
        h.wait_for_writers(0).await;
        assert!(h.ended().await.is_some(), "never ended");
    }

    /// The data file is already uploaded when the index fails to open; ending
    /// the recording then would point readers at an index that does not exist.
    #[tokio::test]
    async fn a_recorder_that_fails_to_open_all_files_does_not_end() {
        let h = Harness::new(Some(FakeS3 {
            fail_create: Some("index.ndjson"),
            ..Default::default()
        }))
        .await;

        let started = h
            .recordings
            .start::<TwoFiles, _>(&h.session_id, None, ())
            .await;
        assert!(started.is_err());
        h.wait_for_writers(0).await;

        assert_eq!(h.s3().completed.len(), 1, "data.ndjson was never finalized");
        assert_eq!(h.ended().await, None);
        assert!(exists(&h.scratch(RecordingFile::NDJsonData).await));
    }

    /// The upload of what was written still succeeds, but it is missing data.
    #[tokio::test]
    async fn a_failed_local_write_does_not_end() {
        let h = Harness::new(Some(FakeS3::default())).await;
        let model = Recording::ActiveModel {
            id: Set(Uuid::new_v4()),
            started: Set(OffsetDateTime::now_utc()),
            session_id: Set(h.session_id),
            name: Set("broken".into()),
            kind: Set(RecordingKind::Terminal),
            metadata: Set("{}".into()),
            generation: Set(RECORDING_GENERATION),
            ..Default::default()
        }
        .insert(&h.db)
        .await
        .unwrap();

        let scratch = h.scratch(RecordingFile::NDJsonData).await;
        std::fs::create_dir_all(scratch.parent().unwrap()).unwrap();
        std::fs::write(&scratch, b"").unwrap();
        let s3 = S3Storage::new(h.s3_config.as_ref().unwrap()).await.unwrap();
        let sink = RecordingSink::S3 {
            // Read-only, so writing to it fails.
            scratch: tokio::fs::File::open(&scratch).await.unwrap(),
            scratch_path: scratch.clone(),
            upload: Some(s3.start_multipart("broken/data.ndjson").await.unwrap()),
        };
        let writer = RawRecordingWriter::new(
            sink,
            model,
            h.db.clone(),
            None,
            WriterShutdown {
                token: h.recordings.shutdown.clone(),
                tracker: h.recordings.shutdown_tracker.clone(),
            },
            Arc::default(),
        )
        .await
        .unwrap();
        writer.write(b"first\n").await.unwrap();
        writer.write(b"second\n").await.unwrap();
        drop(writer);
        h.wait_for_writers(0).await;

        assert_eq!(h.s3().completed.len(), 1, "data.ndjson was never finalized");
        assert_eq!(h.ended().await, None);
        assert!(exists(&scratch));
    }

    /// S3 accepts a multipart upload with a gap in its part numbers, so a lost
    /// part would otherwise complete into a silently truncated object.
    #[tokio::test]
    async fn a_failed_s3_part_does_not_end() {
        let h = Harness::new(Some(FakeS3 {
            fail_part: Some(("data.ndjson", 1)),
            ..Default::default()
        }))
        .await;

        let recording: TwoFiles = h.recordings.start(&h.session_id, None, ()).await.unwrap();
        let data = vec![b'x'; 6 * 1024 * 1024];
        recording.data.write(&data).await.unwrap();
        drop(recording);
        h.wait_for_writers(0).await;

        let scratch = h.scratch(RecordingFile::NDJsonData).await;
        assert_eq!(h.s3().failed_parts.len(), 1, "no part was uploaded");
        assert!(
            h.s3()
                .completed
                .iter()
                .all(|key| !key.ends_with("data.ndjson")),
            "completed with a missing part"
        );
        assert_eq!(h.ended().await, None);
        assert_eq!(
            std::fs::metadata(&scratch).unwrap().len(),
            data.len() as u64
        );
    }

    /// Opens its data file, then never finishes opening the rest.
    struct Stalls;

    impl Recorder for Stalls {
        fn kind() -> RecordingKind {
            RecordingKind::Terminal
        }

        async fn new(opener: &RecordingWriterOpener) -> Result<Self> {
            let _data = opener.open(RecordingFile::NDJsonData).await?;
            std::future::pending().await
        }
    }

    /// A start abandoned half-way (e.g. its session went away) is as incomplete
    /// as one that failed.
    #[tokio::test]
    async fn a_recorder_cancelled_while_opening_its_files_does_not_end() {
        let h = Harness::new(Some(FakeS3::default())).await;

        tokio::select! {
            _ = h.recordings.start::<Stalls, _>(&h.session_id, None, ()) => {
                panic!("construction finished");
            }
            () = h.wait_for_writers(1) => {}
        }
        h.wait_for_writers(0).await;

        assert_eq!(h.s3().completed.len(), 1, "data.ndjson was never finalized");
        assert_eq!(h.ended().await, None);
        assert!(exists(&h.scratch(RecordingFile::NDJsonData).await));
    }
}
