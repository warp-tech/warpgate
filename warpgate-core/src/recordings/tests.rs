//! Each failure test first asserts that the failure it injects actually fired,
//! so a pass is not vacuous.

use std::path::{Path, PathBuf};

use poem::http::{Method, StatusCode};
use poem::listener::{Acceptor, Listener, TcpListener};
use poem::{Request, Response};
use sea_orm::ActiveValue::Set;
use sea_orm::{ConnectionTrait, Database, IntoActiveModel};
use tokio::io::AsyncReadExt;
use warpgate_aws::{S3Credentials, S3RangeRead, S3Storage, S3StorageConfig, StaticCredentials};
use warpgate_db_entities::Parameters::{
    self, ConfigMigrationValues, RecordingsStorageConfig, set_config_migration_values,
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
    fail_complete: Option<&'static str>,
    created: Vec<String>,
    failed_creates: Vec<String>,
    failed_parts: Vec<String>,
    /// (key, part number, body length) of every accepted part.
    parts: Vec<(String, u32, usize)>,
    failed_completes: Vec<String>,
    completed: Vec<String>,
    aborted: Vec<String>,
    /// Bodies served on GET, by request path. Part bodies aren't kept, so
    /// tests seed what a read should return.
    objects: std::collections::HashMap<String, Vec<u8>>,
}

impl FakeS3 {
    fn handle(
        &mut self,
        method: &Method,
        path: &str,
        query: &str,
        len: usize,
        range: Option<&str>,
    ) -> Response {
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
            (&Method::GET, _) => self.get(path, range),
            (&Method::POST, _) if query.split('&').any(|q| q.starts_with("uploads")) => {
                if self.fail_create.is_some_and(|f| path.ends_with(f)) {
                    self.failed_creates.push(path.into());
                    return fail();
                }
                self.created.push(path.into());
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
                self.parts.push((path.into(), n, len));
                Response::builder()
                    .header("ETag", format!("\"{n}\""))
                    .body("")
            }
            (&Method::POST, _) => {
                if self.fail_complete.is_some_and(|f| path.ends_with(f)) {
                    self.failed_completes.push(path.into());
                    return fail();
                }
                self.completed.push(path.into());
                ok(
                    "<CompleteMultipartUploadResult><ETag>\"e\"</ETag></CompleteMultipartUploadResult>",
                )
            }
            (&Method::DELETE, _) => {
                self.aborted.push(path.into());
                Response::builder().status(StatusCode::NO_CONTENT).body("")
            }
            _ => fail(),
        }
    }

    /// GET with just the open-ended `bytes=N-` ranges the player sends.
    fn get(&self, path: &str, range: Option<&str>) -> Response {
        let Some(body) = self.objects.get(path) else {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body("<Error><Code>NoSuchKey</Code><Message>missing</Message></Error>");
        };
        let Some(start) = range.and_then(|r| {
            r.strip_prefix("bytes=")?
                .strip_suffix('-')?
                .parse::<usize>()
                .ok()
        }) else {
            return Response::builder()
                .header("Content-Length", body.len())
                .body(body.clone());
        };
        if start >= body.len() {
            return Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .body("<Error><Code>InvalidRange</Code><Message>range</Message></Error>");
        }
        Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header("Content-Length", body.len() - start)
            .header(
                "Content-Range",
                format!("bytes {start}-{}/{}", body.len() - 1, body.len()),
            )
            .body(body[start..].to_vec())
    }

    fn completed(&self, file: &str) -> bool {
        self.completed.iter().any(|key| key.ends_with(file))
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
        Self::new_with(s3, false).await
    }

    async fn new_with(s3: Option<FakeS3>, proxy_downloads: bool) -> Self {
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
                proxy_downloads,
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
            parameters.recordings_storage =
                Set(serde_json::to_string(&RecordingsStorageConfig::S3(config.clone())).unwrap());
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
            let len = request
                .take_body()
                .into_vec()
                .await
                .map(|b| b.len())
                .unwrap_or_default();
            let uri = request.uri();
            let range = request.headers().get("range").and_then(|v| v.to_str().ok());
            s3.lock().unwrap().handle(
                request.method(),
                uri.path(),
                uri.query().unwrap_or_default(),
                len,
                range,
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

    let recording: TwoFiles = h
        .recordings
        .start(&h.session_id, None, ())
        .await
        .unwrap()
        .unwrap();
    h.wait_for_writers(2).await;

    drop(recording.index);
    h.wait_for_writers(1).await;
    assert_eq!(h.ended().await, None, "ended while data.ndjson was open");

    drop(recording.data);
    h.wait_for_writers(0).await;
    assert!(h.ended().await.is_some(), "never ended");
}

/// index.ndjson fails to complete on S3. The recording is rightly not ended,
/// so readers are sent to the local scratch; data.ndjson's scratch must
/// therefore still be there.
#[tokio::test]
async fn a_failed_finalize_keeps_the_other_files_scratch() {
    let h = Harness::new(Some(FakeS3 {
        fail_complete: Some("index.ndjson"),
        ..Default::default()
    }))
    .await;

    let recording: TwoFiles = h
        .recordings
        .start(&h.session_id, None, ())
        .await
        .unwrap()
        .unwrap();
    recording.data.write(b"data\n").await.unwrap();
    recording.index.write(b"index\n").await.unwrap();
    drop(recording);
    h.wait_for_writers(0).await;

    assert!(
        h.s3().completed("data.ndjson"),
        "data.ndjson was never finalized"
    );
    assert_eq!(
        h.s3().failed_completes.len(),
        1,
        "the index completion failure never fired"
    );
    let recording = h.recording().await;
    assert_eq!(
        recording.ended, None,
        "ended with index.ndjson missing on S3"
    );

    let access = h
        .recordings
        .access(&recording, RecordingFile::NDJsonData)
        .await
        .unwrap();
    assert!(
        access.open_read().await.is_ok(),
        "the reader for a not-ended recording is pointed at a scratch file that no longer exists",
    );
}

/// data.ndjson is already uploaded when index.ndjson fails to open; ending the
/// recording then would point readers at an index that does not exist.
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
    assert!(
        started.is_err(),
        "index.ndjson opened despite the injected failure"
    );
    let failed_creates = h.s3().failed_creates.clone();
    assert!(
        matches!(failed_creates.as_slice(), [key] if key.ends_with("index.ndjson")),
        "start failed, but not on the injected index.ndjson create"
    );
    h.wait_for_writers(0).await;

    assert!(
        h.s3().completed("data.ndjson"),
        "data.ndjson was never finalized"
    );
    let index_on_s3 = h.s3().completed("index.ndjson");
    let ended = h.ended().await;
    assert!(
        ended.is_none(),
        "ended={ended:?} while index.ndjson on S3={index_on_s3}; data scratch exists={}",
        exists(&h.scratch(RecordingFile::NDJsonData).await),
    );
}

/// The scratch write fails, so the upload is missing what was written.
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
        None,
        WriterShutdown {
            token: h.recordings.shutdown.clone(),
            tracker: h.recordings.shutdown_tracker.clone(),
        },
        RecordingCompletion::new(h.db.clone(), model.id)
            .register_writer()
            .await,
    )
    .await
    .unwrap();
    let written = b"first\n".len() + b"second\n".len();
    writer.write(b"first\n").await.unwrap();
    writer.write(b"second\n").await.unwrap();
    drop(writer);
    h.wait_for_writers(0).await;

    assert!(
        h.s3().completed("data.ndjson"),
        "data.ndjson was never finalized"
    );
    let uploaded: usize = h.s3().parts.iter().map(|(_, _, len)| len).sum();
    assert!(uploaded < written, "the local write never failed");
    let ended = h.ended().await;
    assert!(
        ended.is_none(),
        "ended={ended:?} with {uploaded} of {written} written bytes on S3"
    );
    assert!(
        exists(&scratch),
        "the scratch of a not-ended recording is gone"
    );
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

    let recording: TwoFiles = h
        .recordings
        .start(&h.session_id, None, ())
        .await
        .unwrap()
        .unwrap();
    let data = vec![b'x'; 6 * 1024 * 1024];
    recording.data.write(&data).await.unwrap();
    drop(recording);
    h.wait_for_writers(0).await;

    assert_eq!(h.s3().failed_parts.len(), 1, "no part failed");
    let completed = h.s3().completed("data.ndjson");
    let uploaded: usize = h
        .s3()
        .parts
        .iter()
        .filter(|(key, _, _)| key.ends_with("data.ndjson"))
        .map(|(_, _, len)| len)
        .sum();
    let ended = h.ended().await;
    assert!(
        !completed && ended.is_none(),
        "data.ndjson completed={completed} with {uploaded} of {} bytes, ended={ended:?}",
        data.len(),
    );
    let aborted = h.s3().aborted.clone();
    assert!(
        matches!(aborted.as_slice(), [key] if key.ends_with("data.ndjson")),
        "expected exactly one abort, of data.ndjson"
    );

    let mut scratch = Vec::new();
    h.recordings
        .access(&h.recording().await, RecordingFile::NDJsonData)
        .await
        .unwrap()
        .open_read()
        .await
        .unwrap()
        .read_to_end(&mut scratch)
        .await
        .unwrap();
    assert_eq!(scratch.len(), data.len(), "the scratch is not complete");
}

/// Both files are uploaded but storing `ended` fails, so the recording is
/// still read from its scratch, which must therefore still be there.
#[tokio::test]
async fn a_failed_ended_update_keeps_the_scratch() {
    let h = Harness::new(Some(FakeS3::default())).await;

    let recording: TwoFiles = h
        .recordings
        .start(&h.session_id, None, ())
        .await
        .unwrap()
        .unwrap();
    recording.data.write(b"data\n").await.unwrap();
    recording.index.write(b"index\n").await.unwrap();
    drop(recording.index);
    h.wait_for_writers(1).await;

    h.db.execute_unprepared("ALTER TABLE recordings RENAME TO recordings_hidden")
        .await
        .unwrap();
    assert!(
        Recording::Entity::find().one(&h.db).await.is_err(),
        "the recordings table is still reachable"
    );
    drop(recording.data);
    h.wait_for_writers(0).await;
    h.db.execute_unprepared("ALTER TABLE recordings_hidden RENAME TO recordings")
        .await
        .unwrap();

    assert!(
        h.s3().completed("data.ndjson") && h.s3().completed("index.ndjson"),
        "a file was never finalized"
    );
    assert_eq!(h.ended().await, None);
    for file in [RecordingFile::NDJsonData, RecordingFile::Index] {
        let path = h.scratch(file).await;
        assert!(
            exists(&path),
            "a scratch file of the unended recording is gone"
        );
    }
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

    let constructed = tokio::select! {
        _ = h.recordings.start::<Stalls, _>(&h.session_id, None, ()) => true,
        () = h.wait_for_writers(1) => false,
    };
    assert!(!constructed, "construction finished");
    h.wait_for_writers(0).await;

    assert!(
        h.s3().completed("data.ndjson"),
        "data.ndjson was never finalized"
    );
    assert_eq!(h.ended().await, None);
    assert!(exists(&h.scratch(RecordingFile::NDJsonData).await));
}

/// Records a terminal recording to S3 and returns it once ended, along with
/// the request path of its uploaded data.ndjson.
async fn ended_s3_recording(h: &Harness) -> (Recording::Model, String) {
    let recording: TwoFiles = h
        .recordings
        .start(&h.session_id, None, ())
        .await
        .unwrap()
        .unwrap();
    recording.data.write(b"data\n").await.unwrap();
    recording.index.write(b"index\n").await.unwrap();
    drop(recording);
    h.wait_for_writers(0).await;

    let recording = h.recording().await;
    assert!(recording.ended.is_some(), "never ended");
    let key = h
        .s3()
        .completed
        .iter()
        .find(|key| key.ends_with("data.ndjson"))
        .cloned()
        .expect("data.ndjson was never uploaded");
    (recording, key)
}

/// Without the option, completed S3 recordings are still handed to the
/// browser as presigned URLs, so existing setups behave as before.
#[tokio::test]
async fn s3_downloads_redirect_by_default() {
    let h = Harness::new(Some(FakeS3::default())).await;
    let (recording, _) = ended_s3_recording(&h).await;

    let url = h
        .recordings
        .access(&recording, RecordingFile::NDJsonData)
        .await
        .unwrap()
        .external_access_url()
        .await
        .unwrap()
        .expect("no presigned URL");
    assert!(url.contains("X-Amz-Signature"), "not presigned: {url}");
}

/// With proxied downloads the browser never gets a presigned URL; Warpgate
/// reads the object itself and forwards the player's byte ranges to S3.
#[tokio::test]
async fn proxied_s3_downloads_forward_ranges_instead_of_redirecting() {
    let h = Harness::new_with(Some(FakeS3::default()), true).await;
    let (recording, key) = ended_s3_recording(&h).await;
    h.s3().objects.insert(key, b"0123456789".to_vec());

    let access = h
        .recordings
        .access(&recording, RecordingFile::NDJsonData)
        .await
        .unwrap();
    assert_eq!(access.external_access_url().await.unwrap(), None);

    let Some(S3RangeRead::Object(mut object)) =
        access.open_proxied(Some("bytes=4-")).await.unwrap()
    else {
        panic!("expected a partial object");
    };
    assert_eq!(object.content_range.as_deref(), Some("bytes 4-9/10"));
    assert_eq!(object.content_length, Some(6));
    let mut body = Vec::new();
    object.body.read_to_end(&mut body).await.unwrap();
    assert_eq!(body, b"456789");

    let Some(S3RangeRead::Object(mut whole)) = access.open_proxied(None).await.unwrap() else {
        panic!("expected the whole object");
    };
    assert_eq!(whole.content_range, None);
    let mut body = Vec::new();
    whole.body.read_to_end(&mut body).await.unwrap();
    assert_eq!(body, b"0123456789");

    // The player opens at the end of the file to splice in the live stream.
    assert!(matches!(
        access.open_proxied(Some("bytes=10-")).await.unwrap(),
        Some(S3RangeRead::NotSatisfiable)
    ));
}
