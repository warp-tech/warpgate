use std::path::{Path, PathBuf};
use std::time::Duration;

use bytes::Bytes;
use sea_orm::DatabaseConnection;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncWriteExt};
use tracing::error;
use warpgate_aws::{S3MultipartUpload, S3Storage};
use warpgate_common::helpers::fs::secure_file;
use warpgate_common::{GlobalParams, SessionId};
use warpgate_db_entities::Parameters::RecordingsStorageConfig;
use warpgate_db_entities::{Parameters, Recording};

use super::{RecordingFile, Result};

/// Local directory used to buffer in-progress recordings while the backend is S3.
const S3_SCRATCH_SUBDIR: &str = "data/recordings-scratch";
/// How long a presigned recording URL handed to the browser stays valid.
const PRESIGNED_URL_TTL: Duration = Duration::from_secs(3600);

enum Backend {
    Disk,
    S3(S3Storage),
}

/// Where a recording file lives, resolved by [`Storage::access`].
pub enum FileAccess {
    Local(PathBuf),
    S3 { s3: S3Storage, key: String },
}

pub(crate) struct RecordingSinkCleanupGuard {
    scratch_path: Option<PathBuf>,
}

impl Drop for RecordingSinkCleanupGuard {
    fn drop(&mut self) {
        if let Some(path) = self.scratch_path.take() {
            if let Err(error) = std::fs::remove_file(&path) {
                error!(%error, ?path, "Failed to remove local recording scratch");
            }
        }
    }
}

/// The destination for a RawRecordingWriter
/// For S3, the scratch file is cleaned up after upload
pub(crate) enum RecordingSink {
    Disk(File),
    S3 {
        scratch: File,
        scratch_path: PathBuf,
        upload: Option<S3MultipartUpload>,
    },
}

impl RecordingSink {
    fn file(&mut self) -> &mut File {
        match self {
            RecordingSink::Disk(file) => file,
            RecordingSink::S3 { scratch, .. } => scratch,
        }
    }

    pub async fn write_all(&mut self, bytes: &Bytes) -> Result<()> {
        self.file().write_all(&bytes).await?;

        if let Self::S3 { upload, .. } = self {
            if let Some(upload) = upload
                && let Err(error) = upload.push(&bytes).await
            {
                error!(%error, path=%upload.key(), "Failed to stream recording to S3");
            }
        }

        Ok(())
    }

    pub async fn flush(&mut self) -> Result<()> {
        self.file().flush().await?;
        Ok(())
    }

    #[must_use]
    pub async fn finalize(mut self) -> Result<RecordingSinkCleanupGuard> {
        self.flush().await?;

        if let Self::S3 {
            upload,
            scratch_path,
            ..
        } = self
            && let Some(upload) = upload
        {
            upload.finish().await?;
            return Ok(RecordingSinkCleanupGuard {
                scratch_path: Some(scratch_path),
            });
        }

        Ok(RecordingSinkCleanupGuard { scratch_path: None })
    }
}

impl FileAccess {
    pub async fn open_read(&self) -> Result<Box<dyn AsyncRead + Send + Unpin>> {
        match self {
            FileAccess::S3 { s3, key } => Ok(s3.get_reader(&key).await?),
            FileAccess::Local(path) => Ok(Box::new(tokio::fs::File::open(path).await?)),
        }
    }

    pub async fn external_access_url(&self) -> Result<Option<String>> {
        match self {
            FileAccess::S3 { s3, key } => Ok(Some(s3.presign_get(&key, PRESIGNED_URL_TTL).await?)),
            FileAccess::Local(_) => Ok(None),
        }
    }

    pub fn local_path(&self) -> Option<&Path> {
        match self {
            FileAccess::S3 { .. } => None,
            FileAccess::Local(path) => Some(path),
        }
    }
}

/// The effective recordings storage, loaded live from the parameters table so a
/// config change takes effect on the next recording / read. Owns the disk-vs-S3
/// decisions so callers never inspect the backend themselves.
pub(crate) struct Storage {
    enable: bool,
    /// Absolute local root — final location for disk storage, scratch for S3.
    local_root: PathBuf,
    backend: Backend,
}

impl Storage {
    pub(crate) async fn load(db: &DatabaseConnection, params: &GlobalParams) -> Result<Self> {
        let p = Parameters::Entity::get(db).await?;
        let mut local_root = params.paths_relative_to().clone();

        let backend = match p.recordings_storage_config()? {
            RecordingsStorageConfig::Disk(disk) => {
                local_root.push(&disk.path);
                Backend::Disk
            }
            RecordingsStorageConfig::S3(s3) => {
                local_root.push(S3_SCRATCH_SUBDIR);
                Backend::S3(S3Storage::new(&s3).await?)
            }
        };

        Ok(Self {
            enable: p.recordings_enable,
            local_root,
            backend,
        })
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enable
    }

    /// Local folder holding a recording's files (final on disk, scratch on S3).
    pub(crate) fn recording_folder(&self, session_id: &SessionId, name: &str) -> PathBuf {
        self.local_root.join(session_id.to_string()).join(name)
    }

    /// Open the write destination for one recording file. On S3 this also starts
    /// the multipart upload that the local scratch file streams to.
    pub(crate) async fn open_sink(
        &self,
        recording: &Recording::Model,
        file: RecordingFile,
        params: &GlobalParams,
    ) -> Result<RecordingSink> {
        let local_path = local_path_in(&self.local_root, recording, file);

        let local_file = File::options()
            .append(true)
            .create(true)
            .open(&local_path)
            .await?;

        if params.should_secure_files() {
            secure_file(&local_path)?;
        }

        Ok(match &self.backend {
            Backend::S3(s3) => RecordingSink::S3 {
                scratch: local_file,
                scratch_path: local_path,
                upload: Some(s3.start_multipart(&object_path(recording, file)).await?),
            },
            Backend::Disk => RecordingSink::Disk(local_file),
        })
    }

    /// Where a recording file should be read from: local for in-progress
    /// recordings and the disk backend, S3 for completed recordings on S3.
    pub(crate) fn access(
        &self,
        recording: &Recording::Model,
        file: RecordingFile,
    ) -> Result<FileAccess> {
        Ok(match &self.backend {
            Backend::S3(s3) if recording.ended.is_some() && recording.generation >= 2 => {
                FileAccess::S3 {
                    s3: s3.clone(),
                    key: object_path(recording, file),
                }
            }
            _ => FileAccess::Local(local_path_in(&self.local_root, recording, file)),
        })
    }

    /// Delete a recording's files from this storage — its S3 objects (if any)
    /// and the local folder (best-effort; on S3 the scratch is already gone).
    pub(crate) async fn remove(&self, session_id: &SessionId, name: &str) -> Result<()> {
        if let Backend::S3(s3) = &self.backend {
            for file in [
                RecordingFile::NDJsonData,
                RecordingFile::Index,
                RecordingFile::TcpDumpData,
            ] {
                s3.delete(&format!("{session_id}/{name}/{}", file.filename()))
                    .await?;
            }
        }

        let path = self.recording_folder(session_id, name);
        match tokio::fs::metadata(&path).await {
            Ok(meta) if meta.is_dir() => tokio::fs::remove_dir_all(&path).await?,
            Ok(_) => tokio::fs::remove_file(&path).await?,
            Err(_) => return Ok(()),
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
}

/// Local path of a recording file under `root` (generation-aware): gen 1 is a
/// single file, gen 2 is multiple files inside the recording folder.
fn local_path_in(root: &Path, recording: &Recording::Model, file: RecordingFile) -> PathBuf {
    let base = root
        .join(recording.session_id.to_string())
        .join(&recording.name);
    if recording.generation >= 2 {
        base.join(file.filename())
    } else {
        base
    }
}

/// S3 object path (before the configured prefix) of a recording file. Only
/// gen-2 recordings are ever stored on S3.
fn object_path(recording: &Recording::Model, file: RecordingFile) -> String {
    format!(
        "{}/{}/{}",
        recording.session_id,
        recording.name,
        file.filename()
    )
}
