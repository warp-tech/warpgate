use std::path::{Path, PathBuf};
use std::time::Duration;

use bytes::Bytes;
use sea_orm::DatabaseConnection;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncWriteExt};
use tracing::error;
use warpgate_aws::{S3MultipartUpload, S3Storage};
use warpgate_azure::{AzureBlobStorage, AzureBlockUpload, RangedRead};
use warpgate_common::helpers::fs::secure_file;
use warpgate_common::{GlobalParams, TargetSessionId};
use warpgate_db_entities::Parameters::RecordingsStorageConfig;
use warpgate_db_entities::{Parameters, Recording};

use super::{RecordingFile, Result};

/// Local directory used to buffer in-progress recordings while the backend is S3.
const S3_SCRATCH_SUBDIR: &str = "data/recordings-scratch";
/// Local directory used to buffer in-progress recordings while the backend is Azure.
const AZURE_SCRATCH_SUBDIR: &str = "data/recordings-scratch-azure";
/// How long a presigned recording URL handed to the browser stays valid.
const PRESIGNED_URL_TTL: Duration = Duration::from_secs(3600);

enum Backend {
    Disk,
    S3(S3Storage),
    Azure(AzureBlobStorage),
}

/// Where a recording file lives, resolved by [`Storage::access`].
pub enum FileAccess {
    Local(PathBuf),
    S3 {
        s3: S3Storage,
        key: String,
    },
    Azure {
        azure: AzureBlobStorage,
        key: String,
    },
}

#[must_use]
pub struct RecordingSinkCleanupGuard {
    scratch_path: Option<PathBuf>,
}

impl Drop for RecordingSinkCleanupGuard {
    fn drop(&mut self) {
        if let Some(path) = self.scratch_path.take()
            && let Err(error) = std::fs::remove_file(&path)
        {
            error!(%error, ?path, "Failed to remove local recording scratch");
        }
    }
}

/// The destination for a RawRecordingWriter
/// For S3, the scratch file is cleaned up after upload
pub enum RecordingSink {
    Disk(File),
    S3 {
        scratch: File,
        scratch_path: PathBuf,
        upload: Option<S3MultipartUpload>,
    },
    Azure {
        scratch: File,
        scratch_path: PathBuf,
        upload: Option<AzureBlockUpload>,
    },
}

impl RecordingSink {
    const fn file(&mut self) -> &mut File {
        match self {
            Self::Disk(file) => file,
            Self::S3 { scratch, .. } | Self::Azure { scratch, .. } => scratch,
        }
    }

    pub async fn write_all(&mut self, bytes: &Bytes) -> Result<()> {
        self.file().write_all(bytes).await?;

        match self {
            Self::S3 { upload, .. } => {
                if let Some(upload) = upload
                    && let Err(error) = upload.push(bytes).await
                {
                    error!(%error, path=%upload.key(), "Failed to stream recording to S3");
                }
            }
            Self::Azure { upload, .. } => {
                if let Some(upload) = upload
                    && let Err(error) = upload.push(bytes).await
                {
                    error!(%error, path=%upload.key(), "Failed to stream recording to Azure");
                }
            }
            Self::Disk(_) => {}
        }

        Ok(())
    }

    pub async fn flush(&mut self) -> Result<()> {
        self.file().flush().await?;
        Ok(())
    }

    pub async fn finalize(mut self) -> Result<RecordingSinkCleanupGuard> {
        self.flush().await?;

        match self {
            Self::S3 {
                upload: Some(upload),
                scratch_path,
                ..
            } => {
                upload.finish().await?;
                Ok(RecordingSinkCleanupGuard {
                    scratch_path: Some(scratch_path),
                })
            }
            Self::Azure {
                upload: Some(upload),
                scratch_path,
                ..
            } => {
                upload.finish().await?;
                Ok(RecordingSinkCleanupGuard {
                    scratch_path: Some(scratch_path),
                })
            }
            _ => Ok(RecordingSinkCleanupGuard { scratch_path: None }),
        }
    }
}

impl FileAccess {
    pub async fn open_read(&self) -> Result<Box<dyn AsyncRead + Send + Unpin>> {
        match self {
            Self::S3 { s3, key } => Ok(s3.get_reader(key).await?),
            Self::Azure { azure, key } => Ok(azure.get_reader(key).await?),
            Self::Local(path) => Ok(Box::new(tokio::fs::File::open(path).await?)),
        }
    }

    /// Read from `offset` to the end, reporting the file's full size.
    ///
    /// `Some` only where the caller is expected to serve the bytes itself. The
    /// disk backend is served by the static-file handler and S3 by redirect, so
    /// both answer `None` and never reach this path.
    pub async fn open_read_from(&self, offset: u64) -> Result<Option<RangedRead>> {
        match self {
            Self::Azure { azure, key } => Ok(Some(azure.get_reader_from(key, offset).await?)),
            Self::S3 { .. } | Self::Local(_) => Ok(None),
        }
    }

    pub async fn external_access_url(&self) -> Result<Option<String>> {
        match self {
            Self::S3 { s3, key } => Ok(Some(s3.presign_get(key, PRESIGNED_URL_TTL).await?)),
            // Configured to stream through Warpgate: report no external URL so
            // the caller serves the bytes instead of redirecting.
            Self::Azure { azure, .. } if azure.serves_through_warpgate() => Ok(None),
            Self::Azure { azure, key } => Ok(Some(azure.sas_url(key, PRESIGNED_URL_TTL).await?)),
            Self::Local(_) => Ok(None),
        }
    }

    pub fn local_path(&self) -> Option<&Path> {
        match self {
            Self::S3 { .. } | Self::Azure { .. } => None,
            Self::Local(path) => Some(path),
        }
    }
}

/// The effective recordings storage, loaded live from the parameters table so a
/// config change takes effect on the next recording / read. Owns the disk-vs-S3
/// decisions so callers never inspect the backend themselves.
pub struct Storage {
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
                local_root.push(s3.scratch_path.as_deref().unwrap_or(S3_SCRATCH_SUBDIR));
                Backend::S3(S3Storage::new(&s3).await?)
            }
            RecordingsStorageConfig::Azure(azure) => {
                local_root.push(AZURE_SCRATCH_SUBDIR);
                Backend::Azure(AzureBlobStorage::new(&azure).await?)
            }
        };

        Ok(Self {
            enable: p.recordings_enable,
            local_root,
            backend,
        })
    }

    pub(crate) const fn enabled(&self) -> bool {
        self.enable
    }

    /// Local folder holding a recording's files (final on disk, scratch on S3).
    pub(crate) fn recording_folder(&self, session_id: &TargetSessionId, name: &str) -> PathBuf {
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
                upload: Some(s3.start_multipart(&relative_path(recording, file)).await?),
            },
            Backend::Azure(azure) => RecordingSink::Azure {
                scratch: local_file,
                scratch_path: local_path,
                upload: Some(azure.start_upload(&relative_path(recording, file))),
            },
            Backend::Disk => RecordingSink::Disk(local_file),
        })
    }

    /// Where a recording file should be read from: local for in-progress
    /// recordings and the disk backend, S3 for completed recordings on S3.
    pub(crate) fn access(&self, recording: &Recording::Model, file: RecordingFile) -> FileAccess {
        match &self.backend {
            Backend::S3(s3) if recording.ended.is_some() => FileAccess::S3 {
                s3: s3.clone(),
                key: relative_path(recording, file),
            },
            Backend::Azure(azure) if recording.ended.is_some() => FileAccess::Azure {
                azure: azure.clone(),
                key: relative_path(recording, file),
            },
            _ => FileAccess::Local(local_path_in(&self.local_root, recording, file)),
        }
    }

    /// Delete a recording's files from this storage — its remote objects (if
    /// any) and the local folder (best-effort; on object storage the scratch is
    /// already gone).
    pub(crate) async fn remove(&self, session_id: &TargetSessionId, name: &str) -> Result<()> {
        let keys = [
            format!(
                "{session_id}/{name}/{}",
                RecordingFile::NDJsonData.filename()
            ),
            format!("{session_id}/{name}/{}", RecordingFile::Index.filename()),
            format!(
                "{session_id}/{name}/{}",
                RecordingFile::TcpDumpData.filename()
            ),
            // Gen-1 recordings are a single object named after the recording.
            format!("{session_id}/{name}"),
        ];

        match &self.backend {
            Backend::S3(s3) => {
                for key in &keys {
                    s3.delete(key).await?;
                }
            }
            Backend::Azure(azure) => {
                for key in &keys {
                    azure.delete(key).await?;
                }
            }
            Backend::Disk => {}
        }

        let path = self.recording_folder(session_id, name);
        match tokio::fs::metadata(&path).await {
            Ok(meta) if meta.is_dir() => tokio::fs::remove_dir_all(&path).await?,
            Ok(_) => tokio::fs::remove_file(&path).await?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
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

/// Path of a recording file relative to a storage root, shared by the local
/// filesystem and S3 so the two layouts stay identical: gen 1 is a single file,
/// gen 2 is multiple files inside the recording folder.
fn relative_path(recording: &Recording::Model, file: RecordingFile) -> String {
    let base = format!("{}/{}", recording.session_id, recording.name);
    if recording.generation >= 2 {
        format!("{base}/{}", file.filename())
    } else {
        base
    }
}

fn local_path_in(root: &Path, recording: &Recording::Model, file: RecordingFile) -> PathBuf {
    root.join(relative_path(recording, file))
}

#[cfg(test)]
mod tests {
    use uuid::uuid;
    use warpgate_db_entities::Recording::RecordingKind;

    use super::*;

    fn recording(generation: i32) -> Recording::Model {
        Recording::Model {
            id: uuid!("00000000-0000-0000-0000-0000000000ff"),
            name: "0.ndjson".into(),
            started: time::OffsetDateTime::UNIX_EPOCH,
            ended: None,
            session_id: TargetSessionId(uuid!("00000000-0000-0000-0000-00000000000a")),
            kind: RecordingKind::Terminal,
            metadata: "{}".into(),
            generation,
        }
    }

    /// Gen-1 recordings copied verbatim from a filesystem backend into a bucket
    /// must resolve to the same key S3 as they did paths on disk.
    #[test]
    fn relative_path_is_generation_aware() {
        assert_eq!(
            relative_path(&recording(1), RecordingFile::NDJsonData),
            "00000000-0000-0000-0000-00000000000a/0.ndjson"
        );
        assert_eq!(
            relative_path(&recording(2), RecordingFile::NDJsonData),
            "00000000-0000-0000-0000-00000000000a/0.ndjson/data.ndjson"
        );
        assert_eq!(
            local_path_in(Path::new("/data"), &recording(1), RecordingFile::NDJsonData),
            PathBuf::from("/data/00000000-0000-0000-0000-00000000000a/0.ndjson")
        );
    }
}
