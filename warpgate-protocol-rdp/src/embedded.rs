//! A helper to spawn embedded helpers
//!
//! Extracts the embedded helper either into a memfd or a secure tempfile
//! and runs it, removing later on drop

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(not(target_os = "linux"))]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::Context;
#[cfg(not(target_os = "linux"))]
use tempfile::{TempDir, TempPath};
use warpgate_common::WarpgateError;

pub(crate) struct EmbeddedHelper {
    /// gzip-compressed helper image, embedded by `build.rs`.
    blob: &'static [u8],
    /// used for the Linux `memfd` and as the temp-file prefix.
    name: &'static str,
    /// Env var holding an explicit external path override (dev/CI).
    override_env: &'static str,
}

/// A ready-to-spawn helper executable. Owns the temp fd/file so that
/// it can outlive `spawn()`.
#[allow(unused)]
pub(crate) enum HelperExecutable {
    Preexisting(PathBuf),
    #[cfg(target_os = "linux")]
    MemFd {
        memfd: std::fs::File,
        path: PathBuf,
    },
    #[cfg(not(target_os = "linux"))]
    Extracted {
        temp_path: TempPath,
        temp_dir: TempDir,
    },
}

impl HelperExecutable {
    /// Path to use when spawning
    pub fn path(&self) -> &Path {
        match self {
            Self::Preexisting(path) => path,
            // `/proc/self/fd/N` resolves to the memfd at exec time (in the forked child,
            // before CLOEXEC fires); the owned `file` keeps N valid across the spawn.
            #[cfg(target_os = "linux")]
            Self::MemFd { path, .. } => path.as_ref(),
            #[cfg(not(target_os = "linux"))]
            Self::Extracted { temp_path, .. } => temp_path.as_ref(),
        }
    }

    /// A helper referenced by an external path (the override env var); nothing owned.
    const fn preexisting(path: PathBuf) -> Self {
        Self::Preexisting(path)
    }
}

impl EmbeddedHelper {
    pub(crate) const fn new(
        blob: &'static [u8],
        name: &'static str,
        override_env: &'static str,
    ) -> Self {
        Self {
            blob,
            name,
            override_env,
        }
    }

    /// Resolve the helper executable, materialising the embedded copy as needed.
    pub(crate) fn resolve(&self) -> Result<HelperExecutable, WarpgateError> {
        if let Some(path) = std::env::var_os(self.override_env) {
            return Ok(HelperExecutable::preexisting(PathBuf::from(path)));
        }

        #[cfg(target_os = "linux")]
        return self.run_from_memfd();

        #[cfg(not(target_os = "linux"))]
        self.extract_to_tempfile()
    }

    /// Decompress the embedded helper image into `w`.
    fn decompress_into(&self, w: &mut impl std::io::Write) -> Result<(), WarpgateError> {
        let mut decoder = flate2::read::GzDecoder::new(self.blob);
        std::io::copy(&mut decoder, w).context("decompressing helper")?;
        Ok(())
    }

    /// Linux: write the helper into an anonymous `memfd` and run it from
    /// `/proc/self/fd/N`, so it never touches the filesystem.
    #[cfg(target_os = "linux")]
    pub(crate) fn run_from_memfd(&self) -> Result<HelperExecutable, WarpgateError> {
        use std::io::Write as _;

        use rustix::fs::{MemfdFlags, memfd_create};

        let fd = memfd_create(self.name, MemfdFlags::CLOEXEC).context("memfd_create")?;
        let mut file = std::fs::File::from(fd);
        self.decompress_into(&mut file)?;
        file.flush().ok();

        Ok(HelperExecutable::MemFd {
            path: PathBuf::from(&format!("/proc/self/fd/{}", file.as_raw_fd())),
            memfd: file,
        })
    }

    /// Extract the embedded helper to a temp file.
    ///
    /// The writable handle is closed before returning so the spawned child can `exec`
    /// the file (it would otherwise fail with `ETXTBSY`). Off Linux the returned guard
    /// owns the path and unlinks it on drop — after the helper has been spawned — so the
    /// binary is never left on disk. On Linux this is only a rare fallback for when
    /// `memfd` is unavailable; there is no owning field, so the file is persisted.
    #[cfg(not(target_os = "linux"))]
    pub(crate) fn extract_to_tempfile(&self) -> Result<HelperExecutable, WarpgateError> {
        let dir = TempDir::new().context("creating helper cache dir")?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;

        let mut tmp = tempfile::Builder::new()
            .prefix(&format!("{}-", self.name))
            .tempfile_in(&dir)
            .context("creating temp file")?;
        self.decompress_into(tmp.as_file_mut())?;
        tmp.as_file().sync_all().context("flushing helper")?;
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700))
            .context("marking helper executable")?;

        let helper = {
            // Keep the path (closing the write handle); unlinked when the guard drops.
            let temp = tmp.into_temp_path();
            HelperExecutable::Extracted {
                temp_path: temp,
                temp_dir: dir,
            }
        };

        Ok(helper)
    }
}
