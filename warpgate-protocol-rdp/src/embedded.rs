//! Resolving and materialising an embedded helper executable.
//!
//! Warpgate ships one out-of-workspace RDP helper (`warpgate-rdp-helper`, carrying the
//! target-facing client and viewer-facing server as `connect`/`serve` subcommands),
//! compressed and embedded into this crate at build time (see `build.rs`). The
//! materialisation strategy is security-sensitive, so it lives here once:
//!
//! 1. An explicit path override env var, if set, points at an external helper (dev/CI).
//! 2. On Linux the embedded image is written to an anonymous `memfd` and executed
//!    from `/proc/self/fd/N`, so it never touches the filesystem.
//! 3. Elsewhere it is extracted to a private temp file that the returned guard owns
//!    and unlinks on drop.

use std::path::{Path, PathBuf};

use anyhow::Context;
use warpgate_common::WarpgateError;

/// A gzip-compressed embedded helper image plus the metadata needed to
/// materialise and run it.
pub(crate) struct EmbeddedHelper {
    /// gzip-compressed helper image, embedded by `build.rs`.
    blob: &'static [u8],
    /// Name used for the Linux `memfd` and as the temp-file prefix.
    name: &'static str,
    /// Env var holding an explicit external path override (dev/CI).
    override_env: &'static str,
}

/// A ready-to-spawn helper executable. Owns the temp fd/file so that
/// it can outlive `spawn()`.
pub(crate) struct HelperExecutable {
    path: PathBuf,
    #[cfg(not(target_os = "linux"))]
    _temp: Option<tempfile::TempPath>,
    #[cfg(not(target_os = "linux"))]
    _tempdir: Option<tempfile::TempDir>,
    #[cfg(target_os = "linux")]
    _memfd: Option<std::fs::File>,
}

impl HelperExecutable {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// A helper referenced by an external path (the override env var); nothing owned.
    const fn at(path: PathBuf) -> Self {
        Self {
            path,
            #[cfg(not(target_os = "linux"))]
            _temp: None,
            #[cfg(not(target_os = "linux"))]
            _tempdir: None,
            #[cfg(target_os = "linux")]
            _memfd: None,
        }
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
            return Ok(HelperExecutable::at(PathBuf::from(path)));
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
        use std::os::fd::AsRawFd as _;

        use rustix::fs::{MemfdFlags, memfd_create};

        let fd = memfd_create(self.name, MemfdFlags::CLOEXEC).context("memfd_create")?;
        let mut file = std::fs::File::from(fd);
        self.decompress_into(&mut file)?;
        file.flush().ok();

        // `/proc/self/fd/N` resolves to the memfd at exec time (in the forked child,
        // before CLOEXEC fires); the owned `file` keeps N valid across the spawn.
        let path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
        Ok(HelperExecutable {
            path,
            _memfd: Some(file),
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
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().context("creating helper cache dir")?;
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
            HelperExecutable {
                path: temp.to_path_buf(),
                _temp: Some(temp),
                _tempdir: Some(dir),
            }
        };

        Ok(helper)
    }
}
