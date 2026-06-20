//! Resolving and materialising the embedded `warpgate-rdp-helper` executable.
//!
//! The helper is always embedded into this binary at build time (see `build.rs`)
//! At runtime:
//! 1. `WARPGATE_RDP_HELPER`, if set, is used as an explicit path to an
//!    external helper (dev).
//! 2. On Linux the embedded helper is written to an anonymous `memfd` and executed
//!    from `/proc/self/fd/N`
//! 3. Elsewhere it is extracted to a private temp file that the returned guard owns
//!    and unlinks on drop.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::Context;
use warpgate_common::WarpgateError;

/// gzip-compressed helper image, embedded by `build.rs`.
static BLOB: &[u8] = include_bytes!(env!("RDP_HELPER_BLOB"));

/// A ready-to-spawn helper executable. Owns the temp fd/file so that
/// it can outlive spawn()
pub struct HelperExecutable {
    path: PathBuf,
    #[cfg(not(target_os = "linux"))]
    _temp: Option<tempfile::TempPath>,
    #[cfg(not(target_os = "linux"))]
    _tempdir: Option<tempfile::TempDir>,
    #[cfg(target_os = "linux")]
    _memfd: Option<std::fs::File>,
}

impl HelperExecutable {
    pub fn path(&self) -> &Path {
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

/// Resolve the helper executable, materialising the embedded copy as needed.
pub fn resolve() -> Result<HelperExecutable, WarpgateError> {
    if let Some(path) = std::env::var_os("WARPGATE_RDP_HELPER") {
        return Ok(HelperExecutable::at(PathBuf::from(path)));
    }

    #[cfg(target_os = "linux")]
    return run_from_memfd();

    #[cfg(not(target_os = "linux"))]
    extract_to_tempfile()
}

/// Decompress the embedded helper image into `w`.
fn decompress_into(w: &mut impl std::io::Write) -> Result<(), WarpgateError> {
    let mut decoder = flate2::read::GzDecoder::new(BLOB);
    std::io::copy(&mut decoder, w).context("decompressing helper")?;
    Ok(())
}

/// Linux: write the helper into an anonymous `memfd` and run it from
/// `/proc/self/fd/N`, so it never touches the filesystem.
#[cfg(target_os = "linux")]
fn run_from_memfd() -> Result<HelperExecutable, WarpgateError> {
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;

    use rustix::fs::{MemfdFlags, memfd_create};

    let fd = memfd_create("warpgate-rdp-helper", MemfdFlags::CLOEXEC).context("memfd_create")?;
    let mut file = std::fs::File::from(fd);
    decompress_into(&mut file)?;
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
fn extract_to_tempfile() -> Result<HelperExecutable, WarpgateError> {
    let dir = tempfile::TempDir::new().context("creating helper cache dir")?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;

    let mut tmp = tempfile::Builder::new()
        .prefix("warpgate-rdp-helper-")
        .tempfile_in(&dir)
        .context("creating temp file")?;
    decompress_into(tmp.as_file_mut())?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn extracts_then_cleans_up_on_drop() {
        let exe = extract_to_tempfile().unwrap();
        let path = exe.path().to_path_buf();

        let meta = std::fs::metadata(&path).unwrap();
        assert!(meta.is_file());
        assert!(meta.len() > 1_000_000, "extracted helper looks too small");
        assert_ne!(meta.permissions().mode() & 0o111, 0, "not executable");

        drop(exe);
        assert!(!path.exists(), "temp file must be removed on drop");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn memfd_holds_the_helper() {
        let exe = run_from_memfd().unwrap();
        // `/proc/self/fd/N` stats through to the memfd, reporting its real size.
        let meta = std::fs::metadata(exe.path()).unwrap();
        assert!(meta.len() > 1_000_000, "memfd helper looks too small");
    }
}
