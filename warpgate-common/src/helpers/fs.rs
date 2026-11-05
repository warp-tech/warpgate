#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::prelude::PermissionsExt;
use std::path::Path;

use tracing::error;

use crate::GlobalParams;

#[cfg(unix)]
fn maybe_apply_permissions<P: AsRef<Path>>(path: P, mode: u32) -> std::io::Result<()> {
    let permissions = std::fs::Permissions::from_mode(mode);
    let metadata = std::fs::metadata(&path)?;
    let current = metadata.permissions();
    if (current.mode() & 0o777) != permissions.mode() {
        let uid = nix::unistd::geteuid();
        if uid.is_root() || metadata.uid() == uid.as_raw() {
            std::fs::set_permissions(path, permissions)?;
        } else {
            error!(
                "Warning: cannot tighten file permissions for {:?}",
                path.as_ref()
            );
            warn_notice();
        }
    }
    Ok(())
}

// Windows has no mode bits and setting ACLs is not implemented yet.
// `ensure_files_can_be_secured` refuses to run unless `--skip-securing-files`
// says access is restricted some other way, so there is nothing to do here.
#[cfg(windows)]
#[allow(
    clippy::unnecessary_wraps,
    reason = "same signature as the Unix version"
)]
fn maybe_apply_permissions<P: AsRef<Path>>(_path: P, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

fn warn_failure(e: &std::io::Error) {
    error!("Warning: failed to tighten file permissions: {e}");
    warn_notice();
}

fn warn_notice() {
    error!(
        "If you are managing file permissions externally and do not need Warpgate to change them, you can pass --skip-securing-files"
    );
}

pub fn secure_directory<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    maybe_apply_permissions(path.as_ref(), 0o700).inspect_err(warn_failure)
}

pub fn secure_file<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    maybe_apply_permissions(path.as_ref(), 0o600).inspect_err(warn_failure)
}

/// Fails where Warpgate cannot restrict access to its own files, unless
/// `--skip-securing-files` says that is taken care of.
#[cfg(unix)]
#[allow(
    clippy::unnecessary_wraps,
    reason = "same signature as the Windows version"
)]
pub fn ensure_files_can_be_secured(_params: &GlobalParams) -> anyhow::Result<()> {
    Ok(())
}

// Without ACLs the files would keep the ACL they inherit: under ProgramData,
// read access for every local user. Refuse rather than run like that.
#[cfg(windows)]
pub fn ensure_files_can_be_secured(params: &GlobalParams) -> anyhow::Result<()> {
    if !params.should_secure_files() {
        return Ok(());
    }
    anyhow::bail!(
        "Warpgate cannot restrict access to its files on Windows yet. Restrict the config \
         and data directories to SYSTEM, Administrators and the service account, then run: \
         warpgate --skip-securing-files <command>"
    )
}

#[cfg(all(test, windows))]
mod tests {
    use std::path::PathBuf;

    use super::ensure_files_can_be_secured;
    use crate::GlobalParams;

    #[test]
    fn refuses_unsecured_files_unless_skipped() {
        let config = PathBuf::from(r"C:\ProgramData\warpgate\warpgate.yaml");
        let params = GlobalParams::new(config.clone(), true).unwrap();
        let error = ensure_files_can_be_secured(&params)
            .unwrap_err()
            .to_string();
        assert!(error.ends_with("warpgate --skip-securing-files <command>"));

        let params = GlobalParams::new(config, false).unwrap();
        ensure_files_can_be_secured(&params).unwrap();
    }
}
