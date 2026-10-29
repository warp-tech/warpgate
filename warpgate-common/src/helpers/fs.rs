#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::prelude::PermissionsExt;
use std::path::Path;

use tracing::error;

use crate::GlobalParams;

#[cfg(unix)]
fn maybe_apply_permissions<P: AsRef<Path>>(
    path: P,
    permissions: std::fs::Permissions,
) -> std::io::Result<()> {
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

#[cfg(unix)]
fn warn_failure(e: &std::io::Error) {
    error!("Warning: failed to tighten file permissions: {e}");
    warn_notice();
}

fn warn_notice() {
    error!(
        "If you are managing file permissions externally and do not need Warpgate to change them, you can pass --skip-securing-files"
    );
}

#[cfg(unix)]
pub fn secure_directory<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    maybe_apply_permissions(path.as_ref(), std::fs::Permissions::from_mode(0o700))
        .inspect_err(warn_failure)
}

#[cfg(unix)]
pub fn secure_file<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    maybe_apply_permissions(path.as_ref(), std::fs::Permissions::from_mode(0o600))
        .inspect_err(warn_failure)
}

/// Fails where Warpgate cannot restrict access to its own files, unless
/// `--skip-securing-files` says that is taken care of. `data_dir` is named in
/// the error where it is known.
#[cfg(unix)]
#[allow(
    clippy::unnecessary_wraps,
    reason = "same signature as the Windows version"
)]
pub fn ensure_files_can_be_secured(
    _params: &GlobalParams,
    _data_dir: Option<&Path>,
) -> anyhow::Result<()> {
    Ok(())
}

// Windows has no mode bits and setting ACLs is not implemented yet, so the
// files would keep the ACL they inherit: under ProgramData, read access for
// every local user. Refuse rather than run like that.
#[cfg(windows)]
pub fn ensure_files_can_be_secured(
    params: &GlobalParams,
    data_dir: Option<&Path>,
) -> anyhow::Result<()> {
    if !params.should_secure_files() {
        return Ok(());
    }
    let config_dir = params.paths_relative_to();
    let config_dir = if config_dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        config_dir
    };
    let directories = match data_dir {
        Some(data_dir) if data_dir != config_dir => format!(
            "the config directory {} and the data directory {}",
            config_dir.display(),
            data_dir.display()
        ),
        Some(_) => format!("the directory {}", config_dir.display()),
        None => format!(
            "the config directory {} and the data directory",
            config_dir.display()
        ),
    };
    anyhow::bail!(
        "Warpgate cannot restrict access to its files on Windows yet: its config file, \
         database, TLS key and session recordings keep the permissions they inherit, and \
         under C:\\ProgramData every local user can read them. Restrict {directories} to \
         SYSTEM, Administrators and the account Warpgate runs as, then run: \
         warpgate --skip-securing-files <command>"
    )
}

// `ensure_files_can_be_secured` stops every command but `version` and
// `healthcheck` before they get here, so this is reached only by those (or a
// new command left out of that check); say so once (these are called per
// recording) instead of silently doing nothing.
#[cfg(windows)]
fn warn_not_secured() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        error!(
            "Warning: file permissions are not tightened on Windows yet; restrict access to the config, database, TLS key and recordings yourself"
        );
        warn_notice();
    });
}

#[cfg(windows)]
#[allow(
    clippy::unnecessary_wraps,
    reason = "same signature as the Unix version"
)]
pub fn secure_directory<P: AsRef<Path>>(_path: P) -> std::io::Result<()> {
    warn_not_secured();
    Ok(())
}

#[cfg(windows)]
#[allow(
    clippy::unnecessary_wraps,
    reason = "same signature as the Unix version"
)]
pub fn secure_file<P: AsRef<Path>>(_path: P) -> std::io::Result<()> {
    warn_not_secured();
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use std::path::{Path, PathBuf};

    use super::ensure_files_can_be_secured;
    use crate::GlobalParams;

    #[test]
    fn refuses_unsecured_files_and_names_the_directories() {
        let config_dir = PathBuf::from(r"C:\ProgramData\warpgate");
        let params = GlobalParams::new(config_dir.join("warpgate.yaml"), true).unwrap();
        let data_dir = config_dir.join("data");
        let error = ensure_files_can_be_secured(&params, Some(&data_dir))
            .unwrap_err()
            .to_string();
        assert!(error.contains(r"config directory C:\ProgramData\warpgate "));
        assert!(error.contains(r"data directory C:\ProgramData\warpgate\data "));
        assert!(error.ends_with("warpgate --skip-securing-files <command>"));

        let params = GlobalParams::new(config_dir.join("warpgate.yaml"), false).unwrap();
        ensure_files_can_be_secured(&params, Some(Path::new("data"))).unwrap();
    }
}
