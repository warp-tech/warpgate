#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::prelude::PermissionsExt;
use std::path::Path;

use tracing::error;

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

// Windows has no mode bits and ACL tightening is not implemented yet. Say so
// once (these are called per recording) instead of silently doing nothing.
#[cfg(windows)]
fn warn_not_secured() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        error!(
            "Warning: file permissions are not tightened on Windows yet; restrict access to the config, database and recordings directory yourself"
        );
        warn_notice();
    });
}

#[cfg(windows)]
pub fn secure_directory<P: AsRef<Path>>(_path: P) -> std::io::Result<()> {
    warn_not_secured();
    Ok(())
}

#[cfg(windows)]
pub fn secure_file<P: AsRef<Path>>(_path: P) -> std::io::Result<()> {
    warn_not_secured();
    Ok(())
}
