use std::os::unix::prelude::PermissionsExt;
use std::path::Path;

use log::*;

fn maybe_apply_permissions<P: AsRef<Path>>(
    path: P,
    permissions: std::fs::Permissions,
) -> std::io::Result<()> {
    let current = std::fs::metadata(&path)?.permissions();
    if (current.mode() & 0o777) != permissions.mode() {
        std::fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

fn warn_failure(e: &std::io::Error) {
    error!("Warning: failed to tighten file permissions: {}", e);
    error!("If you are managing file permissions externally and do not need Warpgate to change them, you can pass --skip-securing-files")
}

pub fn secure_directory<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    maybe_apply_permissions(path.as_ref(), std::fs::Permissions::from_mode(0o700))
        .inspect_err(warn_failure)
}

pub fn secure_file<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    maybe_apply_permissions(path.as_ref(), std::fs::Permissions::from_mode(0o600))
        .inspect_err(warn_failure)
}
