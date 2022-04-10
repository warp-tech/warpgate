use std::os::unix::prelude::PermissionsExt;
use std::path::Path;

pub fn secure_directory<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    std::fs::set_permissions(path.as_ref(), std::fs::Permissions::from_mode(0o700))
}

pub fn secure_file<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    std::fs::set_permissions(path.as_ref(), std::fs::Permissions::from_mode(0o600))
}
