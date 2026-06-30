//! Resolving and materialising the embedded `warpgate-rdp-helper` (client) executable.
//!
//! The target-facing RDP client helper is embedded into this binary at build time
//! (see `build.rs`) and materialised on first use. The override env var is
//! `WARPGATE_RDP_HELPER`. See [`crate::embedded`] for the materialisation strategy.

use crate::embedded::{EmbeddedHelper, HelperExecutable};
use warpgate_common::WarpgateError;

/// The target-facing RDP client helper, embedded by `build.rs`.
static HELPER: EmbeddedHelper = EmbeddedHelper::new(
    include_bytes!(env!("RDP_HELPER_BLOB")),
    "warpgate-rdp-helper",
    "WARPGATE_RDP_HELPER",
);

/// Resolve the client helper executable, materialising the embedded copy as needed.
pub fn resolve() -> Result<HelperExecutable, WarpgateError> {
    HELPER.resolve()
}

#[cfg(test)]
mod tests {
    use super::HELPER;

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn extracts_then_cleans_up_on_drop() {
        use std::os::unix::fs::PermissionsExt;

        let exe = HELPER.extract_to_tempfile().unwrap();
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
        let exe = HELPER.run_from_memfd().unwrap();
        // `/proc/self/fd/N` stats through to the memfd, reporting its real size.
        let meta = std::fs::metadata(exe.path()).unwrap();
        assert!(meta.len() > 1_000_000, "memfd helper looks too small");
    }
}
