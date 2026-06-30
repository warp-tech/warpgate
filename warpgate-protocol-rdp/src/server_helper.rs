//! Resolving and materialising the embedded `warpgate-rdp-server-helper` (server) executable.
//!
//! The viewer-facing RDP server helper runs the RDP server state machine that
//! standard clients (mstsc/FreeRDP) connect to. Like the client helper it lives
//! outside the cargo workspace (IronRDP's server stack pins `picky`/`sspi`
//! pre-releases that conflict with both `russh` and the client helper's IronRDP
//! generation), is embedded into this binary at build time (see `build.rs`), and
//! is materialised on first use. The override env var is `WARPGATE_RDP_SERVER_HELPER`.
//! See [`crate::embedded`] for the materialisation strategy.

use crate::embedded::{EmbeddedHelper, HelperExecutable};
use warpgate_common::WarpgateError;

/// The viewer-facing RDP server helper, embedded by `build.rs`.
static HELPER: EmbeddedHelper = EmbeddedHelper::new(
    include_bytes!(env!("RDP_SERVER_HELPER_BLOB")),
    "warpgate-rdp-server-helper",
    "WARPGATE_RDP_SERVER_HELPER",
);

/// Resolve the server helper executable, materialising the embedded copy as needed.
pub fn resolve() -> Result<HelperExecutable, WarpgateError> {
    HELPER.resolve()
}
