//! Embeds the standalone `warpgate-rdp-helper` binary into this crate so Warpgate
//! ships as a single executable.
//!
//! The helper is built separately — it has its own lockfile to avoid a RustCrypto
//! pre-release conflict between IronRDP's CredSSP stack and `russh` — so here we
//! only locate the prebuilt artifact, compress it, and stash it in `OUT_DIR` for
//! `include_bytes!`. Embedding is mandatory: if the artifact is missing the build
//! fails (there is no runtime `$PATH` fallback).

use std::error::Error;
use std::io::Write as _;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-env-changed=WARPGATE_RDP_HELPER_BIN");

    let helper = locate_helper().ok_or(
        "warpgate-rdp-helper binary not found. Build it first (`just build-rdp-helper`, or \
         `cd warpgate-rdp-helper && cargo build --release`) or point WARPGATE_RDP_HELPER_BIN at \
         it. The helper is embedded into the main binary and is required.",
    )?;
    println!("cargo:rerun-if-changed={}", helper.display());

    let bytes = std::fs::read(&helper)?;

    // The helper is ~12 MB uncompressed; compress it so we don't bloat the binary.
    let compressed = {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(&bytes)?;
        enc.finish()?
    };

    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").ok_or("OUT_DIR not set")?);
    let blob_path = out_dir.join("rdp-helper.gz");
    std::fs::write(&blob_path, &compressed)?;

    println!("cargo:rustc-env=RDP_HELPER_BLOB={}", blob_path.display());
    Ok(())
}

/// Find the prebuilt helper executable, if any.
fn locate_helper() -> Option<PathBuf> {
    // An explicit path always wins (used by CI / cross builds).
    if let Some(explicit) = std::env::var_os("WARPGATE_RDP_HELPER_BIN") {
        let path = PathBuf::from(explicit);
        return path.is_file().then_some(path);
    }

    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR")?);
    let helper_root = manifest_dir.parent()?.join("warpgate-rdp-helper");

    let target = std::env::var_os("TARGET");
    let mut bin_name = String::from("warpgate-rdp-helper");
    if target
        .as_ref()
        .and_then(|t| t.to_str())
        .is_some_and(|t| t.contains("windows"))
    {
        bin_name.push_str(".exe");
    }

    // Prefer a target-specific build dir (cross-compilation), then the default.
    let mut candidates = Vec::new();
    if let Some(target) = target {
        candidates.push(
            helper_root
                .join("target")
                .join(target)
                .join("release")
                .join(&bin_name),
        );
    }
    candidates.push(helper_root.join("target").join("release").join(&bin_name));

    candidates.into_iter().find(|p| p.is_file())
}
