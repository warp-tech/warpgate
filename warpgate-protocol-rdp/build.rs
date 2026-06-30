//! Embeds the standalone RDP helper binaries into this crate so Warpgate ships as a
//! single executable.
//!
//! Two helpers are embedded: the target-facing client (`warpgate-rdp-helper`) and the
//! viewer-facing server (`warpgate-rdp-server-helper`). Both are built separately — each
//! has its own lockfile to avoid `picky`/`sspi` pre-release conflicts between IronRDP's
//! generations and `russh` — so here we only locate the prebuilt artifacts, compress
//! them, and stash them in `OUT_DIR` for `include_bytes!`. Embedding is mandatory: if an
//! artifact is missing the build fails (there is no runtime `$PATH` fallback).

use std::error::Error;
use std::io::Write as _;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    // Target-facing RDP client helper.
    embed(&Helper {
        bin_env: "WARPGATE_RDP_HELPER_BIN",
        crate_dir: "warpgate-rdp-helper",
        bin_stem: "warpgate-rdp-helper",
        blob_file: "rdp-helper.gz",
        blob_env: "RDP_HELPER_BLOB",
        just_recipe: "build-rdp-helper",
    })?;

    // Viewer-facing RDP server helper (the native RDP endpoint).
    embed(&Helper {
        bin_env: "WARPGATE_RDP_SERVER_HELPER_BIN",
        crate_dir: "warpgate-rdp-server-helper",
        bin_stem: "warpgate-rdp-server-helper",
        blob_file: "rdp-server-helper.gz",
        blob_env: "RDP_SERVER_HELPER_BLOB",
        just_recipe: "build-rdp-server-helper",
    })?;

    Ok(())
}

struct Helper {
    /// Env var holding an explicit path to the prebuilt binary (CI / cross builds).
    bin_env: &'static str,
    /// Sibling crate directory (relative to this crate's parent).
    crate_dir: &'static str,
    /// Binary file stem (without the platform extension).
    bin_stem: &'static str,
    /// Output file name under `OUT_DIR`.
    blob_file: &'static str,
    /// `cargo:rustc-env` var pointing at the compressed blob.
    blob_env: &'static str,
    /// `just` recipe mentioned in the build-failure hint.
    just_recipe: &'static str,
}

fn embed(helper: &Helper) -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-env-changed={}", helper.bin_env);

    let path = locate_helper(helper).ok_or_else(|| {
        format!(
            "{stem} binary not found. Build it first (`just {recipe}`, or `cd {dir} && cargo \
             build --release`) or point {env} at it. The helper is embedded into the main \
             binary and is required.",
            stem = helper.bin_stem,
            recipe = helper.just_recipe,
            dir = helper.crate_dir,
            env = helper.bin_env,
        )
    })?;
    println!("cargo:rerun-if-changed={}", path.display());

    let bytes = std::fs::read(&path)?;

    // The helpers are ~12 MB uncompressed; compress so we don't bloat the binary.
    let compressed = {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(&bytes)?;
        enc.finish()?
    };

    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").ok_or("OUT_DIR not set")?);
    let blob_path = out_dir.join(helper.blob_file);
    std::fs::write(&blob_path, &compressed)?;

    println!("cargo:rustc-env={}={}", helper.blob_env, blob_path.display());
    Ok(())
}

/// Find a prebuilt helper executable, if any.
fn locate_helper(helper: &Helper) -> Option<PathBuf> {
    // An explicit path always wins (used by CI / cross builds).
    if let Some(explicit) = std::env::var_os(helper.bin_env) {
        let path = PathBuf::from(explicit);
        return path.is_file().then_some(path);
    }

    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR")?);
    let helper_root = manifest_dir.parent()?.join(helper.crate_dir);

    let target = std::env::var_os("TARGET");
    let mut bin_name = String::from(helper.bin_stem);
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
