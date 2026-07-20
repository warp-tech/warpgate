//! Embeds the standalone RDP helper binary into this crate so Warpgate ships as a
//! single executable.
//!
//! One helper is embedded: `warpgate-rdp-helper`, which carries both the target-facing
//! client (`connect`) and the viewer-facing server (`serve`) as subcommands.
//!
//! This crate has no cargo dependency on the helper — it only embeds the finished
//! executable — so Cargo cannot order the two builds. The helper must therefore be built
//! first (`just build-rdp-helper`); here we only locate the prebuilt artifact, compress
//! it, and stash it in `OUT_DIR` for `include_bytes!`. Embedding is mandatory: if the
//! artifact is missing the build fails (there is no runtime `$PATH` fallback).

use std::error::Error;
use std::io::Write as _;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    embed(&Helper {
        bin_env: "WARPGATE_RDP_HELPER_BIN",
        bin_stem: "warpgate-rdp-helper",
        blob_file: "rdp-helper.gz",
        blob_env: "RDP_HELPER_BLOB",
        just_recipe: "build-rdp-helper",
    })?;

    Ok(())
}

struct Helper {
    /// Env var holding an explicit path to the prebuilt binary (CI / cross builds).
    bin_env: &'static str,
    /// Binary file stem (without the platform extension), also the package name.
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
            "{stem} binary not found. Build it first (`just {recipe}`, or `cargo build \
             --release -p {stem}`) or point {env} at it. The helper is embedded into the \
             main binary and is required.",
            stem = helper.bin_stem,
            recipe = helper.just_recipe,
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

    println!(
        "cargo:rustc-env={}={}",
        helper.blob_env,
        blob_path.display()
    );
    Ok(())
}

/// Find a prebuilt helper executable, if any.
fn locate_helper(helper: &Helper) -> Option<PathBuf> {
    // An explicit path always wins (used by CI / cross builds).
    if let Some(explicit) = std::env::var_os(helper.bin_env) {
        let path = PathBuf::from(explicit);
        return path.is_file().then_some(path);
    }

    let target = std::env::var_os("TARGET");
    let mut bin_name = String::from(helper.bin_stem);
    if target
        .as_ref()
        .and_then(|t| t.to_str())
        .is_some_and(|t| t.contains("windows"))
    {
        bin_name.push_str(".exe");
    }

    // `OUT_DIR` is `<target>/[<triple>/]<profile>/build/<pkg>-<hash>/out`, so its third
    // ancestor is the profile directory. The helper is always built in release (it is a
    // ~12 MB artifact and gets compressed into this crate regardless of our own profile),
    // and under the same `[<triple>/]` prefix, so it is the profile dir's `release`
    // sibling — which also resolves correctly when cross-compiling.
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR")?);
    let profile_dir = out_dir.ancestors().nth(3)?;
    let path = profile_dir.parent()?.join("release").join(&bin_name);

    path.is_file().then_some(path)
}
