use std::collections::HashMap;

use rust_embed::RustEmbed;
use serde::Deserialize;

#[derive(RustEmbed)]
#[folder = "../warpgate-web/dist"]
pub struct Assets;

#[derive(thiserror::Error, Debug)]
pub enum LookupError {
    #[error("I/O")]
    Io(#[from] std::io::Error),

    #[error("Serde")]
    Serde(#[from] serde_json::Error),

    #[error("File not found in manifest")]
    FileNotFound,

    #[error("Manifest not found")]
    ManifestNotFound,
}

#[derive(Deserialize)]
struct ManifestEntry {
    pub file: String,
}

pub fn lookup_built_file(source: &str) -> Result<String, LookupError> {
    let file = Assets::get("manifest.json").ok_or(LookupError::ManifestNotFound)?;

    let obj: HashMap<String, ManifestEntry> = serde_json::from_slice(&file.data)?;

    obj.get(source)
        .map(|entry| entry.file.clone())
        .ok_or(LookupError::FileNotFound)
}
