use std::ffi::OsStr;
use std::path::PathBuf;
use std::{fs, io};

use walkdir::WalkDir;

pub mod diagnostic;
pub mod parse;
pub mod types;
pub mod validate;

pub fn json_schema() -> schemars::Schema {
    schemars::schema_for!(types::Resource)
}

/// Reads each given file, and every `*.yaml` and `*.yml` under each given
/// directory, sorted by name. Hidden entries are skipped: a Kubernetes
/// ConfigMap mount keeps a second copy of every file in `..data`.
pub fn read_files(paths: &[PathBuf]) -> io::Result<Vec<(PathBuf, String)>> {
    let mut files = Vec::new();
    for root in paths {
        let walk = WalkDir::new(root)
            .follow_links(true)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|e| e.depth() == 0 || !e.file_name().to_string_lossy().starts_with('.'));
        for entry in walk {
            let entry = entry?;
            let is_resource = entry.depth() == 0
                || matches!(
                    entry.path().extension().and_then(OsStr::to_str),
                    Some("yaml" | "yml")
                );
            if !entry.file_type().is_file() || !is_resource {
                continue;
            }
            let source = fs::read_to_string(entry.path()).map_err(|e| {
                io::Error::new(e.kind(), format!("{}: {e}", entry.path().display()))
            })?;
            files.push((entry.into_path(), source));
        }
    }
    Ok(files)
}
