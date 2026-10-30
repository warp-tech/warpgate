use std::collections::HashSet;
use std::ffi::OsStr;
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::{fs, io};

use diagnostic::Diagnostic;
use serde_json::{Value, json};
use walkdir::WalkDir;

pub mod diagnostic;
pub mod parse;
pub mod plan;
pub mod types;
pub mod validate;

pub fn json_schema() -> Value {
    let mut schema = schemars::schema_for!(types::Resource).to_value();
    let mut variant_targets = HashSet::new();
    collect_variant_targets(&schema, &mut variant_targets);
    close_objects(&mut schema, None, &variant_targets);
    schema
}

/// References made next to `properties`, which is how a `kind`-tagged variant
/// adds its tag to the struct it refers to
fn collect_variant_targets(value: &Value, out: &mut HashSet<String>) {
    match value {
        Value::Object(object) => {
            if object.contains_key("properties")
                && let Some(Value::String(target)) = object.get("$ref")
            {
                out.insert(target.clone());
            }
            object
                .values()
                .for_each(|v| collect_variant_targets(v, out));
        }
        Value::Array(items) => items.iter().for_each(|v| collect_variant_targets(v, out)),
        _ => {}
    }
}

/// Lets editors flag an unknown field, as `config validate` does. The struct a
/// tagged variant refers to stays open and the variant is closed instead:
/// `unevaluatedProperties` there sees the tag and the struct's fields together,
/// while inside the struct it would reject the tag.
fn close_objects(value: &mut Value, definition: Option<&str>, variant_targets: &HashSet<String>) {
    match value {
        Value::Object(object) => {
            let refers_here = definition.is_some_and(|d| variant_targets.contains(d));
            if object.contains_key("properties")
                && !object.contains_key("additionalProperties")
                && !refers_here
            {
                object.insert("unevaluatedProperties".into(), Value::Bool(false));
            }
            for (key, child) in object.iter_mut() {
                match (key.as_str(), child) {
                    ("$defs", Value::Object(definitions)) => {
                        for (name, schema) in definitions.iter_mut() {
                            let reference = format!("#/$defs/{name}");
                            close_objects(schema, Some(&reference), variant_targets);
                        }
                    }
                    (_, child) => close_objects(child, None, variant_targets),
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                close_objects(item, None, variant_targets);
            }
        }
        _ => {}
    }
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

/// One `file:line:col path: message` line per diagnostic
pub fn format_text(diagnostics: &[(&Path, Diagnostic)]) -> String {
    diagnostics
        .iter()
        .fold(String::new(), |mut out, (file, d)| {
            let path = if d.path.0.is_empty() {
                String::new()
            } else {
                format!(" {}", d.path)
            };
            // writing to a String cannot fail
            let _ = writeln!(
                out,
                "{}:{}{path}: {}",
                file.display(),
                d.location,
                d.message
            );
            out
        })
}

pub fn format_json(diagnostics: &[(&Path, Diagnostic)]) -> Value {
    diagnostics
        .iter()
        .map(|(file, d)| {
            json!({
                "file": file.display().to_string(),
                "line": d.location.line,
                "column": d.location.column,
                "path": d.path.to_string(),
                "message": d.message,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::json_schema;

    #[test]
    fn the_published_schema_rejects_unknown_fields() {
        let schema = json_schema();
        let closed =
            |schema: &Value| schema.get("unevaluatedProperties") == Some(&Value::Bool(false));
        let definitions = &schema["$defs"];

        assert!(closed(&definitions["TargetSSHOptions"]));
        assert!(closed(&definitions["Metadata"]));
        for variant in definitions["SSHTargetAuth"]["oneOf"].as_array().unwrap() {
            assert!(closed(variant), "{variant}");
        }
        for variant in schema["oneOf"].as_array().unwrap() {
            assert!(closed(variant), "{variant}");
        }
        // Closing the struct a variant refers to would reject the variant's `kind`
        assert!(!closed(&definitions["SshTargetPasswordAuth"]));
        assert!(!closed(&definitions["TargetSpecManifest"]));
    }
}
