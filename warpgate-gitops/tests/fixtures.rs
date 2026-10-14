use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use warpgate_gitops::validate::check_files;
use warpgate_gitops::{format_json, format_text, read_files};

/// `BLESS=1` writes the actual output instead of comparing
fn assert_golden(expected: &Path, actual: &str) {
    if std::env::var_os("BLESS").is_some() {
        fs::write(expected, actual).unwrap();
        return;
    }
    let expected_text = fs::read_to_string(expected)
        .unwrap_or_else(|e| panic!("{}: {e}; run with BLESS=1", expected.display()));
    assert_eq!(actual, expected_text, "{}", expected.display());
}

/// Every entry in `tests/fixtures/invalid` is a file or directory of resources,
/// next to a `.expected` file with its text output
#[test]
fn invalid_fixtures() {
    let mut fixtures: Vec<PathBuf> = fs::read_dir("tests/fixtures/invalid")
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension() != Some(OsStr::new("expected")))
        .collect();
    fixtures.sort();
    assert!(!fixtures.is_empty());

    for fixture in fixtures {
        let files = read_files(std::slice::from_ref(&fixture)).unwrap();
        let diagnostics = check_files(&files);
        assert!(!diagnostics.is_empty(), "{} is valid", fixture.display());
        assert_golden(
            &fixture.with_extension("expected"),
            &format_text(&diagnostics),
        );
    }
}

#[test]
fn json_output() {
    let files = read_files(&["tests/fixtures/invalid/unknown-fields.yaml".into()]).unwrap();
    let json = serde_json::to_string_pretty(&format_json(&check_files(&files))).unwrap();
    assert_golden(
        Path::new("tests/fixtures/invalid/unknown-fields.json.expected"),
        &format!("{json}\n"),
    );
}

#[test]
fn valid_fixtures() {
    let files = read_files(&["tests/fixtures/valid".into()]).unwrap();
    assert!(!files.is_empty());
    assert_eq!(format_text(&check_files(&files)), "");
}

/// A ConfigMap volume links each file to `..data/`, itself a link to a
/// timestamped directory
#[cfg(unix)]
#[test]
fn configmap_mount_is_read_once() {
    use std::os::unix::fs::symlink;

    let mount = Path::new(env!("CARGO_TARGET_TMPDIR")).join("configmap");
    let _ = fs::remove_dir_all(&mount);
    fs::create_dir_all(mount.join("..2026_10_14")).unwrap();
    fs::copy(
        "tests/fixtures/valid/every-field.yaml",
        mount.join("..2026_10_14/every-field.yaml"),
    )
    .unwrap();
    symlink("..2026_10_14", mount.join("..data")).unwrap();
    symlink("..data/every-field.yaml", mount.join("every-field.yaml")).unwrap();

    let files = read_files(&[mount.clone()]).unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].0, mount.join("every-field.yaml"));
    assert_eq!(format_text(&check_files(&files)), "");
}
