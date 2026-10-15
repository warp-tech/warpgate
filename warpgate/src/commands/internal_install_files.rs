use std::cmp::Reverse;
use std::path::Path;

use anyhow::{Context, Result};
use warpgate_common::GlobalParams;
use warpgate_common::helpers::fs::{secure_directory, secure_file};

/// `$NAME` placeholders and their values, longest first so that `$FOO`
/// can't clobber the start of `$FOOBAR`.
type Substitutions = [(String, Option<String>)];

pub fn command(
    params: &GlobalParams,
    substitute_env: &[String],
    source: &Path,
    destination: &Path,
) -> Result<()> {
    let mut substitutions: Vec<_> = substitute_env
        .iter()
        .filter(|name| !name.is_empty())
        .map(|name| (format!("${name}"), std::env::var(name).ok()))
        .collect();
    substitutions.sort_by_key(|(placeholder, _)| Reverse(placeholder.len()));
    install_dir(
        source,
        destination,
        &substitutions,
        params.should_secure_files(),
    )
}

fn install_dir(
    source: &Path,
    destination: &Path,
    substitutions: &Substitutions,
    secure: bool,
) -> Result<()> {
    std::fs::create_dir_all(destination)?;
    for entry in std::fs::read_dir(source).with_context(|| source.display().to_string())? {
        let name = entry?.file_name();
        // Kubernetes Secret and ConfigMap volumes keep the real files in
        // `..data` / `..<timestamp>` and expose them through symlinks.
        if name.to_string_lossy().starts_with('.') {
            continue;
        }
        let (from, to) = (source.join(&name), destination.join(&name));
        if from.is_dir() {
            install_dir(&from, &to, substitutions, secure)?;
            if secure {
                secure_directory(&to)?;
            }
        } else {
            let content = substitute(std::fs::read(&from)?, substitutions)
                .with_context(|| from.display().to_string())?;
            std::fs::write(&to, content)?;
            if secure {
                secure_file(&to)?;
            }
        }
    }
    Ok(())
}

fn substitute(content: Vec<u8>, substitutions: &Substitutions) -> Result<Vec<u8>> {
    let mut text = match String::from_utf8(content) {
        Ok(text) => text,
        Err(binary) => return Ok(binary.into_bytes()),
    };
    for (placeholder, value) in substitutions {
        if text.contains(placeholder.as_str()) {
            let value = value
                .as_deref()
                .with_context(|| format!("{placeholder} is referenced but not set"))?;
            text = text.replace(placeholder.as_str(), value);
        }
    }
    Ok(text.into_bytes())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;

    #[test]
    fn installs_a_kubernetes_volume() {
        let source = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();

        // The layout kubelet's atomic writer produces for a projected volume
        let real = source.path().join("..2026_10_12_00_00_00.000");
        std::fs::create_dir_all(real.join("ssh-keys")).unwrap();
        std::fs::write(real.join("warpgate.yaml"), "url: x:$PASS@$PASSWORD_HOST").unwrap();
        std::fs::write(real.join("ssh-keys/host-ed25519"), "key").unwrap();
        symlink(&real, source.path().join("..data")).unwrap();
        symlink("..data/warpgate.yaml", source.path().join("warpgate.yaml")).unwrap();
        symlink("..data/ssh-keys", source.path().join("ssh-keys")).unwrap();

        let substitutions = [
            ("$PASSWORD_HOST".to_string(), Some("db".to_string())),
            ("$PASS".to_string(), Some("s&/cret".to_string())),
            ("$UNUSED".to_string(), None),
        ];
        install_dir(source.path(), destination.path(), &substitutions, true).unwrap();

        let config = destination.path().join("warpgate.yaml");
        assert_eq!(
            std::fs::read_to_string(&config).unwrap(),
            "url: x:s&/cret@db"
        );
        assert_eq!(
            std::fs::read_to_string(destination.path().join("ssh-keys/host-ed25519")).unwrap(),
            "key"
        );
        assert!(!destination.path().join("..data").exists());
        let mode = std::fs::metadata(&config).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn refuses_unset_referenced_variable() {
        let substitutions = [("$MISSING".to_string(), None)];
        assert!(substitute(b"a: $MISSING".to_vec(), &substitutions).is_err());
    }
}
