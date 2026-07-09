use std::fs::{File, create_dir_all};
use std::path::PathBuf;

use anyhow::{Context, Result};
use russh::keys::{
    Algorithm, HashAlg, PrivateKey, decode_secret_key, encode_pkcs8_pem, load_secret_key,
};
use tracing::*;
use warpgate_common::helpers::fs::{secure_directory, secure_file};
use warpgate_common::helpers::rng::get_crypto_rng;
use warpgate_common::{
    GlobalParams, SecretBackend, SecretError, SecretRef, SecretValue, SshKeysBackend,
    SshKeysSource, WarpgateConfig, WarpgateError,
};

fn key_algos() -> [(Algorithm, &'static str); 2] {
    [
        (Algorithm::Ed25519, "ed25519"),
        (
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
            "rsa",
        ),
    ]
}

fn keys_dir(config: &WarpgateConfig, params: &GlobalParams) -> Result<PathBuf> {
    match &config.store.ssh.keys {
        SshKeysSource::Path(dir) => {
            let mut path = params.paths_relative_to().clone();
            path.push(dir);
            Ok(path)
        }
        SshKeysSource::Backend(b) => anyhow::bail!(
            "SSH keys are managed by secret backend '{}', not on disk",
            b.backend
        ),
    }
}

pub fn generate_keys_on_disk(
    config: &WarpgateConfig,
    params: &GlobalParams,
    prefix: &str,
) -> Result<()> {
    let path = keys_dir(config, params)?;
    create_dir_all(&path)?;
    if params.should_secure_files() {
        secure_directory(&path)?;
    }

    for (algo, suffix) in key_algos() {
        let key_path = path.join(format!("{prefix}-{suffix}"));
        if !key_path.exists() {
            info!("Generating {prefix} key ({algo:?})");
            let key = PrivateKey::random(&mut get_crypto_rng(), algo)
                .context("Failed to generate key")?;
            let f = File::create(&key_path)?;
            encode_pkcs8_pem(&key, f)?;
        }
        if params.should_secure_files() {
            secure_file(&key_path)?;
        }
    }

    Ok(())
}

pub fn load_keys_on_disk(
    config: &WarpgateConfig,
    params: &GlobalParams,
    prefix: &str,
) -> Result<Vec<PrivateKey>> {
    let path = keys_dir(config, params)?;
    Ok(vec![
        load_secret_key(path.join(format!("{prefix}-ed25519")), None)?,
        load_secret_key(path.join(format!("{prefix}-rsa")), None)?,
    ])
}

pub fn load_preferred_key_on_disk(
    config: &WarpgateConfig,
    params: &GlobalParams,
    prefix: &str,
) -> Result<PrivateKey> {
    let path = keys_dir(config, params)?;
    Ok(load_secret_key(path.join(format!("{prefix}-ed25519")), None)?)
}

pub fn keys_managed_externally(config: &WarpgateConfig) -> Option<String> {
    match &config.store.ssh.keys {
        SshKeysSource::Backend(b) => Some(b.backend.clone()),
        SshKeysSource::Path(_) => None,
    }
}

fn secret_ref(b: &SshKeysBackend, field: &str) -> SecretRef {
    SecretRef {
        scheme: "vault".to_string(),
        backend: b.backend.clone(),
        path: b.path.clone(),
        field: Some(field.to_string()),
    }
}

fn encode_pkcs8_pem_string(key: &PrivateKey) -> Result<String> {
    let mut buf = Vec::new();
    encode_pkcs8_pem(key, &mut buf)?;
    Ok(String::from_utf8(buf)?)
}

async fn resolve_key(
    b: &SshKeysBackend,
    backend: &dyn SecretBackend,
    field: &str,
) -> Result<PrivateKey, WarpgateError> {
    let value = backend.resolve(&secret_ref(b, field)).await?;
    Ok(decode_secret_key(value.expose(), None)?)
}

async fn ensure_keys_in_backend(
    b: &SshKeysBackend,
    backend: &dyn SecretBackend,
    prefix: &str,
) -> Result<()> {
    for (algo, suffix) in key_algos() {
        let field = format!("{prefix}-{suffix}");
        let reference = secret_ref(b, &field);
        match backend.resolve(&reference).await {
            Ok(value) => {
                decode_secret_key(value.expose(), None).with_context(|| {
                    format!("stored SSH key '{field}' is not a valid private key")
                })?;
            }
            Err(SecretError::NotFound { .. }) => {
                info!(
                    "Generating SSH {field} key and storing in backend '{}'",
                    b.backend
                );
                let key = PrivateKey::random(&mut get_crypto_rng(), algo)
                    .context("Failed to generate key")?;
                let pem = encode_pkcs8_pem_string(&key)?;
                backend
                    .store(&reference, &SecretValue::new(pem))
                    .await
                    .with_context(|| {
                        format!("failed to store SSH key '{field}' in backend '{}'", b.backend)
                    })?;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub async fn ensure_keys(
    config: &WarpgateConfig,
    params: &GlobalParams,
    backend: &dyn SecretBackend,
    prefix: &str,
) -> Result<(), WarpgateError> {
    match &config.store.ssh.keys {
        SshKeysSource::Path(_) => Ok(generate_keys_on_disk(config, params, prefix)?),
        SshKeysSource::Backend(b) => Ok(ensure_keys_in_backend(b, backend, prefix).await?),
    }
}

pub async fn load_keys(
    config: &WarpgateConfig,
    params: &GlobalParams,
    backend: &dyn SecretBackend,
    prefix: &str,
) -> Result<Vec<PrivateKey>, WarpgateError> {
    match &config.store.ssh.keys {
        SshKeysSource::Path(_) => Ok(load_keys_on_disk(config, params, prefix)?),
        SshKeysSource::Backend(b) => {
            let mut keys = Vec::new();
            for (_algo, suffix) in key_algos() {
                keys.push(resolve_key(b, backend, &format!("{prefix}-{suffix}")).await?);
            }
            Ok(keys)
        }
    }
}

pub async fn load_preferred_key(
    config: &WarpgateConfig,
    params: &GlobalParams,
    backend: &dyn SecretBackend,
    prefix: &str,
) -> Result<PrivateKey, WarpgateError> {
    match &config.store.ssh.keys {
        SshKeysSource::Path(_) => Ok(load_preferred_key_on_disk(config, params, prefix)?),
        SshKeysSource::Backend(b) => resolve_key(b, backend, &format!("{prefix}-ed25519")).await,
    }
}
