use std::fs::{File, create_dir_all};
use std::path::PathBuf;

use anyhow::{Context, Result};
use russh::keys::{
    Algorithm, HashAlg, PrivateKey, decode_secret_key, encode_pkcs8_pem, load_secret_key,
};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use tracing::*;
use uuid::Uuid;
use warpgate_common::encryption::{idempotent_maybe_decrypt, idempotent_maybe_encrypt_secret};
use warpgate_common::helpers::fs::{secure_directory, secure_file};
use warpgate_common::helpers::rng::get_crypto_rng;
use warpgate_common::{
    GlobalParams, SecretBackend, SecretError, SecretRef, SecretValue, SshKeysBackend,
    SshKeysSource, WarpgateConfig, WarpgateError,
};
use warpgate_db_entities::SshClientKey;

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

// --- Host keys: Warpgate's own SSH server identity. Source-configurable via
// `SshConfig.keys` (on disk, or resolved from a secret backend). ---

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

// --- Client keys: the pool of stored keys Warpgate offers when authenticating
// to targets by public key. DB-backed and admin-managed (see `ssh_client_keys`
// / warpgate-admin's `ssh_keys` API), independent of the host key source above. ---

/// Stores the key in the DB unless one with the same public key already
/// exists. `is_default` seeds the default flag; bootstrap keys are stored as
/// default, admin-added keys are not (the admin toggles them afterwards).
pub async fn import_client_key(
    db: &DatabaseConnection,
    label: &str,
    key: &PrivateKey,
    is_default: bool,
) -> Result<Option<SshClientKey::Model>, WarpgateError> {
    // `<algo> <base64>` only — the OpenSSH comment is dropped so that the
    // same key always serializes identically for de-duplication.
    let public_key = key
        .public_key()
        .to_openssh()
        .map_err(russh::keys::Error::from)?
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");

    if SshClientKey::Entity::find()
        .filter(SshClientKey::Column::PublicKey.eq(&public_key))
        .one(db)
        .await?
        .is_some()
    {
        return Ok(None);
    }

    let secret_key = encode_pkcs8_pem_string(key)?;

    Ok(Some(
        SshClientKey::ActiveModel {
            id: Set(Uuid::new_v4()),
            label: Set(label.into()),
            secret_key: Set(idempotent_maybe_encrypt_secret(&secret_key)?),
            public_key: Set(public_key),
            is_default: Set(is_default),
        }
        .insert(db)
        .await?,
    ))
}

/// One-time migration of the on-disk SSH client keys into the DB, generating
/// fresh ones on brand-new installs. Runs only while the key table is empty,
/// so keys later deleted through the admin API don't resurrect from disk.
/// Call at startup.
///
/// The bootstrap keys are stored as default so a target with no specific key
/// selected is offered all of them, matching the previous on-disk behaviour.
///
/// A backend-managed `SshKeysSource` has no on-disk legacy files to migrate,
/// so this just generates fresh keys straight into the DB in that case.
pub async fn ensure_client_keys(
    db: &DatabaseConnection,
    config: &WarpgateConfig,
    params: &GlobalParams,
) -> Result<(), WarpgateError> {
    if SshClientKey::Entity::find().one(db).await?.is_some() {
        return Ok(());
    }

    if let SshKeysSource::Path(dir) = &config.store.ssh.keys {
        let mut path = params.paths_relative_to().clone();
        path.push(dir);
        for name in ["client-ed25519", "client-rsa"] {
            let file = path.join(name);
            if file.exists() {
                let key = load_secret_key(&file, None)?;
                if import_client_key(db, name, &key, true).await?.is_some() {
                    info!("Imported SSH client key {name} from {file:?} into the database");
                }
            }
        }
    }

    if SshClientKey::Entity::find().one(db).await?.is_none() {
        for (algo, label) in [
            (Algorithm::Ed25519, "client-ed25519"),
            (
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha512),
                },
                "client-rsa",
            ),
        ] {
            info!("Generating SSH client key ({algo:?})");
            let key = PrivateKey::random(&mut get_crypto_rng(), algo)
                .map_err(russh::keys::Error::from)?;
            import_client_key(db, label, &key, true).await?;
        }
    }

    Ok(())
}

/// The stored keys to offer a target that authenticates without a specific key
/// selected: the default-flagged ones, or — if none are flagged — every key, so
/// clearing every default never locks targets out.
async fn default_client_keys(
    db: &DatabaseConnection,
) -> Result<Vec<SshClientKey::Model>, WarpgateError> {
    let defaults = SshClientKey::Entity::find_default().all(db).await?;
    if defaults.is_empty() {
        Ok(SshClientKey::Entity::find_ordered().all(db).await?)
    } else {
        Ok(defaults)
    }
}

/// The private keys to try against a target: the specific chosen key, or the
/// default set. A chosen key that no longer exists falls back to the default
/// set (e.g. after the key was deleted, or on a node that hasn't synced it).
pub async fn load_client_keys(
    db: &DatabaseConnection,
    key_id: Option<Uuid>,
) -> Result<Vec<PrivateKey>, WarpgateError> {
    let models = match key_id {
        Some(id) => if let Some(model) = SshClientKey::Entity::find_by_id(id).one(db).await? { vec![model] } else {
            warn!("SSH client key {id} chosen for the target does not exist; using defaults");
            default_client_keys(db).await?
        },
        None => default_client_keys(db).await?,
    };
    models
        .iter()
        .map(|m| {
            Ok(decode_secret_key(
                &idempotent_maybe_decrypt(&m.secret_key)?,
                None,
            )?)
        })
        .collect()
}
