use std::fs::{File, create_dir_all};
use std::path::PathBuf;

use anyhow::{Context, Result};
use russh::keys::{HashAlg, PrivateKey, decode_secret_key, encode_pkcs8_pem, load_secret_key};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use tracing::*;
use uuid::Uuid;
use warpgate_common::encryption::{idempotent_maybe_decrypt, idempotent_maybe_encrypt_secret};
use warpgate_common::helpers::fs::{secure_directory, secure_file};
use warpgate_common::helpers::rng::get_crypto_rng;
use warpgate_common::{GlobalParams, WarpgateConfig, WarpgateError};
use warpgate_db_entities::SshClientKey;

fn get_keys_path(config: &WarpgateConfig, params: &GlobalParams) -> PathBuf {
    let mut path = params.paths_relative_to().clone();
    path.push(&config.store.ssh.keys);
    path
}

pub fn generate_keys(config: &WarpgateConfig, params: &GlobalParams, prefix: &str) -> Result<()> {
    let path = get_keys_path(config, params);
    create_dir_all(&path)?;
    if params.should_secure_files() {
        secure_directory(&path)?;
    }

    for (algo, name) in [
        (russh::keys::Algorithm::Ed25519, format!("{prefix}-ed25519")),
        (
            russh::keys::Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
            format!("{prefix}-rsa"),
        ),
    ] {
        let key_path = path.join(name);
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

pub fn load_keys(
    config: &WarpgateConfig,
    params: &GlobalParams,
    prefix: &str,
) -> Result<Vec<PrivateKey>, russh::keys::Error> {
    let path = get_keys_path(config, params);
    Ok(vec![
        load_secret_key(path.join(format!("{prefix}-ed25519")), None)?,
        load_secret_key(path.join(format!("{prefix}-rsa")), None)?,
    ])
}

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

    let mut buf = Vec::new();
    encode_pkcs8_pem(key, &mut buf)?;
    let secret_key = String::from_utf8(buf).map_err(WarpgateError::other)?;

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
pub async fn ensure_client_keys(
    db: &DatabaseConnection,
    config: &WarpgateConfig,
    params: &GlobalParams,
) -> Result<(), WarpgateError> {
    if SshClientKey::Entity::find().one(db).await?.is_some() {
        return Ok(());
    }

    let path = get_keys_path(config, params);
    for name in ["client-ed25519", "client-rsa"] {
        let file = path.join(name);
        if file.exists() {
            let key = load_secret_key(&file, None)?;
            if import_client_key(db, name, &key, true).await?.is_some() {
                info!("Imported SSH client key {name} from {file:?} into the database");
            }
        }
    }

    if SshClientKey::Entity::find().one(db).await?.is_none() {
        for (algo, label) in [
            (russh::keys::Algorithm::Ed25519, "client-ed25519"),
            (
                russh::keys::Algorithm::Rsa {
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
        Some(id) => {
            if let Some(model) = SshClientKey::Entity::find_by_id(id).one(db).await? {
                vec![model]
            } else {
                warn!("SSH client key {id} chosen for the target does not exist; using defaults");
                default_client_keys(db).await?
            }
        }
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
