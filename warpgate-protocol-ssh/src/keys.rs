use std::path::{Path, PathBuf};

use russh::keys::{
    Algorithm, HashAlg, PrivateKey, decode_secret_key, encode_pkcs8_pem, load_secret_key,
};
use sea_orm::sea_query::Expr;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use tracing::*;
use uuid::Uuid;
use warpgate_common::encryption::{idempotent_maybe_decrypt, idempotent_maybe_encrypt_secret};
use warpgate_common::helpers::rng::get_crypto_rng;
use warpgate_common::{SshHostKeyKind, WarpgateError};
use warpgate_db_entities::{Parameters, SshClientKey};

fn host_key_file(keys_path: &Path, kind: SshHostKeyKind) -> PathBuf {
    keys_path.join(format!("host-{}", kind.name()))
}

pub fn any_host_key_files_present(keys_path: &Path) -> bool {
    SshHostKeyKind::ALL
        .iter()
        .any(|&kind| host_key_file(keys_path, kind).exists())
}

pub async fn ensure_host_keys(
    db: &DatabaseConnection,
    keys_path: &Path,
) -> Result<(), WarpgateError> {
    let row = Parameters::Entity::get(db).await?;
    let stored = [
        (
            SshHostKeyKind::Ed25519,
            &row.ssh_host_key_ed25519,
            Parameters::Column::SshHostKeyEd25519,
        ),
        (
            SshHostKeyKind::Rsa,
            &row.ssh_host_key_rsa,
            Parameters::Column::SshHostKeyRsa,
        ),
    ];
    for (kind, stored, column) in stored {
        let file = host_key_file(keys_path, kind);
        if !file.exists() {
            continue;
        }
        // If the file exists, import it into the DB (overwriting) so that when the files support is removed, the key in the DB is the latest one
        let pem = std::fs::read_to_string(&file)?;
        if idempotent_maybe_decrypt(stored).is_ok_and(|stored| stored == pem) {
            continue;
        }
        info!("Importing SSH host key from {file:?} into the database");
        Parameters::Entity::update_many()
            .col_expr(column, Expr::value(idempotent_maybe_encrypt_secret(&pem)?))
            .exec(db)
            .await?;
    }
    Ok(())
}

pub async fn load_host_keys(db: &DatabaseConnection) -> Result<Vec<PrivateKey>, WarpgateError> {
    let row = Parameters::Entity::get(db).await?;
    [row.ssh_host_key_ed25519, row.ssh_host_key_rsa]
        .into_iter()
        .map(|stored| {
            Ok(decode_secret_key(
                &idempotent_maybe_decrypt(&stored)?,
                None,
            )?)
        })
        .collect()
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

/// One-time migration of the on-disk SSH client keys in `keys_path` into the DB, generating
/// fresh ones on brand-new installs. Runs only while the key table is empty,
/// so keys later deleted through the admin API don't resurrect from disk.
/// Call at startup.
///
/// The bootstrap keys are stored as default so a target with no specific key
/// selected is offered all of them, matching the previous on-disk behaviour.
pub async fn ensure_client_keys(
    db: &DatabaseConnection,
    keys_path: &Path,
) -> Result<(), WarpgateError> {
    if SshClientKey::Entity::find().one(db).await?.is_some() {
        return Ok(());
    }

    for name in ["client-ed25519", "client-rsa"] {
        let file = keys_path.join(name);
        if file.exists() {
            let key = load_secret_key(&file, None)?;
            if import_client_key(db, name, &key, true).await?.is_some() {
                info!("Imported SSH client key {name} from {file:?} into the database");
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
