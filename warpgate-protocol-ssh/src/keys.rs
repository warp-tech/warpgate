use std::path::{Path, PathBuf};

use russh::keys::{Algorithm, HashAlg, PrivateKey, decode_secret_key, load_secret_key};
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use tracing::*;
use warpgate_common::helpers::rng::get_crypto_rng;
use warpgate_common::{
    MaybeSecretRef, SecretRef, SecretResolver, SshClientKeyId, SshHostKeyKind, StoredSecret,
    WarpgateError, public_key_line,
};
use warpgate_core::resources::ssh_client_keys::{self, KeyMaterial, SshClientKeyDataRequest};
use warpgate_core::resources::{Actor, ResourceError};
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
        let pem = if file.exists() {
            let pem = std::fs::read_to_string(&file)?;
            if stored
                .reveal()
                .is_ok_and(|stored| stored.expose_secret() == &pem)
            {
                continue;
            }
            info!("Importing SSH host key from {file:?} into the database");
            pem
        } else if stored
            .reveal()
            .is_ok_and(|stored| stored.expose_secret().is_empty())
        {
            info!("Generating SSH host key ({kind:?})");
            kind.generate_pem()?
        } else {
            continue;
        };
        // CAS write to prevent race between nodes at cluster boot
        Parameters::Entity::update_many()
            .col_expr(column, Expr::value(StoredSecret::encrypted(pem)?))
            .filter(column.eq(stored.clone()))
            .exec(db)
            .await?;
    }
    Ok(())
}

/// The host keys stored in the parameters row.
pub async fn load_host_keys(db: &DatabaseConnection) -> Result<Vec<PrivateKey>, WarpgateError> {
    let row = Parameters::Entity::get(db).await?;
    [row.ssh_host_key_ed25519, row.ssh_host_key_rsa]
        .into_iter()
        .map(|stored| Ok(decode_secret_key(stored.reveal()?.expose_secret(), None)?))
        .collect()
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
            match store_bootstrap_key(db, name, &key).await {
                Ok(()) => info!("Imported SSH client key {name} from {file:?} into the database"),
                Err(ResourceError::KeyTaken) => {}
                Err(error) => return Err(error.into()),
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
            store_bootstrap_key(db, label, &key).await?;
        }
    }

    Ok(())
}

/// Bootstrap keys are stored as default, so a target with no specific key
/// selected is offered all of them
async fn store_bootstrap_key(
    db: &DatabaseConnection,
    label: &str,
    key: &PrivateKey,
) -> Result<(), ResourceError> {
    let data = SshClientKeyDataRequest {
        label: label.into(),
        is_default: true,
    };
    ssh_client_keys::create(db, Actor::Admin, &data, KeyMaterial::inline(key)?).await?;
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
    key_id: Option<SshClientKeyId>,
    secret_backend: &dyn SecretResolver,
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
    let mut keys = Vec::with_capacity(models.len());
    for m in &models {
        let key = match &m.secret_key {
            MaybeSecretRef::Reference(reference) => {
                load_and_sync_referenced_client_key(db, m, reference, secret_backend).await
            }
            stored => stored
                .resolve(secret_backend)
                .await
                .and_then(|pem| Ok(decode_secret_key(pem.expose_secret(), None)?)),
        };
        match key {
            Ok(key) => keys.push(key),
            // A key the admin picked for this target must work or the attempt
            // fails; an unusable key in the default set just isn't offered, so
            // one backend outage doesn't take every stored key with it.
            Err(error) if key_id.is_none() => {
                warn!(label = %m.label, %error, "Skipping SSH client key that could not be loaded");
            }
            Err(error) => return Err(error),
        }
    }
    Ok(keys)
}

/// Resolves a reference row's key, and syncs the stored public key with what the
/// backend currently holds so the admin UI and `client-keys` show the key targets
/// actually see after a rotation in the backend.
async fn load_and_sync_referenced_client_key(
    db: &DatabaseConnection,
    model: &SshClientKey::Model,
    reference: &SecretRef,
    secret_backend: &dyn SecretResolver,
) -> Result<PrivateKey, WarpgateError> {
    let value = secret_backend.resolve(reference).await?;
    let key = decode_secret_key(value.expose_secret(), None)?;
    let public_key = public_key_line(&key)?;
    if public_key != model.public_key {
        info!(label = %model.label, "SSH client key was rotated in its secret backend; updating its public key");
        ssh_client_keys::refresh_public_key(db, model.id, public_key).await?;
    }
    Ok(key)
}
