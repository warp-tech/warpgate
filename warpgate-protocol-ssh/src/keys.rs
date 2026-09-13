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
use warpgate_common::{
    MaybeSecretRef, SecretError, SecretRef, SecretResolver, SshHostKeyKind, StoredSecret,
    WarpgateError,
};
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

/// The host keys: from the secret backend entry referenced in the parameters,
/// otherwise the ones stored in the parameters row.
pub async fn load_host_keys(
    db: &DatabaseConnection,
    secret_backend: &dyn SecretResolver,
) -> Result<Vec<PrivateKey>, WarpgateError> {
    let row = Parameters::Entity::get(db).await?;
    if let Some(reference) = &row.ssh_host_key_secret_ref {
        return load_host_keys_from_backend(&reference.parse()?, secret_backend).await;
    }
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

/// Reads the fields named after each [`SshHostKeyKind`]; a kind without a field is
/// skipped, but at least one key must be present.
pub async fn load_host_keys_from_backend(
    reference: &SecretRef,
    secret_backend: &dyn SecretResolver,
) -> Result<Vec<PrivateKey>, WarpgateError> {
    let mut keys = Vec::new();
    for kind in SshHostKeyKind::ALL {
        let reference = SecretRef {
            field: Some(kind.name().to_owned()),
            ..reference.clone()
        };
        match secret_backend.resolve(&reference).await {
            Ok(pem) => keys.push(decode_secret_key(pem.expose_secret(), None)?),
            Err(SecretError::NotFound { .. }) => {
                debug!("No {} host key at {reference}", kind.name());
            }
            Err(error) => return Err(error.into()),
        }
    }
    if keys.is_empty() {
        return Err(WarpgateError::InconsistentState(format!(
            "no SSH host keys found at {reference}"
        )));
    }
    Ok(keys)
}

fn encode_pkcs8_pem_string(key: &PrivateKey) -> Result<String, WarpgateError> {
    let mut buf = Vec::new();
    encode_pkcs8_pem(key, &mut buf)?;
    String::from_utf8(buf).map_err(WarpgateError::other)
}

/// `<algo> <base64>` only — the OpenSSH comment is dropped so that the same
/// key always serializes identically for de-duplication.
fn public_key_line(key: &PrivateKey) -> Result<String, WarpgateError> {
    Ok(key
        .public_key()
        .to_openssh()
        .map_err(russh::keys::Error::from)?
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" "))
}

/// Inserts a row for `public_key`/`stored_secret_key` unless a key with the
/// same public key already exists. `stored_secret_key` is whatever belongs in
/// the `secret_key` column verbatim — already-encrypted PEM for an inline key,
/// or a `vault://`/`openbao://` reference URI.
async fn insert_client_key(
    db: &DatabaseConnection,
    label: &str,
    public_key: String,
    stored_secret_key: MaybeSecretRef,
    is_default: bool,
) -> Result<Option<SshClientKey::Model>, WarpgateError> {
    if SshClientKey::Entity::find()
        .filter(SshClientKey::Column::PublicKey.eq(&public_key))
        .one(db)
        .await?
        .is_some()
    {
        return Ok(None);
    }

    Ok(Some(
        SshClientKey::ActiveModel {
            id: Set(Uuid::new_v4()),
            label: Set(label.into()),
            secret_key: Set(stored_secret_key),
            public_key: Set(public_key),
            is_default: Set(is_default),
        }
        .insert(db)
        .await?,
    ))
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
    let public_key = public_key_line(key)?;
    let secret_key = encode_pkcs8_pem_string(key)?;
    insert_client_key(
        db,
        label,
        public_key,
        MaybeSecretRef::Inline(StoredSecret::from(idempotent_maybe_encrypt_secret(
            &secret_key,
        )?)),
        is_default,
    )
    .await
}

/// Registers a key whose material lives in a secret backend rather than in
/// Warpgate's own storage: resolves `reference` once (to validate it decodes
/// as a private key and to compute the public key for de-duplication and
/// display), then stores the reference URI itself in the `secret_key` column —
/// the same "inline value or backend reference in one field" scheme target
/// credentials use (see [`warpgate_common::secrets::MaybeSecretRef`]).
pub async fn import_client_key_reference(
    db: &DatabaseConnection,
    label: &str,
    reference: &SecretRef,
    backend: &dyn SecretResolver,
    is_default: bool,
) -> Result<Option<SshClientKey::Model>, WarpgateError> {
    let value = backend.resolve(reference).await?;
    let key = decode_secret_key(value.expose_secret(), None)?;
    let public_key = public_key_line(&key)?;

    insert_client_key(db, label, public_key, reference.clone().into(), is_default).await
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
        if let MaybeSecretRef::Reference(reference) = &m.secret_key {
            match load_referenced_client_key(db, m, reference, secret_backend).await {
                Ok(key) => keys.push(key),
                // A key the admin picked for this target must work or the attempt
                // fails; an unusable key in the default set just isn't offered, so
                // one backend outage doesn't take every stored key with it.
                Err(error) if key_id != Some(m.id) => {
                    warn!(label = %m.label, %error, "Skipping SSH client key that could not be read from its secret backend");
                }
                Err(error) => return Err(error),
            }
        } else {
            keys.push(decode_secret_key(
                m.secret_key.reveal()?.expose_secret(),
                None,
            )?);
        }
    }
    Ok(keys)
}

/// Resolves a reference row's key, and syncs the stored public key with what the
/// backend currently holds so the admin UI and `client-keys` show the key targets
/// actually see after a rotation in the backend.
async fn load_referenced_client_key(
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
        SshClientKey::Entity::update_many()
            .col_expr(SshClientKey::Column::PublicKey, Expr::value(public_key))
            .filter(SshClientKey::Column::Id.eq(model.id))
            .exec(db)
            .await?;
    }
    Ok(key)
}
