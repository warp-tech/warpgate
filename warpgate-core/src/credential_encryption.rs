/// The credential (re)encryption state machinery
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter, Set,
};
use tracing::{error, info, warn};
use warpgate_common::encryption::{Keyring, env_keyring};
use warpgate_common::{
    SshHostKeyKind, StoredSecrets, TargetOptions, WarpgateError, emit_runtime_warning,
};
use warpgate_db_entities::{Parameters, SecretBackend, SshClientKey, Target};

use crate::cluster::alive_nodes;

#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub enum BackfillOutcome {
    /// Nothing left for us to do for now (with the keys we have) - either all done or missing the key(s)
    Settled,
    /// Holding up since not all nodes have the new key yet, retry later
    AwaitingCluster,
}

/// Local state vs cluster state
enum Position {
    /// local key == cluster current key
    InSync,
    /// Cluster key is different -> we do not have the latest key yet
    Behind,
}

/// Bring stored credentials in line with the configured encryption key
pub async fn backfill_credential_encryption(
    db: &DatabaseConnection,
) -> Result<BackfillOutcome, WarpgateError> {
    let ring = env_keyring();
    let position = advance_key_state(db, ring).await?;

    let undecryptable = probe_undecryptable(db).await?;
    report_undecryptable(&undecryptable, ring);

    if matches!(position, Position::Behind) {
        // Can't do anything with these keys
        return Ok(BackfillOutcome::Settled);
    }

    let Some(current_fp) = ring.primary().map(|k| k.fingerprint().to_owned()) else {
        // No key, nothing to do
        return Ok(BackfillOutcome::Settled);
    };

    // Check for running nodes that do not have the latest keys yet
    let stragglers = alive_nodes(db)
        .await?
        .into_iter()
        .filter(|n| n.encryption_key_fingerprint.as_deref() != Some(current_fp.as_str()))
        .count();
    if stragglers > 0 {
        info!(
            "Delaying credential encryption: {stragglers} cluster node(s) do not have the current encryption key yet"
        );
        // See you later
        return Ok(BackfillOutcome::AwaitingCluster);
    }

    let rewritten = rewrite_all(db).await?;
    if rewritten > 0 {
        info!("(Re)encrypted {rewritten} credential(s) with the latest key");
    }

    // At this point key rotation is done
    if undecryptable.is_empty() {
        Parameters::Entity::update_many()
            .col_expr(
                Parameters::Column::RetiringKeyFp,
                Expr::value(Option::<String>::None),
            )
            .filter(Parameters::Column::EncryptionKeyFp.eq(current_fp))
            .filter(Parameters::Column::RetiringKeyFp.is_not_null())
            .exec(db)
            .await?;
    }

    Ok(BackfillOutcome::Settled)
}

/// Progress through key state machine
///
/// Given a new key C,
///
/// encryption_key_fp = A
/// retiring_key_fp = B
///
/// becomes
///
/// encryption_key_fp = C
/// retiring_key_fp = A
async fn advance_key_state(
    db: &DatabaseConnection,
    ring: &Keyring,
) -> Result<Position, WarpgateError> {
    loop {
        let params = Parameters::Entity::get(db).await?;
        let current = params.encryption_key_fp;

        let Some(own) = ring.primary().map(|k| k.fingerprint()) else {
            return Ok(match current {
                None => Position::InSync,
                Some(current_fp) => {
                    emit_runtime_warning(format!(
                        "The cluster encrypts credentials with key {current_fp}, but WARPGATE_ENCRYPTION_KEY is not set on this node, so stored credentials cannot be used here."
                    ));
                    Position::Behind
                }
            });
        };

        match current.as_deref() {
            Some(current_fp) if current_fp == own => return Ok(Position::InSync),
            Some(current_fp) if !ring.contains(current_fp) => {
                emit_runtime_warning(format!(
                    "This node's encryption key ({own}) is not the cluster's current encryption key ({current_fp}). Stored credentials cannot be used on this node until its WARPGATE_ENCRYPTION_KEY is updated."
                ));
                return Ok(Position::Behind);
            }
            // cluster has no key yet or its current key is being retired
            _ => {}
        }

        if cas_key_state(db, &current, own).await? {
            match &current {
                Some(retiring) => info!("Rotating the cluster encryption key: {retiring} -> {own}"),
                None => info!("Cluster encryption key set to {own}"),
            }
            return Ok(Position::InSync);
        }

        // Another node has advanced the state first, recheck
    }
}

/// UPDATE parameters SET current = own, retiring = current WHERE current = <current>
async fn cas_key_state(
    db: &DatabaseConnection,
    current: &Option<String>,
    own: &str,
) -> Result<bool, WarpgateError> {
    let guard = match current {
        Some(fp) => Parameters::Column::EncryptionKeyFp.eq(fp.clone()),
        None => Parameters::Column::EncryptionKeyFp.is_null(),
    };
    let result = Parameters::Entity::update_many()
        .col_expr(
            Parameters::Column::EncryptionKeyFp,
            Expr::value(Some(own.to_owned())),
        )
        .col_expr(
            Parameters::Column::RetiringKeyFp,
            Expr::value(current.clone()),
        )
        .filter(guard)
        .exec(db)
        .await?;

    // true when this node has won the race
    Ok(result.rows_affected > 0)
}

fn parsed_options(target: &Target::Model) -> Option<TargetOptions> {
    serde_json::from_value(target.options.clone())
        .map_err(|error| warn!(target = %target.name, %error, "Skipping a target with unreadable options"))
        .ok()
}

/// Display names of the rows whose credentials cannot be decrypted
async fn probe_undecryptable(db: &DatabaseConnection) -> Result<Vec<String>, WarpgateError> {
    let mut undecryptable = vec![];

    for target in Target::Entity::find().all(db).await? {
        if parsed_options(&target).is_some_and(|mut options| !options.all_decryptable()) {
            undecryptable.push(format!("target `{}`", target.name));
        }
    }

    for key in SshClientKey::Entity::find().all(db).await? {
        if !key.secret_key.clone().all_decryptable() {
            undecryptable.push(format!("SSH client key `{}`", key.label));
        }
    }

    for backend in SecretBackend::Entity::find().all(db).await? {
        if !backend.auth.clone().all_decryptable() {
            undecryptable.push(format!("secret backend `{}`", backend.name));
        }
    }

    let parameters = Parameters::Entity::get(db).await?;
    for (kind, key) in [
        (SshHostKeyKind::Ed25519, &parameters.ssh_host_key_ed25519),
        (SshHostKeyKind::Rsa, &parameters.ssh_host_key_rsa),
    ] {
        if key.reveal().is_err() {
            undecryptable.push(format!("SSH host key ({kind:?})"));
        }
    }

    Ok(undecryptable)
}

fn report_undecryptable(undecryptable: &[String], ring: &Keyring) {
    if undecryptable.is_empty() {
        return;
    }
    let list = undecryptable.join(", ");
    let count = undecryptable.len();
    error!("Could not decrypt stored credentials for: {list}");
    emit_runtime_warning(match ring.primary() {
        Some(key) => format!(
            "{count} stored credential(s) were encrypted with a key other than the current `WARPGATE_ENCRYPTION_KEY` ({}) and cannot be used: {list}",
            key.fingerprint(),
        ),
        None => format!(
            "{count} stored credential(s) are encrypted, but `WARPGATE_ENCRYPTION_KEY` is not set, so those targets cannot be connected to: {list}"
        ),
    });
}

async fn rewrite_all(db: &DatabaseConnection) -> Result<usize, WarpgateError> {
    let mut rewritten = 0;

    for target in Target::Entity::find().all(db).await? {
        let Some(mut options) = parsed_options(&target) else {
            continue;
        };
        if matches!(options.reencrypt_all(), Ok(true)) {
            let mut model: Target::ActiveModel = target.into();
            model.options = Set(serde_json::to_value(options)?);
            rewritten += update_unless_deleted(model.update(db).await)?;
        }
    }

    for key in SshClientKey::Entity::find().all(db).await? {
        let mut secret_key = key.secret_key.clone();
        if matches!(secret_key.reencrypt_all(), Ok(true)) {
            let mut model: SshClientKey::ActiveModel = key.into();
            model.secret_key = Set(secret_key);
            rewritten += update_unless_deleted(model.update(db).await)?;
        }
    }

    for backend in SecretBackend::Entity::find().all(db).await? {
        let mut auth = backend.auth.clone();
        if matches!(auth.reencrypt_all(), Ok(true)) {
            let mut model: SecretBackend::ActiveModel = backend.into();
            model.auth = Set(auth);
            rewritten += update_unless_deleted(model.update(db).await)?;
        }
    }

    let parameters = Parameters::Entity::get(db).await?;
    let mut model = Parameters::ActiveModel {
        id: Set(parameters.id),
        ..Default::default()
    };
    let mut changed = false;
    for (key, slot) in [
        (
            &parameters.ssh_host_key_ed25519,
            &mut model.ssh_host_key_ed25519,
        ),
        (&parameters.ssh_host_key_rsa, &mut model.ssh_host_key_rsa),
    ] {
        let mut key = key.clone();
        if matches!(key.reencrypt_all(), Ok(true)) {
            *slot = Set(key);
            changed = true;
        }
    }
    if changed {
        rewritten += update_unless_deleted(model.update(db).await)?;
    }

    Ok(rewritten)
}

fn update_unless_deleted<M>(result: Result<M, DbErr>) -> Result<usize, WarpgateError> {
    match result {
        Ok(_) => Ok(1),
        Err(DbErr::RecordNotUpdated) => Ok(0),
        Err(e) => Err(e.into()),
    }
}
