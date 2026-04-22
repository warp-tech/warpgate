use std::fs::{create_dir_all, File};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use russh::keys::ssh_key::certificate;
use russh::keys::{encode_pkcs8_pem, load_secret_key, Certificate, HashAlg, PrivateKey, PublicKey};
use tracing::*;
use warpgate_common::helpers::fs::{secure_directory, secure_file};
use warpgate_common::helpers::rng::get_crypto_rng;
use warpgate_common::{GlobalParams, WarpgateConfig};

fn get_keys_path(config: &WarpgateConfig, params: &GlobalParams) -> PathBuf {
    let mut path = params.paths_relative_to().clone();
    path.push(&config.store.ssh.keys);
    path
}

pub fn generate_private(algo: russh::keys::Algorithm) -> Result<PrivateKey, russh::keys::Error> {
    Ok(PrivateKey::random(&mut get_crypto_rng(), algo)?)
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
            let key = generate_private(algo).context("Failed to generate key")?;
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

pub fn issue_temporary_client_certificate(
    user: &str,
    public_key: &PublicKey,
    signing_key: &PrivateKey,
    validity: Duration,
) -> Result<Certificate, russh::keys::Error> {
    // Backdate slightly to tolerate modest clock skew between Warpgate and targets.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| russh::keys::Error::SshKey(e.into()))?
        .as_secs();
    let valid_after = now.saturating_sub(30);
    let valid_before = now.saturating_add(validity.as_secs().max(1));

    let mut cert_builder = certificate::Builder::new_with_random_nonce(
        &mut get_crypto_rng(),
        public_key,
        valid_after,
        valid_before,
    )?;

    cert_builder.cert_type(certificate::CertType::User)?;
    cert_builder.valid_principal(user)?;
    cert_builder.extension("permit-agent-forwarding", "")?;
    cert_builder.extension("permit-port-forwarding", "")?;
    cert_builder.extension("permit-pty", "")?;
    cert_builder.extension("permit-X11-forwarding", "")?;

    Ok(cert_builder.sign(signing_key)?)
}

pub fn load_preferred_key(
    config: &WarpgateConfig,
    params: &GlobalParams,
    prefix: &str,
) -> Result<PrivateKey, russh::keys::Error> {
    let path = get_keys_path(config, params);
    load_secret_key(path.join(format!("{prefix}-ed25519")), None)
}
