use std::fs::{create_dir_all, File};
use std::path::PathBuf;

use anyhow::{Context, Result};
use russh::keys::{encode_pkcs8_pem, load_secret_key, HashAlg, PrivateKey};
use tracing::*;
use warpgate_common::helpers::fs::{secure_directory, secure_file};
use warpgate_common::helpers::rng::get_crypto_rng;
use warpgate_common::WarpgateConfig;

fn get_keys_path(config: &WarpgateConfig) -> PathBuf {
    let mut path = config.paths_relative_to.clone();
    path.push(&config.store.ssh.keys);
    path
}

pub fn generate_keys(config: &WarpgateConfig, prefix: &str) -> Result<()> {
    let path = get_keys_path(config);
    create_dir_all(&path)?;
    secure_directory(&path)?;

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
        secure_file(&key_path)?;
    }

    Ok(())
}

pub fn load_keys(config: &WarpgateConfig, prefix: &str) -> Result<Vec<PrivateKey>, russh::keys::Error> {
    let path = get_keys_path(config);
    Ok(vec![
        load_secret_key(path.join(format!("{prefix}-ed25519")), None)?,
        load_secret_key(path.join(format!("{prefix}-rsa")), None)?,
    ])
}
