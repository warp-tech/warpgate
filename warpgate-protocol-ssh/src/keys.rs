use std::fs::{create_dir_all, File};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use russh::keys::key::PrivateKeyWithHashAlg;
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

pub fn generate_host_keys(config: &WarpgateConfig) -> Result<()> {
    let path = get_keys_path(config);
    create_dir_all(&path)?;
    secure_directory(&path)?;

    let key_path = path.join("host-ed25519");
    if !key_path.exists() {
        info!("Generating Ed25519 host key");
        let key = PrivateKey::random(&mut get_crypto_rng(), russh::keys::Algorithm::Ed25519)
            .context("Failed to generate Ed25519 key")?;
        let f = File::create(&key_path)?;
        encode_pkcs8_pem(&key, f)?;
    }
    secure_file(&key_path)?;

    let key_path = path.join("host-rsa");
    if !key_path.exists() {
        info!("Generating RSA host key (this can take a bit)");
        let key = PrivateKey::random(
            &mut get_crypto_rng(),
            russh::keys::Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
        )
        .context("Failed to generate RSA key")?;
        let f = File::create(&key_path)?;
        encode_pkcs8_pem(&key, f)?;
    }
    secure_file(&key_path)?;

    Ok(())
}

pub fn load_host_keys(config: &WarpgateConfig) -> Result<PrivateKey, russh::keys::Error> {
    let path = get_keys_path(config);
    let mut keys = Vec::new();

    let key_path = path.join("host-ed25519");
    keys.push(load_secret_key(key_path, None)?);

    let key_path = path.join("host-rsa");

    load_secret_key(key_path, None)
}

pub fn generate_client_keys(config: &WarpgateConfig) -> Result<()> {
    let path = get_keys_path(config);
    create_dir_all(&path)?;
    secure_directory(&path)?;

    let key_path = path.join("client-ed25519");
    if !key_path.exists() {
        info!("Generating Ed25519 client key");
        let key = PrivateKey::random(&mut get_crypto_rng(), russh::keys::Algorithm::Ed25519)?;
        let f = File::create(&key_path)?;
        encode_pkcs8_pem(&key, f)?;
    }
    secure_file(&key_path)?;

    let key_path = path.join("client-rsa");
    if !key_path.exists() {
        info!("Generating RSA client key (this can take a bit)");
        let key = PrivateKey::random(
            &mut get_crypto_rng(),
            russh::keys::Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
        )
        .context("Failed to generate RSA key")?;
        let f = File::create(&key_path)?;
        encode_pkcs8_pem(&key, f)?;
    }
    secure_file(&key_path)?;

    Ok(())
}

pub fn load_client_keys(config: &WarpgateConfig) -> Result<Vec<PrivateKey>, russh::keys::Error> {
    let path = get_keys_path(config);
    let mut keys = Vec::new();

    let key_path: PathBuf = path.join("client-ed25519");
    keys.push(load_secret_key(key_path, None)?);

    let key_path = path.join("client-rsa");
    keys.push(load_secret_key(key_path, None)?);

    Ok(keys)
}

pub fn load_all_usable_private_keys(
    config: &WarpgateConfig,
    allow_insecure_algos: bool,
) -> Result<Vec<PrivateKeyWithHashAlg>, russh::keys::Error> {
    let mut keys = vec![];
    for key in load_client_keys(config)? {
        let key = Arc::new(key);
        if key.key_data().is_rsa() {
            for hash in &[Some(HashAlg::Sha512), Some(HashAlg::Sha256)] {
                keys.push(PrivateKeyWithHashAlg::new(key.clone(), *hash)?);
            }
            if allow_insecure_algos {
                keys.push(PrivateKeyWithHashAlg::new(key.clone(), None)?);
            }
        } else {
            keys.push(PrivateKeyWithHashAlg::new(key, None)?);
        }
    }
    Ok(keys)
}
