use std::fs::{create_dir_all, File};
use std::path::PathBuf;

use anyhow::{Context, Result};
use russh::keys::ssh_key::rand_core::OsRng;
use russh::keys::{encode_pkcs8_pem, load_secret_key, Algorithm, HashAlg, PrivateKey};
use tracing::*;
use warpgate_common::helpers::fs::{secure_directory, secure_file};
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
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .context("Failed to generate Ed25519 key")?;
        let f = File::create(&key_path)?;
        encode_pkcs8_pem(&key, f)?;
    }
    secure_file(&key_path)?;

    let key_path = path.join("host-rsa");
    if !key_path.exists() {
        info!("Generating RSA host key (this can take a bit)");
        let key = PrivateKey::random(
            &mut OsRng,
            Algorithm::Rsa {
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

pub fn load_host_keys(config: &WarpgateConfig) -> Result<Vec<PrivateKey>, russh::keys::Error> {
    let path = get_keys_path(config);
    let mut keys = Vec::new();

    let key_path = path.join("host-ed25519");
    keys.push(load_secret_key(key_path, None)?);

    let key_path = path.join("host-rsa");
    keys.push(load_secret_key(key_path, None)?);

    Ok(keys)
}

pub fn generate_client_keys(config: &WarpgateConfig) -> Result<()> {
    let path = get_keys_path(config);
    create_dir_all(&path)?;
    secure_directory(&path)?;

    let key_path = path.join("client-ed25519");
    if !key_path.exists() {
        info!("Generating Ed25519 client key");
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .context("Failed to generate Ed25519 client key")?;
        let f = File::create(&key_path)?;
        encode_pkcs8_pem(&key, f)?;
    }
    secure_file(&key_path)?;

    let key_path = path.join("client-rsa");
    if !key_path.exists() {
        info!("Generating RSA client key (this can take a bit)");
        let key = PrivateKey::random(
            &mut OsRng,
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
        )
        .context("Failed to generate RSA client key")?;
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
