use std::fs::{create_dir_all, File};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use russh::keys::key::{KeyPair, SignatureHash};
use russh::keys::{encode_pkcs8_pem, load_secret_key};
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
        let key = KeyPair::generate_ed25519();
        let f = File::create(&key_path)?;
        encode_pkcs8_pem(&key, f)?;
    }
    secure_file(&key_path)?;

    let key_path = path.join("host-rsa");
    if !key_path.exists() {
        info!("Generating RSA host key");
        let key = KeyPair::generate_rsa(4096, SignatureHash::SHA2_512)
            .context("Failed to generate RSA key")?;
        let f = File::create(&key_path)?;
        encode_pkcs8_pem(&key, f)?;
    }
    secure_file(&key_path)?;

    Ok(())
}

pub fn load_host_keys(config: &WarpgateConfig) -> Result<Vec<KeyPair>, russh::keys::Error> {
    let path = get_keys_path(config);
    let mut keys = Vec::new();

    let key_path = path.join("host-ed25519");
    keys.push(load_and_maybe_resave_ed25519_key(key_path)?);

    let key_path = path.join("host-rsa");
    let key = load_secret_key(key_path, None)?;
    if let Some(key) = key.with_signature_hash(SignatureHash::SHA2_512) {
        keys.push(key)
    }
    if let Some(key) = key.with_signature_hash(SignatureHash::SHA2_256) {
        keys.push(key)
    }
    if let Some(key) = key.with_signature_hash(SignatureHash::SHA1) {
        keys.push(key)
    }

    Ok(keys)
}

pub fn generate_client_keys(config: &WarpgateConfig) -> Result<()> {
    let path = get_keys_path(config);
    create_dir_all(&path)?;
    secure_directory(&path)?;

    let key_path = path.join("client-ed25519");
    if !key_path.exists() {
        info!("Generating Ed25519 client key");
        let key = KeyPair::generate_ed25519();
        let f = File::create(&key_path)?;
        encode_pkcs8_pem(&key, f)?;
    }
    secure_file(&key_path)?;

    let key_path = path.join("client-rsa");
    if !key_path.exists() {
        info!("Generating RSA client key");
        let key = KeyPair::generate_rsa(4096, SignatureHash::SHA2_512)
            .context("Failed to generate RSA client key")?;
        let f = File::create(&key_path)?;
        encode_pkcs8_pem(&key, f)?;
    }
    secure_file(&key_path)?;

    Ok(())
}

pub fn load_client_keys(config: &WarpgateConfig) -> Result<Vec<KeyPair>, russh::keys::Error> {
    let path = get_keys_path(config);
    let mut keys = Vec::new();

    let key_path: PathBuf = path.join("client-ed25519");
    keys.push(load_and_maybe_resave_ed25519_key(key_path)?);

    let key_path = path.join("client-rsa");
    let key = load_secret_key(key_path, None)?;

    #[allow(clippy::unwrap_used)]
    {
        // unwrap only fails for non-RSA keys
        keys.push(key.with_signature_hash(SignatureHash::SHA2_512).unwrap());
        keys.push(key.with_signature_hash(SignatureHash::SHA2_256).unwrap());
        keys.push(key.with_signature_hash(SignatureHash::SHA1).unwrap());
    }

    Ok(keys)
}

/// russh 0.43 has a bug that generates incorrect PKCS#8 encoding for Ed25519 keys
/// This will preemptively try to correctly re-encode and save the key
fn load_and_maybe_resave_ed25519_key<P: AsRef<Path>>(p: P) -> Result<KeyPair, russh::keys::Error> {
    let key = load_secret_key(&p, None)?;
    if let KeyPair::Ed25519(_) = &key {
        if let Ok(f) = File::create(p) {
            if let Err(e) = encode_pkcs8_pem(&key, f) {
                error!("Failed to re-save the Ed25519 key: {e:?}");
            }
        }
    };
    Ok(key)
}
