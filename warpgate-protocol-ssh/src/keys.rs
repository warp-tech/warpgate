use anyhow::Result;
use russh_keys::key::{KeyPair, SignatureHash};
use russh_keys::{encode_pkcs8_pem, load_secret_key};
use std::fs::{create_dir_all, File};
use std::path::PathBuf;
use tracing::*;
use warpgate_common::helpers::fs::secure_directory;
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
        let key = KeyPair::generate_ed25519().unwrap();
        let f = File::create(key_path)?;
        encode_pkcs8_pem(&key, f)?;
    }

    let key_path = path.join("host-rsa");
    if !key_path.exists() {
        info!("Generating RSA host key");
        let key = KeyPair::generate_rsa(4096, SignatureHash::SHA2_512).unwrap();
        let f = File::create(key_path)?;
        encode_pkcs8_pem(&key, f)?;
    }

    Ok(())
}

pub fn load_host_keys(config: &WarpgateConfig) -> Result<Vec<KeyPair>> {
    let path = get_keys_path(config);
    let mut keys = Vec::new();

    let key_path = path.join("host-ed25519");
    keys.push(load_secret_key(key_path, None)?);

    let key_path = path.join("host-rsa");
    keys.push(load_secret_key(key_path, None)?);

    Ok(keys)
}
