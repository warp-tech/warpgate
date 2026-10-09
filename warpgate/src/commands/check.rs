use anyhow::{Context, Result};
use tracing::info;
use warpgate_common::GlobalParams;
use warpgate_tls::{TlsCertificateBundle, TlsPrivateKey};

use crate::config::load_config;

pub async fn command(params: &GlobalParams) -> Result<()> {
    let config = load_config(params, true)?;
    TlsCertificateBundle::from_file(
        params
            .paths_relative_to()
            .join(&config.store.http.certificate),
    )
    .await
    .with_context(|| "Checking HTTPS certificate".to_string())?;
    TlsPrivateKey::from_file(params.paths_relative_to().join(&config.store.http.key))
        .await
        .with_context(|| "Checking HTTPS key".to_string())?;
    if config.store.mysql.enable {
        TlsCertificateBundle::from_file(
            params
                .paths_relative_to()
                .join(&config.store.mysql.certificate),
        )
        .await
        .with_context(|| "Checking MySQL certificate".to_string())?;
        TlsPrivateKey::from_file(params.paths_relative_to().join(&config.store.mysql.key))
            .await
            .with_context(|| "Checking MySQL key".to_string())?;
    }
    if config.store.postgres.enable {
        TlsCertificateBundle::from_file(
            params
                .paths_relative_to()
                .join(&config.store.postgres.certificate),
        )
        .await
        .with_context(|| "Checking PostgreSQL certificate".to_string())?;
        TlsPrivateKey::from_file(params.paths_relative_to().join(&config.store.postgres.key))
            .await
            .with_context(|| "Checking PostgreSQL key".to_string())?;
    }
    // The command whose whole job is finding a broken config must look at
    // `vault:`: an unusable one stops every certificate session. Constructed
    // and dropped — building the client is the validation.
    if let Some(vault) = config.store.vault.clone() {
        let client = warpgate_vault::VaultClient::new(vault)
            .with_context(|| "Checking Vault configuration")?;
        // Construction validates the address, mount and role names. The
        // credential file is read per login, not at construction, so a typo in
        // `token_path` or `secret_id_path` passed this check and then failed
        // every certificate session — the failure this command exists to catch
        // early, and the one thing it was not catching.
        client
            .check_credential()
            .await
            .with_context(|| "Checking the Vault credential")?;
    }

    info!("No problems found");
    Ok(())
}
