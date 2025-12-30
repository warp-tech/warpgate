use anyhow::{Context, Result};
use tracing::*;
use warpgate_common::GlobalParams;
use warpgate_tls::{TlsCertificateBundle, TlsPrivateKey};

use crate::config::load_config;

pub(crate) async fn command(params: &GlobalParams) -> Result<()> {
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
    info!("No problems found");
    Ok(())
}
