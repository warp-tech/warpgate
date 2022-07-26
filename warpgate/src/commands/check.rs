use anyhow::{Context, Result};
use tracing::*;
use warpgate_common::{TlsCertificateBundle, TlsPrivateKey};

use crate::config::load_config;

pub(crate) async fn command(cli: &crate::Cli) -> Result<()> {
    let config = load_config(&cli.config, true)?;
    if config.store.http.enable {
        TlsCertificateBundle::from_file(
            config
                .paths_relative_to
                .join(&config.store.http.certificate),
        )
        .await
        .with_context(|| format!("Checking HTTPS certificate"))?;
        TlsPrivateKey::from_file(config.paths_relative_to.join(&config.store.http.key))
            .await
            .with_context(|| format!("Checking HTTPS key"))?;
    }
    if config.store.mysql.enable {
        TlsCertificateBundle::from_file(
            config
                .paths_relative_to
                .join(&config.store.mysql.certificate),
        )
        .await
        .with_context(|| format!("Checking MySQL certificate"))?;
        TlsPrivateKey::from_file(config.paths_relative_to.join(&config.store.mysql.key))
            .await
            .with_context(|| format!("Checking MySQL key"))?;
    }
    info!("No problems found");
    Ok(())
}
