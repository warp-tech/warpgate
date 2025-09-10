use anyhow::{Context, Result};
use tokio::time::timeout;

use crate::config::load_config;

pub(crate) async fn command(cli: &crate::Cli) -> Result<()> {
    let config = load_config(&cli.config, true)?;

    let url = format!(
        "https://{}/@warpgate/api/info",
        config.store.http.listen.address()
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .use_rustls_tls()
        .build()?;

    let response = timeout(std::time::Duration::from_secs(5), client.get(&url).send())
        .await
        .context("Timeout")?
        .context("Failed to send request")?;

    response.error_for_status()?;

    Ok(())
}
