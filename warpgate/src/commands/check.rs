use crate::config::load_config;
use anyhow::{Context, Result};
use std::net::ToSocketAddrs;
use tracing::*;

pub(crate) async fn command(cli: &crate::Cli) -> Result<()> {
    let config = load_config(&cli.config, true)?;
    config
        .store
        .ssh
        .listen
        .to_socket_addrs()
        .context("Failed to parse SSH listen address")?;
    config
        .store
        .http
        .listen
        .to_socket_addrs()
        .context("Failed to parse admin server listen address")?;
    info!("No problems found");
    Ok(())
}
