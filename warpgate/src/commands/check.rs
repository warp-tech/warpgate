use crate::config::load_config;
use anyhow::{Context, Result};

use futures::StreamExt;
use std::net::ToSocketAddrs;
use tracing::*;
use tracing_subscriber::Layer;

pub(crate) async fn command(cli: &crate::Cli) -> Result<()> {
    let config = load_config(&cli.config)?;
    config
        .store
        .ssh
        .listen
        .to_socket_addrs()
        .context("Failed to parse SSH listen address")?;
    config
        .store
        .web_admin
        .listen
        .to_socket_addrs()
        .context("Failed to parse admin server listen address")?;
    info!("No problems found");
    Ok(())
}
