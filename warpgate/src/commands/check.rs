use anyhow::Result;
use tracing::*;

use crate::config::load_config;

pub(crate) async fn command(cli: &crate::Cli) -> Result<()> {
    load_config(&cli.config, true)?;
    info!("No problems found");
    Ok(())
}
