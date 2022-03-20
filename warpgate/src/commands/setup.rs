use anyhow::Result;
use tracing::*;

pub(crate) async fn command(cli: &crate::Cli) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    info!("Welcome to Warpgate {version}");

    if cli.config.exists() {
        error!("Config file already exists at {}.", cli.config.display());
        error!("To generate a new config file, rename or delete the existing one first.");
        std::process::exit(1);
    }

    Ok(())
}
