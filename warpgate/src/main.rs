#![feature(type_alias_impl_trait, let_else)]
mod commands;
mod config;
mod logging;
use crate::config::load_config;
use anyhow::Result;
use clap::StructOpt;
use logging::init_logging;
use std::path::PathBuf;
use tracing::*;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[derive(clap::Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,

    #[clap(long, short, default_value = "/etc/warpgate.yaml")]
    config: PathBuf,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Run first-time setup and generate a config file
    Setup,
    /// Show Warpgate's SSH client keys
    ClientKeys,
    /// Run Warpgate
    Run,
    /// Create a password hash for use in the config file
    Hash,
    /// Validate config file
    Check,
    /// Test the connection to a target host
    TestTarget { target_name: String },
    /// Generate a new 2FA (TOTP) enrollment key
    GenerateOtp,
}

async fn _main() -> Result<()> {
    let cli = Cli::parse();

    init_logging(load_config(&cli.config, false).ok().as_ref()).await;

    match &cli.command {
        Commands::Run => crate::commands::run::command(&cli).await,
        Commands::Hash => crate::commands::hash::command().await,
        Commands::Check => crate::commands::check::command(&cli).await,
        Commands::TestTarget { target_name } => {
            crate::commands::test_target::command(&cli, target_name).await
        }
        Commands::Setup => crate::commands::setup::command(&cli).await,
        Commands::ClientKeys => crate::commands::client_keys::command(&cli).await,
        Commands::GenerateOtp => crate::commands::otp::command().await,
    }
}

#[tokio::main]
async fn main() {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    if let Err(error) = _main().await {
        error!(?error, "Fatal error");
        std::process::exit(1);
    }
}
