#![feature(type_alias_impl_trait, let_else)]
mod commands;
mod config;
mod logging;
use std::path::PathBuf;

use anyhow::Result;
use clap::{ArgAction, StructOpt};
use logging::init_logging;
use tracing::*;

use crate::config::load_config;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[derive(clap::Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
pub struct Cli {
    #[clap(subcommand)]
    command: Commands,

    #[clap(long, short, default_value = "/etc/warpgate.yaml", action=ArgAction::Set)]
    config: PathBuf,

    #[clap(long, short, action=ArgAction::Count)]
    debug: u8,
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
    Check,
    /// Test the connection to a target host
    TestTarget {
        #[clap(action=ArgAction::Set)]
        target_name: String,
    },
    /// Reset password and auth policy for a user
    RecoverAccess {
        #[clap(action=ArgAction::Set)]
        username: Option<String>,
    },
}

async fn _main() -> Result<()> {
    let cli = Cli::parse();

    init_logging(load_config(&cli.config, false).ok().as_ref(), &cli).await;

    match &cli.command {
        Commands::Run => crate::commands::run::command(&cli).await,
        Commands::Check => crate::commands::check::command(&cli).await,
        Commands::TestTarget { target_name } => {
            crate::commands::test_target::command(&cli, target_name).await
        }
        Commands::Setup => crate::commands::setup::command(&cli).await,
        Commands::ClientKeys => crate::commands::client_keys::command(&cli).await,
        Commands::RecoverAccess { username } => {
            crate::commands::recover_access::command(&cli, username).await
        }
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
