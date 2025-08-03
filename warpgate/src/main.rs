mod commands;
mod config;
mod logging;
mod protocols;
use std::path::PathBuf;

use anyhow::Result;
use clap::{ArgAction, Parser};
use logging::init_logging;
use tracing::*;
use warpgate_common::version::warpgate_version;

use crate::config::load_config;

#[derive(clap::Parser)]
#[clap(author, about, long_about = None)]
pub struct Cli {
    #[clap(subcommand)]
    command: Commands,

    #[clap(long, short, default_value = "/etc/warpgate.yaml", action=ArgAction::Set)]
    config: PathBuf,

    #[clap(long, short, action=ArgAction::Count)]
    debug: u8,
}

#[derive(clap::Subcommand)]
pub(crate) enum Commands {
    /// Run first-time setup and generate a config file
    Setup {
        /// Database URL
        #[clap(long)]
        database_url: Option<String>,
    },
    /// Run first-time setup non-interactively
    UnattendedSetup {
        /// Database URL
        #[clap(long)]
        database_url: Option<String>,

        /// Directory to store data in
        #[clap(long)]
        data_path: String,

        /// HTTP port
        #[clap(long)]
        http_port: u16,

        /// Enable SSH and set port
        #[clap(long)]
        ssh_port: Option<u16>,

        /// Enable MySQL and set port
        #[clap(long)]
        mysql_port: Option<u16>,

        /// Enable PostgreSQL and set port
        #[clap(long)]
        postgres_port: Option<u16>,

        /// Enable session recording
        #[clap(long)]
        record_sessions: bool,

        /// Password for the initial user (required if WARPGATE_ADMIN_PASSWORD env var is not set)
        #[clap(long)]
        admin_password: Option<String>,

        /// External host used to construct URLs (without a port or scheme)
        #[clap(long)]
        external_host: Option<String>,
    },
    /// Show Warpgate's SSH client keys
    ClientKeys,
    /// Run Warpgate
    Run {
        /// Enable an API token (passed via the `WARPGATE_ADMIN_TOKEN` env var) that automatically maps to the first admin user
        #[clap(long, action=ArgAction::SetTrue)]
        enable_admin_token: bool,
    },
    /// Perform basic config checks
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
    /// Show version information
    Version,
}

async fn _main() -> Result<()> {
    let cli = Cli::parse();

    init_logging(load_config(&cli.config, false).ok().as_ref(), &cli).await;

    #[allow(clippy::unwrap_used)]
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    match &cli.command {
        Commands::Version => {
            println!("warpgate {}", warpgate_version());
            Ok(())
        }
        Commands::Run { enable_admin_token } => {
            crate::commands::run::command(&cli, *enable_admin_token).await
        }
        Commands::Check => crate::commands::check::command(&cli).await,
        Commands::TestTarget { target_name } => {
            crate::commands::test_target::command(&cli, target_name).await
        }
        Commands::Setup { .. } | Commands::UnattendedSetup { .. } => {
            crate::commands::setup::command(&cli).await
        }
        Commands::ClientKeys => crate::commands::client_keys::command(&cli).await,
        Commands::RecoverAccess { username } => {
            crate::commands::recover_access::command(&cli, username).await
        }
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = _main().await {
        error!(?error, "Fatal error");
        std::process::exit(1);
    }
}
