mod commands;
mod config;
mod logging;

use std::path::PathBuf;

use anyhow::Result;
use clap::{ArgAction, Parser};
use logging::init_logging;
use tracing::*;
use warpgate_common::version::warpgate_version;
use warpgate_common::{GlobalParams, LogFormat, Secret};

use crate::config::load_config;

#[derive(clap::Parser)]
#[clap(author, about, long_about = None)]
pub struct Cli {
    #[clap(subcommand)]
    command: Commands,

    #[clap(long, short, default_value = "/etc/warpgate.yaml", action=ArgAction::Set, env="WARPGATE_CONFIG")]
    config: PathBuf,

    #[clap(long, short, action=ArgAction::Count)]
    debug: u8,

    /// Log output format (text or json)
    #[clap(long, value_enum)]
    log_format: Option<LogFormat>,

    /// Do not tighten UNIX modes of config and data files
    #[clap(long)]
    skip_securing_files: bool,
}

impl Cli {
    #[allow(clippy::wrong_self_convention)]
    pub fn into_global_params(&self) -> anyhow::Result<GlobalParams> {
        warpgate_common::GlobalParams::new(self.config.clone(), !self.skip_securing_files)
    }
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

        /// Enable Kubernetes and set port
        #[clap(long)]
        kubernetes_port: Option<u16>,

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
    /// Create a new user
    CreateUser {
        #[clap(action=ArgAction::Set)]
        username: String,
        /// Password (required if WARPGATE_NEW_USER_PASSWORD env var is not set)
        #[clap(short, long, action=ArgAction::Set)]
        password: Option<String>,
        #[clap(short, long, action=ArgAction::Set)]
        role: Option<String>,
    },
    /// Reset password and auth policy for a user
    RecoverAccess {
        #[clap(action=ArgAction::Set)]
        username: Option<String>,
    },
    /// Show version information
    Version,
    /// Automatic healthcheck for running Warpgate in a container
    Healthcheck,
}

async fn _main() -> Result<()> {
    let cli = Cli::parse();
    let params = cli.into_global_params()?;

    init_logging(load_config(&params, false).ok().as_ref(), &cli).await?;

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
            crate::commands::run::command(&params, *enable_admin_token).await
        }
        Commands::Check => crate::commands::check::command(&params).await,
        Commands::CreateUser {
            username,
            password: explicit_password,
            role,
        } => {
            #[allow(clippy::collapsible_else_if)]
            let password = if let Some(p) = explicit_password {
                p.to_owned()
            } else {
                if let Ok(p) = std::env::var("WARPGATE_NEW_USER_PASSWORD") {
                    p
                } else {
                    error!("You must supply the password either through the --password option");
                    error!("or the WARPGATE_NEW_USER_PASSWORD environment variable.");
                    std::process::exit(1);
                }
            };

            crate::commands::create_user::command(
                &params,
                username,
                &Secret::new(password.clone()),
                role,
            )
            .await
        }
        Commands::Setup { .. } | Commands::UnattendedSetup { .. } => {
            crate::commands::setup::command(&cli, &params).await
        }
        Commands::ClientKeys => crate::commands::client_keys::command(&params).await,
        Commands::RecoverAccess { username } => {
            crate::commands::recover_access::command(&params, username).await
        }
        Commands::Healthcheck => crate::commands::healthcheck::command(&params).await,
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = _main().await {
        error!(?error, "Fatal error");
        std::process::exit(1);
    }
}
