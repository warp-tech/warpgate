#![feature(type_alias_impl_trait, let_else)]
use crate::config::load_config;
use anyhow::{Context, Result};
use clap::StructOpt;
use futures::StreamExt;
use std::io::stdin;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::sync::Arc;
use time::{format_description, UtcOffset};
use tracing::*;
use tracing_subscriber::filter::dynamic_filter_fn;
use tracing_subscriber::fmt::time::OffsetTime;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};
use warpgate_common::hash::hash_password;
use warpgate_common::{ProtocolServer, Services, Target, TargetTestError, WarpgateConfig};
use warpgate_protocol_ssh::SSHProtocolServer;

mod config;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[derive(clap::Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,

    #[clap(long, short)]
    config: PathBuf,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Run Warpgate
    Run,
    /// Create a password hash for use in the config file
    Hash,
    /// Validate config file
    Check,
    /// Test the connection to a target host
    TestTarget { target_name: String },
}

fn init_logging() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "warpgate=info")
    }

    let offset = UtcOffset::current_local_offset()
        .unwrap_or_else(|_| UtcOffset::from_whole_seconds(0).unwrap());

    let env_filter = Arc::new(EnvFilter::from_default_env());
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_timer(OffsetTime::new(
            offset,
            format_description::parse("[day].[month].[year] [hour]:[minute]:[second]").unwrap(),
        ))
        .with_filter(dynamic_filter_fn(move |m, c| {
            env_filter.enabled(m, c.clone())
        }));

    let r = tracing_subscriber::registry();

    #[cfg(all(debug_assertions, feature = "console-subscriber"))]
    let console_layer = console_subscriber::spawn();

    #[cfg(all(debug_assertions, feature = "console-subscriber"))]
    let r = r.with(console_layer);

    r.with(fmt_layer).init();
}

async fn cmd_run(config: WarpgateConfig) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    info!(%version, "Warpgate");

    let services = Services::new(config.clone()).await?;

    let mut other_futures = futures::stream::FuturesUnordered::new();
    let mut protocol_futures = futures::stream::FuturesUnordered::new();

    protocol_futures.push(
        SSHProtocolServer::new(&services).await?.run(
            config
                .store
                .ssh
                .listen
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| anyhow::anyhow!("Failed to resolve the listen address"))?,
        ),
    );

    if config.store.web_admin.enable {
        let admin = warpgate_admin::AdminServer::new(&services);
        let admin_future = admin.run(
            config
                .store
                .web_admin
                .listen
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| {
                    anyhow::anyhow!("Failed to resolve the listen address for the admin server")
                })?,
        );
        other_futures.push(admin_future);
    }

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                break
            }
            result = protocol_futures.next() => {
                match result {
                    Some(Err(error)) => {
                        error!(?error, "SSH server error");
                    },
                    None => break,
                    _ => (),
                }
            }
            result = other_futures.next(), if !other_futures.is_empty() => {
                match result {
                    Some(Err(error)) => {
                        error!(?error, "Error");
                    },
                    None => break,
                    _ => (),
                }
            }
        }
    }

    info!("Exiting");
    Ok(())
}

async fn cmd_hash() -> Result<()> {
    let mut input = String::new();

    if atty::is(atty::Stream::Stdin) {
        input = dialoguer::Password::new()
            .with_prompt("Password to be hashed")
            .interact()?;
    } else {
        stdin().read_line(&mut input)?;
    }

    let hash = hash_password(&input);
    println!("{}", hash);
    Ok(())
}

async fn cmd_check(config: WarpgateConfig) -> Result<()> {
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

async fn cmd_test_target(config: WarpgateConfig, target_name: &String) -> Result<()> {
    let Some(target) = config
        .store
        .targets
        .iter()
        .find(|x| &x.name == target_name)
        .map(Target::clone) else {
        error!("Target not found: {}", target_name);
        return Ok(());
    };

    let services = Services::new(config.clone()).await?;

    let s = warpgate_protocol_ssh::SSHProtocolServer::new(&services).await?;
    match s.test_target(target).await {
        Err(TargetTestError::AuthenticationError) => {
            error!("Authentication failed");
        }
        Err(TargetTestError::ConnectionError(error)) => {
            error!(?error, "Connection error");
        }
        Err(TargetTestError::Io(error)) => {
            error!(?error, "I/O error");
        }
        Err(TargetTestError::Misconfigured(error)) => {
            error!(?error, "Misconfigured");
        }
        Err(TargetTestError::Unreachable) => {
            error!("Target is unreachable");
        }
        Ok(()) => {
            info!("Connection successful!");
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    init_logging();

    let cli = Cli::parse();
    let config = load_config(&cli.config)?;

    match &cli.command {
        Commands::Run => cmd_run(config).await,
        Commands::Hash => cmd_hash().await,
        Commands::Check => cmd_check(config).await,
        Commands::TestTarget { target_name } => cmd_test_target(config, target_name).await,
    }
}
