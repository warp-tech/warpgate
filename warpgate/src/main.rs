#![feature(type_alias_impl_trait, let_else)]
mod commands;
mod config;
use anyhow::Result;
use clap::StructOpt;
use futures::StreamExt;
use std::path::PathBuf;
use std::sync::Arc;
use time::{format_description, UtcOffset};
use tracing::*;
use tracing_subscriber::filter::dynamic_filter_fn;
use tracing_subscriber::fmt::time::OffsetTime;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

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

#[tokio::main]
async fn main() -> Result<()> {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    init_logging();

    let cli = Cli::parse();

    match &cli.command {
        Commands::Run => crate::commands::run::command(&cli).await,
        Commands::Hash => crate::commands::hash::command().await,
        Commands::Check => crate::commands::check::command(&cli).await,
        Commands::TestTarget { target_name } => {
            crate::commands::test_target::command(&cli, target_name).await
        }
    }
}
