#![feature(type_alias_impl_trait, let_else)]
use anyhow::Result;
use std::net::{SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::Arc;
use time::{format_description, UtcOffset};
use tracing::*;
use tracing_subscriber::filter::dynamic_filter_fn;
use tracing_subscriber::fmt::time::OffsetTime;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

mod compat;
mod config;
mod ssh;

use crate::config::load_config;
use crate::ssh::SSHProtocolServer;
use warpgate_common::Services;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn init_logging() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "warpgate=info")
    }

    let offset =
        UtcOffset::current_local_offset().unwrap_or(UtcOffset::from_whole_seconds(0).unwrap());

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

    let version = env!("CARGO_PKG_VERSION");
    info!(%version, "Warpgate");

    let services = Services::new(load_config()?).await?;

    let admin = warpgate_admin::AdminServer::new(&services);

    let address = "0.0.0.0:2222".to_socket_addrs().unwrap().next().unwrap();

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        result = SSHProtocolServer::new(&services).run(address) => {
            if let Err(error) = result {
                error!(?error, "SSH server error");
            }
        }
        result = admin.run(SocketAddr::from_str("0.0.0.0:8888").unwrap()) => {
            if let Err(error) = result {
                error!(?error, "Admin server error");
            }
        }
    }

    info!("Exiting");
    Ok(())
}
