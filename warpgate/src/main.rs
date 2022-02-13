#![feature(type_alias_impl_trait)]

use anyhow::Result;
use std::net::{ToSocketAddrs, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use time::{format_description, UtcOffset};
use tokio::sync::Mutex;
use tracing::*;
use tracing_subscriber::filter::dynamic_filter_fn;
use tracing_subscriber::fmt::time::OffsetTime;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

mod ssh;

use warpgate_common::State;
use crate::ssh::SSHProtocolServer;

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

    #[cfg(debug_assertions)]
    let console_layer = console_subscriber::spawn();

    #[cfg(debug_assertions)]
    let r = r.with(console_layer);

    r.with(fmt_layer).init();
}

#[tokio::main]
async fn main() -> Result<()> {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    init_logging();

    let state = State::new();
    let state = Arc::new(Mutex::new(state));

    tokio::spawn({
        let state = state.clone();
        async move {
            let admin = warpgate_admin::AdminServer::new(state);
            admin.run(SocketAddr::from_str("0.0.0.0:8888").unwrap()).await;
        }
    });

    let address = "0.0.0.0:2222".to_socket_addrs().unwrap().next().unwrap();
    SSHProtocolServer::new(state).run(address).await?;
    info!("Exiting");
    Ok(())
}
