#![feature(type_alias_impl_trait)]

use anyhow::Result;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use time::{format_description, UtcOffset};
use tracing::*;
use tracing_subscriber::filter::{dynamic_filter_fn, filter_fn};
use tracing_subscriber::fmt::time::OffsetTime;
use tracing_subscriber::layer::{Layered, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

mod misc;
mod ssh;

use crate::ssh::SSHProtocolServer;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[tokio::main]
async fn main() -> Result<()> {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info")
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

    let mut r = tracing_subscriber::registry();

    #[cfg(debug_assertions)]
    let console_layer = console_subscriber::spawn();

    #[cfg(debug_assertions)]
    let r = r.with(console_layer);

    r.with(fmt_layer).init();

    let address = "0.0.0.0:2222".to_socket_addrs().unwrap().next().unwrap();
    SSHProtocolServer::new().run(address).await?;
    info!("Exiting");
    Ok(())
}
