use std::sync::Arc;

use anyhow::{Context, Result};
use time::{format_description, UtcOffset};
use tracing_log::LogTracer;
use tracing_subscriber::filter::dynamic_filter_fn;
use tracing_subscriber::fmt::time::OffsetTime;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};
use warpgate_common::{LogFormat, WarpgateConfig};
use warpgate_core::logging::{
    make_database_logger_layer, make_json_console_logger_layer, make_socket_logger_layer,
};

use crate::Cli;

pub async fn init_logging(config: Option<&WarpgateConfig>, cli: &Cli) -> Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        match cli.debug {
            0 => std::env::set_var("RUST_LOG", "warpgate=info"),
            1 => std::env::set_var("RUST_LOG", "warpgate=debug"),
            2 => std::env::set_var("RUST_LOG", "warpgate=debug,russh=debug"),
            _ => std::env::set_var("RUST_LOG", "debug"),
        }
    }

    LogTracer::init().context("Failed to initialize log compatibility layer")?;

    let offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);

    let env_filter = Arc::new(EnvFilter::from_default_env());
    let enable_colors = console::user_attended();

    // Determine effective log format (CLI overrides config)
    let log_format = cli
        .log_format
        .or(config.map(|c| c.store.log.format))
        .unwrap_or_default();

    let registry = tracing_subscriber::registry();

    // #[cfg(all(debug_assertions, feature = "tokio-console"))]
    // let console_layer = console_subscriber::spawn();
    // #[cfg(all(debug_assertions, feature = "tokio-console"))]
    // let registry = registry.with(console_layer);

    let socket_layer = match config {
        Some(config) => Some(make_socket_logger_layer(config).await),
        None => None,
    };

    // Create JSON console layer (only active when format is JSON)
    let json_layer = (log_format == LogFormat::Json).then(|| {
        let env_filter = env_filter.clone();
        make_json_console_logger_layer().with_filter(dynamic_filter_fn(move |m, c| {
            env_filter.enabled(m, c.clone())
        }))
    });

    // Create text console layers (only active when format is Text)
    let text_layer_non_interactive = (log_format == LogFormat::Text && !console::user_attended())
        .then({
            let env_filter = env_filter.clone();
            || {
                tracing_subscriber::fmt::layer()
                    .with_ansi(enable_colors)
                    .with_timer(OffsetTime::new(
                        offset,
                        #[allow(clippy::unwrap_used)]
                        format_description::parse("[day].[month].[year] [hour]:[minute]:[second]")
                            .unwrap(),
                    ))
                    .with_filter(dynamic_filter_fn(move |m, c| {
                        env_filter.enabled(m, c.clone())
                    }))
            }
        });

    let text_layer_interactive =
        (log_format == LogFormat::Text && console::user_attended()).then(|| {
            tracing_subscriber::fmt::layer()
                .compact()
                .with_ansi(enable_colors)
                .with_target(false)
                .with_timer(OffsetTime::new(
                    offset,
                    #[allow(clippy::unwrap_used)]
                    format_description::parse("[hour]:[minute]:[second]").unwrap(),
                ))
                .with_filter(dynamic_filter_fn(move |m, c| {
                    env_filter.enabled(m, c.clone())
                }))
        });

    let registry = registry
        .with(json_layer)
        .with(text_layer_non_interactive)
        .with(text_layer_interactive);

    let registry = registry
        .with(make_database_logger_layer())
        .with(socket_layer);

    registry.init();
    Ok(())
}
