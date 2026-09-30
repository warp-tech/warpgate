use std::sync::Arc;

use anyhow::{Context, Result};
use time::{UtcOffset, format_description};
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
        #[allow(unsafe_code)]
        unsafe {
            match cli.debug {
                0 => std::env::set_var("RUST_LOG", "audit=info,warpgate=info"),
                1 => std::env::set_var("RUST_LOG", "audit=info,warpgate=debug"),
                2 => std::env::set_var("RUST_LOG", "audit=info,warpgate=debug,russh=debug"),
                _ => std::env::set_var("RUST_LOG", "debug"),
            }
        }
    }

    LogTracer::init().context("Failed to initialize log compatibility layer")?;

    let offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);

    // The AWS SDK logs the credentials it resolved — including the access key ID —
    // at INFO. That is never worth having in Warpgate's log, so it is filtered out
    // regardless of what RUST_LOG asks for; a target-specific directive outranks a
    // broad one like `debug`.
    //
    // Four crates, not one. `aws_config` was silenced and the crates underneath it
    // were not, which is the same half-applied shape as fixing one call site of a
    // sanitiser: `aws_smithy_runtime` redacts headers but prints response bodies
    // verbatim through the SDK's `Debug`, so at `RUST_LOG=trace` an IMDS or
    // container credential response — secret key and session token included —
    // lands in the log file. Reachable only at trace, which is the setting an
    // operator turns on precisely when a session will not connect, and the output
    // most likely to be pasted into an issue.
    let env_filter = Arc::new(
        [
            "aws_config",
            "aws_smithy_runtime",
            "aws_smithy_runtime_api",
            "aws_credential_types",
        ]
        .into_iter()
        .try_fold(EnvFilter::from_default_env(), |filter, crate_name| {
            Ok::<_, anyhow::Error>(filter.add_directive(format!("{crate_name}=warn").parse()?))
        })?,
    );
    let enable_colors = console::user_attended();

    // Determine effective log format (CLI overrides config)
    let log_format = cli
        .log_format
        .or_else(|| config.map(|c| c.store.log.format))
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
                        format_description::parse_borrowed::<1>(
                            "[day].[month].[year] [hour]:[minute]:[second]",
                        )
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
                    format_description::parse_borrowed::<1>("[hour]:[minute]:[second]").unwrap(),
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
