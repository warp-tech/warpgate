use std::sync::Arc;

use time::{format_description, UtcOffset};
use tracing_subscriber::filter::dynamic_filter_fn;
use tracing_subscriber::fmt::time::OffsetTime;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};
use warpgate_common::WarpgateConfig;
use warpgate_core::logging::{make_database_logger_layer, make_socket_logger_layer};

pub async fn init_logging(config: Option<&WarpgateConfig>) {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "warpgate=info")
    }

    let offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);

    let env_filter = Arc::new(EnvFilter::from_default_env());
    let enable_colors = console::user_attended();

    let registry = tracing_subscriber::registry();

    #[cfg(all(debug_assertions, feature = "console-subscriber"))]
    let console_layer = console_subscriber::spawn();
    #[cfg(all(debug_assertions, feature = "console-subscriber"))]
    let registry = registry.with(console_layer);

    let socket_layer = match config {
        Some(config) => Some(make_socket_logger_layer(config).await),
        None => None,
    };

    let registry = registry
        .with((!console::user_attended()).then({
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
        }))
        .with(console::user_attended().then({
            || {
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
            }
        }))
        .with(make_database_logger_layer())
        .with(socket_layer);

    registry.init();
}
