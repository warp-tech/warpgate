use std::sync::Arc;
use time::{format_description, UtcOffset};
use tracing_subscriber::filter::dynamic_filter_fn;
use tracing_subscriber::fmt::time::OffsetTime;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

pub fn init_logging() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "warpgate=info")
    }

    let offset = UtcOffset::current_local_offset()
        .unwrap_or_else(|_| UtcOffset::from_whole_seconds(0).unwrap());

    let env_filter = Arc::new(EnvFilter::from_default_env());
    let enable_colors = console::user_attended();

    let full_fmt_layer = {
        let env_filter = env_filter.clone();
        tracing_subscriber::fmt::layer()
            .with_ansi(enable_colors)
            .with_timer(OffsetTime::new(
                offset,
                format_description::parse("[day].[month].[year] [hour]:[minute]:[second]").unwrap(),
            ))
            .with_filter(dynamic_filter_fn(move |m, c| {
                env_filter.enabled(m, c.clone())
            }))
    };
    let compact_fmt_layer = {
        tracing_subscriber::fmt::layer()
            .compact()
            .with_ansi(enable_colors)
            .with_target(false)
            .with_timer(OffsetTime::new(
                offset,
                format_description::parse("[hour]:[minute]:[second]").unwrap(),
            ))
            .with_filter(dynamic_filter_fn(move |m, c| {
                env_filter.enabled(m, c.clone())
            }))
    };
    let r = tracing_subscriber::registry();

    #[cfg(all(debug_assertions, feature = "console-subscriber"))]
    let console_layer = console_subscriber::spawn();
    #[cfg(all(debug_assertions, feature = "console-subscriber"))]
    let r = r.with(console_layer);

    let r = r.with(if !console::user_attended() {
        Some(full_fmt_layer)
    } else {
        None
    });
    let r = r.with(if console::user_attended() {
        Some(compact_fmt_layer)
    } else {
        None
    });

    r.init();
}
