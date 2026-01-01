use std::io::{self, Write};

use chrono::Utc;
use serde::Serialize;
use serde_json::json;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

use super::values::{RecordVisitor, SerializedRecordValues};

#[derive(Serialize)]
struct JsonLogEntry {
    timestamp: String,
    level: &'static str,
    target: String,
    message: String,
    #[serde(flatten)]
    fields: SerializedRecordValues,
}

pub struct JsonConsoleLayer;

impl<S> Layer<S> for JsonConsoleLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        // Only log warpgate events (same filter as ValuesLogLayer)
        if !event.metadata().target().starts_with("warpgate") {
            return;
        }

        // Collect span fields (same pattern as ValuesLogLayer)
        let mut values = SerializedRecordValues::new();

        let current = ctx.current_span();
        let parent_id = event.parent().or_else(|| current.id());
        if let Some(parent_id) = parent_id {
            if let Some(span) = ctx.span(parent_id) {
                for span in span.scope().from_root() {
                    if let Some(other_values) = span.extensions().get::<SerializedRecordValues>() {
                        values.extend((*other_values).clone().into_iter());
                    }
                }
            }
        }

        // Record event fields
        event.record(&mut RecordVisitor::new(&mut values));

        // Extract message before moving values
        let message = values.remove("message").unwrap_or_default();

        let entry = JsonLogEntry {
            timestamp: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            level: level_to_str(event.metadata().level()),
            target: event.metadata().target().to_string(),
            message,
            fields: values,
        };

        // Serialize with fallback on error (Requirement 3.3)
        let json = match serde_json::to_string(&entry) {
            Ok(j) => j,
            Err(_) => {
                json!({
                    "timestamp": entry.timestamp,
                    "level": entry.level,
                    "target": entry.target,
                    "message": entry.message,
                    "_serialization_error": true
                })
                .to_string()
            }
        };

        let _ = writeln!(io::stdout(), "{}", json);
    }

    fn on_new_span(
        &self,
        attrs: &tracing_core::span::Attributes<'_>,
        id: &tracing_core::span::Id,
        ctx: Context<'_, S>,
    ) {
        // Store span values for later collection (same as ValuesLogLayer)
        let Some(span) = ctx.span(id) else { return };
        if !span.metadata().target().starts_with("warpgate") {
            return;
        }

        let mut values = SerializedRecordValues::new();
        attrs.record(&mut RecordVisitor::new(&mut values));
        span.extensions_mut().replace(values);
    }
}

pub fn make_json_console_logger_layer<S>() -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    JsonConsoleLayer
}

fn level_to_str(level: &Level) -> &'static str {
    match *level {
        Level::TRACE => "trace",
        Level::DEBUG => "debug",
        Level::INFO => "info",
        Level::WARN => "warn",
        Level::ERROR => "error",
    }
}
