use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

use super::values::{RecordVisitor, SerializedRecordValues, collect_event_values};

pub struct ValuesLogLayer<C>
where
    C: Fn(SerializedRecordValues, String),
{
    callback: C,
}

impl<C> ValuesLogLayer<C>
where
    C: Fn(SerializedRecordValues, String),
{
    pub const fn new(callback: C) -> Self {
        Self { callback }
    }
}

impl<C, S> tracing_subscriber::Layer<S> for ValuesLogLayer<C>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    C: Fn(SerializedRecordValues, String),
    Self: 'static,
{
    fn on_new_span(
        &self,
        attrs: &tracing_core::span::Attributes<'_>,
        id: &tracing_core::span::Id,
        ctx: Context<'_, S>,
    ) {
        let Some(span) = ctx.span(id) else { return };
        if !is_warpgate_target(span.metadata()) {
            return;
        }

        let mut values = SerializedRecordValues::new();
        attrs.record(&mut RecordVisitor::new(&mut values));
        span.extensions_mut().replace(values);
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        if !is_warpgate_target(event.metadata()) {
            return;
        }
        if event.metadata().level() > &Level::INFO {
            return;
        }

        let values = collect_event_values(event, &ctx);

        (self.callback)(values, event.metadata().target().to_string());
    }
}

fn is_warpgate_target(md: &'static Metadata<'static>) -> bool {
    let target = md.target();
    target.starts_with("warpgate") || target == "audit"
}
