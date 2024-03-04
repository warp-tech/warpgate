use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

use super::values::{RecordVisitor, SerializedRecordValues};

pub struct ValuesLogLayer<C>
where
    C: Fn(SerializedRecordValues),
{
    callback: C,
}

impl<C> ValuesLogLayer<C>
where
    C: Fn(SerializedRecordValues),
{
    pub fn new(callback: C) -> Self {
        Self { callback }
    }
}

impl<C, S> tracing_subscriber::Layer<S> for ValuesLogLayer<C>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    C: Fn(SerializedRecordValues),
    Self: 'static,
{
    fn on_new_span(
        &self,
        attrs: &tracing_core::span::Attributes<'_>,
        id: &tracing_core::span::Id,
        ctx: Context<'_, S>,
    ) {
        let Some(span) = ctx.span(id) else { return };
        if !span.metadata().target().starts_with("warpgate") {
            return;
        }

        let mut values = SerializedRecordValues::new();
        attrs.record(&mut RecordVisitor::new(&mut values));
        span.extensions_mut().replace(values);
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        if !event.metadata().target().starts_with("warpgate") {
            return;
        }
        if event.metadata().level() > &Level::INFO {
            return;
        }

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

        event.record(&mut RecordVisitor::new(&mut values));

        (self.callback)(values);
    }
}
