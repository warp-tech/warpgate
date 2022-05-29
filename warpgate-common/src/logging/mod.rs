mod database;
mod values;

use once_cell::sync::OnceCell;
use sea_orm::{ActiveModelTrait, DatabaseConnection};
use std::fmt::Write;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::*;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use uuid::Uuid;
use warpgate_db_entities::LogEntry;

use self::values::{RecordVisitor, SerializedRecordValues};

static LOG_SENDER: OnceCell<tokio::sync::broadcast::Sender<LogEntry::ActiveModel>> =
    OnceCell::new();

pub struct DatabaseLogger {}

impl DatabaseLogger {
    pub fn new() -> Self {
        let _ = LOG_SENDER.set(tokio::sync::broadcast::channel(1024).0);
        Self {}
    }
}

pub fn install_database_logger(database: Arc<Mutex<DatabaseConnection>>) {
    tokio::spawn(async move {
        let mut receiver = LOG_SENDER.get().unwrap().subscribe();
        loop {
            match receiver.recv().await {
                Err(_) => break,
                Ok(log_entry) => {
                    let database = database.lock().await;
                    if let Err(error) = log_entry.insert(&*database).await {
                        error!(?error, "Failed to store log entry");
                    }
                }
            }
        }
    });
}

impl<S> tracing_subscriber::Layer<S> for DatabaseLogger
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    Self: 'static,
{
    fn on_new_span(
        &self,
        attrs: &tracing_core::span::Attributes<'_>,
        id: &tracing_core::span::Id,
        ctx: Context<'_, S>,
    ) {
        let Some(span) = ctx.span(id) else {
            return
        };
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
        let parent_id = event.parent().or(current.id());
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

        if let Some(sender) = LOG_SENDER.get() {
            if let Some(entry) = values_to_log_entry_data(values) {
                let _ = sender.send(entry);
            }
        }
    }
}

fn values_to_log_entry_data(mut values: SerializedRecordValues) -> Option<LogEntry::ActiveModel> {
    let session_id = (*values).remove("session");
    let username = (*values).remove("session_username");
    let mut text = String::new();
    if let Some(message) = (*values).remove("message") {
        text.push_str(&message);
        text.push(' ');
    }

    for (key, value) in values.into_values().into_iter() {
        _ = write!(text, "{}={} ", key, value);
    }

    text.pop();

    use sea_orm::ActiveValue::Set;
    let session_id = session_id.and_then(|x| Uuid::parse_str(&x).ok());
    let Some(session_id) = session_id else {
            return None
        };

    Some(LogEntry::ActiveModel {
        id: Set(Uuid::new_v4()),
        text: Set(text),
        session_id: Set(session_id),
        username: Set(username),
        timestamp: Set(chrono::Utc::now()),
        ..Default::default()
    })
}
