use once_cell::sync::OnceCell;
use sea_orm::DatabaseConnection;
use std::fmt::{Debug, Write};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::field::Visit;
use tracing::{Event, Subscriber, Level};
use tracing_core::Field;
use tracing_subscriber::layer::Context;

static LOG_SENDER: OnceCell<tokio::sync::broadcast::Sender<String>> = OnceCell::new();

pub struct DatabaseLogger {
    database: OnceCell<Arc<Mutex<DatabaseConnection>>>,
}

impl DatabaseLogger {
    pub fn new() -> Self {
        let _ = LOG_SENDER.set(tokio::sync::broadcast::channel(1024).0);
        Self {
            database: OnceCell::new(),
        }
    }

    pub fn set_database(&self, database: Arc<Mutex<DatabaseConnection>>) {
        let _ = self.database.set(database);
    }
}

impl<S> tracing_subscriber::Layer<S> for DatabaseLogger
where
    S: Subscriber,
    Self: 'static,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if !event.metadata().target().starts_with("warpgate") {
            return;
        }
        if event.metadata().level() > &Level::INFO {
            return;
        }
        let mut visitor = RecordVisitor::new();
        event.record(&mut visitor);
        println!("Event: {}", visitor.to_string());
    }
}

struct RecordVisitor {
    buffer: String,
}

impl RecordVisitor {
    pub fn new() -> Self {
        Self {
            buffer: "".to_owned(),
        }
    }

    pub fn to_string(self) -> String {
        self.buffer
    }
}

impl Visit for RecordVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        if field.name() == "message" {
            let _ = write!(&mut self.buffer, "{:?}", value);
        } else {
            let _ = write!(&mut self.buffer, " {}={:?}", field.name(), value);
        }
    }
}
