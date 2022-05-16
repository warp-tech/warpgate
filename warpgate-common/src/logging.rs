use once_cell::sync::OnceCell;
use sea_orm::{ActiveModelTrait, DatabaseConnection};
use std::fmt::{Debug, Write};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::field::Visit;
use tracing::*;
use tracing_core::Field;
use tracing_subscriber::layer::Context;
use uuid::Uuid;
use warpgate_db_entities::LogEntry;

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

        if let Some(sender) = LOG_SENDER.get() {
            if let Some(entry) = visitor.to_entry() {
                let _ = sender.send(entry);
            }
        }
    }
}

struct RecordVisitor {
    buffer: String,
    session_id: Option<String>,
    username: Option<String>,
}

impl RecordVisitor {
    pub fn new() -> Self {
        Self {
            buffer: "".to_owned(),
            session_id: None,
            username: None,
        }
    }

    pub fn to_entry(self) -> Option<LogEntry::ActiveModel> {
        use sea_orm::ActiveValue::Set;
        let session_id = self.session_id.and_then(|x| Uuid::parse_str(&x).ok());
        let Some(session_id) = session_id else {
            return None
        };
        Some(LogEntry::ActiveModel {
            id: Set(Uuid::new_v4()),
            text: Set(self.buffer),
            session_id: Set(session_id),
            username: Set(self.username),
            timestamp: Set(chrono::Utc::now()),
            ..Default::default()
        })
    }
}

impl Visit for RecordVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        if field.name() == "message" {
            let _ = write!(&mut self.buffer, "{:?}", value);
        } else if field.name() == "session" {
            self.session_id = Some(format!("{:?}", value));
        } else if field.name() == "username" {
            self.username = Some(format!("{:?}", value));
        } else {
            let _ = write!(&mut self.buffer, " {}={:?}", field.name(), value);
        }
    }
}
