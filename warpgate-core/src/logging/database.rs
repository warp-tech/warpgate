use std::sync::Arc;

use once_cell::sync::OnceCell;
use sea_orm::query::JsonValue;
use sea_orm::{ActiveModelTrait, DatabaseConnection};
use tokio::sync::Mutex;
use tracing::*;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;
use uuid::Uuid;
use warpgate_common::helpers::locks::DebugLock;
use warpgate_db_entities::LogEntry;

use super::layer::ValuesLogLayer;
use super::values::SerializedRecordValues;

static LOG_SENDER: OnceCell<tokio::sync::broadcast::Sender<LogEntry::ActiveModel>> =
    OnceCell::new();

pub fn make_database_logger_layer<S>() -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let _ = LOG_SENDER.set(tokio::sync::broadcast::channel(1024).0);
    ValuesLogLayer::new(|values| {
        if let Some(sender) = LOG_SENDER.get() {
            if let Some(entry) = values_to_log_entry_data(values) {
                let _ = sender.send(entry);
            }
        }
    })
}

pub fn install_database_logger(database: Arc<Mutex<DatabaseConnection>>) {
    tokio::spawn(async move {
        #[allow(clippy::expect_used)]
        let mut receiver = LOG_SENDER
            .get()
            .expect("Log sender not ready yet")
            .subscribe();
        loop {
            match receiver.recv().await {
                Err(_) => break,
                Ok(log_entry) => {
                    let database = database.lock2().await;
                    if let Err(error) = log_entry.insert(&*database).await {
                        error!(?error, "Failed to store log entry");
                    }
                }
            }
        }
    });
}

fn values_to_log_entry_data(mut values: SerializedRecordValues) -> Option<LogEntry::ActiveModel> {
    let session_id = (*values).remove("session");
    let username = (*values).remove("session_username");
    let message = (*values).remove("message").unwrap_or_default();

    use sea_orm::ActiveValue::Set;
    let session_id = session_id.and_then(|x| Uuid::parse_str(&x).ok())?;

    Some(LogEntry::ActiveModel {
        id: Set(Uuid::new_v4()),
        text: Set(message),
        values: Set(values
            .into_values()
            .into_iter()
            .map(|(k, v)| (k, JsonValue::from(v)))
            .collect()),
        session_id: Set(session_id),
        username: Set(username),
        timestamp: Set(chrono::Utc::now()),
    })
}
