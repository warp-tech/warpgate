use std::sync::OnceLock;

use sea_orm::query::JsonValue;
use sea_orm::{ActiveModelTrait, DatabaseConnection};
use time::OffsetDateTime;
use tracing::{Subscriber, error};
use tracing_subscriber::Layer;
use tracing_subscriber::registry::LookupSpan;
use uuid::Uuid;
pub use warpgate_common::helpers::logging::format_related_ids;
use warpgate_db_entities::LogEntry;

use super::layer::ValuesLogLayer;
use super::values::SerializedRecordValues;

static LOG_SENDER: OnceLock<tokio::sync::broadcast::Sender<LogEntry::ActiveModel>> =
    OnceLock::new();

pub fn make_database_logger_layer<S>() -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let _ = LOG_SENDER.set(tokio::sync::broadcast::channel(1024).0);
    ValuesLogLayer::new(|values, target| {
        if let Some(sender) = LOG_SENDER.get()
            && let Some(entry) = values_to_log_entry_data(values, target)
        {
            let _ = sender.send(entry);
        }
    })
}

pub fn install_database_logger(database: DatabaseConnection) {
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
                    if let Err(error) = log_entry.insert(&database).await {
                        error!(?error, "Failed to store log entry");
                    }
                }
            }
        }
    });
}

fn values_to_log_entry_data(
    mut values: SerializedRecordValues,
    target: String,
) -> Option<LogEntry::ActiveModel> {
    use sea_orm::ActiveValue::Set;

    let session_id = (*values).remove("session");
    let username = (*values)
        .remove("session_username")
        .or_else(|| (*values).get("username").cloned());
    let related_users = (*values).remove("related_users");
    let related_access_roles = (*values).remove("related_access_roles");
    let related_admin_roles = (*values).remove("related_admin_roles");
    let message = (*values).remove("message").unwrap_or_default();

    let session_id = session_id.and_then(|x| Uuid::parse_str(&x).ok())?;

    Some(LogEntry::ActiveModel {
        id: Set(Uuid::new_v4()),
        text: Set(message),
        target: Set(target),
        values: Set(values
            .into_values()
            .into_iter()
            .map(|(k, v)| (k, JsonValue::from(v)))
            .collect()),
        session_id: Set(session_id),
        username: Set(username),
        related_users: Set(related_users),
        related_access_roles: Set(related_access_roles),
        related_admin_roles: Set(related_admin_roles),
        timestamp: Set(OffsetDateTime::now_utc()),
    })
}
