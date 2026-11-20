use std::sync::LazyLock;

use sea_orm::query::JsonValue;
use sea_orm::{ActiveModelTrait, DatabaseConnection, DbErr};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tracing::{Subscriber, error};
use tracing_subscriber::Layer;
use tracing_subscriber::registry::LookupSpan;
use uuid::Uuid;
pub use warpgate_common::helpers::logging::format_related_ids;
use warpgate_db_entities::LogEntry;

use super::layer::ValuesLogLayer;
use super::values::SerializedRecordValues;

/// Entries wait here until [`install_database_logger`] or
/// [`flush_database_logger`] stores them. An audit entry is never dropped.
// ponytail: unbounded, so it grows while the database is slower than the
// logging; bound it and count the drops if that ever shows up
struct Queue {
    sender: UnboundedSender<LogEntry::ActiveModel>,
    receiver: Mutex<UnboundedReceiver<LogEntry::ActiveModel>>,
}

static QUEUE: LazyLock<Queue> = LazyLock::new(|| {
    let (sender, receiver) = unbounded_channel();
    Queue {
        sender,
        receiver: Mutex::new(receiver),
    }
});

pub fn make_database_logger_layer<S>() -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    ValuesLogLayer::new(|values, target| {
        if let Some(entry) = values_to_log_entry_data(values, target) {
            let _ = QUEUE.sender.send(entry);
        }
    })
}

pub fn install_database_logger(database: DatabaseConnection) {
    tokio::spawn(async move {
        let mut receiver = QUEUE.receiver.lock().await;
        while let Some(entry) = receiver.recv().await {
            if let Err(error) = entry.insert(&database).await {
                error!(?error, "Failed to store log entry");
            }
        }
    });
}

/// Stores the entries logged so far, for a command that exits without running
/// [`install_database_logger`].
pub async fn flush_database_logger(database: &DatabaseConnection) -> Result<(), DbErr> {
    // The logger task holds the lock for good and stores the entries itself
    let Ok(mut receiver) = QUEUE.receiver.try_lock() else {
        return Ok(());
    };
    while let Ok(entry) = receiver.try_recv() {
        entry.insert(database).await?;
    }
    Ok(())
}

fn values_to_log_entry_data(
    mut values: SerializedRecordValues,
    target: String,
) -> Option<LogEntry::ActiveModel> {
    use sea_orm::ActiveValue::Set;

    let session_id = (*values)
        .remove("session")
        .and_then(|x| Uuid::parse_str(&x).ok());

    // include audit events even if they don't have a session ID
    if session_id.is_none() && target != "audit" {
        return None;
    }

    // In a session, username field = session user
    // outside it's the subject and session_username is the actor
    let username = (*values).remove("session_username").or_else(|| {
        (*values)
            .get("username")
            .cloned()
            .filter(|_| session_id.is_some())
    });
    let related_users = (*values).remove("related_users");
    let related_access_roles = (*values).remove("related_access_roles");
    let related_admin_roles = (*values).remove("related_admin_roles");
    let message = (*values).remove("message").unwrap_or_default();

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

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::{EntityTrait, PaginatorTrait};

    use super::*;
    use crate::resources::tests::db;

    #[tokio::test]
    async fn flush_stores_every_queued_entry() {
        let db = db().await;
        for _ in 0..2000 {
            let mut values = SerializedRecordValues::new();
            values.insert("message", "event".into());
            QUEUE
                .sender
                .send(values_to_log_entry_data(values, "audit".into()).unwrap())
                .unwrap();
        }
        flush_database_logger(&db).await.unwrap();
        assert_eq!(LogEntry::Entity::find().count(&db).await.unwrap(), 2000);
    }
}
