use std::future::Future;
use std::sync::OnceLock;

use sea_orm::query::JsonValue;
use sea_orm::{ActiveModelTrait, DatabaseConnection};
use time::OffsetDateTime;
use tokio::sync::broadcast::Receiver;
use tokio::sync::broadcast::error::RecvError;
use tracing::{Subscriber, error, warn};
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
        let receiver = LOG_SENDER
            .get()
            .expect("Log sender not ready yet")
            .subscribe();
        consume_log_entries(receiver, |log_entry| async {
            if let Err(error) = log_entry.insert(&database).await {
                error!(?error, "Failed to store log entry");
            }
        })
        .await;
    });
}

async fn consume_log_entries<T: Clone, F: Future<Output = ()>>(
    mut receiver: Receiver<T>,
    mut sink: impl FnMut(T) -> F,
) {
    loop {
        match receiver.recv().await {
            Ok(entry) => sink(entry).await,
            Err(RecvError::Lagged(skipped)) => {
                warn!(
                    skipped,
                    "Database log consumer lagged; skipping log entries"
                );
            }
            Err(RecvError::Closed) => break,
        }
    }
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::sync::{broadcast, mpsc, oneshot};
    use tokio::time::timeout;

    use super::consume_log_entries;

    #[tokio::test]
    async fn consumer_continues_after_lag_and_stops_when_closed() {
        timeout(Duration::from_secs(5), async {
            let (sender, receiver) = broadcast::channel(2);
            let (delivered, mut received) = mpsc::unbounded_channel();
            let (release, blocked) = oneshot::channel();
            let mut blocked = Some(blocked);
            let consumer = tokio::spawn(consume_log_entries(receiver, move |entry| {
                let delivered = delivered.clone();
                let blocked = blocked.take();
                async move {
                    delivered.send(entry).unwrap();
                    if let Some(blocked) = blocked {
                        blocked.await.unwrap();
                    }
                }
            }));

            sender.send(0).unwrap();
            assert_eq!(received.recv().await, Some(0));

            // The first sink call is blocked, so three sends overflow capacity two.
            for entry in 1..=3 {
                sender.send(entry).unwrap();
            }
            release.send(()).unwrap();
            assert_eq!(received.recv().await, Some(2));

            sender.send(4).unwrap();
            assert_eq!(received.recv().await, Some(3));
            assert_eq!(received.recv().await, Some(4));

            drop(sender);
            consumer.await.unwrap();
            assert_eq!(received.recv().await, None);
        })
        .await
        .expect("consumer must deliver entries after lag and terminate when closed");
    }
}
