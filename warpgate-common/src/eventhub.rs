use std::sync::Arc;

use tokio::sync::mpsc::error::{SendError, TrySendError};
use tokio::sync::mpsc::{Receiver, Sender, channel};

use crate::helpers::locks::{Mutex, MutexGuard};

pub struct EventSender<E> {
    subscriptions: SubscriptionStore<E>,
}

impl<E> Clone for EventSender<E> {
    fn clone(&self) -> Self {
        Self {
            subscriptions: self.subscriptions.clone(),
        }
    }
}

impl<E> EventSender<E> {
    async fn cleanup_subscriptions(&self) -> MutexGuard<'_, SubscriptionStoreInner<E>> {
        let mut subscriptions = self.subscriptions.lock().await;
        subscriptions.retain(|(_, s)| !s.is_closed());
        subscriptions
    }
}

impl<'h, E: Clone + 'h> EventSender<E> {
    pub async fn send_all(&'h self, event: E) -> Result<(), SendError<E>> {
        let (has_subscriptions, senders) = {
            let subscriptions = self.cleanup_subscriptions().await;
            (
                !subscriptions.is_empty(),
                subscriptions
                    .iter()
                    .rev()
                    .filter(|(filter, _)| filter(&event))
                    .map(|(_, sender)| sender.clone())
                    .collect::<Vec<_>>(),
            )
        };

        if has_subscriptions {
            for sender in senders {
                let _ = sender.send(event.clone()).await;
            }
            Ok(())
        } else {
            Err(SendError(event))
        }
    }
}

impl<'h, E: 'h> EventSender<E> {
    pub async fn send_once(&'h self, event: E) -> Result<(), SendError<E>> {
        let sender = {
            let subscriptions = self.cleanup_subscriptions().await;
            subscriptions
                .iter()
                .rev()
                .find(|(filter, _)| filter(&event))
                .map(|(_, sender)| sender.clone())
        };

        match sender {
            Some(sender) => sender.send(event).await,
            None => Err(SendError(event)),
        }
    }

    pub async fn try_send_once(&'h self, event: E) -> Result<(), TrySendError<E>> {
        let sender = {
            let subscriptions = self.cleanup_subscriptions().await;
            subscriptions
                .iter()
                .rev()
                .find(|(filter, _)| filter(&event))
                .map(|(_, sender)| sender.clone())
        };

        match sender {
            Some(sender) => sender.try_send(event),
            None => Err(TrySendError::Closed(event)),
        }
    }
}

pub struct EventSubscription<E>(Receiver<E>);

impl<E> EventSubscription<E> {
    pub async fn recv(&mut self) -> Option<E> {
        self.0.recv().await
    }
}

type SubscriptionStoreInner<E> = Vec<(Box<dyn Fn(&E) -> bool + Send>, Sender<E>)>;
type SubscriptionStore<E> = Arc<Mutex<SubscriptionStoreInner<E>>>;

pub struct EventHub<E: Send> {
    subscriptions: SubscriptionStore<E>,
    capacity: usize,
}

impl<E: Send> EventHub<E> {
    pub fn setup(capacity: usize) -> (Self, EventSender<E>) {
        let subscriptions = Arc::new(Mutex::new(vec![]));
        (
            Self {
                subscriptions: subscriptions.clone(),
                capacity,
            },
            EventSender { subscriptions },
        )
    }

    pub async fn subscribe<F: Fn(&E) -> bool + Send + 'static>(
        &'_ self,
        filter: F,
    ) -> EventSubscription<E> {
        let (sender, receiver) = channel(self.capacity);
        let mut subscriptions = self.subscriptions.lock().await;
        subscriptions.push((Box::new(filter), sender));
        EventSubscription(receiver)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::EventHub;

    #[tokio::test]
    async fn send_once_waits_for_subscription_capacity() {
        let (hub, sender) = EventHub::setup(1);
        let mut subscription = hub.subscribe(|_| true).await;

        sender.send_once(1).await.unwrap();
        let mut blocked_send = Box::pin(sender.send_once(2));
        assert!(
            timeout(Duration::from_millis(10), &mut blocked_send)
                .await
                .is_err()
        );

        assert_eq!(subscription.recv().await, Some(1));
        blocked_send.await.unwrap();
        assert_eq!(subscription.recv().await, Some(2));
    }

    #[tokio::test]
    async fn try_send_once_fails_when_subscription_is_full() {
        let (hub, sender) = EventHub::setup(1);
        let mut subscription = hub.subscribe(|_| true).await;

        sender.try_send_once(1).await.unwrap();
        assert!(sender.try_send_once(2).await.is_err());
        assert_eq!(subscription.recv().await, Some(1));
    }
}
