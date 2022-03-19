use std::sync::Arc;
use tokio::sync::broadcast::error::SendError;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct EventSender<'h, E: Clone> {
    subscriptions: SubscriptionStore<'h, E>,
}

impl<'h, E: Clone + 'h> EventSender<'h, E> {
    pub async fn send(&'h self, event: E) -> Result<(), SendError<E>> {
        let mut subscriptions = self.subscriptions.lock().await;
        subscriptions
            .drain_filter(|(ref f, ref s)| {
                if f(&event) {
                    s.send(event.clone()).map(|_| false).unwrap_or(true)
                } else {
                    false
                }
            })
            .for_each(drop);
        if subscriptions.is_empty() {
            Err(SendError(event))
        } else {
            Ok(())
        }
    }
}

pub struct EventSubscription<E>(UnboundedReceiver<E>);

impl<E> EventSubscription<E> {
    pub async fn recv(&mut self) -> Option<E> {
        self.0.recv().await
    }
}

type SubscriptionStore<'h, E> = Arc<Mutex<Vec<(Box<dyn Fn(&E) -> bool + 'h>, UnboundedSender<E>)>>>;

pub struct EventHub<'h, E: Clone + Send> {
    subscriptions: SubscriptionStore<'h, E>,
}

impl<'h, E: Clone + Send> EventHub<'h, E> {
    pub fn setup() -> (Self, EventSender<'h, E>) {
        let subscriptions = Arc::new(Mutex::new(vec![]));
        (
            Self {
                subscriptions: subscriptions.clone(),
            },
            EventSender { subscriptions },
        )
    }

    pub async fn subscribe<F: Fn(&E) -> bool + Send + 'h>(
        &mut self,
        filter: F,
    ) -> EventSubscription<E> {
        let (sender, receiver) = unbounded_channel();
        let mut subscriptions = self.subscriptions.lock().await;
        subscriptions.push((Box::new(filter), sender));
        EventSubscription(receiver)
    }
}
