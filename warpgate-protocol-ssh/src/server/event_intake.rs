//! The session event loop's intake, and the one place the outbound data budget
//! is enforced.
//!
//! Events arrive on two subscriptions: target-side ones, which may need to be
//! written to the client, and everything else. A target-side event is only
//! handed out with an outbound slot already claimed, so handling it can enqueue
//! its write without waiting. While no slot is free the loop keeps serving
//! everything else — that is what lets it answer the russh handler, whose
//! reader is the only thing that can process the client's window updates and
//! so release the slots (#2494).

use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use warpgate_common::eventhub::EventSubscription;

pub struct EventIntake<E> {
    control: EventSubscription<E>,
    target: EventSubscription<E>,
    slots: Arc<Semaphore>,
    slot: Option<OwnedSemaphorePermit>,
}

impl<E> EventIntake<E> {
    pub const fn new(
        control: EventSubscription<E>,
        target: EventSubscription<E>,
        slots: Arc<Semaphore>,
    ) -> Self {
        Self {
            control,
            target,
            slots,
            slot: None,
        }
    }

    /// `None` once the hub is gone or the budget has been closed.
    pub async fn next(&mut self) -> Option<E> {
        if self.slot.is_none() {
            let slots = self.slots.clone();
            tokio::select! {
                event = self.control.recv() => return event,
                slot = slots.acquire_owned() => self.slot = Some(slot.ok()?),
            }
        }
        tokio::select! {
            event = self.control.recv() => event,
            event = self.target.recv() => event,
        }
    }

    /// The slot claimed for the target-side event just handed out. Passed to
    /// the write it pays for, which releases it once the data has reached
    /// russh. Empty when the last event came from the control side.
    pub const fn take_slot(&mut self) -> Option<OwnedSemaphorePermit> {
        self.slot.take()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;
    use warpgate_common::eventhub::EventHub;

    use super::*;

    const TICK: Duration = Duration::from_millis(50);
    const PATIENCE: Duration = Duration::from_millis(500);

    fn is_target(event: &&'static str) -> bool {
        event.starts_with("target")
    }

    #[tokio::test]
    async fn target_events_wait_for_an_outbound_slot() {
        let (hub, sender) = EventHub::setup(4);
        let control = hub.subscribe(|e| !is_target(e)).await;
        let target = hub.subscribe(is_target).await;
        let mut intake = EventIntake::new(control, target, Arc::new(Semaphore::new(1)));

        sender.send_once("target-1").await.unwrap();
        assert_eq!(intake.next().await, Some("target-1"));
        let slot = intake.take_slot();
        assert!(slot.is_some(), "a target event must arrive with its slot");

        // The write is still in flight, so the budget is spent.
        sender.send_once("target-2").await.unwrap();
        assert!(timeout(TICK, intake.next()).await.is_err());

        // Control events must keep flowing regardless.
        sender.send_once("control").await.unwrap();
        assert_eq!(
            timeout(PATIENCE, intake.next()).await.unwrap(),
            Some("control")
        );
        assert!(intake.take_slot().is_none());

        drop(slot);
        assert_eq!(
            timeout(PATIENCE, intake.next()).await.unwrap(),
            Some("target-2")
        );
        assert!(intake.take_slot().is_some());
    }
}
