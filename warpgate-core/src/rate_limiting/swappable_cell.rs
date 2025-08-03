use governor::clock::QuantaInstant;
use tokio::sync::watch;
use warpgate_common::WarpgateError;

use super::shared_limiter::SharedWarpgateRateLimiter;
use super::RateLimiterDirection;

pub struct SwappableLimiterCellHandle {
    sender: watch::Sender<Option<SharedWarpgateRateLimiter>>,
}

impl SwappableLimiterCellHandle {
    pub fn replace(&self, limiter: Option<SharedWarpgateRateLimiter>) {
        let _ = self.sender.send(limiter);
    }
}

/// Houses a replaceable shared reference to a `WarpgateRateLimiter` rate limiter.
/// Cloning the cell will provide a copy that is synchronized with the original
#[derive(Clone)]
pub struct SwappableLimiterCell {
    inner: Option<SharedWarpgateRateLimiter>,
    receiver: watch::Receiver<Option<SharedWarpgateRateLimiter>>,
    sender: watch::Sender<Option<SharedWarpgateRateLimiter>>,
}

impl SwappableLimiterCell {
    pub fn empty() -> Self {
        let (sender, receiver) = watch::channel(None);
        Self {
            inner: None,
            receiver,
            sender,
        }
    }

    pub fn handle(&self) -> SwappableLimiterCellHandle {
        SwappableLimiterCellHandle {
            sender: self.sender.clone(),
        }
    }

    fn _maybe_update(&mut self) {
        let _ref = self.receiver.borrow_and_update();
        if _ref.has_changed() {
            self.inner = _ref.as_ref().cloned();
        }
    }

    #[must_use = "Must use the Instant to wait"]
    pub fn bytes_ready_at(
        &mut self,
        direction: RateLimiterDirection,
        bytes: usize,
    ) -> Result<Option<QuantaInstant>, WarpgateError> {
        self._maybe_update();
        let Some(ref rate_limiter) = self.inner else {
            return Ok(None);
        };
        rate_limiter.lock().bytes_ready_at(direction, bytes)
    }
}
