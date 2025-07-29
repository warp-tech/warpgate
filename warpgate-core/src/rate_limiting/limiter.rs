use std::num::{NonZero, NonZeroU32};
use std::sync::Arc;

use governor::clock::{Clock, QuantaClock, QuantaInstant};
use governor::{DefaultDirectRateLimiter, NotUntil, Quota};
use tokio::sync::{mpsc, watch, Mutex};
use warpgate_common::WarpgateError;

pub struct WarpgateRateLimiterHandle {
    sender: watch::Sender<NonZeroU32>,
}

impl WarpgateRateLimiterHandle {
    pub fn replace(&self, bytes_per_second: NonZeroU32) {
        let _ = self.sender.send(bytes_per_second);
    }
}

fn _construct_limiter(bytes_per_second: NonZeroU32) -> DefaultDirectRateLimiter {
    let max_cells = NonZeroU32::MAX;
    let rate_limiter = DefaultDirectRateLimiter::direct(
        Quota::per_second(bytes_per_second).allow_burst(max_cells),
    );
    // We keep the burst capacity high to allow checking in large buffers but
    // consume (burst - per_second) tokens initially to ensure that the rate limiter is in its "normal" state
    #[allow(clippy::unwrap_used)] // checked
    let _ = rate_limiter.check_n(
        (u32::from(max_cells) - u32::from(bytes_per_second))
            .try_into()
            .unwrap(),
    );
    rate_limiter
}

pub struct WarpgateRateLimiter {
    rate_limiter: Arc<Mutex<DefaultDirectRateLimiter>>,
    receiver: watch::Receiver<NonZeroU32>,
    sender: watch::Sender<NonZeroU32>,
}

impl WarpgateRateLimiter {
    pub fn now() -> QuantaInstant {
        QuantaClock::default().now().into()
    }

    pub fn new(bytes_per_second: NonZeroU32) -> Self {
        let rate_limiter = _construct_limiter(bytes_per_second);
        let (sender, receiver) = watch::channel(bytes_per_second);
        Self {
            rate_limiter: Arc::new(Mutex::new(rate_limiter)),
            receiver,
            sender,
        }
    }

    pub fn handle(&self) -> WarpgateRateLimiterHandle {
        WarpgateRateLimiterHandle {
            sender: self.sender.clone(),
        }
    }

    async fn _maybe_update(&self) {
        let mut this_rl = self.rate_limiter.lock().await;
        let _ref = self.receiver.borrow_and_update();
        if _ref.has_changed() {
            *this_rl = _construct_limiter(*_ref);
        }
    }

    pub async fn until_bytes_ready(&self, bytes: usize) -> Result<(), WarpgateError> {
        self._maybe_update().await;
        let bytes = match NonZero::new(bytes as u32) {
            Some(bytes) => bytes,
            None => return Ok(()),
        };
        self.rate_limiter.lock().await.until_n_ready(bytes).await?;
        Ok(())
    }
}
