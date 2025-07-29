use std::num::{NonZero, NonZeroU32};
use std::sync::Arc;

use governor::clock::{Clock, QuantaClock, QuantaInstant};
use governor::{DefaultDirectRateLimiter, Quota};
use tokio::sync::{watch, Mutex};
use warpgate_common::WarpgateError;

pub struct WarpgateRateLimiterHandle {
    sender: watch::Sender<Option<Arc<Mutex<DefaultDirectRateLimiter>>>>,
}

impl WarpgateRateLimiterHandle {
    pub fn replace(&self, limiter: Option<Arc<Mutex<DefaultDirectRateLimiter>>>) {
        let _ = self.sender.send(limiter);
    }
}

pub fn new_rate_limiter(bytes_per_second: NonZeroU32) -> Arc<Mutex<DefaultDirectRateLimiter>> {
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
    Arc::new(Mutex::new(rate_limiter))
}

/// Houses a replaceable shared reference to a rate limiter
pub struct WarpgateRateLimiter {
    rate_limiter: Option<Arc<Mutex<DefaultDirectRateLimiter>>>,
    receiver: watch::Receiver<Option<Arc<Mutex<DefaultDirectRateLimiter>>>>,
    sender: watch::Sender<Option<Arc<Mutex<DefaultDirectRateLimiter>>>>,
}

impl WarpgateRateLimiter {
    pub fn now() -> QuantaInstant {
        QuantaClock::default().now().into()
    }

    pub fn empty() -> Self {
        let (sender, receiver) = watch::channel(None);
        Self {
            rate_limiter: None,
            receiver,
            sender,
        }
    }

    pub fn new(bytes_per_second: NonZeroU32) -> Self {
        let rate_limiter = new_rate_limiter(bytes_per_second);
        let (sender, receiver) = watch::channel(Some(rate_limiter));
        Self {
            rate_limiter: None,
            receiver,
            sender,
        }
    }

    pub fn handle(&self) -> WarpgateRateLimiterHandle {
        WarpgateRateLimiterHandle {
            sender: self.sender.clone(),
        }
    }

    async fn _maybe_update(&mut self) {
        let _ref = self.receiver.borrow_and_update();
        if _ref.has_changed() {
            self.rate_limiter = _ref.as_ref().cloned();
        }
    }

    pub async fn until_bytes_ready(&mut self, bytes: usize) -> Result<(), WarpgateError> {
        self._maybe_update().await;
        let Some(ref rate_limiter) = self.rate_limiter else {
            return Ok(());
        };
        let bytes = match NonZero::new(bytes as u32) {
            Some(bytes) => bytes,
            None => return Ok(()),
        };
        rate_limiter.lock().await.until_n_ready(bytes).await?;
        Ok(())
    }
}
