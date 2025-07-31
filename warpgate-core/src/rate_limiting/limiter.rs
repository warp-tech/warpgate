use std::num::{NonZero, NonZeroU32};
use std::sync::Arc;
use std::time::Duration;

use governor::clock::{Clock, QuantaClock, QuantaInstant};
use governor::{DefaultDirectRateLimiter, Quota};
use tokio::sync::{watch, Mutex};
use warpgate_common::WarpgateError;

pub struct SwappableLimiterCellHandle {
    sender: watch::Sender<Option<Arc<Mutex<WarpgateRateLimiter>>>>,
}

impl SwappableLimiterCellHandle {
    pub fn replace(&self, limiter: Option<Arc<Mutex<WarpgateRateLimiter>>>) {
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

pub fn assert_valid_quota(v: u32) -> Result<NonZeroU32, WarpgateError> {
    NonZeroU32::new(v).ok_or(WarpgateError::RateLimiterInvalidQuota(v))
}

/// Houses a replaceable shared reference to a `WarpgateRateLimiter` rate limiter.
/// Cloning the cell will provide a copy that is synchronized with the original
#[derive(Clone)]
pub struct SwappableLimiterCell {
    inner: Option<Arc<Mutex<WarpgateRateLimiter>>>,
    receiver: watch::Receiver<Option<Arc<Mutex<WarpgateRateLimiter>>>>,
    sender: watch::Sender<Option<Arc<Mutex<WarpgateRateLimiter>>>>,
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

    async fn _maybe_update(&mut self) {
        let _ref = self.receiver.borrow_and_update();
        if _ref.has_changed() {
            self.inner = _ref.as_ref().cloned();
        }
    }

    #[must_use]
    pub async fn until_bytes_ready(
        &mut self,
        bytes: usize,
    ) -> Result<Option<Duration>, WarpgateError> {
        self._maybe_update().await;
        let Some(ref rate_limiter) = self.inner else {
            return Ok(None);
        };
        rate_limiter.lock().await.until_bytes_ready(bytes).await
    }
}

/// Houses a replaceable shared reference to a `governor` rate limiter
///
/// NB There are two types of "replacements" going on with rate limiters:
/// * Swapping out a limiter in a RateLimitedStream e.g. when one logs in
///   and now a user limit applies to them
/// * Replacing the limit inside a limiter when the limit is changed
///   by the admin. This is `WarpgateRateLimiter::replace()`
pub struct WarpgateRateLimiter {
    rate_limiter: Option<Arc<Mutex<DefaultDirectRateLimiter>>>,
}

impl WarpgateRateLimiter {
    pub fn now() -> QuantaInstant {
        QuantaClock::default().now()
    }

    pub fn unlimited() -> Self {
        Self { rate_limiter: None }
    }

    pub fn limited(bytes_per_second: NonZeroU32) -> Self {
        let rate_limiter = new_rate_limiter(bytes_per_second);
        Self {
            rate_limiter: Some(rate_limiter),
        }
    }

    pub fn new(bytes_per_second: Option<u32>) -> Result<Self, WarpgateError> {
        match bytes_per_second {
            Some(bytes) => Ok(Self::limited(assert_valid_quota(bytes)?)),
            None => Ok(Self::unlimited()),
        }
    }

    pub fn replace(&mut self, bytes_per_second: Option<u32>) -> Result<(), WarpgateError> {
        let limiter = match bytes_per_second {
            None => None,
            Some(bytes) => Some(new_rate_limiter(assert_valid_quota(bytes)?)),
        };
        self.rate_limiter = limiter;
        Ok(())
    }

    #[must_use]
    pub async fn until_bytes_ready(
        &mut self,
        bytes: usize,
    ) -> Result<Option<Duration>, WarpgateError> {
        let Some(ref rate_limiter) = self.rate_limiter else {
            return Ok(None);
        };
        let bytes = match NonZero::new(bytes as u32) {
            Some(bytes) => bytes,
            None => return Ok(None),
        };
        match rate_limiter.lock().await.check_n(bytes)? {
            Ok(_) => Ok(None),
            Err(e) => {
                let wait = e.wait_time_from(Self::now());
                Ok(Some(wait))
            }
        }
    }
}
