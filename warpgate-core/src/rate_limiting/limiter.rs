use std::fmt::Debug;
use std::num::{NonZero, NonZeroU32};

use governor::clock::{Clock, QuantaClock, QuantaInstant};
use governor::Quota;
use warpgate_common::WarpgateError;

use super::shared_limiter::SharedWarpgateRateLimiter;
use super::{InnerRateLimiter, RateLimiterDirection};

pub fn new_rate_limiter(bytes_per_second: NonZeroU32) -> InnerRateLimiter {
    let max_cells = NonZeroU32::MAX;
    let rate_limiter =
        InnerRateLimiter::keyed(Quota::per_second(bytes_per_second).allow_burst(max_cells));
    // Keep the burst capacity high to allow checking in large buffers but
    // consume (burst - per_second) cells initially to ensure that
    // the rate limiter is in its "normal" state
    #[allow(clippy::unwrap_used)] // checked
    for key in [RateLimiterDirection::Read, RateLimiterDirection::Write] {
        let _ = rate_limiter.check_key_n(
            &key,
            (u32::from(max_cells) - u32::from(bytes_per_second))
                .try_into()
                .unwrap(),
        );
    }
    rate_limiter
}

pub fn assert_valid_quota(v: u32) -> Result<NonZeroU32, WarpgateError> {
    NonZeroU32::new(v).ok_or(WarpgateError::RateLimiterInvalidQuota(v))
}

/// Houses a replaceable shared reference to a `governor` rate limiter
///
/// Note: this struct cannot be publicly instantiated without being
/// container in a `SharedWarpgateRateLimiter` because we want to prevent
/// somebody putting it in a tokio::sync::Mutex.
///
/// See [super] for details.
pub struct WarpgateRateLimiter {
    inner: Option<(InnerRateLimiter, NonZeroU32)>,
}

impl Debug for WarpgateRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WarpgateRateLimiter")
            .field("bytes_per_second", &self.inner.as_ref().map(|x| x.1))
            .finish()
    }
}

impl WarpgateRateLimiter {
    pub fn now() -> QuantaInstant {
        QuantaClock::default().now()
    }

    pub fn unlimited() -> SharedWarpgateRateLimiter {
        Self { inner: None }.share()
    }

    pub fn limited(bytes_per_second: NonZeroU32) -> SharedWarpgateRateLimiter {
        let rate_limiter = new_rate_limiter(bytes_per_second);
        Self {
            inner: Some((rate_limiter, bytes_per_second)),
        }
        .share()
    }

    #[allow(clippy::new_ret_no_self)]
    pub fn new(bytes_per_second: Option<u32>) -> Result<SharedWarpgateRateLimiter, WarpgateError> {
        match bytes_per_second {
            Some(bytes) => Ok(Self::limited(assert_valid_quota(bytes)?)),
            None => Ok(Self::unlimited()),
        }
    }

    pub fn replace(&mut self, bytes_per_second: Option<u32>) -> Result<(), WarpgateError> {
        match bytes_per_second {
            None => {
                self.inner = None;
            }
            Some(bytes) => {
                let bps = assert_valid_quota(bytes)?;
                self.inner = Some((new_rate_limiter(bps), bps))
            }
        };
        Ok(())
    }

    #[must_use = "Must use the Instant to wait"]
    pub fn bytes_ready_at(
        &self,
        direction: RateLimiterDirection,
        bytes: usize,
    ) -> Result<Option<QuantaInstant>, WarpgateError> {
        let Some(ref inner) = self.inner else {
            return Ok(None);
        };
        let bytes = match NonZero::new(bytes as u32) {
            Some(bytes) => bytes,
            None => return Ok(None),
        };
        match inner.0.check_key_n(&direction, bytes)? {
            Ok(_) => Ok(None),
            Err(e) => Ok(Some(e.earliest_possible())),
        }
    }

    fn share(self) -> SharedWarpgateRateLimiter {
        SharedWarpgateRateLimiter::new(self)
    }
}
