use std::num::{NonZero, NonZeroU32};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::Duration;

use governor::clock::{Clock, QuantaClock, QuantaInstant};
use governor::{DefaultKeyedRateLimiter, Quota};
use tokio::sync::watch;
use warpgate_common::WarpgateError;

mod shared_limiter {
    use super::*;

    #[derive(Clone)]
    pub struct SharedWarpgateRateLimiter {
        inner: Arc<std::sync::Mutex<WarpgateRateLimiter>>,
    }

    impl SharedWarpgateRateLimiter {
        pub(crate) fn new(limiter: WarpgateRateLimiter) -> Self {
            Self {
                inner: Arc::new(std::sync::Mutex::new(limiter)),
            }
        }

        pub fn lock(&self) -> SharedWarpgateRateLimiterGuard<'_> {
            SharedWarpgateRateLimiterGuard::new(self.inner.lock().unwrap())
        }
    }

    mod guard {
        use super::*;

        pub struct SharedWarpgateRateLimiterGuard<'a> {
            inner: std::sync::MutexGuard<'a, WarpgateRateLimiter>,
            // prevent locks across awaits
            _non_sendable: std::marker::PhantomData<*const ()>,
        }

        impl<'a> SharedWarpgateRateLimiterGuard<'a> {
            pub fn new(inner: std::sync::MutexGuard<'a, WarpgateRateLimiter>) -> Self {
                Self {
                    inner,
                    _non_sendable: std::marker::PhantomData,
                }
            }
        }

        impl Deref for SharedWarpgateRateLimiterGuard<'_> {
            type Target = WarpgateRateLimiter;

            fn deref(&self) -> &Self::Target {
                &self.inner
            }
        }

        impl DerefMut for SharedWarpgateRateLimiterGuard<'_> {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.inner
            }
        }
    }

    pub use guard::SharedWarpgateRateLimiterGuard;
}

pub use shared_limiter::SharedWarpgateRateLimiter;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum RateLimiterDirection {
    Read,
    Write,
}

pub type InnerRateLimiter = DefaultKeyedRateLimiter<RateLimiterDirection>;

pub struct SwappableLimiterCellHandle {
    sender: watch::Sender<Option<SharedWarpgateRateLimiter>>,
}

impl SwappableLimiterCellHandle {
    pub fn replace(&self, limiter: Option<SharedWarpgateRateLimiter>) {
        let _ = self.sender.send(limiter);
    }
}

pub fn new_rate_limiter(bytes_per_second: NonZeroU32) -> InnerRateLimiter {
    let max_cells = NonZeroU32::MAX;
    let rate_limiter =
        InnerRateLimiter::keyed(Quota::per_second(bytes_per_second).allow_burst(max_cells));
    // We keep the burst capacity high to allow checking in large buffers but
    // consume (burst - per_second) tokens initially to ensure that the rate limiter is in its "normal" state
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

    #[must_use = "Must use the duration and wait"]
    pub fn until_bytes_ready(
        &mut self,
        direction: RateLimiterDirection,
        bytes: usize,
    ) -> Result<Option<Duration>, WarpgateError> {
        self._maybe_update();
        let Some(ref rate_limiter) = self.inner else {
            return Ok(None);
        };
        rate_limiter.lock().until_bytes_ready(direction, bytes)
    }
}

/// Houses a replaceable shared reference to a `governor` rate limiter
///
/// Note: this struct cannot be publicly instantiated without being
/// container in a `SharedWarpgateRateLimiter` because we want to prevent
/// somebody putting it in a tokio::sync::Mutex.
///
/// The issue with that is that if it's then used with a `RateLimitedStream`,
/// the semantics of tokio::io::split (internal lock between read and write halves)
/// will cause deadlock if read and write futures are interleaved and one of them has
/// a pending wait on the async mutex.
///
/// So intead we force it to be wrapped in a sync Mutex and never be used
/// across awaits.
///
/// NB There are two types of "replacements" going on with rate limiters:
/// * Swapping out a limiter in a RateLimitedStream e.g. when one logs in
///   and now a user limit applies to them
/// * Replacing the limit inside a limiter when the limit is changed
///   by the admin. This is `WarpgateRateLimiter::replace()`
pub struct WarpgateRateLimiter {
    rate_limiter: Option<InnerRateLimiter>,
}

impl WarpgateRateLimiter {
    pub fn now() -> QuantaInstant {
        QuantaClock::default().now()
    }

    pub fn unlimited() -> SharedWarpgateRateLimiter {
        Self { rate_limiter: None }.share()
    }

    pub fn limited(bytes_per_second: NonZeroU32) -> SharedWarpgateRateLimiter {
        let rate_limiter = new_rate_limiter(bytes_per_second);
        Self {
            rate_limiter: Some(rate_limiter),
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
        let limiter = match bytes_per_second {
            None => None,
            Some(bytes) => Some(new_rate_limiter(assert_valid_quota(bytes)?)),
        };
        self.rate_limiter = limiter;
        Ok(())
    }

    #[must_use = "Must use the duration and wait"]
    pub fn until_bytes_ready(
        &mut self,
        direction: RateLimiterDirection,
        bytes: usize,
    ) -> Result<Option<Duration>, WarpgateError> {
        let Some(ref rate_limiter) = self.rate_limiter else {
            return Ok(None);
        };
        let bytes = match NonZero::new(bytes as u32) {
            Some(bytes) => bytes,
            None => return Ok(None),
        };
        match rate_limiter.check_key_n(&direction, bytes)? {
            Ok(_) => Ok(None),
            Err(e) => {
                let wait = e.wait_time_from(Self::now());
                Ok(Some(wait))
            }
        }
    }

    fn share(self) -> SharedWarpgateRateLimiter {
        SharedWarpgateRateLimiter::new(self)
    }
}
