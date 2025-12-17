use std::fmt::Debug;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use super::WarpgateRateLimiter;

#[derive(Clone, Debug)]
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
        #[allow(clippy::unwrap_used, reason = "panic on poison")]
        SharedWarpgateRateLimiterGuard::new(self.inner.lock().unwrap())
    }
}

/// Encapsulates a shared reference to a `WarpgateRateLimiter` in a mutex
/// and prevents locks from being sent across awaits
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
