//! ## Hierarchy
//!
//! * [WarpgateRateLimiter] - wraps a [governor::DefaultKeyedRateLimiter], allows mutating the quota and provides app specific logic. Each [WarpgateRateLimiter] houses its own unique rate limiter.
//! * [SharedWarpgateRateLimiter] - makes [WarpgateRateLimiter] shareable and locked.
//! * [SwappableLimiterCell] - a cell containing a [SharedWarpgateRateLimiter] reference which can be swapped out wholesale. Multiple [SwappableLimiterCell]s can reference the same rate limiter instance.
//!
//! ## Why are limiters locked with a [std::sync::Mutex]?
//!
//! The issue with that is that if a limiter in a [tokio] Mutex is then used
//! within a `RateLimitedStream`, then the semantics of
//! [tokio::io::split] (internal lock between read and write halves)
//! will cause deadlock if read and write futures are interleaved and one of them has
//! a pending wait on the async mutex.
//!
//! So instead we force it to always be wrapped in a [SharedWarpgateRateLimiter]
//! with a sync mutex inside and never be used across awaits.

//! ## Why different wrapper types?
//!
//! There are two types of live "replacements" going on with rate limiters:
//! * Swapping out a limiter in a [RateLimitedStream]'s [SwappableLimiterCellHandle]
//!   when the related entity changes, e.g. when the user logs in and now
//!   a user limit applies to them. This is [SwappableLimiterCellHandle::replace]
//! * Replacing the limit inside a concrete [WarpgateRateLimiter] when the limit
//!   is changed by the admin. This is [WarpgateRateLimiter::replace]

mod limiter;
mod registry;
mod shared_limiter;
mod stack;
mod stream;
mod swappable_cell;

use governor::DefaultKeyedRateLimiter;
pub use limiter::WarpgateRateLimiter;
pub use registry::RateLimiterRegistry;
pub use shared_limiter::{SharedWarpgateRateLimiter, SharedWarpgateRateLimiterGuard};
pub use stack::{stack_rate_limiters, RateLimiterStackHandle};
pub use stream::RateLimitedStream;
pub use swappable_cell::{SwappableLimiterCell, SwappableLimiterCellHandle};

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum RateLimiterDirection {
    Read,
    Write,
}

pub type InnerRateLimiter = DefaultKeyedRateLimiter<RateLimiterDirection>;
