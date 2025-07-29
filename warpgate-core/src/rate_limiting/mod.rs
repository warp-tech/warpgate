use std::num::NonZeroU32;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

mod limiter;
mod registry;
mod stream;

pub use limiter::WarpgateRateLimiter;
pub use registry::RateLimiterRegistry;
pub use stream::RateLimitedStream;

use crate::rate_limiting::limiter::WarpgateRateLimiterHandle;

pub struct RateLimiterStackHandle {
    pub user: WarpgateRateLimiterHandle,
    pub target: WarpgateRateLimiterHandle,
    pub global: WarpgateRateLimiterHandle,
}

pub fn stack_rate_limiters<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: S,
) -> (
    impl AsyncRead + AsyncWrite + Unpin + Send,
    RateLimiterStackHandle,
) {
    let user_limiter = WarpgateRateLimiter::new(NonZeroU32::MAX);
    let user_handle = user_limiter.handle();
    let target_limiter = WarpgateRateLimiter::new(NonZeroU32::MAX);
    let target_handle = target_limiter.handle();
    let global_limiter = WarpgateRateLimiter::new(NonZeroU32::MAX);
    let global_handle = global_limiter.handle();

    let stream = RateLimitedStream::new(stream, Arc::new(Mutex::new(global_limiter)));
    let stream = RateLimitedStream::new(stream, Arc::new(Mutex::new(user_limiter)));
    let stream = RateLimitedStream::new(stream, Arc::new(Mutex::new(target_limiter)));

    (
        stream,
        RateLimiterStackHandle {
            user: user_handle,
            target: target_handle,
            global: global_handle,
        },
    )
}
