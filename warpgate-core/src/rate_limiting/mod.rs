use tokio::io::{AsyncRead, AsyncWrite};

mod limiter;
mod registry;
mod stream;

pub use limiter::WarpgateRateLimiter;
pub use registry::RateLimiterRegistry;
pub use stream::RateLimitedStream;

use crate::rate_limiting::limiter::SwappableLimiterCellHandle;

pub struct RateLimiterStackHandle {
    pub user: SwappableLimiterCellHandle,
    pub target: SwappableLimiterCellHandle,
    pub global: SwappableLimiterCellHandle,
}

pub fn stack_rate_limiters<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: S,
) -> (
    impl AsyncRead + AsyncWrite + Unpin + Send,
    RateLimiterStackHandle,
) {
    let (stream, global_handle) = RateLimitedStream::new_unlimited(stream);
    let (stream, user_handle) = RateLimitedStream::new_unlimited(stream);
    let (stream, target_handle) = RateLimitedStream::new_unlimited(stream);

    (
        stream,
        RateLimiterStackHandle {
            user: user_handle,
            target: target_handle,
            global: global_handle,
        },
    )
}
