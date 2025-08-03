use tokio::io::{AsyncRead, AsyncWrite};

use super::swappable_cell::SwappableLimiterCellHandle;
use super::RateLimitedStream;

/// Three [RateLimitedStream]s in a trenchcoat, one with a global limiter,
/// one with a user limiter and one with a target limiter, wrapping each other.
/// The handle lets you swap out the limiters in each of them remotely.
/// Created via [stack_rate_limiters].
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
