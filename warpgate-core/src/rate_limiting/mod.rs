mod stream;
mod limiter;

pub use stream::RateLimitedStream;
pub use limiter::WarpgateRateLimiter;
use tokio::io::{AsyncRead, AsyncWrite};


// pub fn stack_rate_limiters<S: AsyncRead + AsyncWrite + Unpin>(
//     stream: S,

// ) -> RateLimitedStream<S> {
//     RateLimitedStream::new(stream, WarpgateRateLimiter::new(bytes_per_second))
// }
