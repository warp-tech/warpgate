use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::FutureExt;
use governor::clock::Reference;
use governor::Jitter;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::rate_limiting::{
    RateLimiterDirection, SwappableLimiterCell, SwappableLimiterCellHandle, WarpgateRateLimiter,
};

type WaitFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

enum PendingWaitState {
    /// No active wait -> may start new wait on poll.
    /// The usize is the number of bytes processed in the last operation.
    Empty(usize),
    /// Active wait is pending -> polls the wait
    Waiting(usize, WaitFuture),
    /// Active wait has ended -> polls as Ready
    Ready,
}

/// A Future-like container that can polled for I/O rate limiting.
/// Remembers the state of the wait and can be reset.
/// Call `poll_rate_limit` with IO operation params to wait.
/// Once a single wait is done, will always poll Ready until `.reset()` is called.
struct PendingWait {
    state: PendingWaitState,
    direction: RateLimiterDirection,
}

impl PendingWait {
    pub fn new(direction: RateLimiterDirection) -> Self {
        Self {
            state: PendingWaitState::Empty(0),
            direction,
        }
    }

    fn poll_rate_limit(
        &mut self,
        limiter: &mut SwappableLimiterCell,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        // The loop runs at most 2x
        loop {
            if let PendingWaitState::Empty(len) = self.state {
                // Check if we need to wait
                match limiter.bytes_ready_at(self.direction, len) {
                    Ok(None) => {
                        self.state = PendingWaitState::Ready;
                    }
                    Ok(Some(at)) => {
                        let now_quanta = WarpgateRateLimiter::now();
                        let now_tokio = Instant::now();

                        let delta = Duration::from(at.duration_since(now_quanta));
                        let a = 10; // percent
                        let tokio_deadline =
                            Jitter::new(delta * (100 - a) / 100, delta * a * 2 / 100) + now_tokio;

                        let fut = tokio::time::sleep_until(tokio_deadline.into()).boxed();

                        self.state = PendingWaitState::Waiting(len, fut);
                    }
                    Err(e) => {
                        self.state = PendingWaitState::Empty(0);
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Other,
                            e.to_string(),
                        )));
                    }
                };
            };
            match self.state {
                PendingWaitState::Empty(_) => unreachable!(),
                PendingWaitState::Waiting(len, ref mut fut) => match fut.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(_) => {
                        // !!
                        // Since we did not consume any cells
                        // we need to try again and maybe wait
                        // again if there aren't enough available yet.
                        self.state = PendingWaitState::Empty(len);
                        continue;
                    }
                },
                PendingWaitState::Ready => {}
            }
            break;
        }

        Poll::Ready(Ok(()))
    }

    pub fn reset(&mut self, last_chunk_size: usize) {
        self.state = PendingWaitState::Empty(last_chunk_size);
    }
}

// Deadlock alert: the same stream's `read_wait` internal future can become
// paused while something else is waiting on `write_wait`, leading to a deadlock
// since both are accessing the SwappableLimiterCell's internal lock.

pub struct RateLimitedStream<T> {
    inner: T,
    limiter: SwappableLimiterCell,
    read_wait: PendingWait,
    write_wait: PendingWait,
}

impl<T: Send> RateLimitedStream<T> {
    pub fn new(inner: T, limiter: SwappableLimiterCell) -> Self {
        Self {
            inner,
            limiter,
            read_wait: PendingWait::new(RateLimiterDirection::Read),
            write_wait: PendingWait::new(RateLimiterDirection::Write),
        }
    }

    pub fn new_unlimited(inner: T) -> (Self, SwappableLimiterCellHandle) {
        let limiter = SwappableLimiterCell::empty();
        let handle = limiter.handle();
        (
            Self {
                inner,
                limiter,
                read_wait: PendingWait::new(RateLimiterDirection::Read),
                write_wait: PendingWait::new(RateLimiterDirection::Write),
            },
            handle,
        )
    }
}

impl<T: AsyncRead + Unpin + Send> RateLimitedStream<T> {
    fn poll_read_nowait(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let prev_remaining = buf.remaining();
        let ret = Pin::new(&mut self.inner).poll_read(cx, buf);
        if ret.is_ready() {
            let read = prev_remaining - buf.remaining();
            // Read completed, reset waiter
            self.read_wait.reset(read);
        }
        ret
    }
}

impl<T: AsyncWrite + Unpin + Send> RateLimitedStream<T> {
    fn poll_write_nowait(
        &mut self,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let ret = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(result) = &ret {
            // Write completed, reset waiter
            self.write_wait.reset(match result {
                Ok(bytes_written) => *bytes_written,
                Err(_) => 0,
            });
        }
        ret
    }
}

impl<T: AsyncRead + Unpin + Send> AsyncRead for RateLimitedStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        let to_read = buf.remaining();
        if to_read == 0 {
            // ready check
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }

        match this.read_wait.poll_rate_limit(&mut this.limiter, cx) {
            Poll::Ready(Ok(())) => this.poll_read_nowait(cx, buf),
            x => x,
        }
    }
}

impl<T: AsyncWrite + Unpin + Send> AsyncWrite for RateLimitedStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();

        if data.is_empty() {
            // A ready check from tokio
            return Pin::new(&mut this.inner).poll_write(cx, data);
        }

        match this.write_wait.poll_rate_limit(&mut this.limiter, cx) {
            Poll::Ready(Ok(())) => this.poll_write_nowait(cx, data),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
