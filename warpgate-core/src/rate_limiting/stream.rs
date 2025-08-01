use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::FutureExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::rate_limiting::limiter::{
    RateLimiterDirection, SwappableLimiterCell, SwappableLimiterCellHandle,
};

type WaitFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

enum PendingWaitState {
    /// No active wait -> may start new wait on poll
    Empty,
    /// Active wait is pending -> polls the wait
    Waiting(WaitFuture),
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
            state: PendingWaitState::Empty,
            direction,
        }
    }

    fn poll_rate_limit(
        self: &mut PendingWait,
        limiter: &mut SwappableLimiterCell,
        len: usize,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        if let PendingWaitState::Empty = self.state {
            // Check if we need to wait
            match limiter.until_bytes_ready(self.direction, len) {
                Ok(None) => {
                    self.state = PendingWaitState::Ready;
                }
                Ok(Some(dur)) => {
                    let fut = tokio::time::sleep(dur).boxed();
                    self.state = PendingWaitState::Waiting(fut);
                }
                Err(e) => {
                    self.state = PendingWaitState::Empty;
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.to_string())));
                }
            };
        };
        match self.state {
            PendingWaitState::Empty => unreachable!(),
            PendingWaitState::Waiting(ref mut fut) => match fut.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(_) => {
                    self.state = PendingWaitState::Ready;
                }
            },
            PendingWaitState::Ready => {}
        }

        Poll::Ready(Ok(()))
    }

    pub fn reset(&mut self) {
        self.state = PendingWaitState::Empty;
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
        let ret = Pin::new(&mut self.inner).poll_read(cx, buf);
        if ret.is_ready() {
            // Read completed, reset waiter
            self.read_wait.reset();
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
        if ret.is_ready() {
            // Read completed, reset waiter
            self.write_wait.reset();
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

        match this
            .read_wait
            .poll_rate_limit(&mut this.limiter, to_read, cx)
        {
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

        match this
            .write_wait
            .poll_rate_limit(&mut this.limiter, data.len(), cx)
        {
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
