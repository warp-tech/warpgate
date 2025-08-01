use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use warpgate_common::WarpgateError;

use crate::rate_limiting::limiter::{
    RateLimiterDirection, SwappableLimiterCell, SwappableLimiterCellHandle,
};

type WaitFuture = Pin<Box<dyn Future<Output = Result<(), WarpgateError>> + Send>>;

enum PendingWait {
    Empty,
    Waiting(WaitFuture),
    Ready,
}

// impl Future for PendingWait {
//     type Output = Result<(), WarpgateError>;

//     fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
//         let this = self.get_mut();
//         match this {
//             PendingWait::Empty => Poll::Pending,
//             PendingWait::Waiting(ref mut fut) => {
//                 let res = fut.as_mut().poll(cx);
//                 if let Poll::Ready(_) = res {
//                     *this = PendingWait::Ready;
//                 }
//                 res
//             },
//             PendingWait::Ready => Poll::Ready(Ok(())),
//         }
//     }
// }

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
            read_wait: PendingWait::Empty,
            write_wait: PendingWait::Empty,
        }
    }

    pub fn new_unlimited(inner: T) -> (Self, SwappableLimiterCellHandle) {
        let limiter = SwappableLimiterCell::empty();
        let handle = limiter.handle();
        (
            Self {
                inner,
                limiter,
                read_wait: PendingWait::Empty,
                write_wait: PendingWait::Empty,
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
        if let Poll::Ready(_) = ret {
            // Read completed, reset waiter
            self.read_wait = PendingWait::Empty;
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
        if let Poll::Ready(_) = ret {
            // Read completed, reset waiter
            self.write_wait = PendingWait::Empty;
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

        match this.read_wait {
            PendingWait::Empty => {
                let mut limiter = this.limiter.clone();
                let fut = Box::pin(async move {
                    if let Some(wait) = limiter
                        .until_bytes_ready(RateLimiterDirection::Read, to_read)
                        .await?
                    {
                        tokio::time::sleep(wait).await;
                    };
                    Ok(())
                });
                this.read_wait = PendingWait::Waiting(fut);
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            PendingWait::Waiting(ref mut fut) => {
                // Already waiting for a previous read
                match fut.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => {
                        this.read_wait = PendingWait::Ready;
                        match result {
                            Err(e) => {
                                this.read_wait = PendingWait::Empty;
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::Other,
                                    e.to_string(),
                                )));
                            }
                            Ok(()) => {}
                        }
                        return this.poll_read_nowait(cx, buf);
                    }
                }
            }
            PendingWait::Ready => return this.poll_read_nowait(cx, buf),
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
            // ready check
            return Pin::new(&mut this.inner).poll_write(cx, data);
        }

        match this.write_wait {
            PendingWait::Empty => {
                let len = data.len();
                let mut limiter = this.limiter.clone();
                let fut = Box::pin(async move {
                    if let Some(wait) = limiter
                        .until_bytes_ready(RateLimiterDirection::Write, len)
                        .await?
                    {
                        tokio::time::sleep(wait).await;
                    };
                    Ok(())
                });
                this.write_wait = PendingWait::Waiting(fut);
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            PendingWait::Waiting(ref mut fut) => match fut.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => {
                    this.write_wait = PendingWait::Ready;
                    match result {
                        Err(e) => {
                            this.write_wait = PendingWait::Empty;
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::Other,
                                e.to_string(),
                            )));
                        }
                        Ok(()) => {}
                    }
                    return this.poll_write_nowait(cx, data);
                }
            },
            PendingWait::Ready => return this.poll_write_nowait(cx, data),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
