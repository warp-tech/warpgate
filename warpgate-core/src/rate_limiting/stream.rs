use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::sync::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use warpgate_common::WarpgateError;

use crate::rate_limiting::WarpgateRateLimiter;

pub struct RateLimitedStream<T> {
    inner: T,
    limiter: Arc<Mutex<WarpgateRateLimiter>>,
    pending_read:
        Option<Pin<Box<dyn std::future::Future<Output = Result<(), WarpgateError>> + Send>>>,
    pending_write: Option<(
        usize,
        Pin<Box<dyn std::future::Future<Output = Result<(), WarpgateError>> + Send>>,
    )>,
}

impl<T> RateLimitedStream<T> {
    pub fn new(inner: T, limiter: Arc<Mutex<WarpgateRateLimiter>>) -> Self {
        Self {
            inner,
            limiter,
            pending_read: None,
            pending_write: None,
        }
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
        if to_read > 0 {
            if this.pending_read.is_none() {
                let limiter = Arc::clone(&this.limiter);
                let fut = Box::pin(async move {
                    let mut guard = limiter.lock().await;
                    guard.until_bytes_ready(to_read).await
                });
                this.pending_read = Some(fut);
            }
            let fut = this.pending_read.as_mut().unwrap();
            match fut.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.to_string())))
                }
                Poll::Ready(Ok(())) => {
                    this.pending_read.take();
                }
            }
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin + Send> AsyncWrite for RateLimitedStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();
        if !data.is_empty() {
            if this.pending_write.is_none() {
                let len = data.len();
                let limiter = Arc::clone(&this.limiter);
                let fut = Box::pin(async move {
                    let mut guard = limiter.lock().await;
                    guard.until_bytes_ready(len).await
                });
                this.pending_write = Some((len, fut));
            }
            let (_len, fut) = this.pending_write.as_mut().unwrap();
            match fut.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.to_string())))
                }
                Poll::Ready(Ok(())) => {
                    this.pending_write.take();
                    return Pin::new(&mut this.inner).poll_write(cx, data);
                }
            }
        }
        Pin::new(&mut this.inner).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
