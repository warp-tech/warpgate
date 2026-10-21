//! Dialing the target and pumping bytes, with the counters and the audit trail
//! that go with a tunnel.

use std::io::ErrorKind;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::Instant;
use warpgate_core::logging::{AuditEvent, TcpTunnelSubject};

use crate::proto::strip_brackets;

/// How long the whole dial of the target, DNS included, may take.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Dials the configured target. The name is resolved afresh on every call, and
/// each address it resolves to is tried in order.
pub async fn connect(host: &str, port: u16) -> std::io::Result<TcpStream> {
    tokio::time::timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((strip_brackets(host), port)),
    )
    .await
    .unwrap_or_else(|_| Err(ErrorKind::TimedOut.into()))
}

/// Byte counts and the time of the last traffic, shared between the pump and the
/// audit record, which must be able to report them however the tunnel ends.
pub struct Counters {
    to_target: AtomicU64,
    from_target: AtomicU64,
    last_activity_ms: AtomicU64,
    started: Instant,
}

impl Counters {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            to_target: AtomicU64::new(0),
            from_target: AtomicU64::new(0),
            last_activity_ms: AtomicU64::new(0),
            started: Instant::now(),
        })
    }

    fn touch(&self) {
        let elapsed = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_activity_ms.store(elapsed, Ordering::Relaxed);
    }

    fn idle_for(&self) -> Duration {
        let last = Duration::from_millis(self.last_activity_ms.load(Ordering::Relaxed));
        self.started.elapsed().saturating_sub(last)
    }

    pub fn bytes_to_target(&self) -> u64 {
        self.to_target.load(Ordering::Relaxed)
    }

    pub fn bytes_from_target(&self) -> u64 {
        self.from_target.load(Ordering::Relaxed)
    }
}

/// The client's side of the tunnel: what it reads went towards the target and
/// what is written to it came back from there.
pub struct CountingStream<S> {
    inner: S,
    counters: Arc<Counters>,
}

impl<S> CountingStream<S> {
    pub const fn new(inner: S, counters: Arc<Counters>) -> Self {
        Self { inner, counters }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(poll, Poll::Ready(Ok(()))) {
            let read = buf.filled().len().saturating_sub(before);
            self.counters
                .to_target
                .fetch_add(read as u64, Ordering::Relaxed);
            self.counters.touch();
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = poll {
            self.counters
                .from_target
                .fetch_add(written as u64, Ordering::Relaxed);
            self.counters.touch();
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Why a tunnel ended.
#[derive(Debug)]
pub enum TunnelEnd {
    Closed,
    IdleTimeout,
    Error(std::io::Error),
}

impl TunnelEnd {
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::IdleTimeout => "idle_timeout",
            Self::Error(_) => "error",
        }
    }
}

/// Copies both ways until either side closes, fails or, if an idle timeout is
/// set, nothing has moved for that long.
pub async fn pump<C, U>(
    client: &mut C,
    upstream: &mut U,
    idle_timeout: Option<Duration>,
    counters: &Counters,
) -> TunnelEnd
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let idle = async {
        let Some(idle_timeout) = idle_timeout else {
            return std::future::pending().await;
        };
        loop {
            let idle_for = counters.idle_for();
            if idle_for >= idle_timeout {
                return;
            }
            tokio::time::sleep(idle_timeout.saturating_sub(idle_for)).await;
        }
    };

    tokio::select! {
        result = tokio::io::copy_bidirectional(client, upstream) => match result {
            Ok(_) => TunnelEnd::Closed,
            Err(error) => TunnelEnd::Error(error),
        },
        () = idle => TunnelEnd::IdleTimeout,
    }
}

/// The audit record of an open tunnel. `TcpTunnelClosed` is emitted when this is
/// dropped, so a tunnel that an administrator kills (which drops the session
/// future) or that fails still gets its closing event; the reason is `aborted`
/// unless [`Self::finish`] said otherwise.
pub struct TunnelAudit {
    subject: TcpTunnelSubject,
    counters: Arc<Counters>,
    reason: &'static str,
}

impl TunnelAudit {
    pub fn open(subject: TcpTunnelSubject, counters: Arc<Counters>) -> Self {
        AuditEvent::TcpTunnelOpened {
            subject: subject.clone(),
        }
        .emit();
        Self {
            subject,
            counters,
            reason: "aborted",
        }
    }

    pub const fn finish(&mut self, reason: &'static str) {
        self.reason = reason;
    }

    fn closed_event(&self) -> AuditEvent {
        AuditEvent::TcpTunnelClosed {
            subject: self.subject.clone(),
            bytes_to_target: self.counters.bytes_to_target(),
            bytes_from_target: self.counters.bytes_from_target(),
            reason: self.reason.to_owned(),
        }
    }
}

impl Drop for TunnelAudit {
    fn drop(&mut self) {
        self.closed_event().emit();
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use uuid::Uuid;

    use super::*;

    fn subject() -> TcpTunnelSubject {
        TcpTunnelSubject {
            session_id: Uuid::nil(),
            user_id: Uuid::nil(),
            username: "u".into(),
            target_id: Uuid::nil(),
            target_name: "t".into(),
            client_ip: "127.0.0.1".into(),
        }
    }

    #[tokio::test]
    async fn pump_counts_both_directions_and_ends_when_closed() {
        let (mut client_far, client_near) = duplex(1024);
        let (mut upstream_far, mut upstream) = duplex(1024);
        let counters = Counters::new();
        let mut client = CountingStream::new(client_near, counters.clone());

        let driver = tokio::spawn(async move {
            client_far.write_all(b"hello").await.unwrap();
            let mut got = [0u8; 5];
            upstream_far.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"hello");
            upstream_far.write_all(b"hi back!").await.unwrap();
            let mut back = [0u8; 8];
            client_far.read_exact(&mut back).await.unwrap();
            assert_eq!(&back, b"hi back!");
            client_far.shutdown().await.unwrap();
            upstream_far.shutdown().await.unwrap();
        });

        let end = pump(&mut client, &mut upstream, None, &counters).await;
        driver.await.unwrap();
        assert!(matches!(end, TunnelEnd::Closed), "{end:?}");
        assert_eq!(counters.bytes_to_target(), 5);
        assert_eq!(counters.bytes_from_target(), 8);
    }

    #[tokio::test(start_paused = true)]
    async fn pump_ends_after_the_idle_timeout() {
        let (_client_far, client_near) = duplex(64);
        let (_upstream_far, mut upstream) = duplex(64);
        let counters = Counters::new();
        let mut client = CountingStream::new(client_near, counters.clone());

        let end = pump(
            &mut client,
            &mut upstream,
            Some(Duration::from_secs(30)),
            &counters,
        )
        .await;
        assert!(matches!(end, TunnelEnd::IdleTimeout), "{end:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn traffic_resets_the_idle_timeout() {
        let (mut client_far, client_near) = duplex(64);
        let (_upstream_far, mut upstream) = duplex(64);
        let counters = Counters::new();
        let mut client = CountingStream::new(client_near, counters.clone());

        let started = Instant::now();
        let driver = tokio::spawn(async move {
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_secs(20)).await;
                client_far.write_all(b"x").await.unwrap();
            }
            client_far
        });
        let end = pump(
            &mut client,
            &mut upstream,
            Some(Duration::from_secs(30)),
            &counters,
        )
        .await;
        let _keep_open = driver.await.unwrap();
        assert!(matches!(end, TunnelEnd::IdleTimeout));
        // three pings 20 s apart, then 30 s of silence
        assert!(started.elapsed() >= Duration::from_secs(90));
    }

    #[test]
    fn an_unfinished_tunnel_is_reported_as_aborted() {
        let counters = Counters::new();
        counters.to_target.store(3, Ordering::Relaxed);
        counters.from_target.store(4, Ordering::Relaxed);
        let mut audit = TunnelAudit::open(subject(), counters);

        let AuditEvent::TcpTunnelClosed {
            bytes_to_target,
            bytes_from_target,
            reason,
            ..
        } = audit.closed_event()
        else {
            panic!("not a TcpTunnelClosed");
        };
        assert_eq!((bytes_to_target, bytes_from_target), (3, 4));
        assert_eq!(reason, "aborted");

        audit.finish("closed");
        let AuditEvent::TcpTunnelClosed { reason, .. } = audit.closed_event() else {
            panic!("not a TcpTunnelClosed");
        };
        assert_eq!(reason, "closed");
    }

    #[tokio::test]
    async fn connect_reports_a_refused_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        connect("127.0.0.1", port).await.unwrap();
        drop(listener);
        let error = connect("127.0.0.1", port).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ConnectionRefused);
    }

    #[tokio::test]
    async fn connect_accepts_a_bracketed_ipv6_literal() {
        let Ok(listener) = tokio::net::TcpListener::bind("[::1]:0").await else {
            return; // no IPv6 loopback here
        };
        let port = listener.local_addr().unwrap().port();
        connect("[::1]", port).await.unwrap();
        connect("::1", port).await.unwrap();
    }
}
