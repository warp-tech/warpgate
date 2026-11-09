use std::fmt::Debug;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use futures::stream::iter;
use futures::{Stream, StreamExt};
use poem::listener::{AcceptorExt, BoxAcceptor, TcpAcceptor};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::wrappers::TcpListenerStream;
use tracing::warn;

use crate::WarpgateError;

#[derive(Clone, PartialEq, Eq, JsonSchema)]
pub struct ListenEndpoint(SocketAddr);

/// IPv6 sockets are v6-only, so `[::]` and `0.0.0.0` can be bound side by
/// side on one port regardless of the `bindv6only` sysctl.
fn bind_socket(addr: SocketAddr) -> std::io::Result<Socket> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    // Lets a restarted listener rebind while connections it accepted linger in
    // TIME_WAIT. On Windows, SO_REUSEADDR would instead allow taking over a
    // port another socket is actively listening on, so std and mio skip it there.
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(socket)
}

fn listen_on(addr: SocketAddr) -> std::io::Result<std::net::TcpListener> {
    let socket = bind_socket(addr)?;
    socket.listen(1024)?;
    Ok(socket.into())
}

impl ListenEndpoint {
    pub const fn address(&self) -> SocketAddr {
        self.0
    }

    /// `[::]` means every interface of both families, and the IPv6 socket is
    /// v6-only (see [`bind_socket`]), so IPv4 needs a listener of its own.
    fn addresses_to_listen_on(&self) -> Vec<SocketAddr> {
        if self.0.ip() == Ipv6Addr::UNSPECIFIED {
            vec![
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), self.0.port()),
                self.0,
            ]
        } else {
            vec![self.0]
        }
    }

    /// Binds every address without listening, so nothing can connect before
    /// the real listener is up (e.g. a `wait_port()` poll racing startup).
    pub fn probe(&self) -> Result<(), WarpgateError> {
        let _bound = self
            .addresses_to_listen_on()
            .into_iter()
            .map(bind_socket)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(())
    }

    // async so that `from_std` only runs inside the runtime it registers with
    // (it panics anywhere else)
    #[allow(clippy::unused_async)]
    pub async fn tcp_listeners(&self) -> Result<Vec<TcpListener>, WarpgateError> {
        Ok(self
            .addresses_to_listen_on()
            .into_iter()
            .map(|addr| TcpListener::from_std(listen_on(addr)?))
            .collect::<std::io::Result<_>>()?)
    }

    pub async fn poem_acceptor(&self) -> Result<BoxAcceptor, WarpgateError> {
        self.tcp_listeners()
            .await?
            .into_iter()
            .map(|listener| TcpAcceptor::from_tokio(listener).map(AcceptorExt::boxed))
            .reduce(|a, b| Ok(a?.combine(b?).boxed()))
            .ok_or_else(|| WarpgateError::InconsistentState("no address to listen on".into()))?
            .map_err(Into::into)
    }

    pub async fn tcp_accept_stream(
        &self,
    ) -> Result<impl Stream<Item = TcpStream> + Unpin + Send + 'static, WarpgateError> {
        Ok(iter(
            self.tcp_listeners()
                .await?
                .into_iter()
                .map(TcpListenerStream::new),
        )
        .flatten_unordered(None)
        .filter_map(|result| async {
            match result {
                Ok(stream) => Some(stream),
                Err(error) => {
                    // #1962 - accept errors as transient (e.g. EMFILE)
                    // and don't kill the listener
                    warn!(%error, "Failed to accept connection");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    None
                }
            }
        })
        .boxed())
    }

    pub const fn port(&self) -> u16 {
        self.0.port()
    }
}

impl From<SocketAddr> for ListenEndpoint {
    fn from(addr: SocketAddr) -> Self {
        Self(addr)
    }
}

impl<'de> Deserialize<'de> for ListenEndpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v: String = Deserialize::deserialize::<D>(deserializer)?;
        let v = v
            .to_socket_addrs()
            .map_err(|e| {
                serde::de::Error::custom(format!(
                    "failed to resolve {v} into a TCP endpoint: {e:?}"
                ))
            })?
            .next()
            .ok_or_else(|| {
                serde::de::Error::custom(format!("failed to resolve {v} into a TCP endpoint"))
            })?;
        Ok(Self(v))
    }
}

impl Serialize for ListenEndpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl Debug for ListenEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::*;

    #[tokio::test]
    async fn rebinds_while_accepted_connections_are_in_time_wait() {
        let endpoint = ListenEndpoint::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
        let listener = endpoint.tcp_listeners().await.unwrap().pop().unwrap();
        let addr = listener.local_addr().unwrap();

        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        // The side that closes first is the one left in TIME_WAIT.
        drop(server);
        client.read_to_end(&mut Vec::new()).await.unwrap();
        drop(client);
        drop(listener);

        let plain = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        assert!(
            plain.bind(&addr.into()).is_err(),
            "port should be held by TIME_WAIT without SO_REUSEADDR"
        );

        let endpoint = ListenEndpoint::from(addr);
        endpoint.probe().unwrap();
        endpoint.tcp_listeners().await.unwrap();
    }

    #[tokio::test]
    async fn unspecified_v6_listens_on_both_families() {
        let port = std::net::TcpListener::bind((Ipv6Addr::UNSPECIFIED, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let endpoint = ListenEndpoint::from(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)));
        endpoint.probe().unwrap();
        let listeners = endpoint.tcp_listeners().await.unwrap();

        let families: Vec<_> = listeners
            .iter()
            .map(|l| l.local_addr().unwrap().is_ipv4())
            .collect();
        assert_eq!(families, [true, false]);

        for listener in listeners {
            let loopback: std::net::IpAddr = if listener.local_addr().unwrap().is_ipv4() {
                Ipv4Addr::LOCALHOST.into()
            } else {
                Ipv6Addr::LOCALHOST.into()
            };
            let client = TcpStream::connect((loopback, port)).await.unwrap();
            let (_, peer) = listener.accept().await.unwrap();
            assert_eq!(peer, client.local_addr().unwrap());
        }
    }
}
