use std::fmt::Debug;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use futures::stream::{iter, FuturesUnordered};
use futures::{Stream, StreamExt, TryStreamExt};
use poem::listener::Listener;
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::wrappers::TcpListenerStream;

use crate::WarpgateError;

#[derive(Clone)]
pub struct ListenEndpoint(SocketAddr);

impl ListenEndpoint {
    pub fn addresses_to_listen_on(&self) -> Vec<SocketAddr> {
        // For [::], explicitly return both addresses so that we are not affected
        // by the state of the ipv6only sysctl.
        if self.0.ip() == Ipv6Addr::UNSPECIFIED {
            vec![
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), self.0.port()),
                SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), self.0.port()),
            ]
        } else {
            vec![self.0]
        }
    }

    pub async fn tcp_listeners(&self) -> Result<Vec<TcpListener>, WarpgateError> {
        Ok(self
            .addresses_to_listen_on()
            .into_iter()
            .map(TcpListener::bind)
            .collect::<FuturesUnordered<_>>()
            .try_collect()
            .await?)
    }

    pub async fn poem_listener(&self) -> Result<poem::listener::BoxListener, WarpgateError> {
        let addrs = self.addresses_to_listen_on();
        #[allow(clippy::unwrap_used)] // length known >=1
        let (first, rest) = addrs.split_first().unwrap();
        let mut listener: poem::listener::BoxListener =
            poem::listener::TcpListener::bind(first.to_string()).boxed();
        for addr in rest {
            listener = listener
                .combine(poem::listener::TcpListener::bind(addr.to_string()))
                .boxed();
        }

        Ok(listener)
    }

    pub async fn tcp_accept_stream(
        &self,
    ) -> Result<impl Stream<Item = std::io::Result<TcpStream>>, WarpgateError> {
        Ok(iter(
            self.tcp_listeners()
                .await?
                .into_iter()
                .map(TcpListenerStream::new),
        )
        .flatten())
    }

    pub fn port(&self) -> u16 {
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
