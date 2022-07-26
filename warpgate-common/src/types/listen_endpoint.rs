use std::fmt::Debug;
use std::net::{SocketAddr, ToSocketAddrs};
use std::ops::Deref;

use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct ListenEndpoint(pub SocketAddr);

impl Deref for ListenEndpoint {
    type Target = SocketAddr;
    fn deref(&self) -> &Self::Target {
        &self.0
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
