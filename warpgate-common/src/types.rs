use std::fmt::Debug;
use std::net::{SocketAddr, ToSocketAddrs};
use std::ops::Deref;

use bytes::Bytes;
use data_encoding::HEXLOWER;
use rand::Rng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::helpers::rng::get_crypto_rng;

pub type SessionId = Uuid;
pub type ProtocolName = &'static str;

#[derive(PartialEq, Eq, Clone)]
pub struct Secret<T>(T);

impl Secret<String> {
    pub fn random() -> Self {
        Secret::new(HEXLOWER.encode(&Bytes::from_iter(get_crypto_rng().gen::<[u8; 32]>())))
    }
}

impl<T> Secret<T> {
    pub const fn new(v: T) -> Self {
        Self(v)
    }

    pub fn expose_secret(&self) -> &T {
        &self.0
    }
}

impl<T> From<T> for Secret<T> {
    fn from(v: T) -> Self {
        Self::new(v)
    }
}

impl<'de, T> Deserialize<'de> for Secret<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = Deserialize::deserialize::<D>(deserializer)?;
        Ok(Self::new(v))
    }
}

impl<T> Serialize for Secret<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<T> Debug for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<secret>")
    }
}

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
