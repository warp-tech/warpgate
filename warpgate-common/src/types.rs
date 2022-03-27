use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use uuid::Uuid;

pub type SessionId = Uuid;

#[derive(PartialEq, Clone)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    pub const fn new(v: T) -> Self {
        Self(v)
    }

    pub fn expose_secret(&self) -> &T {
        &self.0
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
