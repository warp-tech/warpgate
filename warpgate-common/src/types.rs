use std::fmt::Display;
use std::hash::{Hash, Hasher};
use std::ops::Deref;

use serde::Serialize;
use uuid::Uuid;

pub type SessionId = Uuid;

#[derive(Debug, Copy, Clone, Serialize)]
pub struct UUID(pub Uuid);

impl UUID {
    pub fn parse_str(input: &str) -> Result<UUID, uuid::Error> {
        Ok(UUID(Uuid::parse_str(input)?))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<UUID, uuid::Error> {
        Ok(UUID(Uuid::from_slice(bytes)?))
    }
}

impl From<Uuid> for UUID {
    fn from(uuid: Uuid) -> Self {
        UUID(uuid)
    }
}

impl From<UUID> for Uuid {
    fn from(uuid: UUID) -> Uuid {
        uuid.0
    }
}

impl Display for UUID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Deref for UUID {
    type Target = Uuid;

    fn deref(&self) -> &Uuid {
        &self.0
    }
}

impl Hash for UUID {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }

    fn hash_slice<H: Hasher>(data: &[Self], state: &mut H)
    where
        Self: Sized,
    {
        let inner: Vec<Uuid> = data.iter().map(|s| s.0).collect();
        Uuid::hash_slice(inner.as_ref(), state);
    }
}

impl PartialEq for UUID {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl Eq for UUID {}
