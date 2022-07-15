use bytes::Bytes;
use serde::Serializer;

use super::serde_base64;
use crate::Secret;

pub fn serialize<S: Serializer>(secret: &Secret<Bytes>, serializer: S) -> Result<S::Ok, S::Error> {
    serde_base64::serialize(secret.expose_secret().as_ref(), serializer)
}

pub fn deserialize<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Secret<Bytes>, D::Error> {
    let inner = serde_base64::deserialize(deserializer)?;
    Ok(Secret::new(inner))
}
