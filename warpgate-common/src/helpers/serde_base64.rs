use bytes::Bytes;
use data_encoding::BASE64;
use serde::{Deserialize, Serializer};

pub fn serialize<S>(bytes: &Bytes, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&BASE64.encode(bytes))
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(BASE64
        .decode(s.as_bytes())
        .map_err(serde::de::Error::custom)?
        .into())
}
