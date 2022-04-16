use data_encoding::BASE64;
use serde::{Deserialize, Serializer};

pub fn serialize<S: Serializer, B: AsRef<[u8]>>(
    bytes: B,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&BASE64.encode(bytes.as_ref()))
}

pub fn deserialize<'de, D: serde::Deserializer<'de>, B: From<Vec<u8>>>(
    deserializer: D,
) -> Result<B, D::Error> {
    let s = String::deserialize(deserializer)?;
    Ok(BASE64
        .decode(s.as_bytes())
        .map_err(serde::de::Error::custom)?
        .into())
}
