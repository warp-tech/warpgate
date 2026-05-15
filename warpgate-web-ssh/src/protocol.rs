use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;
use warpgate_protocol_ssh::RCState;

#[derive(Clone, Debug)]
pub struct Base64Bytes(pub Bytes);

impl Serialize for Base64Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Base64Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = STANDARD.decode(s).map_err(serde::de::Error::custom)?;
        Ok(Self(Bytes::from(bytes)))
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    OpenChannel {
        cols: Option<u32>,
        rows: Option<u32>,
    },
    Input {
        channel_id: Uuid,
        data: Base64Bytes,
    },
    Resize {
        channel_id: Uuid,
        cols: u32,
        rows: u32,
    },
    CloseChannel {
        channel_id: Uuid,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    ConnectionState { state: RCState },
    Output { channel_id: Uuid, data: Base64Bytes },
    ChannelOpened { channel_id: Uuid },
    ChannelClosed { channel_id: Uuid },
    Eof { channel_id: Uuid },
    ExitStatus { channel_id: Uuid, code: u32 },
    Error { message: String },
}
