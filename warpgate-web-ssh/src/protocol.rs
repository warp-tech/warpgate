use bytes::Bytes;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warpgate_protocol_ssh::RCState;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    OpenChannel {
        cols: Option<u32>,
        rows: Option<u32>,
    },
    Input {
        channel_id: Uuid,
        #[serde(with = "warpgate_common::helpers::serde_base64")]
        data: Bytes,
    },
    Resize {
        channel_id: Uuid,
        cols: u32,
        rows: u32,
    },
    CloseChannel {
        channel_id: Uuid,
    },
    AcceptHostKey,
    RejectHostKey,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    ConnectionState {
        state: RCState,
    },
    Output {
        channel_id: Uuid,
        #[serde(with = "warpgate_common::helpers::serde_base64")]
        data: Bytes,
    },
    ChannelOpened {
        channel_id: Uuid,
    },
    ChannelClosed {
        channel_id: Uuid,
    },
    Eof {
        channel_id: Uuid,
    },
    ExitStatus {
        channel_id: Uuid,
        code: u32,
    },
    Error {
        message: String,
    },
    HostKeyUnknown {
        host: String,
        port: u16,
        key_type: String,
        key_base64: String,
    },
}
