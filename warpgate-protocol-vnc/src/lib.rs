use warpgate_common::ProtocolName;

mod client;

pub use client::{VncClientHandles, connect};

pub static PROTOCOL_NAME: ProtocolName = "VNC";
