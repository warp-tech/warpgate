mod auth;
pub mod connection;
pub mod connector;
mod messages;
mod security;

pub use connection::VncClient;
// Warpgate fork addition (see PATCHES.md): expose the decode loop for proxy recording.
pub use connection::decode_loop;
pub use connector::VncConnector;
