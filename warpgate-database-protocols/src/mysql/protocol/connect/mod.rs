//! Connection Phase
//!
//! <https://dev.mysql.com/doc/internals/en/connection-phase.html>

mod auth_switch;
mod handshake;
mod handshake_response;
mod ssl_request;

pub use auth_switch::{AuthSwitchRequest, AuthSwitchResponse};
pub use handshake::Handshake;
pub use handshake_response::HandshakeResponse;
pub use ssl_request::SslRequest;
