//! Oracle TNS/TTC protocol primitives for the Warpgate Oracle protocol.
//!
//! The gateway terminates O5LOGON on both legs — acting as an Oracle *server*
//! towards the client (validating the Warpgate user against a stored 12c
//! verifier) and as an Oracle *client* towards the real database (logging in
//! with the target's stored credentials) — then relays TTC traffic and extracts
//! SQL text for audit. This crate holds the wire formats and the crypto; the
//! async session lives in `warpgate-protocol-oracle`.

pub mod audit;
pub mod client_auth;
pub mod client_crypto;
pub mod client_info;
pub mod constants;
pub mod crypto;
pub mod error;
pub mod execute;
pub mod handshake;
pub mod negotiation;
pub mod o5logon;
pub mod packet;
pub mod server_auth;
pub mod ttc;
