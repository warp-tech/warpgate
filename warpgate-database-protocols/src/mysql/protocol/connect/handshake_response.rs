use std::str::FromStr;

use bytes::{Buf, Bytes};

use crate::error::Error;
use crate::io::{BufExt, BufMutExt, Decode, Encode};
use crate::mysql::io::{MySqlBufExt, MySqlBufMutExt};
use crate::mysql::protocol::auth::AuthPlugin;
use crate::mysql::protocol::connect::ssl_request::SslRequest;
use crate::mysql::protocol::Capabilities;

// https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse
// https://mariadb.com/kb/en/connection/#client-handshake-response

#[derive(Debug)]
pub struct HandshakeResponse {
    pub database: Option<String>,

    /// Max size of a command packet that the client wants to send to the server
    pub max_packet_size: u32,

    /// Default collation for the connection
    pub collation: u8,

    /// Name of the SQL account which client wants to log in
    pub username: String,

    /// Authentication method used by the client
    pub auth_plugin: Option<AuthPlugin>,

    /// Opaque authentication response
    pub auth_response: Option<Bytes>,
}

impl Encode<'_, Capabilities> for HandshakeResponse {
    fn encode_with(&self, buf: &mut Vec<u8>, mut capabilities: Capabilities) {
        if self.auth_plugin.is_none() {
            // ensure PLUGIN_AUTH is set *only* if we have a defined plugin
            capabilities.remove(Capabilities::PLUGIN_AUTH);
        }

        // NOTE: Half of this packet is identical to the SSL Request packet
        SslRequest {
            max_packet_size: self.max_packet_size,
            collation: self.collation,
        }
        .encode_with(buf, capabilities);

        buf.put_str_nul(&self.username);

        if capabilities.contains(Capabilities::PLUGIN_AUTH_LENENC_DATA) {
            if let Some(response) = &self.auth_response {
                buf.put_bytes_lenenc(response);
            } else {
                buf.put_bytes_lenenc(&[]);
            }
        } else if capabilities.contains(Capabilities::SECURE_CONNECTION) {
            if let Some(response) = &self.auth_response {
                buf.push(response.len() as u8);
                buf.extend(response);
            } else {
                buf.push(0);
            }
        } else {
            buf.push(0);
        }

        if capabilities.contains(Capabilities::CONNECT_WITH_DB) {
            if let Some(database) = &self.database {
                buf.put_str_nul(database);
            } else {
                buf.push(0);
            }
        }

        if capabilities.contains(Capabilities::PLUGIN_AUTH) {
            if let Some(plugin) = &self.auth_plugin {
                buf.put_str_nul(plugin.name());
            } else {
                buf.push(0);
            }
        }
    }
}

impl Decode<'_, &mut Capabilities> for HandshakeResponse {
    fn decode_with(mut buf: Bytes, server_capabilities: &mut Capabilities) -> Result<Self, Error> {
        let mut capabilities = buf.get_u32_le() as u64;
        let max_packet_size = buf.get_u32_le();
        let collation = buf.get_u8();
        buf.advance(19);

        let partial_cap = Capabilities::from_bits_truncate(capabilities);

        if partial_cap.contains(Capabilities::MYSQL) {
            // reserved: string<4>
            buf.advance(4);
        } else {
            capabilities += (buf.get_u32_le() as u64) << 32;
        }

        let partial_cap = Capabilities::from_bits_truncate(capabilities);
        if partial_cap.contains(Capabilities::SSL) && buf.is_empty() {
            return Ok(HandshakeResponse {
                collation,
                max_packet_size,
                username: "".to_string(),
                auth_response: None,
                auth_plugin: None,
                database: None,
            });
        }
        let username = buf.get_str_nul()?;

        let auth_response = if partial_cap.contains(Capabilities::PLUGIN_AUTH_LENENC_DATA) {
            Some(buf.get_bytes_lenenc())
        } else if partial_cap.contains(Capabilities::SECURE_CONNECTION) {
            let len = buf.get_u8();
            Some(buf.get_bytes(len as usize))
        } else {
            Some(buf.get_bytes_nul()?)
        };

        let database = if partial_cap.contains(Capabilities::CONNECT_WITH_DB) {
            Some(buf.get_str_nul()?)
        } else {
            None
        };

        let auth_plugin: Option<AuthPlugin> = if partial_cap.contains(Capabilities::PLUGIN_AUTH) {
            Some(AuthPlugin::from_str(&buf.get_str_nul()?)?)
        } else {
            None
        };

        *server_capabilities &= Capabilities::from_bits_truncate(capabilities);

        Ok(HandshakeResponse {
            collation,
            max_packet_size,
            username,
            auth_response,
            auth_plugin,
            database,
        })
    }
}
