pub mod auth;
pub mod capabilities;
pub mod connect;
pub mod packet;
pub mod response;
pub mod row;
pub mod text;

pub use capabilities::Capabilities;
pub use packet::Packet;
pub use row::Row;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod truncation_tests {
    use bytes::Bytes;

    use super::Capabilities;
    use super::auth::AuthPlugin;
    use super::connect::{AuthSwitchRequest, Handshake, HandshakeResponse};
    use super::response::{EofPacket, ErrPacket, OkPacket};
    use super::text::{ColumnDefinition, Query};
    use crate::io::{Decode, Encode};

    /// Feeds every strict prefix of a valid packet to `decode`; it must
    /// return (Ok or Err) rather than panic.
    fn assert_prefixes_dont_panic<T>(
        packet: &[u8],
        decode: impl Fn(Bytes) -> Result<T, crate::error::Error>,
    ) {
        assert!(decode(Bytes::copy_from_slice(packet)).is_ok());
        for len in 0..packet.len() {
            let _ = decode(Bytes::copy_from_slice(packet.get(..len).unwrap()));
        }
    }

    fn handshake_response(capabilities: Capabilities) -> Vec<u8> {
        let mut buf = vec![];
        HandshakeResponse {
            database: Some("db".into()),
            max_packet_size: 1 << 24,
            collation: 45,
            username: "user".into(),
            auth_plugin: Some(AuthPlugin::MySqlNativePassword),
            auth_response: Some(Bytes::from_static(b"scramble")),
        }
        .encode_with(&mut buf, capabilities);
        buf
    }

    #[test]
    fn truncated_client_packets() {
        let base =
            Capabilities::PROTOCOL_41 | Capabilities::PLUGIN_AUTH | Capabilities::CONNECT_WITH_DB;
        for caps in [
            base | Capabilities::PLUGIN_AUTH_LENENC_DATA,
            base | Capabilities::SECURE_CONNECTION,
            base,
        ] {
            assert_prefixes_dont_panic(&handshake_response(caps), |b| {
                HandshakeResponse::decode_with(b, &mut Capabilities::all())
            });
        }
        assert_prefixes_dont_panic(b"\x03SELECT 1", Query::decode);
    }

    #[test]
    fn truncated_server_packets() {
        assert_prefixes_dont_panic(
            b"\n8.0.18\x00\x19\x00\x00\x00\x114aB0c\x06g\x00\xff\xff\xff\x02\x00\xff\xc7\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00tL\x03s\x0f[4\rl4. \x00caching_sha2_password\x00",
            Handshake::decode,
        );
        assert_prefixes_dont_panic(
            b"\x00\xfc\x01\x00\xfd\x01\x00\x00\x02\x00\x00\x00",
            OkPacket::decode,
        );
        assert_prefixes_dont_panic(b"\xff\x19\x04#42000Unknown database", |b| {
            ErrPacket::decode_with(b, Capabilities::PROTOCOL_41)
        });
        assert_prefixes_dont_panic(b"\xfe\x00\x00\x02\x00", |b| {
            EofPacket::decode_with(b, Capabilities::empty())
        });
        assert_prefixes_dont_panic(
            b"\xfemysql_native_password\x00abc\x00",
            AuthSwitchRequest::decode,
        );
        assert_prefixes_dont_panic(
            b"\x03def\x00\x00\x00\x01a\x01a\x0c\x21\x00\x0b\x00\x00\x00\x03\x00\x00\x00\x00\x00",
            |b| ColumnDefinition::decode_with(b, Capabilities::empty()),
        );
    }
}
