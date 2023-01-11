use bytes::buf::Chain;
use bytes::{Buf, BufMut, Bytes};

use crate::error::Error;
use crate::io::{BufExt, BufMutExt, Decode, Encode};
use crate::mysql::protocol::auth::AuthPlugin;
use crate::mysql::protocol::response::Status;
use crate::mysql::protocol::Capabilities;

// https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::Handshake
// https://mariadb.com/kb/en/connection/#initial-handshake-packet

#[derive(Debug)]
pub struct Handshake {
    #[allow(unused)]
    pub protocol_version: u8,
    pub server_version: String,
    #[allow(unused)]
    pub connection_id: u32,
    pub server_capabilities: Capabilities,
    #[allow(unused)]
    pub server_default_collation: u8,
    #[allow(unused)]
    pub status: Status,
    pub auth_plugin: Option<AuthPlugin>,
    pub auth_plugin_data: Chain<Bytes, Bytes>,
}

impl Decode<'_> for Handshake {
    fn decode_with(mut buf: Bytes, _: ()) -> Result<Self, Error> {
        let protocol_version = buf.get_u8(); // int<1>
        let server_version = buf.get_str_nul()?; // string<NUL>
        let connection_id = buf.get_u32_le(); // int<4>
        let auth_plugin_data_1 = buf.get_bytes(8); // string<8>

        buf.advance(1); // reserved: string<1>

        let capabilities_1 = buf.get_u16_le(); // int<2>
        let mut capabilities = Capabilities::from_bits_truncate(capabilities_1.into());

        let collation = buf.get_u8(); // int<1>
        let status = Status::from_bits_truncate(buf.get_u16_le());

        let capabilities_2 = buf.get_u16_le(); // int<2>
        capabilities |= Capabilities::from_bits_truncate(((capabilities_2 as u32) << 16).into());

        let auth_plugin_data_len = if capabilities.contains(Capabilities::PLUGIN_AUTH) {
            buf.get_u8()
        } else {
            buf.advance(1); // int<1>
            0
        };

        buf.advance(6); // reserved: string<6>

        if capabilities.contains(Capabilities::MYSQL) {
            buf.advance(4); // reserved: string<4>
        } else {
            let capabilities_3 = buf.get_u32_le(); // int<4>
            capabilities |= Capabilities::from_bits_truncate((capabilities_3 as u64) << 32);
        }

        let auth_plugin_data_2 = if capabilities.contains(Capabilities::SECURE_CONNECTION) {
            let len = ((auth_plugin_data_len as isize) - 9).max(12) as usize;
            let v = buf.get_bytes(len);
            buf.advance(1); // NUL-terminator

            v
        } else {
            Bytes::new()
        };

        let auth_plugin = if capabilities.contains(Capabilities::PLUGIN_AUTH) {
            Some(buf.get_str_nul()?.parse()?)
        } else {
            None
        };

        Ok(Self {
            protocol_version,
            server_version,
            connection_id,
            server_default_collation: collation,
            status,
            server_capabilities: capabilities,
            auth_plugin,
            auth_plugin_data: auth_plugin_data_1.chain(auth_plugin_data_2),
        })
    }
}

impl Encode<'_, ()> for Handshake {
    fn encode_with(&self, buf: &mut Vec<u8>, _: ()) {
        buf.put_u8(self.protocol_version);
        buf.put_str_nul(&self.server_version);
        buf.put_u32_le(self.connection_id);
        buf.put_slice(self.auth_plugin_data.first_ref());
        buf.put_u8(0x00);
        buf.put_u16_le((self.server_capabilities.bits() & 0x0000_FFFF) as u16);
        buf.put_u8(self.server_default_collation);
        buf.put_u16_le(self.status.bits());
        buf.put_u16_le(((self.server_capabilities.bits() & 0xFFFF_0000) >> 16) as u16);

        if self.server_capabilities.contains(Capabilities::PLUGIN_AUTH) {
            buf.put_u8((self.auth_plugin_data.last_ref().len() + 8 + 1) as u8);
        } else {
            buf.put_u8(0);
        }

        buf.put_slice(&[0_u8; 10][..]);

        if self
            .server_capabilities
            .contains(Capabilities::SECURE_CONNECTION)
        {
            buf.put_slice(self.auth_plugin_data.last_ref());
            buf.put_u8(0);
        }

        if self.server_capabilities.contains(Capabilities::PLUGIN_AUTH) {
            if let Some(auth_plugin) = self.auth_plugin {
                buf.put_str_nul(auth_plugin.name());
            }
        }
    }
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_decode_handshake_mysql_8_0_18() {
    const HANDSHAKE_MYSQL_8_0_18: &[u8] = b"\n8.0.18\x00\x19\x00\x00\x00\x114aB0c\x06g\x00\xff\xff\xff\x02\x00\xff\xc7\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00tL\x03s\x0f[4\rl4. \x00caching_sha2_password\x00";

    let mut p = Handshake::decode(HANDSHAKE_MYSQL_8_0_18.into()).unwrap();

    assert_eq!(p.protocol_version, 10);

    p.server_capabilities.toggle(
        Capabilities::MYSQL
            | Capabilities::FOUND_ROWS
            | Capabilities::LONG_FLAG
            | Capabilities::CONNECT_WITH_DB
            | Capabilities::NO_SCHEMA
            | Capabilities::COMPRESS
            | Capabilities::ODBC
            | Capabilities::LOCAL_FILES
            | Capabilities::IGNORE_SPACE
            | Capabilities::PROTOCOL_41
            | Capabilities::INTERACTIVE
            | Capabilities::SSL
            | Capabilities::TRANSACTIONS
            | Capabilities::SECURE_CONNECTION
            | Capabilities::MULTI_STATEMENTS
            | Capabilities::MULTI_RESULTS
            | Capabilities::PS_MULTI_RESULTS
            | Capabilities::PLUGIN_AUTH
            | Capabilities::CONNECT_ATTRS
            | Capabilities::PLUGIN_AUTH_LENENC_DATA
            | Capabilities::CAN_HANDLE_EXPIRED_PASSWORDS
            | Capabilities::SESSION_TRACK
            | Capabilities::DEPRECATE_EOF
            | Capabilities::ZSTD_COMPRESSION_ALGORITHM
            | Capabilities::SSL_VERIFY_SERVER_CERT
            | Capabilities::OPTIONAL_RESULTSET_METADATA
            | Capabilities::REMEMBER_OPTIONS,
    );

    assert!(p.server_capabilities.is_empty());

    assert_eq!(p.server_default_collation, 255);
    assert!(p.status.contains(Status::SERVER_STATUS_AUTOCOMMIT));

    assert!(matches!(
        p.auth_plugin,
        Some(AuthPlugin::CachingSha2Password)
    ));

    assert_eq!(
        &*p.auth_plugin_data.into_iter().collect::<Vec<_>>(),
        &[17, 52, 97, 66, 48, 99, 6, 103, 116, 76, 3, 115, 15, 91, 52, 13, 108, 52, 46, 32,]
    );
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_decode_handshake_mariadb_10_4_7() {
    const HANDSHAKE_MARIA_DB_10_4_7: &[u8] = b"\n5.5.5-10.4.7-MariaDB-1:10.4.7+maria~bionic\x00\x0b\x00\x00\x00t6L\\j\"dS\x00\xfe\xf7\x08\x02\x00\xff\x81\x15\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00U14Oph9\"<H5n\x00mysql_native_password\x00";

    let mut p = Handshake::decode(HANDSHAKE_MARIA_DB_10_4_7.into()).unwrap();

    assert_eq!(p.protocol_version, 10);

    assert_eq!(
        &*p.server_version,
        "5.5.5-10.4.7-MariaDB-1:10.4.7+maria~bionic"
    );

    p.server_capabilities.toggle(
        Capabilities::FOUND_ROWS
            | Capabilities::LONG_FLAG
            | Capabilities::CONNECT_WITH_DB
            | Capabilities::NO_SCHEMA
            | Capabilities::COMPRESS
            | Capabilities::ODBC
            | Capabilities::LOCAL_FILES
            | Capabilities::IGNORE_SPACE
            | Capabilities::PROTOCOL_41
            | Capabilities::INTERACTIVE
            | Capabilities::TRANSACTIONS
            | Capabilities::SECURE_CONNECTION
            | Capabilities::MULTI_STATEMENTS
            | Capabilities::MULTI_RESULTS
            | Capabilities::PS_MULTI_RESULTS
            | Capabilities::PLUGIN_AUTH
            | Capabilities::CONNECT_ATTRS
            | Capabilities::PLUGIN_AUTH_LENENC_DATA
            | Capabilities::CAN_HANDLE_EXPIRED_PASSWORDS
            | Capabilities::SESSION_TRACK
            | Capabilities::DEPRECATE_EOF
            | Capabilities::REMEMBER_OPTIONS,
    );

    assert!(p.server_capabilities.is_empty());

    assert_eq!(p.server_default_collation, 8);
    assert!(p.status.contains(Status::SERVER_STATUS_AUTOCOMMIT));
    assert!(matches!(
        p.auth_plugin,
        Some(AuthPlugin::MySqlNativePassword)
    ));

    assert_eq!(
        &*p.auth_plugin_data.into_iter().collect::<Vec<_>>(),
        &[116, 54, 76, 92, 106, 34, 100, 83, 85, 49, 52, 79, 112, 104, 57, 34, 60, 72, 53, 110,]
    );
}
