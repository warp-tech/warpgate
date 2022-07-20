use bytes::{Buf, BufMut, Bytes};

use crate::err_protocol;
use crate::error::Error;
use crate::io::{Decode, Encode};
use crate::mysql::io::{MySqlBufExt, MySqlBufMutExt};
use crate::mysql::protocol::response::Status;

/// Indicates successful completion of a previous command sent by the client.
#[derive(Debug)]
pub struct OkPacket {
    pub affected_rows: u64,
    pub last_insert_id: u64,
    pub status: Status,
    pub warnings: u16,
}

impl Decode<'_> for OkPacket {
    fn decode_with(mut buf: Bytes, _: ()) -> Result<Self, Error> {
        let header = buf.get_u8();
        if header != 0 && header != 0xfe {
            return Err(err_protocol!(
                "expected 0x00 or 0xfe (OK_Packet) but found 0x{:02x}",
                header
            ));
        }

        let affected_rows = buf.get_uint_lenenc();
        let last_insert_id = buf.get_uint_lenenc();
        let status = Status::from_bits_truncate(buf.get_u16_le());
        let warnings = buf.get_u16_le();

        Ok(Self {
            affected_rows,
            last_insert_id,
            status,
            warnings,
        })
    }
}

impl Encode<'_, ()> for OkPacket {
    fn encode_with(&self, buf: &mut Vec<u8>, _: ()) {
        buf.put_u8(0);
        buf.put_uint_lenenc(self.affected_rows);
        buf.put_uint_lenenc(self.last_insert_id);
        buf.put_u16_le(self.status.bits());
        buf.put_u16_le(self.warnings);
    }
}

#[test]
fn test_decode_ok_packet() {
    const DATA: &[u8] = b"\x00\x00\x00\x02@\x00\x00";

    let p = OkPacket::decode(DATA.into()).unwrap();

    assert_eq!(p.affected_rows, 0);
    assert_eq!(p.last_insert_id, 0);
    assert_eq!(p.warnings, 0);
    assert!(p.status.contains(Status::SERVER_STATUS_AUTOCOMMIT));
    assert!(p.status.contains(Status::SERVER_SESSION_STATE_CHANGED));
}
