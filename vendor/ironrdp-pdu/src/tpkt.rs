use ironrdp_core::{
    ReadCursor, WriteCursor, ensure_fixed_part_size, read_padding, unsupported_version_err, write_padding,
};

use crate::{DecodeResult, EncodeResult};

/// TPKT header
///
/// TPKTs are defined in:
///
/// - <https://www.rfc-editor.org/rfc/rfc1006> — RFC 1006 - ISO Transport Service on top of the TCP
/// - <http://www.itu.int/rec/T-REC-T.123/> — ITU-T T.123 (01/2007) - Network-specific data protocol
///   stacks for multimedia conferencing
///
/// ```diagram
///       TPKT Header
///  ____________________   byte
/// |                    |
/// |     3 (version)    |   1
/// |____________________|
/// |                    |
/// |      Reserved      |   2
/// |____________________|
/// |                    |
/// |    Length (MSB)    |   3
/// |____________________|
/// |                    |
/// |    Length (LSB)    |   4
/// |____________________|
/// |                    |
/// |     X.224 TPDU     |   5 - ?
///          ....
/// ```
///
/// A TPKT header is of fixed length 4, and the following X.224 TPDU is at least three bytes long.
/// Therefore, the minimum TPKT length is 7, and the maximum TPKT length is 65535. Because the TPKT
/// length includes the TPKT header (4 bytes), the maximum X.224 TPDU length is 65531.
#[derive(PartialEq, Eq, Debug)]
pub struct TpktHeader {
    /// This field contains the length of entire packet in octets, including packet-header.
    pub packet_length: u16,
}

impl TpktHeader {
    pub const VERSION: u8 = 3;

    pub const SIZE: usize = 4;

    pub const NAME: &'static str = "TpktHeader";

    const FIXED_PART_SIZE: usize = Self::SIZE;

    pub fn read(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let version = src.read_u8();

        if version != Self::VERSION {
            return Err(unsupported_version_err!("TPKT version", version));
        }

        read_padding!(src, 1);

        let packet_length = src.read_u16_be();

        Ok(Self { packet_length })
    }

    pub fn write(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u8(Self::VERSION);

        write_padding!(dst, 1);

        dst.write_u16_be(self.packet_length);

        Ok(())
    }

    pub fn packet_length(&self) -> usize {
        usize::from(self.packet_length)
    }
}
