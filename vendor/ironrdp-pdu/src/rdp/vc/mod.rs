#[cfg(test)]
mod tests;

use bitflags::bitflags;
use ironrdp_core::{Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, ensure_fixed_part_size};

const CHANNEL_PDU_HEADER_SIZE: usize = 8;

/// Channel PDU Header (CHANNEL_PDU_HEADER)
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ChannelPduHeader {
    /// The total length in bytes of the uncompressed channel data, excluding this header
    ///
    /// The data can span multiple Virtual Channel PDUs and the individual chunks will need to be
    /// reassembled in that case (section 3.1.5.2.2 of MS-RDPBCGR).
    pub length: u32,
    pub flags: ChannelControlFlags,
}

impl ChannelPduHeader {
    const NAME: &'static str = "ChannelPduHeader";

    const FIXED_PART_SIZE: usize = CHANNEL_PDU_HEADER_SIZE;
}

impl Encode for ChannelPduHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u32(self.length);
        dst.write_u32(self.flags.bits());
        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for ChannelPduHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let total_length = src.read_u32();
        let flags = ChannelControlFlags::from_bits_retain(src.read_u32());
        Ok(Self {
            length: total_length,
            flags,
        })
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct ChannelControlFlags: u32 {
        const FLAG_FIRST = 0x0000_0001;
        const FLAG_LAST = 0x0000_0002;
        const FLAG_SHOW_PROTOCOL = 0x0000_0010;
        const FLAG_SUSPEND = 0x0000_0020;
        const FLAG_RESUME  = 0x0000_0040;
        const FLAG_SHADOW_PERSISTENT = 0x0000_0080;
        const PACKET_COMPRESSED = 0x0020_0000;
        const PACKET_AT_FRONT = 0x0040_0000;
        const PACKET_FLUSHED = 0x0080_0000;
        const COMPRESSION_TYPE_MASK = 0x000F_0000;

        const _ = !0;
    }
}
