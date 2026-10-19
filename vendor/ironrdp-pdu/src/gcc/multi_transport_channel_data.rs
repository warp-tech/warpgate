use bitflags::bitflags;
use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, ensure_fixed_part_size, invalid_field_err,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct MultiTransportChannelData {
    pub flags: MultiTransportFlags,
}

impl MultiTransportChannelData {
    const NAME: &'static str = "MultiTransportChannelData";

    const FIXED_PART_SIZE: usize = 4 /* flags */;
}

impl Encode for MultiTransportChannelData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

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

impl<'de> Decode<'de> for MultiTransportChannelData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let flags = MultiTransportFlags::from_bits(src.read_u32())
            .ok_or_else(|| invalid_field_err!("flags", "invalid multitransport flags"))?;

        Ok(Self { flags })
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct MultiTransportFlags: u32 {
        const TRANSPORT_TYPE_UDP_FECR = 0x01;
        const TRANSPORT_TYPE_UDP_FECL = 0x04;
        const TRANSPORT_TYPE_UDP_PREFERRED = 0x100;
        const SOFT_SYNC_TCP_TO_UDP = 0x200;
    }
}
