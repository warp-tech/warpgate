use bitflags::bitflags;
use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, ensure_fixed_part_size, read_padding,
    write_padding,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ScanCodePdu {
    pub flags: KeyboardFlags,
    pub key_code: u16,
}

impl ScanCodePdu {
    const NAME: &'static str = "ScanCodePdu";

    const FIXED_PART_SIZE: usize = 2 /* flags */ + 2 /* keycode */ + 2 /* padding */;
}

impl Encode for ScanCodePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(self.flags.bits());
        dst.write_u16(self.key_code);
        write_padding!(dst, 2);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for ScanCodePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let flags = KeyboardFlags::from_bits_retain(src.read_u16());
        let key_code = src.read_u16();
        read_padding!(src, 2);

        Ok(Self { flags, key_code })
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct KeyboardFlags: u16 {
        const EXTENDED = 0x0100;
        const EXTENDED_1 = 0x0200;
        const DOWN = 0x4000;
        const RELEASE = 0x8000;

        const _ = !0;
    }
}
