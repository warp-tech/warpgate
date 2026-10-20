use bitflags::bitflags;
use ironrdp_core::{Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, ensure_fixed_part_size};

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct LargePointer {
    pub flags: LargePointerSupportFlags,
}

impl LargePointer {
    const NAME: &'static str = "LargePointer";

    const FIXED_PART_SIZE: usize = 2;
}

impl Encode for LargePointer {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(self.flags.bits());

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for LargePointer {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let flags = LargePointerSupportFlags::from_bits_retain(src.read_u16());

        Ok(Self { flags })
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct LargePointerSupportFlags: u16 {
        const UP_TO_96X96_PIXELS = 1;
        const UP_TO_384X384_PIXELS = 2;

        const _ = !0;
    }
}

#[cfg(test)]
mod test {
    use ironrdp_core::{decode, encode_vec};

    use super::*;

    const LARGE_POINTER_PDU_BUFFER: [u8; 2] = [0x01, 0x00];
    const LARGE_POINTER_PDU: LargePointer = LargePointer {
        flags: LargePointerSupportFlags::UP_TO_96X96_PIXELS,
    };

    #[test]
    fn from_buffer_correctly_parses_large_pointer() {
        assert_eq!(LARGE_POINTER_PDU, decode(LARGE_POINTER_PDU_BUFFER.as_ref()).unwrap());
    }

    #[test]
    fn to_buffer_correctly_serializes_large_pointer() {
        let expected = LARGE_POINTER_PDU_BUFFER.as_ref();

        let buffer = encode_vec(&LARGE_POINTER_PDU).unwrap();
        assert_eq!(expected, buffer.as_slice());
    }

    #[test]
    fn buffer_length_is_correct_for_large_pointer() {
        assert_eq!(LARGE_POINTER_PDU_BUFFER.len(), LARGE_POINTER_PDU.size());
    }
}
