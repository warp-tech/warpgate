#[cfg(test)]
mod tests;

use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, ensure_fixed_part_size, invalid_field_err,
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive as _;

const BRUSH_LENGTH: usize = 4;

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, FromPrimitive)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum SupportLevel {
    Default = 0,
    Color8x8 = 1,
    ColorFull = 2,
}

impl SupportLevel {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u32(self) -> u32 {
        self as u32
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Brush {
    pub support_level: SupportLevel,
}

impl Brush {
    const NAME: &'static str = "Brush";

    const FIXED_PART_SIZE: usize = BRUSH_LENGTH;
}

impl Encode for Brush {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u32(self.support_level.as_u32());

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for Brush {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let support_level = SupportLevel::from_u32(src.read_u32())
            .ok_or_else(|| invalid_field_err!("supportLevel", "invalid brush support level"))?;

        Ok(Brush { support_level })
    }
}
