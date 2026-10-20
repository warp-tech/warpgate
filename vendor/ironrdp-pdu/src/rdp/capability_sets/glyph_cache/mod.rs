#[cfg(test)]
mod tests;

use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, ensure_fixed_part_size, invalid_field_err,
    write_padding,
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive as _;

pub const GLYPH_CACHE_NUM: usize = 10;

const GLYPH_CACHE_LENGTH: usize = 48;
const CACHE_DEFINITION_LENGTH: usize = 4;

#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, FromPrimitive)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum GlyphSupportLevel {
    None = 0,
    Partial = 1,
    Full = 2,
    Encode = 3,
}

impl GlyphSupportLevel {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u16(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Default)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct CacheDefinition {
    pub entries: u16,
    pub max_cell_size: u16,
}

impl CacheDefinition {
    const NAME: &'static str = "CacheDefinition";

    const FIXED_PART_SIZE: usize = CACHE_DEFINITION_LENGTH;
}

impl Encode for CacheDefinition {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(self.entries);
        dst.write_u16(self.max_cell_size);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for CacheDefinition {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let entries = src.read_u16();
        let max_cell_size = src.read_u16();

        Ok(CacheDefinition { entries, max_cell_size })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct GlyphCache {
    pub glyph_cache: [CacheDefinition; GLYPH_CACHE_NUM],
    pub frag_cache: CacheDefinition,
    pub glyph_support_level: GlyphSupportLevel,
}

impl GlyphCache {
    const NAME: &'static str = "GlyphCache";

    const FIXED_PART_SIZE: usize = GLYPH_CACHE_LENGTH;
}

impl Encode for GlyphCache {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        for glyph in self.glyph_cache.iter() {
            glyph.encode(dst)?;
        }

        self.frag_cache.encode(dst)?;

        dst.write_u16(self.glyph_support_level.as_u16());
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

impl<'de> Decode<'de> for GlyphCache {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let mut glyph_cache = [CacheDefinition::default(); GLYPH_CACHE_NUM];

        for glyph in glyph_cache.iter_mut() {
            *glyph = CacheDefinition::decode(src)?;
        }

        let frag_cache = CacheDefinition::decode(src)?;
        let glyph_support_level = GlyphSupportLevel::from_u16(src.read_u16())
            .ok_or_else(|| invalid_field_err!("glyphSupport", "invalid glyph support level"))?;
        let _padding = src.read_u16();

        Ok(GlyphCache {
            glyph_cache,
            frag_cache,
            glyph_support_level,
        })
    }
}
