use core::iter;

use bit_field::BitField as _;
use bitflags::bitflags;
use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, cast_length, ensure_fixed_part_size,
    ensure_size, invalid_field_err,
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive as _;

use crate::codecs::rfx::Block;

const CONTEXT_ID: u8 = 0;
const TILE_SIZE: u16 = 0x0040;
const COLOR_CONVERSION_ICT: u16 = 1;
const CLW_XFORM_DWT_53_A: u16 = 1;
const SCALAR_QUANTIZATION: u16 = 1;
const LRF: bool = true;
const CBT_REGION: u16 = 0xcac1;
const NUMBER_OF_TILESETS: u16 = 1;
const CBT_TILESET: u16 = 0xcac2;
const IDX: u16 = 0;
const IS_LAST_TILESET_FLAG: bool = true;
const RECTANGLE_SIZE: usize = 8;

/// [2.2.2.2.4] TS_RFX_CONTEXT
///
/// [2.2.2.2.4]: https://learn.microsoft.com/pt-br/openspecs/windows_protocols/ms-rdprfx/bde1ce78-5d9e-44c1-8a15-5843fa12270a
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ContextPdu {
    pub flags: OperatingMode,
    pub entropy_algorithm: EntropyAlgorithm,
}

impl ContextPdu {
    const NAME: &'static str = "RfxContext";

    const FIXED_PART_SIZE: usize = 1 /* ctxId */ + 2 /* tileSize */ + 2 /* properties */;
}

impl Encode for ContextPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u8(CONTEXT_ID);
        dst.write_u16(TILE_SIZE);

        let mut properties: u16 = 0;
        properties.set_bits(0..3, self.flags.bits());
        properties.set_bits(3..5, COLOR_CONVERSION_ICT);
        properties.set_bits(5..9, CLW_XFORM_DWT_53_A);
        properties.set_bits(9..13, self.entropy_algorithm.as_u16());
        properties.set_bits(13..15, SCALAR_QUANTIZATION);
        properties.set_bit(15, false); // reserved
        dst.write_u16(properties);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for ContextPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let id = src.read_u8();
        if id != CONTEXT_ID {
            return Err(invalid_field_err!("ctxId", "Invalid context ID"));
        }

        let tile_size = src.read_u16();
        if tile_size != TILE_SIZE {
            return Err(invalid_field_err!("tileSize", "Invalid tile size"));
        }

        let properties = src.read_u16();
        let flags = OperatingMode::from_bits_retain(properties.get_bits(0..3));
        let color_conversion_transform = properties.get_bits(3..5);
        if color_conversion_transform != COLOR_CONVERSION_ICT {
            return Err(invalid_field_err!("cct", "Invalid color conversion transform"));
        }

        let dwt = properties.get_bits(5..9);
        if dwt != CLW_XFORM_DWT_53_A {
            return Err(invalid_field_err!("dwt", "Invalid DWT"));
        }

        let entropy_algorithm_bits = properties.get_bits(9..13);
        let entropy_algorithm = EntropyAlgorithm::from_u16(entropy_algorithm_bits)
            .ok_or_else(|| invalid_field_err!("entropy_algorithm", "Invalid entropy algorithm"))?;

        let quantization_type = properties.get_bits(13..15);
        if quantization_type != SCALAR_QUANTIZATION {
            return Err(invalid_field_err!("qt", "Invalid quantization type"));
        }

        let _reserved = properties.get_bit(15);

        Ok(Self {
            flags,
            entropy_algorithm,
        })
    }
}

/// [2.2.2.3.1] TS_RFX_FRAME_BEGIN
///
/// [2.2.2.3.1]: https://learn.microsoft.com/pt-br/openspecs/windows_protocols/ms-rdprfx/7a938a26-3fc2-436b-bc84-09dfff59b5e7
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct FrameBeginPdu {
    pub index: u32,
    pub number_of_regions: i16,
}

impl FrameBeginPdu {
    const NAME: &'static str = "RfxFrameBegin";

    const FIXED_PART_SIZE: usize = 4 /* frameIdx */ + 2 /* numRegions */;
}

impl Encode for FrameBeginPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u32(self.index);
        dst.write_i16(self.number_of_regions);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for FrameBeginPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let index = src.read_u32();
        let number_of_regions = src.read_i16();

        Ok(Self {
            index,
            number_of_regions,
        })
    }
}

/// [2.2.2.3.2] TS_RFX_FRAME_END
///
/// [2.2.2.3.1]: https://learn.microsoft.com/pt-br/openspecs/windows_protocols/ms-rdprfx/b4cb2676-0268-450b-ad32-72f66d0598e8
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct FrameEndPdu;

impl FrameEndPdu {
    const NAME: &'static str = "RfxFrameEnd";

    const FIXED_PART_SIZE: usize = 0;
}

impl Encode for FrameEndPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for FrameEndPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        Ok(Self)
    }
}

/// [2.2.2.3.3] TS_RFX_REGION
///
/// [2.2.2.3.3]: https://learn.microsoft.com/pt-br/openspecs/windows_protocols/ms-rdprfx/23d2a1d6-1be0-4357-83eb-998b66ddd4d9
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct RegionPdu {
    pub rectangles: Vec<RfxRectangle>,
}

impl RegionPdu {
    const NAME: &'static str = "RfxRegion";

    const FIXED_PART_SIZE: usize = 1 /* regionFlags */ + 2 /* numRects */ + 2 /* regionType */ + 2 /* numTilesets */;
}

impl Encode for RegionPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        let mut region_flags = 0;
        region_flags.set_bit(0, LRF);
        dst.write_u8(region_flags);

        dst.write_u16(cast_length!("numRectangles", self.rectangles.len())?);
        for rectangle in self.rectangles.iter() {
            rectangle.encode(dst)?;
        }

        dst.write_u16(CBT_REGION);
        dst.write_u16(NUMBER_OF_TILESETS);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.rectangles.len() * RECTANGLE_SIZE
    }
}

impl<'de> Decode<'de> for RegionPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let region_flags = src.read_u8();
        let lrf = region_flags.get_bit(0);
        if lrf != LRF {
            return Err(invalid_field_err!("lrf", "Invalid lrf"));
        }

        let number_of_rectangles = usize::from(src.read_u16());

        ensure_size!(in: src, size: number_of_rectangles * RECTANGLE_SIZE);

        let rectangles = iter::repeat_with(|| RfxRectangle::decode(src))
            .take(number_of_rectangles)
            .collect::<Result<Vec<_>, _>>()?;

        ensure_size!(in: src, size: 4);

        let region_type = src.read_u16();
        if region_type != CBT_REGION {
            return Err(invalid_field_err!("regionType", "Invalid region type"));
        }

        let number_of_tilesets = src.read_u16();
        if number_of_tilesets != NUMBER_OF_TILESETS {
            return Err(invalid_field_err!("numTilesets", "Invalid number of tilesets"));
        }

        Ok(Self { rectangles })
    }
}

/// [2.2.2.3.4] TS_RFX_TILESET
///
/// [2.2.2.3.4] https://learn.microsoft.com/pt-br/openspecs/windows_protocols/ms-rdprfx/7c926114-4bea-4c69-a9a1-caa6e88847a6
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct TileSetPdu<'a> {
    pub entropy_algorithm: EntropyAlgorithm,
    pub quants: Vec<Quant>,
    pub tiles: Vec<Tile<'a>>,
}

impl TileSetPdu<'_> {
    const NAME: &'static str = "RfxTileSet";

    const FIXED_PART_SIZE: usize = 2 /* subtype */ + 2 /* idx */ + 2 /* properties */ + 1 /* numQuant */ + 1 /* tileSize */+ 2 /* numTiles */ + 4 /* tilesDataSize */;
}

impl Encode for TileSetPdu<'_> {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(CBT_TILESET);
        dst.write_u16(IDX);

        let mut properties: u16 = 0;
        properties.set_bit(0, IS_LAST_TILESET_FLAG);
        properties.set_bits(1..4, OperatingMode::empty().bits()); // The decoder MUST ignore this flag
        properties.set_bits(4..6, COLOR_CONVERSION_ICT);
        properties.set_bits(6..10, CLW_XFORM_DWT_53_A);
        properties.set_bits(10..14, self.entropy_algorithm.as_u16());
        properties.set_bits(14..16, SCALAR_QUANTIZATION);
        dst.write_u16(properties);

        dst.write_u8(cast_length!("numQuant", self.quants.len())?);
        dst.write_u8(u8::try_from(TILE_SIZE).expect("TILE_SIZE value fits into u8"));
        dst.write_u16(cast_length!("numTiles", self.tiles.len())?);

        let tiles_data_size = self.tiles.iter().map(|t| Block::Tile(t.clone()).size()).sum::<usize>();
        dst.write_u32(cast_length!("tilesDataSize", tiles_data_size)?);

        for quant in &self.quants {
            quant.encode(dst)?;
        }

        for tile in &self.tiles {
            Block::Tile(tile.clone()).encode(dst)?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
            + self.quants.iter().map(Encode::size).sum::<usize>()
            + self.tiles.iter().map(|t| Block::Tile(t.clone()).size()).sum::<usize>()
    }
}

impl<'de> Decode<'de> for TileSetPdu<'de> {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let subtype = src.read_u16();
        if subtype != CBT_TILESET {
            return Err(invalid_field_err!("subtype", "Invalid message type"));
        }

        let id_of_context = src.read_u16();
        if id_of_context != IDX {
            return Err(invalid_field_err!("id_of_context", "Invalid RFX context"));
        }

        let properties = src.read_u16();
        let is_last = properties.get_bit(0);
        if is_last != IS_LAST_TILESET_FLAG {
            return Err(invalid_field_err!("last", "Invalid last flag"));
        }

        // The encoder MUST set `flags` value to the value of flags
        // that is set in the properties field of TS_RFX_CONTEXT.
        // The decoder MUST ignore this flag and MUST use the flags specified
        // in the flags field of the TS_RFX_CONTEXT.

        let color_conversion_transform = properties.get_bits(4..6);
        if color_conversion_transform != COLOR_CONVERSION_ICT {
            return Err(invalid_field_err!("cct", "Invalid color conversion"));
        }

        let dwt = properties.get_bits(6..10);
        if dwt != CLW_XFORM_DWT_53_A {
            return Err(invalid_field_err!("xft", "Invalid DWT"));
        }

        let entropy_algorithm_bits = properties.get_bits(10..14);
        let entropy_algorithm = EntropyAlgorithm::from_u16(entropy_algorithm_bits)
            .ok_or_else(|| invalid_field_err!("entropy", "Invalid entropy algorithm"))?;

        let quantization_type = properties.get_bits(14..16);
        if quantization_type != SCALAR_QUANTIZATION {
            return Err(invalid_field_err!("scalar", "Invalid quantization type"));
        }

        let number_of_quants = usize::from(src.read_u8());

        let tile_size = u16::from(src.read_u8());
        if tile_size != TILE_SIZE {
            return Err(invalid_field_err!("tile_size", "Invalid tile size"));
        }

        let number_of_tiles = usize::from(src.read_u16());
        let _tiles_data_size = src.read_u32();

        let quants = iter::repeat_with(|| Quant::decode(src))
            .take(number_of_quants)
            .collect::<Result<Vec<_>, _>>()?;

        let tiles = iter::repeat_with(|| Block::decode(src))
            .take(number_of_tiles)
            .collect::<Result<Vec<_>, _>>()?;

        let tiles = tiles
            .into_iter()
            .map(|b| match b {
                Block::Tile(tile) => Ok(tile),
                _ => Err(invalid_field_err!("tile", "Invalid block type, expected Tile")),
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            entropy_algorithm,
            quants,
            tiles,
        })
    }
}
/// [2.2.2.1.6] TS_RFX_RECT
///
/// [2.2.2.1.6]: https://learn.microsoft.com/pt-br/openspecs/windows_protocols/ms-rdprfx/26eb819a-955b-4b08-b3a0-997231170059
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct RfxRectangle {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
}

impl RfxRectangle {
    const NAME: &'static str = "RfxRectangle";

    const FIXED_PART_SIZE: usize = 4 * 2 /* x, y, width, height */;
}

impl Encode for RfxRectangle {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(self.x);
        dst.write_u16(self.y);
        dst.write_u16(self.width);
        dst.write_u16(self.height);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for RfxRectangle {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let x = src.read_u16();
        let y = src.read_u16();
        let width = src.read_u16();
        let height = src.read_u16();

        Ok(Self { x, y, width, height })
    }
}

/// 2.2.2.1.5 TS_RFX_CODEC_QUANT
///
/// [2.2.2.1.5]: https://learn.microsoft.com/pt-br/openspecs/windows_protocols/ms-rdprfx/3e9c8af4-7539-4c9d-95de-14b1558b902c
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Quant {
    pub ll3: u8,
    pub lh3: u8,
    pub hl3: u8,
    pub hh3: u8,
    pub lh2: u8,
    pub hl2: u8,
    pub hh2: u8,
    pub lh1: u8,
    pub hl1: u8,
    pub hh1: u8,
}

// The quantization values control the compression rate and quality. The value
// range is between 6 and 15. The higher value, the higher compression rate and
// lower quality.
//
// This is the default values being use by the MS RDP server, and we will also
// use it as our default values for the encoder.
impl Default for Quant {
    fn default() -> Self {
        Self {
            ll3: 6,
            lh3: 6,
            hl3: 6,
            hh3: 6,
            lh2: 7,
            hl2: 7,
            hh2: 8,
            lh1: 8,
            hl1: 8,
            hh1: 9,
        }
    }
}

impl Quant {
    const NAME: &'static str = "RfxFrameEnd";

    const FIXED_PART_SIZE: usize = 5 /* 10 * 4 bits */;
}

impl Encode for Quant {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        let mut level3 = 0;
        level3.set_bits(0..4, u16::from(self.ll3));
        level3.set_bits(4..8, u16::from(self.lh3));
        level3.set_bits(8..12, u16::from(self.hl3));
        level3.set_bits(12..16, u16::from(self.hh3));

        let mut level2_with_lh1 = 0;
        level2_with_lh1.set_bits(0..4, u16::from(self.lh2));
        level2_with_lh1.set_bits(4..8, u16::from(self.hl2));
        level2_with_lh1.set_bits(8..12, u16::from(self.hh2));
        level2_with_lh1.set_bits(12..16, u16::from(self.lh1));

        let mut level1 = 0;
        level1.set_bits(0..4, self.hl1);
        level1.set_bits(4..8, self.hh1);

        dst.write_u16(level3);
        dst.write_u16(level2_with_lh1);
        dst.write_u8(level1);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for Quant {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        #![allow(
            clippy::similar_names,
            reason = "it’s hard to do better than ll3, lh3, etc without going overly verbose"
        )]

        ensure_fixed_part_size!(in: src);

        let ll3lh3 = src.read_u8();
        let ll3 = ll3lh3.get_bits(0..4);
        let lh3 = ll3lh3.get_bits(4..8);

        let hl3hh3 = src.read_u8();
        let hl3 = hl3hh3.get_bits(0..4);
        let hh3 = hl3hh3.get_bits(4..8);

        let lh2hl2 = src.read_u8();
        let lh2 = lh2hl2.get_bits(0..4);
        let hl2 = lh2hl2.get_bits(4..8);

        let hh2lh1 = src.read_u8();
        let hh2 = hh2lh1.get_bits(0..4);
        let lh1 = hh2lh1.get_bits(4..8);

        let hl1hh1 = src.read_u8();
        let hl1 = hl1hh1.get_bits(0..4);
        let hh1 = hl1hh1.get_bits(4..8);

        Ok(Self {
            ll3,
            lh3,
            hl3,
            hh3,
            lh2,
            hl2,
            hh2,
            lh1,
            hl1,
            hh1,
        })
    }
}
/// [2.2.2.3.4.1] TS_RFX_TILE
///
/// [2.2.2.3.4.1]: https://learn.microsoft.com/pt-br/openspecs/windows_protocols/ms-rdprfx/89e669ed-b6dd-4591-a267-73a72bc6d84e
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Tile<'a> {
    pub y_quant_index: u8,
    pub cb_quant_index: u8,
    pub cr_quant_index: u8,

    pub x: u16,
    pub y: u16,

    pub y_data: &'a [u8],
    pub cb_data: &'a [u8],
    pub cr_data: &'a [u8],
}

impl Tile<'_> {
    const NAME: &'static str = "RfxTile";

    const FIXED_PART_SIZE: usize = 1 /* quantIdxY */ + 1 /* quantIdxCb */ + 1 /* quantIdxCr */ + 2 /* xIdx */ + 2 /* yIdx */ + 2 /* YLen */ + 2 /* CbLen */ + 2 /* CrLen */;
}

impl Encode for Tile<'_> {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u8(self.y_quant_index);
        dst.write_u8(self.cb_quant_index);
        dst.write_u8(self.cr_quant_index);

        dst.write_u16(self.x);
        dst.write_u16(self.y);

        dst.write_u16(cast_length!("YLen", self.y_data.len())?);
        dst.write_u16(cast_length!("CbLen", self.cb_data.len())?);
        dst.write_u16(cast_length!("CrLen", self.cr_data.len())?);

        dst.write_slice(self.y_data);
        dst.write_slice(self.cb_data);
        dst.write_slice(self.cr_data);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.y_data.len() + self.cb_data.len() + self.cr_data.len()
    }
}

impl<'de> Decode<'de> for Tile<'de> {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        #![allow(clippy::similar_names)] // It’s hard to find better names for cr, cb, etc.
        ensure_fixed_part_size!(in: src);

        let y_quant_index = src.read_u8();
        let cb_quant_index = src.read_u8();
        let cr_quant_index = src.read_u8();

        let x = src.read_u16();
        let y = src.read_u16();

        let y_component_length = usize::from(src.read_u16());
        let cb_component_length = usize::from(src.read_u16());
        let cr_component_length = usize::from(src.read_u16());

        ensure_size!(in: src, size: y_component_length + cb_component_length + cr_component_length);

        let y_data = src.read_slice(y_component_length);
        let cb_data = src.read_slice(cb_component_length);
        let cr_data = src.read_slice(cr_component_length);

        Ok(Self {
            y_quant_index,
            cb_quant_index,
            cr_quant_index,

            x,
            y,

            y_data,
            cb_data,
            cr_data,
        })
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u16)]
pub enum EntropyAlgorithm {
    Rlgr1 = 0x01,
    Rlgr3 = 0x04,
}

impl EntropyAlgorithm {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u16(self) -> u16 {
        self as u16
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct OperatingMode: u16 {
        const IMAGE_MODE = 0x02; // if not set, the codec is operating in video mode

        const _ = !0;
    }
}
