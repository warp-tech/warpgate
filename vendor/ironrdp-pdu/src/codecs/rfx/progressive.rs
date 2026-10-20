//! RemoteFX Progressive Codec wire types ([MS-RDPEGFX] 2.2.4.2).
//!
//! The progressive codec delivers multi-pass bitmap updates via
//! `WireToSurface2Pdu` (codecId 0x0009). Tiles start at coarse quality
//! and refine over successive upgrade passes.
//!
//! Block types share a 6-byte header: `blockType(u16) + blockLen(u32)`.
//! The payload of a `WireToSurface2Pdu.bitmapData` is a sequence of these
//! blocks forming a progressive bitmap stream.

use core::iter;

use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, cast_length, ensure_fixed_part_size,
    ensure_size, invalid_field_err,
};

use super::RfxRectangle;

// Wire constants
const SYNC_MAGIC: u32 = 0xCACCACCA;
const SYNC_VERSION: u16 = 0x0100;
const TILE_SIZE: u16 = 0x0040;
/// Block header size as u32 for checked_sub arithmetic (avoids `as` cast).
const BLOCK_HEADER_SIZE_U32: u32 = 6;

/// Progressive block type discriminator.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u16)]
pub enum ProgressiveBlockType {
    Sync = 0xCCC0,
    FrameBegin = 0xCCC1,
    FrameEnd = 0xCCC2,
    Context = 0xCCC3,
    Region = 0xCCC4,
    TileSimple = 0xCCC5,
    TileFirst = 0xCCC6,
    TileUpgrade = 0xCCC7,
}

impl ProgressiveBlockType {
    fn from_u16(val: u16) -> Option<Self> {
        match val {
            0xCCC0 => Some(Self::Sync),
            0xCCC1 => Some(Self::FrameBegin),
            0xCCC2 => Some(Self::FrameEnd),
            0xCCC3 => Some(Self::Context),
            0xCCC4 => Some(Self::Region),
            0xCCC5 => Some(Self::TileSimple),
            0xCCC6 => Some(Self::TileFirst),
            0xCCC7 => Some(Self::TileUpgrade),
            _ => None,
        }
    }

    #[expect(
        clippy::as_conversions,
        reason = "repr(u16) discriminant cast is the canonical pattern"
    )]
    fn as_u16(self) -> u16 {
        self as u16
    }
}

/// 6-byte block header shared by all progressive blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ProgressiveBlockHeader {
    pub block_type: ProgressiveBlockType,
    pub block_len: u32,
}

impl ProgressiveBlockHeader {
    const NAME: &'static str = "ProgressiveBlockHeader";
    pub const SIZE: usize = 6;
    const FIXED_PART_SIZE: usize = Self::SIZE;
}

impl Encode for ProgressiveBlockHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);
        dst.write_u16(self.block_type.as_u16());
        dst.write_u32(self.block_len);
        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::SIZE
    }
}

impl Decode<'_> for ProgressiveBlockHeader {
    fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);
        let raw = src.read_u16();
        let block_type = ProgressiveBlockType::from_u16(raw)
            .ok_or_else(|| invalid_field_err!("blockType", "unknown progressive block type"))?;
        let block_len = src.read_u32();
        Ok(Self { block_type, block_len })
    }
}

// ---------------------------------------------------------------------------
// Quantization types (progressive nibble order)
// ---------------------------------------------------------------------------

/// Per-component quantization values with the progressive nibble packing.
///
/// The progressive codec swaps HL/LH at each level compared to classic RFX:
/// Classic:      LL3, LH3, HL3, HH3, LH2, HL2, HH2, LH1, HL1, HH1
/// Progressive:  LL3, HL3, LH3, HH3, HL2, LH2, HH2, HL1, LH1, HH1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ComponentCodecQuant {
    pub ll3: u8,
    pub hl3: u8,
    pub lh3: u8,
    pub hh3: u8,
    pub hl2: u8,
    pub lh2: u8,
    pub hh2: u8,
    pub hl1: u8,
    pub lh1: u8,
    pub hh1: u8,
}

impl ComponentCodecQuant {
    const NAME: &'static str = "ComponentCodecQuant";
    /// 10 nibbles packed into 5 bytes.
    pub const SIZE: usize = 5;
    const FIXED_PART_SIZE: usize = Self::SIZE;

    /// All-zero quant (no extra quantization, full quality).
    pub const LOSSLESS: Self = Self {
        ll3: 0,
        hl3: 0,
        lh3: 0,
        hh3: 0,
        hl2: 0,
        lh2: 0,
        hh2: 0,
        hl1: 0,
        lh1: 0,
        hh1: 0,
    };

    /// Return the quantization value for a given subband index (0..9).
    /// Band order: HL1, LH1, HH1, HL2, LH2, HH2, HL3, LH3, HH3, LL3
    pub fn for_band(&self, band_idx: usize) -> u8 {
        match band_idx {
            0 => self.hl1,
            1 => self.lh1,
            2 => self.hh1,
            3 => self.hl2,
            4 => self.lh2,
            5 => self.hh2,
            6 => self.hl3,
            7 => self.lh3,
            8 => self.hh3,
            9 => self.ll3,
            _ => 0,
        }
    }
}

impl Encode for ComponentCodecQuant {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);
        // Progressive nibble order: LL3|HL3, LH3|HH3, HL2|LH2, HH2|HL1, LH1|HH1
        dst.write_u8(self.ll3 | (self.hl3 << 4));
        dst.write_u8(self.lh3 | (self.hh3 << 4));
        dst.write_u8(self.hl2 | (self.lh2 << 4));
        dst.write_u8(self.hh2 | (self.hl1 << 4));
        dst.write_u8(self.lh1 | (self.hh1 << 4));
        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::SIZE
    }
}

impl Decode<'_> for ComponentCodecQuant {
    fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);
        let b0 = src.read_u8();
        let b1 = src.read_u8();
        let b2 = src.read_u8();
        let b3 = src.read_u8();
        let b4 = src.read_u8();
        Ok(Self {
            ll3: b0 & 0x0F,
            hl3: b0 >> 4,
            lh3: b1 & 0x0F,
            hh3: b1 >> 4,
            hl2: b2 & 0x0F,
            lh2: b2 >> 4,
            hh2: b3 & 0x0F,
            hl1: b3 >> 4,
            lh1: b4 & 0x0F,
            hh1: b4 >> 4,
        })
    }
}

/// Per-quality-level progressive quantization: quality byte + 3 component quants.
///
/// `quality` ranges from 0 (minimum) to 0xFF (full quality / no extra quantization).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ProgressiveCodecQuant {
    pub quality: u8,
    pub y_quant: ComponentCodecQuant,
    pub cb_quant: ComponentCodecQuant,
    pub cr_quant: ComponentCodecQuant,
}

impl ProgressiveCodecQuant {
    const NAME: &'static str = "ProgressiveCodecQuant";
    /// 1 byte quality + 3 x 5 bytes = 16 bytes.
    pub const SIZE: usize = 16;
    const FIXED_PART_SIZE: usize = Self::SIZE;
}

impl Encode for ProgressiveCodecQuant {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);
        dst.write_u8(self.quality);
        self.y_quant.encode(dst)?;
        self.cb_quant.encode(dst)?;
        self.cr_quant.encode(dst)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::SIZE
    }
}

impl Decode<'_> for ProgressiveCodecQuant {
    #[expect(clippy::similar_names, reason = "y/cb/cr quant names follow spec terminology")]
    fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);
        let quality = src.read_u8();
        let y_quant = ComponentCodecQuant::decode(src)?;
        let cb_quant = ComponentCodecQuant::decode(src)?;
        let cr_quant = ComponentCodecQuant::decode(src)?;
        Ok(Self {
            quality,
            y_quant,
            cb_quant,
            cr_quant,
        })
    }
}

// ---------------------------------------------------------------------------
// Individual block types
// ---------------------------------------------------------------------------

/// RFX_PROGRESSIVE_SYNC: magic 0xCACCACCA + version 0x0100.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ProgressiveSyncPdu;

impl ProgressiveSyncPdu {
    const NAME: &'static str = "ProgressiveSync";
    const FIXED_PART_SIZE: usize = 4 /* magic */ + 2 /* version */;
}

impl Encode for ProgressiveSyncPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);
        dst.write_u32(SYNC_MAGIC);
        dst.write_u16(SYNC_VERSION);
        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl Decode<'_> for ProgressiveSyncPdu {
    fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);
        let magic = src.read_u32();
        if magic != SYNC_MAGIC {
            return Err(invalid_field_err!("magic", "invalid progressive sync magic"));
        }
        let version = src.read_u16();
        if version != SYNC_VERSION {
            return Err(invalid_field_err!("version", "unsupported progressive version"));
        }
        Ok(Self)
    }
}

/// RFX_PROGRESSIVE_FRAME_BEGIN.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ProgressiveFrameBeginPdu {
    pub frame_index: u32,
    pub region_count: u16,
}

impl ProgressiveFrameBeginPdu {
    const NAME: &'static str = "ProgressiveFrameBegin";
    const FIXED_PART_SIZE: usize = 4 /* frameIndex */ + 2 /* regionCount */;
}

impl Encode for ProgressiveFrameBeginPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);
        dst.write_u32(self.frame_index);
        dst.write_u16(self.region_count);
        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl Decode<'_> for ProgressiveFrameBeginPdu {
    fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);
        let frame_index = src.read_u32();
        let region_count = src.read_u16();
        Ok(Self {
            frame_index,
            region_count,
        })
    }
}

/// RFX_PROGRESSIVE_FRAME_END (empty body).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ProgressiveFrameEndPdu;

impl ProgressiveFrameEndPdu {
    const NAME: &'static str = "ProgressiveFrameEnd";
    const FIXED_PART_SIZE: usize = 0;
}

impl Encode for ProgressiveFrameEndPdu {
    fn encode(&self, _dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl Decode<'_> for ProgressiveFrameEndPdu {
    fn decode(_src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        Ok(Self)
    }
}

/// RFX_PROGRESSIVE_CONTEXT.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ProgressiveContextPdu {
    pub context_id: u8,
    pub tile_size: u16,
    pub flags: u8,
}

/// Bit 0 of context flags: use reduce-extrapolate DWT.
pub const FLAG_DWT_REDUCE_EXTRAPOLATE: u8 = 0x01;

impl ProgressiveContextPdu {
    const NAME: &'static str = "ProgressiveContext";
    const FIXED_PART_SIZE: usize = 1 /* ctxId */ + 2 /* tileSize */ + 1 /* flags */;

    /// Whether the reduce-extrapolate DWT variant is selected.
    pub fn uses_reduce_extrapolate(&self) -> bool {
        self.flags & FLAG_DWT_REDUCE_EXTRAPOLATE != 0
    }
}

impl Encode for ProgressiveContextPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);
        dst.write_u8(self.context_id);
        dst.write_u16(self.tile_size);
        dst.write_u8(self.flags);
        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl Decode<'_> for ProgressiveContextPdu {
    fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);
        let context_id = src.read_u8();
        let tile_size = src.read_u16();
        if tile_size != TILE_SIZE {
            return Err(invalid_field_err!("tileSize", "only 64x64 tiles supported"));
        }
        let flags = src.read_u8();
        Ok(Self {
            context_id,
            tile_size,
            flags,
        })
    }
}

// ---------------------------------------------------------------------------
// Tile blocks
// ---------------------------------------------------------------------------

/// TILE_SIMPLE: non-progressive full-quality tile (single pass).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct TileSimple<'a> {
    pub quant_idx_y: u8,
    pub quant_idx_cb: u8,
    pub quant_idx_cr: u8,
    pub x_idx: u16,
    pub y_idx: u16,
    pub flags: u8,
    pub y_data: &'a [u8],
    pub cb_data: &'a [u8],
    pub cr_data: &'a [u8],
    pub tail_data: &'a [u8],
}

impl TileSimple<'_> {
    const NAME: &'static str = "TileSimple";
    /// Fixed header: 3 quant idx + 2 x_idx + 2 y_idx + 1 flags + 4x2 lengths = 16 bytes.
    const HEADER_SIZE: usize = 3 + 2 + 2 + 1 + 8;
}

impl Encode for TileSimple<'_> {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());
        dst.write_u8(self.quant_idx_y);
        dst.write_u8(self.quant_idx_cb);
        dst.write_u8(self.quant_idx_cr);
        dst.write_u16(self.x_idx);
        dst.write_u16(self.y_idx);
        dst.write_u8(self.flags);
        dst.write_u16(cast_length!("yLen", self.y_data.len())?);
        dst.write_u16(cast_length!("cbLen", self.cb_data.len())?);
        dst.write_u16(cast_length!("crLen", self.cr_data.len())?);
        dst.write_u16(cast_length!("tailLen", self.tail_data.len())?);
        dst.write_slice(self.y_data);
        dst.write_slice(self.cb_data);
        dst.write_slice(self.cr_data);
        dst.write_slice(self.tail_data);
        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::HEADER_SIZE + self.y_data.len() + self.cb_data.len() + self.cr_data.len() + self.tail_data.len()
    }
}

impl<'de> Decode<'de> for TileSimple<'de> {
    #[expect(clippy::similar_names, reason = "y/cb/cr quant and length names follow spec")]
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_size!(ctx: Self::NAME, in: src, size: Self::HEADER_SIZE);
        let quant_idx_y = src.read_u8();
        let quant_idx_cb = src.read_u8();
        let quant_idx_cr = src.read_u8();
        let x_idx = src.read_u16();
        let y_idx = src.read_u16();
        let flags = src.read_u8();
        let y_len = usize::from(src.read_u16());
        let cb_len = usize::from(src.read_u16());
        let cr_len = usize::from(src.read_u16());
        let tail_len = usize::from(src.read_u16());

        let total = y_len + cb_len + cr_len + tail_len;
        ensure_size!(ctx: Self::NAME, in: src, size: total);
        let y_data = src.read_slice(y_len);
        let cb_data = src.read_slice(cb_len);
        let cr_data = src.read_slice(cr_len);
        let tail_data = src.read_slice(tail_len);

        Ok(Self {
            quant_idx_y,
            quant_idx_cb,
            quant_idx_cr,
            x_idx,
            y_idx,
            flags,
            y_data,
            cb_data,
            cr_data,
            tail_data,
        })
    }
}

/// TILE_FIRST: first progressive pass (coarse quality).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct TileFirst<'a> {
    pub quant_idx_y: u8,
    pub quant_idx_cb: u8,
    pub quant_idx_cr: u8,
    pub x_idx: u16,
    pub y_idx: u16,
    pub flags: u8,
    pub quality: u8,
    pub y_data: &'a [u8],
    pub cb_data: &'a [u8],
    pub cr_data: &'a [u8],
    pub tail_data: &'a [u8],
}

impl TileFirst<'_> {
    const NAME: &'static str = "TileFirst";
    /// Same as TileSimple + 1 byte for quality = 17 bytes.
    const HEADER_SIZE: usize = 3 + 2 + 2 + 1 + 1 + 8;
}

impl Encode for TileFirst<'_> {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());
        dst.write_u8(self.quant_idx_y);
        dst.write_u8(self.quant_idx_cb);
        dst.write_u8(self.quant_idx_cr);
        dst.write_u16(self.x_idx);
        dst.write_u16(self.y_idx);
        dst.write_u8(self.flags);
        dst.write_u8(self.quality);
        dst.write_u16(cast_length!("yLen", self.y_data.len())?);
        dst.write_u16(cast_length!("cbLen", self.cb_data.len())?);
        dst.write_u16(cast_length!("crLen", self.cr_data.len())?);
        dst.write_u16(cast_length!("tailLen", self.tail_data.len())?);
        dst.write_slice(self.y_data);
        dst.write_slice(self.cb_data);
        dst.write_slice(self.cr_data);
        dst.write_slice(self.tail_data);
        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::HEADER_SIZE + self.y_data.len() + self.cb_data.len() + self.cr_data.len() + self.tail_data.len()
    }
}

impl<'de> Decode<'de> for TileFirst<'de> {
    #[expect(clippy::similar_names, reason = "y/cb/cr quant and length names follow spec")]
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_size!(ctx: Self::NAME, in: src, size: Self::HEADER_SIZE);
        let quant_idx_y = src.read_u8();
        let quant_idx_cb = src.read_u8();
        let quant_idx_cr = src.read_u8();
        let x_idx = src.read_u16();
        let y_idx = src.read_u16();
        let flags = src.read_u8();
        let quality = src.read_u8();
        let y_len = usize::from(src.read_u16());
        let cb_len = usize::from(src.read_u16());
        let cr_len = usize::from(src.read_u16());
        let tail_len = usize::from(src.read_u16());

        let total = y_len + cb_len + cr_len + tail_len;
        ensure_size!(ctx: Self::NAME, in: src, size: total);
        let y_data = src.read_slice(y_len);
        let cb_data = src.read_slice(cb_len);
        let cr_data = src.read_slice(cr_len);
        let tail_data = src.read_slice(tail_len);

        Ok(Self {
            quant_idx_y,
            quant_idx_cb,
            quant_idx_cr,
            x_idx,
            y_idx,
            flags,
            quality,
            y_data,
            cb_data,
            cr_data,
            tail_data,
        })
    }
}

/// TILE_UPGRADE: progressive refinement pass.
///
/// Each component has separate SRL and raw data streams.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct TileUpgrade<'a> {
    pub quant_idx_y: u8,
    pub quant_idx_cb: u8,
    pub quant_idx_cr: u8,
    pub x_idx: u16,
    pub y_idx: u16,
    pub quality: u8,
    pub y_srl_data: &'a [u8],
    pub y_raw_data: &'a [u8],
    pub cb_srl_data: &'a [u8],
    pub cb_raw_data: &'a [u8],
    pub cr_srl_data: &'a [u8],
    pub cr_raw_data: &'a [u8],
}

impl TileUpgrade<'_> {
    const NAME: &'static str = "TileUpgrade";
    /// 3 quant + 2 x + 2 y + 1 quality + 6x2 lengths = 20 bytes.
    const HEADER_SIZE: usize = 3 + 2 + 2 + 1 + 12;
}

impl Encode for TileUpgrade<'_> {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());
        dst.write_u8(self.quant_idx_y);
        dst.write_u8(self.quant_idx_cb);
        dst.write_u8(self.quant_idx_cr);
        dst.write_u16(self.x_idx);
        dst.write_u16(self.y_idx);
        dst.write_u8(self.quality);
        dst.write_u16(cast_length!("ySrlLen", self.y_srl_data.len())?);
        dst.write_u16(cast_length!("yRawLen", self.y_raw_data.len())?);
        dst.write_u16(cast_length!("cbSrlLen", self.cb_srl_data.len())?);
        dst.write_u16(cast_length!("cbRawLen", self.cb_raw_data.len())?);
        dst.write_u16(cast_length!("crSrlLen", self.cr_srl_data.len())?);
        dst.write_u16(cast_length!("crRawLen", self.cr_raw_data.len())?);
        dst.write_slice(self.y_srl_data);
        dst.write_slice(self.y_raw_data);
        dst.write_slice(self.cb_srl_data);
        dst.write_slice(self.cb_raw_data);
        dst.write_slice(self.cr_srl_data);
        dst.write_slice(self.cr_raw_data);
        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::HEADER_SIZE
            + self.y_srl_data.len()
            + self.y_raw_data.len()
            + self.cb_srl_data.len()
            + self.cb_raw_data.len()
            + self.cr_srl_data.len()
            + self.cr_raw_data.len()
    }
}

impl<'de> Decode<'de> for TileUpgrade<'de> {
    #[expect(clippy::similar_names, reason = "SRL/raw per component is inherently similar")]
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_size!(ctx: Self::NAME, in: src, size: Self::HEADER_SIZE);
        let quant_idx_y = src.read_u8();
        let quant_idx_cb = src.read_u8();
        let quant_idx_cr = src.read_u8();
        let x_idx = src.read_u16();
        let y_idx = src.read_u16();
        let quality = src.read_u8();
        let y_srl_len = usize::from(src.read_u16());
        let y_raw_len = usize::from(src.read_u16());
        let cb_srl_len = usize::from(src.read_u16());
        let cb_raw_len = usize::from(src.read_u16());
        let cr_srl_len = usize::from(src.read_u16());
        let cr_raw_len = usize::from(src.read_u16());

        let total = y_srl_len + y_raw_len + cb_srl_len + cb_raw_len + cr_srl_len + cr_raw_len;
        ensure_size!(ctx: Self::NAME, in: src, size: total);
        let y_srl_data = src.read_slice(y_srl_len);
        let y_raw_data = src.read_slice(y_raw_len);
        let cb_srl_data = src.read_slice(cb_srl_len);
        let cb_raw_data = src.read_slice(cb_raw_len);
        let cr_srl_data = src.read_slice(cr_srl_len);
        let cr_raw_data = src.read_slice(cr_raw_len);

        Ok(Self {
            quant_idx_y,
            quant_idx_cb,
            quant_idx_cr,
            x_idx,
            y_idx,
            quality,
            y_srl_data,
            y_raw_data,
            cb_srl_data,
            cb_raw_data,
            cr_srl_data,
            cr_raw_data,
        })
    }
}

// ---------------------------------------------------------------------------
// Region container
// ---------------------------------------------------------------------------

/// A progressive tile: one of the three tile block types.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum ProgressiveTile<'a> {
    Simple(TileSimple<'a>),
    First(TileFirst<'a>),
    Upgrade(TileUpgrade<'a>),
}

impl ProgressiveTile<'_> {
    pub fn x_idx(&self) -> u16 {
        match self {
            Self::Simple(t) => t.x_idx,
            Self::First(t) => t.x_idx,
            Self::Upgrade(t) => t.x_idx,
        }
    }

    pub fn y_idx(&self) -> u16 {
        match self {
            Self::Simple(t) => t.y_idx,
            Self::First(t) => t.y_idx,
            Self::Upgrade(t) => t.y_idx,
        }
    }
}

/// RFX_PROGRESSIVE_REGION: the main container holding rects, quant tables, and tiles.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ProgressiveRegion<'a> {
    pub tile_size: u8,
    pub rects: Vec<RfxRectangle>,
    pub quant_vals: Vec<ComponentCodecQuant>,
    pub quant_prog_vals: Vec<ProgressiveCodecQuant>,
    pub flags: u8,
    pub tiles: Vec<ProgressiveTile<'a>>,
}

impl ProgressiveRegion<'_> {
    const NAME: &'static str = "ProgressiveRegion";
    /// tileSize(1) + numRects(2) + numQuant(1) + numProgQuant(1)
    /// + flags(1) + numTiles(2) + tileDataSize(4) = 12 bytes.
    const HEADER_SIZE: usize = 12;

    /// Whether this region uses the reduce-extrapolate DWT variant.
    pub fn uses_reduce_extrapolate(&self) -> bool {
        self.flags & FLAG_DWT_REDUCE_EXTRAPOLATE != 0
    }
}

impl Encode for ProgressiveRegion<'_> {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u8(self.tile_size);
        dst.write_u16(cast_length!("numRects", self.rects.len())?);
        dst.write_u8(cast_length!("numQuant", self.quant_vals.len())?);
        dst.write_u8(cast_length!("numProgQuant", self.quant_prog_vals.len())?);
        dst.write_u8(self.flags);
        dst.write_u16(cast_length!("numTiles", self.tiles.len())?);

        // Compute tile data size (sum of block header + tile body for each tile)
        let tile_data_size: usize = self
            .tiles
            .iter()
            .map(|t| {
                ProgressiveBlockHeader::SIZE
                    + match t {
                        ProgressiveTile::Simple(s) => s.size(),
                        ProgressiveTile::First(f) => f.size(),
                        ProgressiveTile::Upgrade(u) => u.size(),
                    }
            })
            .sum();
        dst.write_u32(cast_length!("tileDataSize", tile_data_size)?);

        for rect in &self.rects {
            rect.encode(dst)?;
        }
        for qv in &self.quant_vals {
            qv.encode(dst)?;
        }
        for qpv in &self.quant_prog_vals {
            qpv.encode(dst)?;
        }

        // Each tile is wrapped in a block header
        for tile in &self.tiles {
            let (block_type, body_size) = match tile {
                ProgressiveTile::Simple(s) => (ProgressiveBlockType::TileSimple, s.size()),
                ProgressiveTile::First(f) => (ProgressiveBlockType::TileFirst, f.size()),
                ProgressiveTile::Upgrade(u) => (ProgressiveBlockType::TileUpgrade, u.size()),
            };
            let block_len: u32 = cast_length!("tileBlockLen", ProgressiveBlockHeader::SIZE + body_size)?;
            let header = ProgressiveBlockHeader { block_type, block_len };
            header.encode(dst)?;
            match tile {
                ProgressiveTile::Simple(s) => s.encode(dst)?,
                ProgressiveTile::First(f) => f.encode(dst)?,
                ProgressiveTile::Upgrade(u) => u.encode(dst)?,
            }
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        let rect_size: usize = self.rects.iter().map(Encode::size).sum();
        let quant_size = self.quant_vals.len() * ComponentCodecQuant::SIZE;
        let prog_quant_size = self.quant_prog_vals.len() * ProgressiveCodecQuant::SIZE;
        let tile_data_size: usize = self
            .tiles
            .iter()
            .map(|t| {
                ProgressiveBlockHeader::SIZE
                    + match t {
                        ProgressiveTile::Simple(s) => s.size(),
                        ProgressiveTile::First(f) => f.size(),
                        ProgressiveTile::Upgrade(u) => u.size(),
                    }
            })
            .sum();
        Self::HEADER_SIZE + rect_size + quant_size + prog_quant_size + tile_data_size
    }
}

impl<'de> Decode<'de> for ProgressiveRegion<'de> {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_size!(ctx: Self::NAME, in: src, size: Self::HEADER_SIZE);

        let tile_size = src.read_u8();
        if tile_size != 0x40 {
            return Err(invalid_field_err!("tileSize", "only 64x64 tiles supported"));
        }

        let num_rects = usize::from(src.read_u16());
        let num_quant = usize::from(src.read_u8());
        let num_prog_quant = usize::from(src.read_u8());
        let flags = src.read_u8();

        if num_rects == 0 {
            return Err(invalid_field_err!(
                "numRects",
                "region must contain at least one rectangle"
            ));
        }
        if num_quant > 7 {
            return Err(invalid_field_err!("numQuant", "quant count exceeds maximum of 7"));
        }
        let num_tiles = usize::from(src.read_u16());
        let _tile_data_size = src.read_u32();

        // Rectangles (4 x u16 = 8 bytes each)
        const RFX_RECT_SIZE: usize = 8;
        ensure_size!(ctx: Self::NAME, in: src, size: num_rects * RFX_RECT_SIZE);
        let rects = iter::repeat_with(|| RfxRectangle::decode(src))
            .take(num_rects)
            .collect::<Result<Vec<_>, _>>()?;

        // Base quantization values
        ensure_size!(ctx: Self::NAME, in: src, size: num_quant * ComponentCodecQuant::SIZE);
        let quant_vals = iter::repeat_with(|| ComponentCodecQuant::decode(src))
            .take(num_quant)
            .collect::<Result<Vec<_>, _>>()?;

        // Progressive quantization values
        ensure_size!(ctx: Self::NAME, in: src, size: num_prog_quant * ProgressiveCodecQuant::SIZE);
        let quant_prog_vals = iter::repeat_with(|| ProgressiveCodecQuant::decode(src))
            .take(num_prog_quant)
            .collect::<Result<Vec<_>, _>>()?;

        // Tile blocks (each preceded by a block header)
        let mut tiles = Vec::with_capacity(num_tiles);
        for _ in 0..num_tiles {
            let header = ProgressiveBlockHeader::decode(src)?;
            let body_len = header
                .block_len
                .checked_sub(BLOCK_HEADER_SIZE_U32)
                .ok_or_else(|| invalid_field_err!("blockLen", "tile block length too small"))?;
            let body_len: usize = cast_length!("tileBodyLen", body_len)?;
            ensure_size!(ctx: Self::NAME, in: src, size: body_len);
            let tile_src = &mut ReadCursor::new(src.read_slice(body_len));

            let tile = match header.block_type {
                ProgressiveBlockType::TileSimple => ProgressiveTile::Simple(TileSimple::decode(tile_src)?),
                ProgressiveBlockType::TileFirst => ProgressiveTile::First(TileFirst::decode(tile_src)?),
                ProgressiveBlockType::TileUpgrade => ProgressiveTile::Upgrade(TileUpgrade::decode(tile_src)?),
                _ => {
                    return Err(invalid_field_err!("blockType", "expected tile block inside region"));
                }
            };
            tiles.push(tile);
        }

        let quant_count = quant_vals.len();
        for tile in &tiles {
            let indices = match tile {
                ProgressiveTile::Simple(t) => [t.quant_idx_y, t.quant_idx_cb, t.quant_idx_cr],
                ProgressiveTile::First(t) => [t.quant_idx_y, t.quant_idx_cb, t.quant_idx_cr],
                ProgressiveTile::Upgrade(t) => [t.quant_idx_y, t.quant_idx_cb, t.quant_idx_cr],
            };
            if indices.iter().any(|&i| usize::from(i) >= quant_count) {
                return Err(invalid_field_err!("quantIdx", "tile quant index out of range"));
            }
        }

        Ok(Self {
            tile_size,
            rects,
            quant_vals,
            quant_prog_vals,
            flags,
            tiles,
        })
    }
}

// ---------------------------------------------------------------------------
// Top-level block enum + stream parser
// ---------------------------------------------------------------------------

/// A progressive block in the bitmap stream.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum ProgressiveBlock<'a> {
    Sync(ProgressiveSyncPdu),
    FrameBegin(ProgressiveFrameBeginPdu),
    FrameEnd(ProgressiveFrameEndPdu),
    Context(ProgressiveContextPdu),
    Region(ProgressiveRegion<'a>),
}

/// Parse a progressive bitmap stream (the `bitmapData` from `WireToSurface2Pdu`).
///
/// Returns the sequence of progressive blocks. The stream always starts with
/// SYNC + CONTEXT, followed by FRAME_BEGIN, one or more REGION blocks (containing
/// tiles), and FRAME_END.
pub fn decode_progressive_stream<'a>(data: &'a [u8]) -> DecodeResult<Vec<ProgressiveBlock<'a>>> {
    let mut blocks = Vec::new();
    let mut src = ReadCursor::new(data);

    while src.len() >= ProgressiveBlockHeader::SIZE {
        let header = ProgressiveBlockHeader::decode(&mut src)?;
        let body_len = header
            .block_len
            .checked_sub(BLOCK_HEADER_SIZE_U32)
            .ok_or_else(|| invalid_field_err!("blockLen", "block length too small"))?;
        let body_len: usize = cast_length!("bodyLen", body_len)?;
        ensure_size!(ctx: "ProgressiveStream", in: src, size: body_len);

        // Fixed-size blocks have normative blockLen values (MS-RDPEGFX 2.2.4.2.1)
        let expected_body: Option<usize> = match header.block_type {
            ProgressiveBlockType::Sync => Some(ProgressiveSyncPdu::FIXED_PART_SIZE),
            ProgressiveBlockType::FrameBegin => Some(ProgressiveFrameBeginPdu::FIXED_PART_SIZE),
            ProgressiveBlockType::FrameEnd => Some(ProgressiveFrameEndPdu::FIXED_PART_SIZE),
            ProgressiveBlockType::Context => Some(ProgressiveContextPdu::FIXED_PART_SIZE),
            _ => None,
        };
        if let Some(expected) = expected_body {
            if body_len != expected {
                return Err(invalid_field_err!("blockLen", "unexpected size for fixed-size block"));
            }
        }

        let body_src = &mut ReadCursor::new(src.read_slice(body_len));

        let block = match header.block_type {
            ProgressiveBlockType::Sync => ProgressiveBlock::Sync(ProgressiveSyncPdu::decode(body_src)?),
            ProgressiveBlockType::FrameBegin => {
                ProgressiveBlock::FrameBegin(ProgressiveFrameBeginPdu::decode(body_src)?)
            }
            ProgressiveBlockType::FrameEnd => ProgressiveBlock::FrameEnd(ProgressiveFrameEndPdu::decode(body_src)?),
            ProgressiveBlockType::Context => ProgressiveBlock::Context(ProgressiveContextPdu::decode(body_src)?),
            ProgressiveBlockType::Region => ProgressiveBlock::Region(ProgressiveRegion::decode(body_src)?),
            // Tile blocks should only appear inside regions; skip at top level
            ProgressiveBlockType::TileSimple | ProgressiveBlockType::TileFirst | ProgressiveBlockType::TileUpgrade => {
                return Err(invalid_field_err!("blockType", "tile block outside of region"));
            }
        };
        blocks.push(block);
    }

    Ok(blocks)
}

/// Encode a progressive bitmap stream into bytes.
///
pub fn encode_progressive_stream(blocks: &[ProgressiveBlock<'_>]) -> EncodeResult<Vec<u8>> {
    let total_size: usize = blocks
        .iter()
        .map(|b| {
            ProgressiveBlockHeader::SIZE
                + match b {
                    ProgressiveBlock::Sync(s) => s.size(),
                    ProgressiveBlock::FrameBegin(f) => f.size(),
                    ProgressiveBlock::FrameEnd(f) => f.size(),
                    ProgressiveBlock::Context(c) => c.size(),
                    ProgressiveBlock::Region(r) => r.size(),
                }
        })
        .sum();

    let mut buf = vec![0u8; total_size];
    let mut dst = WriteCursor::new(&mut buf);

    for block in blocks {
        let (block_type, body_size) = match block {
            ProgressiveBlock::Sync(s) => (ProgressiveBlockType::Sync, s.size()),
            ProgressiveBlock::FrameBegin(f) => (ProgressiveBlockType::FrameBegin, f.size()),
            ProgressiveBlock::FrameEnd(f) => (ProgressiveBlockType::FrameEnd, f.size()),
            ProgressiveBlock::Context(c) => (ProgressiveBlockType::Context, c.size()),
            ProgressiveBlock::Region(r) => (ProgressiveBlockType::Region, r.size()),
        };
        let block_len: u32 = cast_length!("blockLen", ProgressiveBlockHeader::SIZE + body_size)?;
        ProgressiveBlockHeader { block_type, block_len }.encode(&mut dst)?;

        match block {
            ProgressiveBlock::Sync(s) => s.encode(&mut dst)?,
            ProgressiveBlock::FrameBegin(f) => f.encode(&mut dst)?,
            ProgressiveBlock::FrameEnd(f) => f.encode(&mut dst)?,
            ProgressiveBlock::Context(c) => c.encode(&mut dst)?,
            ProgressiveBlock::Region(r) => r.encode(&mut dst)?,
        }
    }

    Ok(buf)
}

#[cfg(test)]
#[expect(clippy::similar_names, reason = "y/cb/cr test variables follow spec terminology")]
mod tests {
    use super::*;

    #[test]
    fn component_codec_quant_round_trip() {
        let original = ComponentCodecQuant {
            ll3: 6,
            hl3: 7,
            lh3: 8,
            hh3: 9,
            hl2: 10,
            lh2: 11,
            hh2: 12,
            hl1: 13,
            lh1: 14,
            hh1: 15,
        };
        let mut buf = [0u8; ComponentCodecQuant::SIZE];
        original.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        let decoded = ComponentCodecQuant::decode(&mut ReadCursor::new(&buf)).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn progressive_codec_quant_round_trip() {
        let original = ProgressiveCodecQuant {
            quality: 0x80,
            y_quant: ComponentCodecQuant {
                ll3: 1,
                hl3: 2,
                lh3: 3,
                hh3: 4,
                hl2: 5,
                lh2: 6,
                hh2: 7,
                hl1: 8,
                lh1: 9,
                hh1: 10,
            },
            cb_quant: ComponentCodecQuant::LOSSLESS,
            cr_quant: ComponentCodecQuant::LOSSLESS,
        };
        let mut buf = [0u8; ProgressiveCodecQuant::SIZE];
        original.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        let decoded = ProgressiveCodecQuant::decode(&mut ReadCursor::new(&buf)).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn sync_round_trip() {
        let original = ProgressiveSyncPdu;
        let mut buf = [0u8; 64];
        let header_size = ProgressiveBlockHeader::SIZE;
        let body_size = original.size();
        let block_len = u32::try_from(header_size + body_size).unwrap();
        let mut dst = WriteCursor::new(&mut buf);
        ProgressiveBlockHeader {
            block_type: ProgressiveBlockType::Sync,
            block_len,
        }
        .encode(&mut dst)
        .unwrap();
        original.encode(&mut dst).unwrap();
        let written = header_size + body_size;
        let blocks = decode_progressive_stream(&buf[..written]).unwrap();
        assert_eq!(blocks.len(), 1);
        assert!(matches!(blocks[0], ProgressiveBlock::Sync(_)));
    }

    #[test]
    fn context_pdu_round_trip() {
        let original = ProgressiveContextPdu {
            context_id: 0,
            tile_size: 0x0040,
            flags: FLAG_DWT_REDUCE_EXTRAPOLATE,
        };
        assert!(original.uses_reduce_extrapolate());

        let mut buf = [0u8; ProgressiveContextPdu::FIXED_PART_SIZE];
        original.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        let decoded = ProgressiveContextPdu::decode(&mut ReadCursor::new(&buf)).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn tile_simple_round_trip() {
        let y_data = &[1, 2, 3, 4, 5];
        let cb_data = &[6, 7];
        let cr_data = &[8, 9, 10];
        let tail_data = &[];

        let original = TileSimple {
            quant_idx_y: 0,
            quant_idx_cb: 0,
            quant_idx_cr: 0,
            x_idx: 3,
            y_idx: 7,
            flags: 0,
            y_data,
            cb_data,
            cr_data,
            tail_data,
        };
        let mut buf = vec![0u8; original.size()];
        original.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        let decoded = TileSimple::decode(&mut ReadCursor::new(&buf)).unwrap();
        assert_eq!(decoded.x_idx, 3);
        assert_eq!(decoded.y_idx, 7);
        assert_eq!(decoded.y_data, y_data);
        assert_eq!(decoded.cb_data, cb_data);
        assert_eq!(decoded.cr_data, cr_data);
    }

    #[test]
    fn tile_first_round_trip() {
        let original = TileFirst {
            quant_idx_y: 0,
            quant_idx_cb: 1,
            quant_idx_cr: 0,
            x_idx: 0,
            y_idx: 0,
            flags: 0,
            quality: 0x40,
            y_data: &[10, 20],
            cb_data: &[30],
            cr_data: &[40],
            tail_data: &[],
        };
        let mut buf = vec![0u8; original.size()];
        original.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        let decoded = TileFirst::decode(&mut ReadCursor::new(&buf)).unwrap();
        assert_eq!(decoded.quality, 0x40);
        assert_eq!(decoded.quant_idx_cb, 1);
    }

    #[test]
    fn tile_upgrade_round_trip() {
        let original = TileUpgrade {
            quant_idx_y: 0,
            quant_idx_cb: 0,
            quant_idx_cr: 0,
            x_idx: 1,
            y_idx: 2,
            quality: 0x80,
            y_srl_data: &[1, 2, 3],
            y_raw_data: &[4, 5],
            cb_srl_data: &[6],
            cb_raw_data: &[],
            cr_srl_data: &[7, 8],
            cr_raw_data: &[9],
        };
        let mut buf = vec![0u8; original.size()];
        original.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        let decoded = TileUpgrade::decode(&mut ReadCursor::new(&buf)).unwrap();
        assert_eq!(decoded.quality, 0x80);
        assert_eq!(decoded.y_srl_data, &[1, 2, 3]);
        assert_eq!(decoded.cr_raw_data, &[9]);
    }

    #[test]
    fn full_stream_round_trip() {
        let quant = ComponentCodecQuant {
            ll3: 6,
            hl3: 6,
            lh3: 6,
            hh3: 6,
            hl2: 7,
            lh2: 7,
            hh2: 8,
            hl1: 8,
            lh1: 8,
            hh1: 9,
        };
        let prog_quant = ProgressiveCodecQuant {
            quality: 0x40,
            y_quant: quant,
            cb_quant: quant,
            cr_quant: quant,
        };

        let region = ProgressiveRegion {
            tile_size: 0x40,
            rects: vec![RfxRectangle {
                x: 0,
                y: 0,
                width: 64,
                height: 64,
            }],
            quant_vals: vec![quant],
            quant_prog_vals: vec![prog_quant],
            flags: FLAG_DWT_REDUCE_EXTRAPOLATE,
            tiles: vec![ProgressiveTile::First(TileFirst {
                quant_idx_y: 0,
                quant_idx_cb: 0,
                quant_idx_cr: 0,
                x_idx: 0,
                y_idx: 0,
                flags: 0,
                quality: 0x40,
                y_data: &[0xAA; 50],
                cb_data: &[0xBB; 30],
                cr_data: &[0xCC; 20],
                tail_data: &[],
            })],
        };

        let blocks = vec![
            ProgressiveBlock::Sync(ProgressiveSyncPdu),
            ProgressiveBlock::Context(ProgressiveContextPdu {
                context_id: 0,
                tile_size: 0x0040,
                flags: FLAG_DWT_REDUCE_EXTRAPOLATE,
            }),
            ProgressiveBlock::FrameBegin(ProgressiveFrameBeginPdu {
                frame_index: 0,
                region_count: 1,
            }),
            ProgressiveBlock::Region(region),
            ProgressiveBlock::FrameEnd(ProgressiveFrameEndPdu),
        ];

        let encoded = encode_progressive_stream(&blocks).unwrap();
        let decoded = decode_progressive_stream(&encoded).unwrap();

        assert_eq!(decoded.len(), 5);
        assert!(matches!(decoded[0], ProgressiveBlock::Sync(_)));
        assert!(matches!(decoded[1], ProgressiveBlock::Context(_)));
        assert!(matches!(decoded[2], ProgressiveBlock::FrameBegin(_)));
        assert!(matches!(decoded[4], ProgressiveBlock::FrameEnd(_)));

        if let ProgressiveBlock::Region(r) = &decoded[3] {
            assert_eq!(r.rects.len(), 1);
            assert_eq!(r.quant_vals.len(), 1);
            assert_eq!(r.quant_prog_vals.len(), 1);
            assert_eq!(r.tiles.len(), 1);
            assert!(r.uses_reduce_extrapolate());
            if let ProgressiveTile::First(t) = &r.tiles[0] {
                assert_eq!(t.quality, 0x40);
                assert_eq!(t.y_data.len(), 50);
            } else {
                panic!("expected TileFirst");
            }
        } else {
            panic!("expected Region");
        }
    }

    #[test]
    fn nibble_order_differs_from_classic() {
        // Verify that progressive ComponentCodecQuant has HL/LH swapped vs classic
        let prog = ComponentCodecQuant {
            ll3: 1,
            hl3: 2,
            lh3: 3,
            hh3: 4,
            hl2: 5,
            lh2: 6,
            hh2: 7,
            hl1: 8,
            lh1: 9,
            hh1: 10,
        };
        let mut buf = [0u8; 5];
        prog.encode(&mut WriteCursor::new(&mut buf)).unwrap();

        // First byte: low nibble = LL3(1), high nibble = HL3(2) → 0x21
        assert_eq!(buf[0], 0x21);
        // Second byte: low nibble = LH3(3), high nibble = HH3(4) → 0x43
        assert_eq!(buf[1], 0x43);
        // Third byte: low nibble = HL2(5), high nibble = LH2(6) → 0x65
        assert_eq!(buf[2], 0x65);

        // Compare: classic Quant would have LL3|LH3, HL3|HH3 order
        // So our first byte would be 0x31 (not 0x21) in classic order
    }

    #[test]
    fn reject_tile_block_at_top_level() {
        // A tile block at the top level should be rejected
        let mut buf = [0u8; 64];
        let mut dst = WriteCursor::new(&mut buf);
        ProgressiveBlockHeader {
            block_type: ProgressiveBlockType::TileSimple,
            block_len: 6 + 16, // header + minimal body
        }
        .encode(&mut dst)
        .unwrap();
        // Fill minimal tile body
        let tile = TileSimple {
            quant_idx_y: 0,
            quant_idx_cb: 0,
            quant_idx_cr: 0,
            x_idx: 0,
            y_idx: 0,
            flags: 0,
            y_data: &[],
            cb_data: &[],
            cr_data: &[],
            tail_data: &[],
        };
        tile.encode(&mut dst).unwrap();
        let written = 6 + tile.size();
        let result = decode_progressive_stream(&buf[..written]);
        assert!(result.is_err());
    }

    #[test]
    fn empty_stream() {
        let blocks = decode_progressive_stream(&[]).unwrap();
        assert!(blocks.is_empty());
    }

    #[test]
    fn component_codec_quant_for_band() {
        let q = ComponentCodecQuant {
            ll3: 10,
            hl3: 1,
            lh3: 2,
            hh3: 3,
            hl2: 4,
            lh2: 5,
            hh2: 6,
            hl1: 7,
            lh1: 8,
            hh1: 9,
        };
        // Band order: HL1, LH1, HH1, HL2, LH2, HH2, HL3, LH3, HH3, LL3
        assert_eq!(q.for_band(0), 7); // HL1
        assert_eq!(q.for_band(1), 8); // LH1
        assert_eq!(q.for_band(2), 9); // HH1
        assert_eq!(q.for_band(3), 4); // HL2
        assert_eq!(q.for_band(9), 10); // LL3
    }
}
