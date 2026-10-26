use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, cast_int, cast_length, ensure_fixed_part_size,
    ensure_size, invalid_field_err,
};

// Represents `TS_POINT16` described in [MS-RDPBCGR] 2.2.9.1.1.4.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Point16 {
    pub x: u16,
    pub y: u16,
}

impl Point16 {
    const NAME: &'static str = "TS_POINT16";
    const FIXED_PART_SIZE: usize = 2 /* x */ + 2 /* y */;
}

impl Encode for Point16 {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u16(self.x);
        dst.write_u16(self.y);
        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl Decode<'_> for Point16 {
    fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let x = src.read_u16();
        let y = src.read_u16();

        Ok(Self { x, y })
    }
}

/// According to [MS-RDPBCGR] 2.2.9.1.1.4.2 `TS_POINTERPOSATTRIBUTE` has the same layout
/// as `TS_POINT16`
pub type PointerPositionAttribute = Point16;

/// Represents `TS_COLORPOINTERATTRIBUTE` described in [MS-RDPBCGR] 2.2.9.1.1.4.4
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ColorPointerAttribute<'a> {
    pub cache_index: u16,
    pub hot_spot: Point16,
    pub width: u16,
    pub height: u16,
    pub xor_mask: &'a [u8],
    pub and_mask: &'a [u8],
}

impl ColorPointerAttribute<'_> {
    const NAME: &'static str = "TS_COLORPOINTERATTRIBUTE";
    const FIXED_PART_SIZE: usize =
        2 /* cacheIdx */ + 2 /* width */ + 2 /* height */ + 2 /* lenAnd */ + 2 /* lenOr */ + Point16::FIXED_PART_SIZE;
}

macro_rules! check_masks_alignment {
    ($and_mask:expr, $xor_mask:expr, $pointer_height:expr, $large_ptr:expr) => {{
        const AND_MASK_SIZE_FIELD: &str = "lengthAndMask";
        const XOR_MASK_SIZE_FIELD: &str = "lengthXorMask";
        const U32_MAX: usize = 0xFFFFFFFF;

        let pointer_height: usize = cast_int!("pointer height", $pointer_height)?;

        let check_mask = |mask: &[u8], field: &'static str| {
            if $pointer_height == 0 {
                return Err(invalid_field_err!(field, "pointer height cannot be zero"));
            }
            if $large_ptr && (mask.len() > U32_MAX) {
                return Err(invalid_field_err!(field, "pointer mask is too big for u32 size"));
            }
            if !$large_ptr && (mask.len() > usize::from(u16::MAX)) {
                return Err(invalid_field_err!(field, "pointer mask is too big for u16 size"));
            }
            if (mask.len() % pointer_height) != 0 {
                return Err(invalid_field_err!(field, "pointer mask have incomplete scanlines"));
            }
            if (mask.len() / pointer_height) % 2 != 0 {
                return Err(invalid_field_err!(
                    field,
                    "pointer mask scanlines should be aligned to 16 bits"
                ));
            }
            Ok(())
        };

        check_mask($and_mask, AND_MASK_SIZE_FIELD)?;
        check_mask($xor_mask, XOR_MASK_SIZE_FIELD)
    }};
}

impl Encode for ColorPointerAttribute<'_> {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        check_masks_alignment!(self.and_mask, self.xor_mask, self.height, false)?;

        dst.write_u16(self.cache_index);
        self.hot_spot.encode(dst)?;
        dst.write_u16(self.width);
        dst.write_u16(self.height);

        dst.write_u16(cast_length!("and mask length", self.and_mask.len())?);
        dst.write_u16(cast_length!("xor mask length", self.xor_mask.len())?);
        // Note that masks are written in reverse order. It is not a mistake, that is how the
        // message is defined in [MS-RDPBCGR]
        dst.write_slice(self.xor_mask);
        dst.write_slice(self.and_mask);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.xor_mask.len() + self.and_mask.len()
    }
}

impl<'a> Decode<'a> for ColorPointerAttribute<'a> {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let cache_index = src.read_u16();
        let hot_spot = Point16::decode(src)?;
        let width = src.read_u16();
        let height = src.read_u16();
        // Convert to usize during the addition to prevent overflow and match expected type
        let length_and_mask = usize::from(src.read_u16());
        let length_xor_mask = usize::from(src.read_u16());

        let expected_masks_size = length_and_mask + length_xor_mask;
        ensure_size!(in: src, size: expected_masks_size);

        let xor_mask = src.read_slice(length_xor_mask);
        let and_mask = src.read_slice(length_and_mask);

        check_masks_alignment!(and_mask, xor_mask, height, false)?;

        Ok(Self {
            cache_index,
            hot_spot,
            width,
            height,
            xor_mask,
            and_mask,
        })
    }
}

/// Represents `TS_POINTERATTRIBUTE` described in [MS-RDPBCGR] 2.2.9.1.1.4.5
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct PointerAttribute<'a> {
    pub xor_bpp: u16,
    pub color_pointer: ColorPointerAttribute<'a>,
}

impl PointerAttribute<'_> {
    const NAME: &'static str = "TS_POINTERATTRIBUTE";
    const FIXED_PART_SIZE: usize = 2 /* xorBpp */;
}

impl Encode for PointerAttribute<'_> {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u16(self.xor_bpp);
        self.color_pointer.encode(dst)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.color_pointer.size()
    }
}

impl<'a> Decode<'a> for PointerAttribute<'a> {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let xor_bpp = src.read_u16();
        let color_pointer = ColorPointerAttribute::decode(src)?;

        Ok(Self { xor_bpp, color_pointer })
    }
}

/// Represents `TS_CACHEDPOINTERATTRIBUTE` described in [MS-RDPBCGR] 2.2.9.1.1.4.6
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct CachedPointerAttribute {
    pub cache_index: u16,
}

impl CachedPointerAttribute {
    const NAME: &'static str = "TS_CACHEDPOINTERATTRIBUTE";
    const FIXED_PART_SIZE: usize = 2 /* cacheIdx */;
}

impl Encode for CachedPointerAttribute {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u16(self.cache_index);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl Decode<'_> for CachedPointerAttribute {
    fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let cache_index = src.read_u16();

        Ok(Self { cache_index })
    }
}

/// Represents `TS_FP_LARGEPOINTERATTRIBUTE` described in [MS-RDPBCGR] 2.2.9.1.2.1.11
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct LargePointerAttribute<'a> {
    pub xor_bpp: u16,
    pub cache_index: u16,
    pub hot_spot: Point16,
    pub width: u16,
    pub height: u16,
    pub xor_mask: &'a [u8],
    pub and_mask: &'a [u8],
}

impl LargePointerAttribute<'_> {
    const NAME: &'static str = "TS_FP_LARGEPOINTERATTRIBUTE";
    const FIXED_PART_SIZE: usize =
        2 /* xorBpp */ + 2 /* cacheIdx */ + 4 /* hotSpot */ + 2 /* width */ + 2 /* height */ +
        4 /* andMaskLen */ + 4 /* xorMaskLen */;
}

impl Encode for LargePointerAttribute<'_> {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        check_masks_alignment!(self.and_mask, self.xor_mask, self.height, true)?;

        dst.write_u16(self.xor_bpp);
        dst.write_u16(self.cache_index);
        self.hot_spot.encode(dst)?;
        dst.write_u16(self.width);
        dst.write_u16(self.height);

        dst.write_u32(cast_length!("and mask length", self.and_mask.len())?);
        dst.write_u32(cast_length!("xor mask length", self.xor_mask.len())?);
        // See comment in `ColorPointerAttribute::encode` about encoding order
        dst.write_slice(self.xor_mask);
        dst.write_slice(self.and_mask);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.xor_mask.len() + self.and_mask.len()
    }
}

impl<'a> Decode<'a> for LargePointerAttribute<'a> {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let xor_bpp = src.read_u16();
        let cache_index = src.read_u16();
        let hot_spot = Point16::decode(src)?;
        let width = src.read_u16();
        let height = src.read_u16();
        // Convert to usize to prevent overflow during addition
        let length_and_mask = cast_length!("and mask length", src.read_u32())?;
        let length_xor_mask = cast_length!("xor mask length", src.read_u32())?;

        let expected_masks_size = length_and_mask + length_xor_mask;
        ensure_size!(in: src, size: expected_masks_size);

        let xor_mask = src.read_slice(length_xor_mask);
        let and_mask = src.read_slice(length_and_mask);

        check_masks_alignment!(and_mask, xor_mask, height, true)?;

        Ok(Self {
            xor_bpp,
            cache_index,
            hot_spot,
            width,
            height,
            xor_mask,
            and_mask,
        })
    }
}

/// Pointer-related FastPath update messages (inner FastPath packet data)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum PointerUpdateData<'a> {
    SetHidden,
    SetDefault,
    SetPosition(PointerPositionAttribute),
    Color(ColorPointerAttribute<'a>),
    Cached(CachedPointerAttribute),
    New(PointerAttribute<'a>),
    Large(LargePointerAttribute<'a>),
}
