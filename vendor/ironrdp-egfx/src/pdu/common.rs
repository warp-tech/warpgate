use ironrdp_pdu::{
    Decode, DecodeError, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, ensure_fixed_part_size,
    invalid_field_err,
};

/// 2.2.1.1 RDPGFX_POINT16
///
/// [2.2.1.1]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/dd4f5693-e2d1-470e-b3d1-e760a3134876>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Point {
    pub x: u16,
    pub y: u16,
}

impl Point {
    const NAME: &'static str = "GfxPoint";

    const FIXED_PART_SIZE: usize = 2 /* X */ + 2 /* Y */;
}

impl Encode for Point {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

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

impl<'de> Decode<'de> for Point {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let x = src.read_u16();
        let y = src.read_u16();

        Ok(Self { x, y })
    }
}

/// 2.2.1.3 RDPGFX_COLOR32
///
/// [2.2.1.3]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/8ea9699d-d511-4e16-b7d3-74d6fc0e0652>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Color {
    pub b: u8,
    pub g: u8,
    pub r: u8,
    pub xa: u8,
}

impl Color {
    const NAME: &'static str = "GfxColor";

    pub const FIXED_PART_SIZE: usize = 4 /* BGRA */;
}

impl Encode for Color {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u8(self.b);
        dst.write_u8(self.g);
        dst.write_u8(self.r);
        dst.write_u8(self.xa);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for Color {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let b = src.read_u8();
        let g = src.read_u8();
        let r = src.read_u8();
        let xa = src.read_u8();

        Ok(Self { b, g, r, xa })
    }
}

/// 2.2.1.4 RDPGFX_PIXELFORMAT
///
/// [2.2.1.4]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/80afb419-0cd5-49f8-8256-f77cc1787ec9>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PixelFormat {
    XRgb = 0x20,
    ARgb = 0x21,
}

impl TryFrom<u8> for PixelFormat {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x20 => Ok(PixelFormat::XRgb),
            0x21 => Ok(PixelFormat::ARgb),
            _ => Err(invalid_field_err!("PixelFormat", "invalid pixel format")),
        }
    }
}

impl From<PixelFormat> for u8 {
    #[expect(clippy::as_conversions, reason = "repr(u8) enum discriminant")]
    fn from(value: PixelFormat) -> Self {
        value as u8
    }
}
