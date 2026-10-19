#[cfg(test)]
mod tests;

use bit_field::BitField as _;
use bitflags::bitflags;
use ironrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeResult, InvalidFieldErr as _, ReadCursor, WriteCursor,
    cast_length, decode_cursor, ensure_fixed_part_size, ensure_size, invalid_field_err,
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive as _;

use super::bitmap::BitmapUpdateData;
use super::pointer::PointerUpdateData;
use super::surface_commands::{SURFACE_COMMAND_HEADER_SIZE, SurfaceCommand};
use crate::per;
use crate::rdp::client_info::CompressionType;
use crate::rdp::headers::{CompressionFlags, SHARE_DATA_HEADER_COMPRESSION_MASK};

/// Implements the Fast-Path RDP message header PDU.
/// TS_FP_UPDATE_PDU
#[expect(
    clippy::partial_pub_fields,
    reason = "this structure is used in the match expression in the integration tests"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct FastPathHeader {
    pub flags: EncryptionFlags,
    pub data_length: usize,
    forced_long_length: bool,
}

impl FastPathHeader {
    const NAME: &'static str = "TS_FP_UPDATE_PDU header";
    const FIXED_PART_SIZE: usize = 1 /* EncryptionFlags */;

    pub fn new(flags: EncryptionFlags, data_length: usize) -> Self {
        Self {
            flags,
            data_length,
            forced_long_length: false,
        }
    }

    fn minimal_size(&self) -> usize {
        // it may then be +2 if > 0x7f
        let len = self.data_length + Self::FIXED_PART_SIZE + 1;

        Self::FIXED_PART_SIZE + per::sizeof_length(len)
    }
}

impl Encode for FastPathHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        let mut header = 0u8;
        header.set_bits(0..2, 0); // fast-path action
        header.set_bits(6..8, self.flags.bits());
        dst.write_u8(header);

        let length = self.data_length + self.size();
        let length = cast_length!("length", length)?;

        if self.forced_long_length {
            // Preserve same layout for header as received
            per::write_long_length(dst, length);
        } else {
            per::write_length(dst, length);
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        if self.forced_long_length {
            Self::FIXED_PART_SIZE + per::U16_SIZE
        } else {
            self.minimal_size()
        }
    }
}

impl<'de> Decode<'de> for FastPathHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let header = src.read_u8();
        let flags = EncryptionFlags::from_bits_retain(header.get_bits(6..8));

        let (length, sizeof_length) = per::read_length(src).map_err(|e| {
            DecodeError::invalid_field("", "length", "Invalid encoded fast path PDU length").with_source(e)
        })?;
        let length = usize::from(length);
        if length < sizeof_length + Self::FIXED_PART_SIZE {
            return Err(invalid_field_err!(
                "length",
                "received fastpath PDU length is smaller than header size"
            ));
        }
        let data_length = length - sizeof_length - Self::FIXED_PART_SIZE;
        // Detect case, when received packet has non-optimal packet length packing.
        let forced_long_length = per::sizeof_length(length) != sizeof_length;

        Ok(FastPathHeader {
            flags,
            data_length,
            forced_long_length,
        })
    }
}

/// TS_FP_UPDATE
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct FastPathUpdatePdu<'a> {
    pub fragmentation: Fragmentation,
    pub update_code: UpdateCode,
    pub compression_flags: Option<CompressionFlags>,
    // NOTE: always Some when compression flags is Some
    pub compression_type: Option<CompressionType>,
    pub data: &'a [u8],
}

impl FastPathUpdatePdu<'_> {
    const NAME: &'static str = "TS_FP_UPDATE";
    const FIXED_PART_SIZE: usize = 1 /* header */;
}

impl Encode for FastPathUpdatePdu<'_> {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        let data_len = cast_length!("data length", self.data.len())?;

        let mut header = 0u8;
        header.set_bits(0..4, self.update_code.as_u8());
        header.set_bits(4..6, self.fragmentation.as_u8());
        if self.compression_flags.is_some() {
            // The COMPRESSION_USED bit must be set on the header byte before it
            // is written, so the decoder knows a compression flags byte follows.
            header.set_bits(6..8, Compression::COMPRESSION_USED.bits());
        }

        dst.write_u8(header);

        if self.compression_flags.is_some() {
            let compression_flags_with_type =
                self.compression_flags.map(|f| f.bits()).unwrap_or(0) | self.compression_type.map_or(0, |f| f.as_u8());
            dst.write_u8(compression_flags_with_type);
        }

        dst.write_u16(data_len);
        dst.write_slice(self.data);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        let compression_flags_size = if self.compression_flags.is_some() { 1 } else { 0 };

        Self::FIXED_PART_SIZE + compression_flags_size + 2 /* len */ + self.data.len()
    }
}

impl<'de> Decode<'de> for FastPathUpdatePdu<'de> {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let header = src.read_u8();

        let update_code = header.get_bits(0..4);
        let update_code = UpdateCode::from_u8(update_code)
            .ok_or_else(|| invalid_field_err!("updateHeader", "Invalid update code"))?;

        let fragmentation = header.get_bits(4..6);
        let fragmentation = Fragmentation::from_u8(fragmentation)
            .ok_or_else(|| invalid_field_err!("updateHeader", "Invalid fragmentation"))?;

        let compression = Compression::from_bits_retain(header.get_bits(6..8));

        let (compression_flags, compression_type) = if compression.contains(Compression::COMPRESSION_USED) {
            let expected_size = 1 /* flags_with_type */ + 2 /* len */;
            ensure_size!(in: src, size: expected_size);

            let compression_flags_with_type = src.read_u8();
            let compression_flags =
                CompressionFlags::from_bits_retain(compression_flags_with_type & !SHARE_DATA_HEADER_COMPRESSION_MASK);
            let compression_type =
                CompressionType::from_u8(compression_flags_with_type & SHARE_DATA_HEADER_COMPRESSION_MASK)
                    .ok_or_else(|| invalid_field_err!("compressionFlags", "invalid compression type"))?;

            (Some(compression_flags), Some(compression_type))
        } else {
            let expected_size = 2 /* len */;
            ensure_size!(in: src, size: expected_size);

            (None, None)
        };

        let data_length = usize::from(src.read_u16());
        ensure_size!(in: src, size: data_length);
        let data = src.read_slice(data_length);

        Ok(Self {
            fragmentation,
            update_code,
            compression_flags,
            compression_type,
            data,
        })
    }
}

/// TS_FP_UPDATE data
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum FastPathUpdate<'a> {
    SurfaceCommands(Vec<SurfaceCommand<'a>>),
    Bitmap(BitmapUpdateData<'a>),
    Pointer(PointerUpdateData<'a>),
    /// Raw palette update data (TS_UPDATE_PALETTE_DATA).
    /// Layout: pad(2) + numberColors(u32) + N x TS_COLOR_QUAD [B, G, R, pad].
    /// See MS-RDPBCGR 2.2.9.1.1.3.1.1.
    Palette(&'a [u8]),
}

impl<'a> FastPathUpdate<'a> {
    const NAME: &'static str = "TS_FP_UPDATE data";

    pub fn decode_with_code(src: &'a [u8], code: UpdateCode) -> DecodeResult<Self> {
        let mut cursor = ReadCursor::<'a>::new(src);
        Self::decode_cursor_with_code(&mut cursor, code)
    }

    pub fn decode_cursor_with_code(src: &mut ReadCursor<'a>, code: UpdateCode) -> DecodeResult<Self> {
        match code {
            UpdateCode::SurfaceCommands => {
                let mut commands = Vec::with_capacity(1);
                while src.len() >= SURFACE_COMMAND_HEADER_SIZE {
                    commands.push(decode_cursor::<SurfaceCommand<'_>>(src)?);
                }

                Ok(Self::SurfaceCommands(commands))
            }
            UpdateCode::Bitmap => Ok(Self::Bitmap(decode_cursor(src)?)),
            UpdateCode::Palette => {
                let data = src.remaining();
                src.advance(data.len());
                Ok(Self::Palette(data))
            }
            UpdateCode::HiddenPointer => Ok(Self::Pointer(PointerUpdateData::SetHidden)),
            UpdateCode::DefaultPointer => Ok(Self::Pointer(PointerUpdateData::SetDefault)),
            UpdateCode::PositionPointer => Ok(Self::Pointer(PointerUpdateData::SetPosition(decode_cursor(src)?))),
            UpdateCode::ColorPointer => {
                let color = decode_cursor(src)?;
                Ok(Self::Pointer(PointerUpdateData::Color(color)))
            }
            UpdateCode::CachedPointer => Ok(Self::Pointer(PointerUpdateData::Cached(decode_cursor(src)?))),
            UpdateCode::NewPointer => Ok(Self::Pointer(PointerUpdateData::New(decode_cursor(src)?))),
            UpdateCode::LargePointer => Ok(Self::Pointer(PointerUpdateData::Large(decode_cursor(src)?))),
            _ => Err(invalid_field_err!("updateCode", "unsupported fast-path update code")),
        }
    }

    pub fn as_short_name(&self) -> &str {
        match self {
            Self::SurfaceCommands(_) => "Surface Commands",
            Self::Bitmap(_) => "Bitmap",
            Self::Pointer(_) => "Pointer",
            Self::Palette(_) => "Palette",
        }
    }
}

impl Encode for FastPathUpdate<'_> {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        match self {
            Self::SurfaceCommands(commands) => {
                for command in commands {
                    command.encode(dst)?;
                }
            }
            Self::Bitmap(bitmap) => {
                bitmap.encode(dst)?;
            }
            Self::Pointer(pointer) => match pointer {
                PointerUpdateData::SetHidden => {}
                PointerUpdateData::SetDefault => {}
                PointerUpdateData::SetPosition(inner) => inner.encode(dst)?,
                PointerUpdateData::Color(inner) => inner.encode(dst)?,
                PointerUpdateData::Cached(inner) => inner.encode(dst)?,
                PointerUpdateData::New(inner) => inner.encode(dst)?,
                PointerUpdateData::Large(inner) => inner.encode(dst)?,
            },
            Self::Palette(data) => {
                dst.write_slice(data);
            }
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        match self {
            Self::SurfaceCommands(commands) => commands.iter().map(|c| c.size()).sum::<usize>(),
            Self::Bitmap(bitmap) => bitmap.size(),
            Self::Palette(data) => data.len(),
            Self::Pointer(pointer) => match pointer {
                PointerUpdateData::SetHidden => 0,
                PointerUpdateData::SetDefault => 0,
                PointerUpdateData::SetPosition(inner) => inner.size(),
                PointerUpdateData::Color(inner) => inner.size(),
                PointerUpdateData::Cached(inner) => inner.size(),
                PointerUpdateData::New(inner) => inner.size(),
                PointerUpdateData::Large(inner) => inner.size(),
            },
        }
    }
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum UpdateCode {
    Orders = 0x0,
    Bitmap = 0x1,
    Palette = 0x2,
    Synchronize = 0x3,
    SurfaceCommands = 0x4,
    HiddenPointer = 0x5,
    DefaultPointer = 0x6,
    PositionPointer = 0x8,
    ColorPointer = 0x9,
    CachedPointer = 0xa,
    NewPointer = 0xb,
    LargePointer = 0xc,
}

impl UpdateCode {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl From<&FastPathUpdate<'_>> for UpdateCode {
    fn from(update: &FastPathUpdate<'_>) -> Self {
        match update {
            FastPathUpdate::SurfaceCommands(_) => Self::SurfaceCommands,
            FastPathUpdate::Bitmap(_) => Self::Bitmap,
            FastPathUpdate::Palette(_) => Self::Palette,
            FastPathUpdate::Pointer(action) => match action {
                PointerUpdateData::SetHidden => Self::HiddenPointer,
                PointerUpdateData::SetDefault => Self::DefaultPointer,
                PointerUpdateData::SetPosition(_) => Self::PositionPointer,
                PointerUpdateData::Color(_) => Self::ColorPointer,
                PointerUpdateData::Cached(_) => Self::CachedPointer,
                PointerUpdateData::New(_) => Self::NewPointer,
                PointerUpdateData::Large(_) => Self::LargePointer,
            },
        }
    }
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum Fragmentation {
    Single = 0x0,
    Last = 0x1,
    First = 0x2,
    Next = 0x3,
}

impl Fragmentation {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct EncryptionFlags: u8 {
        const SECURE_CHECKSUM = 0x1;
        const ENCRYPTED = 0x2;

        const _ = !0;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct Compression: u8 {
        const COMPRESSION_USED = 0x2;

        const _ = !0;
    }
}
