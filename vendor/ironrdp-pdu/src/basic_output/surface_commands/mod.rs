#[cfg(test)]
mod tests;

use bitflags::bitflags;
use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, cast_length, ensure_fixed_part_size,
    ensure_size, invalid_field_err,
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive as _;

use crate::geometry::ExclusiveRectangle;

pub const SURFACE_COMMAND_HEADER_SIZE: usize = 2;

// TS_SURFCMD
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum SurfaceCommand<'a> {
    SetSurfaceBits(SurfaceBitsPdu<'a>),
    FrameMarker(FrameMarkerPdu),
    StreamSurfaceBits(SurfaceBitsPdu<'a>),
}

impl SurfaceCommand<'_> {
    const NAME: &'static str = "TS_SURFCMD";
    const FIXED_PART_SIZE: usize = 2 /* cmdType */;
}

impl Encode for SurfaceCommand<'_> {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        let cmd_type = SurfaceCommandType::from(self);
        dst.write_u16(cmd_type.as_u16());

        match self {
            Self::SetSurfaceBits(pdu) | Self::StreamSurfaceBits(pdu) => pdu.encode(dst),
            Self::FrameMarker(pdu) => pdu.encode(dst),
        }?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        SURFACE_COMMAND_HEADER_SIZE
            + match self {
                Self::SetSurfaceBits(pdu) | Self::StreamSurfaceBits(pdu) => pdu.size(),
                Self::FrameMarker(pdu) => pdu.size(),
            }
    }
}

impl<'de> Decode<'de> for SurfaceCommand<'de> {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let cmd_type = src.read_u16();
        let cmd_type = SurfaceCommandType::from_u16(cmd_type)
            .ok_or_else(|| invalid_field_err!("cmdType", "invalid surface command"))?;

        match cmd_type {
            SurfaceCommandType::SetSurfaceBits => Ok(Self::SetSurfaceBits(SurfaceBitsPdu::decode(src)?)),
            SurfaceCommandType::FrameMarker => Ok(Self::FrameMarker(FrameMarkerPdu::decode(src)?)),
            SurfaceCommandType::StreamSurfaceBits => Ok(Self::StreamSurfaceBits(SurfaceBitsPdu::decode(src)?)),
        }
    }
}

// TS_SURFCMD_STREAM_SURF_BITS and TS_SURFCMD_SET_SURF_BITS
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct SurfaceBitsPdu<'a> {
    pub destination: ExclusiveRectangle,
    pub extended_bitmap_data: ExtendedBitmapDataPdu<'a>,
}

impl SurfaceBitsPdu<'_> {
    const NAME: &'static str = "TS_SURFCMD_x_SURFACE_BITS_PDU";
}

impl Encode for SurfaceBitsPdu<'_> {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        self.destination.encode(dst)?;
        self.extended_bitmap_data.encode(dst)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        self.destination.size() + self.extended_bitmap_data.size()
    }
}

impl<'de> Decode<'de> for SurfaceBitsPdu<'de> {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let destination = ExclusiveRectangle::decode(src)?;
        let extended_bitmap_data = ExtendedBitmapDataPdu::decode(src)?;

        Ok(Self {
            destination,
            extended_bitmap_data,
        })
    }
}

// TS_FRAME_MARKER
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct FrameMarkerPdu {
    pub frame_action: FrameAction,
    pub frame_id: Option<u32>,
}

impl FrameMarkerPdu {
    const NAME: &'static str = "TS_FRAME_MARKER_PDU";
    const FIXED_PART_SIZE: usize = 2 /* frameAction */ + 4 /* frameId */;
}

impl Encode for FrameMarkerPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(self.frame_action.as_u16());
        dst.write_u32(self.frame_id.unwrap_or(0));

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for FrameMarkerPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_size!(in: src, size: 2);

        let frame_action = src.read_u16();

        let frame_action = FrameAction::from_u16(frame_action)
            .ok_or_else(|| invalid_field_err!("frameAction", "invalid frame action"))?;

        let frame_id = if src.is_empty() {
            // Sometimes Windows 10 RDP server sends not complete FrameMarker PDU (without frame ID),
            // so we made frame ID field as optional (not officially)

            None
        } else {
            ensure_size!(in: src, size: 4);
            Some(src.read_u32())
        };

        Ok(Self { frame_action, frame_id })
    }
}

// TS_BITMAP_DATA_EX
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ExtendedBitmapDataPdu<'a> {
    pub bpp: u8,
    pub codec_id: u8,
    pub width: u16,
    pub height: u16,
    pub header: Option<BitmapDataHeader>,
    pub data: &'a [u8],
}

impl core::fmt::Debug for ExtendedBitmapDataPdu<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExtendedBitmapDataPdu")
            .field("bpp", &self.bpp)
            .field("codec_id", &self.codec_id)
            .field("width", &self.width)
            .field("height", &self.height)
            .field("header", &self.header)
            .field("data_len", &self.data.len())
            .finish()
    }
}

impl ExtendedBitmapDataPdu<'_> {
    const NAME: &'static str = "TS_BITMAP_DATA_EX";
    const FIXED_PART_SIZE: usize = 1 /* bpp */ + 1 /* flags */ + 1 /* reserved */ + 1 /* codecId */ + 2 /* width */ + 2 /* height */ + 4 /* len */;
}

impl Encode for ExtendedBitmapDataPdu<'_> {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        let data_len = cast_length!("bitmap data length", self.data.len())?;

        dst.write_u8(self.bpp);
        let flags = if self.header.is_some() {
            BitmapDataFlags::COMPRESSED_BITMAP_HEADER_PRESENT
        } else {
            BitmapDataFlags::empty()
        };
        dst.write_u8(flags.bits());
        dst.write_u8(0); // reserved
        dst.write_u8(self.codec_id);
        dst.write_u16(self.width);
        dst.write_u16(self.height);
        dst.write_u32(data_len);
        if let Some(header) = &self.header {
            header.encode(dst)?;
        }
        dst.write_slice(self.data);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.header.as_ref().map_or(0, |h| h.size()) + self.data.len()
    }
}

impl<'de> Decode<'de> for ExtendedBitmapDataPdu<'de> {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let bpp = src.read_u8();
        let flags = BitmapDataFlags::from_bits_retain(src.read_u8());
        let _reserved = src.read_u8();
        let codec_id = src.read_u8();
        let width = src.read_u16();
        let height = src.read_u16();
        let data_length = cast_length!("bitmap data length", src.read_u32())?;

        let expected_remaining_size = if flags.contains(BitmapDataFlags::COMPRESSED_BITMAP_HEADER_PRESENT) {
            data_length + BitmapDataHeader::ENCODED_SIZE
        } else {
            data_length
        };

        ensure_size!(in: src, size: expected_remaining_size);

        let header = if flags.contains(BitmapDataFlags::COMPRESSED_BITMAP_HEADER_PRESENT) {
            Some(BitmapDataHeader::decode(src)?)
        } else {
            None
        };

        let data = src.read_slice(data_length);

        Ok(Self {
            bpp,
            codec_id,
            width,
            height,
            header,
            data,
        })
    }
}

// TS_COMPRESSED_BITMAP_HEADER_EX
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct BitmapDataHeader {
    pub high_unique_id: u32,
    pub low_unique_id: u32,
    pub tm_milliseconds: u64,
    pub tm_seconds: u64,
}

impl BitmapDataHeader {
    const NAME: &'static str = "TS_COMPRESSED_BITMAP_HEADER_EX";
    const FIXED_PART_SIZE: usize = 4 /* highUniqueId */ + 4 /* lowUniqueId */ + 8 /* tmMilli */ + 8 /* tmSeconds */;

    pub const ENCODED_SIZE: usize = Self::FIXED_PART_SIZE;
}

impl Encode for BitmapDataHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u32(self.high_unique_id);
        dst.write_u32(self.low_unique_id);
        dst.write_u64(self.tm_milliseconds);
        dst.write_u64(self.tm_seconds);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl Decode<'_> for BitmapDataHeader {
    fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let high_unique_id = src.read_u32();
        let low_unique_id = src.read_u32();
        let tm_milliseconds = src.read_u64();
        let tm_seconds = src.read_u64();

        Ok(Self {
            high_unique_id,
            low_unique_id,
            tm_milliseconds,
            tm_seconds,
        })
    }
}

#[derive(Debug, Copy, Clone, PartialEq, FromPrimitive)]
#[repr(u16)]
enum SurfaceCommandType {
    SetSurfaceBits = 0x01,
    FrameMarker = 0x04,
    StreamSurfaceBits = 0x06,
}

impl SurfaceCommandType {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u16(self) -> u16 {
        self as u16
    }
}

impl From<&SurfaceCommand<'_>> for SurfaceCommandType {
    fn from(command: &SurfaceCommand<'_>) -> Self {
        match command {
            SurfaceCommand::SetSurfaceBits(_) => Self::SetSurfaceBits,
            SurfaceCommand::FrameMarker(_) => Self::FrameMarker,
            SurfaceCommand::StreamSurfaceBits(_) => Self::StreamSurfaceBits,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u16)]
pub enum FrameAction {
    Begin = 0x00,
    End = 0x01,
}

impl FrameAction {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct BitmapDataFlags: u8 {
        const COMPRESSED_BITMAP_HEADER_PRESENT = 0x01;

        const _ = !0;
    }
}
