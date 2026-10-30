mod data_messages;
mod header_messages;
pub mod progressive;

use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, cast_length, ensure_fixed_part_size,
    ensure_size, invalid_field_err,
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive as _;

use crate::rdp::capability_sets::{RfxCaps, RfxCapset};

#[rustfmt::skip]
pub use self::data_messages::{
    ContextPdu, EntropyAlgorithm, FrameBeginPdu, FrameEndPdu, OperatingMode, Quant, RegionPdu, RfxRectangle, Tile,
    TileSetPdu,
};
pub use self::header_messages::{ChannelsPdu, CodecVersionsPdu, RfxChannel, SyncPdu};

const CODEC_ID: u8 = 1;
const CHANNEL_ID_FOR_CONTEXT: u8 = 0xFF;
const CHANNEL_ID_FOR_OTHER_VALUES: u8 = 0x00;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum Block<'a> {
    Tile(Tile<'a>),
    Caps(RfxCaps),
    CapabilitySet(RfxCapset),
    Sync(SyncPdu),
    CodecVersions(CodecVersionsPdu),
    Channels(ChannelsPdu),
    CodecChannel(CodecChannel<'a>),
}

impl Block<'_> {
    const NAME: &'static str = "RfxBlock";

    const FIXED_PART_SIZE: usize = BlockHeader::FIXED_PART_SIZE;

    pub fn block_type(&self) -> BlockType {
        match self {
            Block::Tile(_) => BlockType::Tile,
            Block::Caps(_) => BlockType::Capabilities,
            Block::CapabilitySet(_) => BlockType::CapabilitySet,
            Block::Sync(_) => BlockType::Sync,
            Block::Channels(_) => BlockType::Channels,
            Block::CodecVersions(_) => BlockType::CodecVersions,
            Block::CodecChannel(CodecChannel::Context(_)) => BlockType::Context,
            Block::CodecChannel(CodecChannel::FrameBegin(_)) => BlockType::FrameBegin,
            Block::CodecChannel(CodecChannel::FrameEnd(_)) => BlockType::FrameEnd,
            Block::CodecChannel(CodecChannel::Region(_)) => BlockType::Region,
            Block::CodecChannel(CodecChannel::TileSet(_)) => BlockType::Extension,
        }
    }
}

impl Encode for Block<'_> {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        let ty = self.block_type();
        let data_length = self.size();
        BlockHeader { ty, data_length }.encode(dst)?;

        if let Block::CodecChannel(c) = self {
            let channel_id = c.channel_id();
            CodecChannelHeader { channel_id }.encode(dst)?;
        }

        match self {
            Block::Tile(t) => t.encode(dst),
            Block::Caps(c) => c.encode(dst),
            Block::CapabilitySet(c) => c.encode(dst),
            Block::Sync(s) => s.encode(dst),
            Block::Channels(c) => c.encode(dst),
            Block::CodecVersions(c) => c.encode(dst),
            Block::CodecChannel(CodecChannel::Context(c)) => c.encode(dst),
            Block::CodecChannel(CodecChannel::FrameBegin(f)) => f.encode(dst),
            Block::CodecChannel(CodecChannel::FrameEnd(f)) => f.encode(dst),
            Block::CodecChannel(CodecChannel::Region(r)) => r.encode(dst),
            Block::CodecChannel(CodecChannel::TileSet(t)) => t.encode(dst),
        }
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
            + if matches!(self, Block::CodecChannel(_)) {
                CodecChannelHeader::FIXED_PART_SIZE
            } else {
                0
            }
            + match self {
                Block::Tile(t) => t.size(),
                Block::Caps(c) => c.size(),
                Block::CapabilitySet(c) => c.size(),
                Block::Sync(s) => s.size(),
                Block::Channels(c) => c.size(),
                Block::CodecVersions(c) => c.size(),
                Block::CodecChannel(CodecChannel::Context(c)) => c.size(),
                Block::CodecChannel(CodecChannel::FrameBegin(f)) => f.size(),
                Block::CodecChannel(CodecChannel::FrameEnd(f)) => f.size(),
                Block::CodecChannel(CodecChannel::Region(r)) => r.size(),
                Block::CodecChannel(CodecChannel::TileSet(t)) => t.size(),
            }
    }
}

impl<'de> Decode<'de> for Block<'de> {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = BlockHeader::decode(src)?;
        let mut len = header.size();
        if header.ty.is_channel() {
            let channel = CodecChannelHeader::decode(src)?;
            let expected_id = if header.ty == BlockType::Context {
                CHANNEL_ID_FOR_CONTEXT
            } else {
                CHANNEL_ID_FOR_OTHER_VALUES
            };
            if channel.channel_id != expected_id {
                return Err(invalid_field_err!("channelId", "Invalid channel ID"));
            }
            len += channel.size();
        }
        let data_len = header
            .data_length
            .checked_sub(len)
            .ok_or_else(|| invalid_field_err!("blockLen", "Invalid block length"))?;
        ensure_size!(in: src, size: data_len);
        let src = &mut ReadCursor::new(src.read_slice(data_len));
        match header.ty {
            BlockType::Tile => Ok(Self::Tile(Tile::decode(src)?)),
            BlockType::Capabilities => Ok(Self::Caps(RfxCaps::decode(src)?)),
            BlockType::CapabilitySet => Ok(Self::CapabilitySet(RfxCapset::decode(src)?)),
            BlockType::Sync => Ok(Self::Sync(SyncPdu::decode(src)?)),
            BlockType::Channels => Ok(Self::Channels(ChannelsPdu::decode(src)?)),
            BlockType::CodecVersions => Ok(Self::CodecVersions(CodecVersionsPdu::decode(src)?)),
            BlockType::Context => Ok(Self::CodecChannel(CodecChannel::Context(ContextPdu::decode(src)?))),
            BlockType::FrameBegin => Ok(Self::CodecChannel(CodecChannel::FrameBegin(FrameBeginPdu::decode(
                src,
            )?))),
            BlockType::FrameEnd => Ok(Self::CodecChannel(CodecChannel::FrameEnd(FrameEndPdu::decode(src)?))),
            BlockType::Region => Ok(Self::CodecChannel(CodecChannel::Region(RegionPdu::decode(src)?))),
            BlockType::Extension => Ok(Self::CodecChannel(CodecChannel::TileSet(TileSetPdu::decode(src)?))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum CodecChannel<'a> {
    Context(ContextPdu),
    FrameBegin(FrameBeginPdu),
    FrameEnd(FrameEndPdu),
    Region(RegionPdu),
    TileSet(TileSetPdu<'a>),
}

impl CodecChannel<'_> {
    fn channel_id(&self) -> u8 {
        if matches!(self, CodecChannel::Context(_)) {
            CHANNEL_ID_FOR_CONTEXT
        } else {
            CHANNEL_ID_FOR_OTHER_VALUES
        }
    }
}

/// [2.2.2.1.1] TS_RFX_BLOCKT
///
/// [2.2.2.1.1]: https://learn.microsoft.com/pt-br/openspecs/windows_protocols/ms-rdprfx/1e1b69a9-c2aa-4b13-bd44-23dcf96d4a74
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct BlockHeader {
    pub ty: BlockType,
    pub data_length: usize,
}

impl BlockHeader {
    const NAME: &'static str = "RfxBlockHeader";

    const FIXED_PART_SIZE: usize = 2 /* blockType */ + 4 /* blockLen */;
}

impl Encode for BlockHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(self.ty.as_u16());
        dst.write_u32(cast_length!("data len", self.data_length)?);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for BlockHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let ty = src.read_u16();
        let ty = BlockType::from_u16(ty).ok_or_else(|| invalid_field_err!("blockType", "Invalid block type"))?;
        let data_length: usize = cast_length!("block length", src.read_u32())?;
        data_length
            .checked_sub(Self::FIXED_PART_SIZE)
            .ok_or_else(|| invalid_field_err!("blockLen", "Invalid block length"))?;

        Ok(Self { ty, data_length })
    }
}

/// [2.2.2.1.2] TS_RFX_CODEC_CHANNELT
///
/// [2.2.2.1.2]: https://learn.microsoft.com/pt-br/openspecs/windows_protocols/ms-rdprfx/56b78b0c-6eef-40cc-b9da-96d21f197c14
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct CodecChannelHeader {
    channel_id: u8,
}

impl CodecChannelHeader {
    const NAME: &'static str = "CodecChannelHeader";

    const FIXED_PART_SIZE: usize = 1 /* codecId */ + 1 /* channelId */;
}

impl Encode for CodecChannelHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u8(CODEC_ID);
        dst.write_u8(self.channel_id);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl Decode<'_> for CodecChannelHeader {
    fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let codec_id = src.read_u8();
        if codec_id != CODEC_ID {
            return Err(invalid_field_err!("codecId", "Invalid codec ID"));
        }

        let channel_id = src.read_u8();

        Ok(Self { channel_id })
    }
}

/// [2.2.3.1] TS_FRAME_ACKNOWLEDGE_PDU
///
/// [2.2.3.1]: https://learn.microsoft.com/pt-br/openspecs/windows_protocols/ms-rdprfx/24364aa2-9a7f-4d86-bcfb-67f5a6c19064
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct FrameAcknowledgePdu {
    pub frame_id: u32,
}

impl FrameAcknowledgePdu {
    const NAME: &'static str = "FrameAcknowledgePdu";

    const FIXED_PART_SIZE: usize = 4 /* frameId */;
}

impl Encode for FrameAcknowledgePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u32(self.frame_id);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for FrameAcknowledgePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let frame_id = src.read_u32();

        Ok(Self { frame_id })
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u16)]
pub enum BlockType {
    Tile = 0xCAC3,
    Capabilities = 0xCBC0,
    CapabilitySet = 0xCBC1,
    Sync = 0xCCC0,
    CodecVersions = 0xCCC1,
    Channels = 0xCCC2,
    Context = 0xCCC3,
    FrameBegin = 0xCCC4,
    FrameEnd = 0xCCC5,
    Region = 0xCCC6,
    Extension = 0xCCC7,
}

impl BlockType {
    fn is_channel(&self) -> bool {
        matches!(
            self,
            BlockType::Context | BlockType::FrameBegin | BlockType::FrameEnd | BlockType::Region | BlockType::Extension
        )
    }

    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u16(self) -> u16 {
        self as u16
    }
}
