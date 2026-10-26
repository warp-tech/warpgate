use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, cast_length, decode, ensure_fixed_part_size,
    ensure_size, invalid_field_err, unsupported_value_err, write_padding,
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive as _;

use crate::utils;

mod bitmap;
mod bitmap_cache;
mod bitmap_codecs;
mod brush;
mod frame_acknowledge;
mod general;
mod glyph_cache;
mod input;
mod large_pointer;
mod multifragment_update;
mod offscreen_bitmap_cache;
mod order;
mod pointer;
mod sound;
mod surface_commands;
mod virtual_channel;

pub use self::bitmap::{Bitmap, BitmapDrawingFlags};
pub use self::bitmap_cache::{
    BITMAP_CACHE_ENTRIES_NUM, BitmapCache, BitmapCacheRev2, CacheEntry, CacheFlags, CellInfo,
};
pub use self::bitmap_codecs::{
    BitmapCodecs, CODEC_ID_NONE, CODEC_ID_QOI, CODEC_ID_QOIZ, CODEC_ID_REMOTEFX, CaptureFlags, Codec, CodecId,
    CodecProperty, EntropyBits, Guid, NsCodec, RemoteFxContainer, RfxCaps, RfxCapset, RfxClientCapsContainer, RfxICap,
    RfxICapFlags, client_codecs_capabilities, server_codecs_capabilities,
};
pub use self::brush::{Brush, SupportLevel};
pub use self::frame_acknowledge::FrameAcknowledge;
pub use self::general::{General, GeneralExtraFlags, MajorPlatformType, MinorPlatformType, PROTOCOL_VER};
pub use self::glyph_cache::{CacheDefinition, GLYPH_CACHE_NUM, GlyphCache, GlyphSupportLevel};
pub use self::input::{Input, InputFlags};
pub use self::large_pointer::{LargePointer, LargePointerSupportFlags};
pub use self::multifragment_update::MultifragmentUpdate;
pub use self::offscreen_bitmap_cache::OffscreenBitmapCache;
pub use self::order::{Order, OrderFlags, OrderSupportExFlags, OrderSupportIndex};
pub use self::pointer::Pointer;
pub use self::sound::{Sound, SoundFlags};
pub use self::surface_commands::{CmdFlags, SurfaceCommands};
pub use self::virtual_channel::{VirtualChannel, VirtualChannelFlags};

pub const SERVER_CHANNEL_ID: u16 = 0x03ea;

const SOURCE_DESCRIPTOR_LENGTH_FIELD_SIZE: usize = 2;
const COMBINED_CAPABILITIES_LENGTH_FIELD_SIZE: usize = 2;
const NUMBER_CAPABILITIES_FIELD_SIZE: usize = 2;
const PADDING_SIZE: usize = 2;
const SESSION_ID_FIELD_SIZE: usize = 4;
const CAPABILITY_SET_TYPE_FIELD_SIZE: usize = 2;
const CAPABILITY_SET_LENGTH_FIELD_SIZE: usize = 2;
const ORIGINATOR_ID_FIELD_SIZE: usize = 2;

const NULL_TERMINATOR: &str = "\0";

/// [2.2.1.13.1] Server Demand Active PDU
///
/// [2.2.1.13.1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/a07abad1-38bb-4a1a-96c9-253e3d5440df
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ServerDemandActive {
    pub pdu: DemandActive,
}

impl ServerDemandActive {
    const NAME: &'static str = "ServerDemandActive";

    const FIXED_PART_SIZE: usize = SESSION_ID_FIELD_SIZE;
}

impl Encode for ServerDemandActive {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        self.pdu.encode(dst)?;
        dst.write_u32(0); // This field is ignored by the client

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.pdu.size()
    }
}

impl<'de> Decode<'de> for ServerDemandActive {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let pdu = DemandActive::decode(src)?;

        ensure_size!(in: src, size: 4);
        let _session_id = src.read_u32();

        Ok(Self { pdu })
    }
}

/// [2.2.1.13.2] Client Confirm Active PDU
///
/// [2.2.1.13.2]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/4c3c2710-0bf0-4c54-8e69-aff40ffcde66
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ClientConfirmActive {
    /// According to [MSDN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/4e9722c3-ad83-43f5-af5a-529f73d88b48),
    /// this field MUST be set to [SERVER_CHANNEL_ID](constant.SERVER_CHANNEL_ID.html).
    /// However, the Microsoft RDP client takes this value from a server's
    /// [PduSource](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/73d01865-2eae-407f-9b2c-87e31daac471)
    /// field of the [Server Demand Active PDU](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/bd612af5-cb54-43a2-9646-438bc3ecf5db).
    /// Therefore, checking the `originator_id` field is the responsibility of the user of the library.
    pub originator_id: u16,
    pub pdu: DemandActive,
}

impl ClientConfirmActive {
    const NAME: &'static str = "ClientConfirmActive";

    const FIXED_PART_SIZE: usize = ORIGINATOR_ID_FIELD_SIZE;
}

impl Encode for ClientConfirmActive {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(self.originator_id);

        self.pdu.encode(dst)
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.pdu.size()
    }
}

impl<'de> Decode<'de> for ClientConfirmActive {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let originator_id = src.read_u16();
        let pdu = DemandActive::decode(src)?;

        Ok(Self { originator_id, pdu })
    }
}

/// 2.2.1.13.1.1 Demand Active PDU Data (TS_DEMAND_ACTIVE_PDU)
///
/// [2.2.1.13.1.1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/bd612af5-cb54-43a2-9646-438bc3ecf5db
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct DemandActive {
    pub source_descriptor: String,
    pub capability_sets: Vec<CapabilitySet>,
}

impl DemandActive {
    const NAME: &'static str = "DemandActive";

    const FIXED_PART_SIZE: usize = SOURCE_DESCRIPTOR_LENGTH_FIELD_SIZE + COMBINED_CAPABILITIES_LENGTH_FIELD_SIZE;
}

impl Encode for DemandActive {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        let combined_length = self.capability_sets.iter().map(Encode::size).sum::<usize>()
            + NUMBER_CAPABILITIES_FIELD_SIZE
            + PADDING_SIZE;

        dst.write_u16(cast_length!(
            "sourceDescLen",
            self.source_descriptor.len() + NULL_TERMINATOR.len()
        )?);
        dst.write_u16(cast_length!("combinedLen", combined_length)?);
        dst.write_slice(self.source_descriptor.as_ref());
        dst.write_slice(NULL_TERMINATOR.as_bytes());
        dst.write_u16(cast_length!("len", self.capability_sets.len())?);
        write_padding!(dst, 2);

        for capability_set in self.capability_sets.iter() {
            capability_set.encode(dst)?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
            + self.source_descriptor.len()
            + 1
            + NUMBER_CAPABILITIES_FIELD_SIZE
            + PADDING_SIZE
            + self.capability_sets.iter().map(Encode::size).sum::<usize>()
    }
}

impl<'de> Decode<'de> for DemandActive {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let source_descriptor_length = usize::from(src.read_u16());
        // The combined size in bytes of the numberCapabilities, pad2Octets, and capabilitySets fields.
        let _combined_capabilities_length = usize::from(src.read_u16());

        ensure_size!(in: src, size: source_descriptor_length);
        let source_descriptor = utils::decode_string(
            src.read_slice(source_descriptor_length),
            utils::CharacterSet::Ansi,
            false,
        )?;

        ensure_size!(in: src, size: 2 + 2);
        let capability_sets_count = usize::from(src.read_u16());
        let _padding = src.read_u16();

        let mut capability_sets = Vec::with_capacity(capability_sets_count);

        for _ in 0..capability_sets_count {
            capability_sets.push(CapabilitySet::decode(src)?);
        }

        Ok(Self {
            source_descriptor,
            capability_sets,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum CapabilitySet {
    // mandatory
    General(General),
    Bitmap(Bitmap),
    Order(Order),
    BitmapCache(BitmapCache),
    BitmapCacheRev2(BitmapCacheRev2),
    Pointer(Pointer),
    Sound(Sound),
    Input(Input),
    Brush(Brush),
    GlyphCache(GlyphCache),
    OffscreenBitmapCache(OffscreenBitmapCache),
    VirtualChannel(VirtualChannel),

    // optional
    Control(Vec<u8>),
    WindowActivation(Vec<u8>),
    Share(Vec<u8>),
    Font(Vec<u8>),
    BitmapCacheHostSupport(Vec<u8>),
    DesktopComposition(Vec<u8>),
    MultiFragmentUpdate(MultifragmentUpdate),
    LargePointer(LargePointer),
    SurfaceCommands(SurfaceCommands),
    BitmapCodecs(BitmapCodecs),

    // other
    FrameAcknowledge(FrameAcknowledge),
    ColorCache(Vec<u8>),
    DrawNineGridCache(Vec<u8>),
    DrawGdiPlus(Vec<u8>),
    Rail(Vec<u8>),
    WindowList(Vec<u8>),
    BitmapCacheV3(Vec<u8>),
}

impl CapabilitySet {
    const NAME: &'static str = "CapabilitySet";

    const FIXED_PART_SIZE: usize = CAPABILITY_SET_TYPE_FIELD_SIZE + CAPABILITY_SET_LENGTH_FIELD_SIZE;
}

impl Encode for CapabilitySet {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        match self {
            CapabilitySet::General(capset) => {
                dst.write_u16(CapabilitySetType::General.as_u16());
                dst.write_u16(cast_length!(
                    "len",
                    capset.size() + CAPABILITY_SET_TYPE_FIELD_SIZE + CAPABILITY_SET_LENGTH_FIELD_SIZE
                )?);
                capset.encode(dst)?;
            }
            CapabilitySet::Bitmap(capset) => {
                dst.write_u16(CapabilitySetType::Bitmap.as_u16());
                dst.write_u16(cast_length!(
                    "len",
                    capset.size() + CAPABILITY_SET_TYPE_FIELD_SIZE + CAPABILITY_SET_LENGTH_FIELD_SIZE
                )?);
                capset.encode(dst)?;
            }
            CapabilitySet::Order(capset) => {
                dst.write_u16(CapabilitySetType::Order.as_u16());
                dst.write_u16(cast_length!(
                    "len",
                    capset.size() + CAPABILITY_SET_TYPE_FIELD_SIZE + CAPABILITY_SET_LENGTH_FIELD_SIZE
                )?);
                capset.encode(dst)?;
            }
            CapabilitySet::BitmapCache(capset) => {
                dst.write_u16(CapabilitySetType::BitmapCache.as_u16());
                dst.write_u16(cast_length!(
                    "len",
                    capset.size() + CAPABILITY_SET_TYPE_FIELD_SIZE + CAPABILITY_SET_LENGTH_FIELD_SIZE
                )?);
                capset.encode(dst)?;
            }
            CapabilitySet::BitmapCacheRev2(capset) => {
                dst.write_u16(CapabilitySetType::BitmapCacheRev2.as_u16());
                dst.write_u16(cast_length!(
                    "len",
                    capset.size() + CAPABILITY_SET_TYPE_FIELD_SIZE + CAPABILITY_SET_LENGTH_FIELD_SIZE
                )?);
                capset.encode(dst)?;
            }
            CapabilitySet::Pointer(capset) => {
                dst.write_u16(CapabilitySetType::Pointer.as_u16());
                dst.write_u16(cast_length!(
                    "len",
                    capset.size() + CAPABILITY_SET_TYPE_FIELD_SIZE + CAPABILITY_SET_LENGTH_FIELD_SIZE
                )?);
                capset.encode(dst)?;
            }
            CapabilitySet::Sound(capset) => {
                dst.write_u16(CapabilitySetType::Sound.as_u16());
                dst.write_u16(cast_length!(
                    "len",
                    capset.size() + CAPABILITY_SET_TYPE_FIELD_SIZE + CAPABILITY_SET_LENGTH_FIELD_SIZE
                )?);
                capset.encode(dst)?;
            }
            CapabilitySet::Input(capset) => {
                dst.write_u16(CapabilitySetType::Input.as_u16());
                dst.write_u16(cast_length!(
                    "len",
                    capset.size() + CAPABILITY_SET_TYPE_FIELD_SIZE + CAPABILITY_SET_LENGTH_FIELD_SIZE
                )?);
                capset.encode(dst)?;
            }
            CapabilitySet::Brush(capset) => {
                dst.write_u16(CapabilitySetType::Brush.as_u16());
                dst.write_u16(cast_length!(
                    "len",
                    capset.size() + CAPABILITY_SET_TYPE_FIELD_SIZE + CAPABILITY_SET_LENGTH_FIELD_SIZE
                )?);
                capset.encode(dst)?;
            }
            CapabilitySet::GlyphCache(capset) => {
                dst.write_u16(CapabilitySetType::GlyphCache.as_u16());
                dst.write_u16(cast_length!(
                    "len",
                    capset.size() + CAPABILITY_SET_TYPE_FIELD_SIZE + CAPABILITY_SET_LENGTH_FIELD_SIZE
                )?);
                capset.encode(dst)?;
            }
            CapabilitySet::OffscreenBitmapCache(capset) => {
                dst.write_u16(CapabilitySetType::OffscreenBitmapCache.as_u16());
                dst.write_u16(cast_length!(
                    "len",
                    capset.size() + CAPABILITY_SET_TYPE_FIELD_SIZE + CAPABILITY_SET_LENGTH_FIELD_SIZE
                )?);
                capset.encode(dst)?;
            }
            CapabilitySet::VirtualChannel(capset) => {
                dst.write_u16(CapabilitySetType::VirtualChannel.as_u16());
                dst.write_u16(cast_length!(
                    "len",
                    capset.size() + CAPABILITY_SET_TYPE_FIELD_SIZE + CAPABILITY_SET_LENGTH_FIELD_SIZE
                )?);
                capset.encode(dst)?;
            }
            CapabilitySet::SurfaceCommands(capset) => {
                dst.write_u16(CapabilitySetType::SurfaceCommands.as_u16());
                dst.write_u16(cast_length!(
                    "len",
                    capset.size() + CAPABILITY_SET_TYPE_FIELD_SIZE + CAPABILITY_SET_LENGTH_FIELD_SIZE
                )?);
                capset.encode(dst)?;
            }
            CapabilitySet::BitmapCodecs(capset) => {
                dst.write_u16(CapabilitySetType::BitmapCodecs.as_u16());
                dst.write_u16(cast_length!(
                    "len",
                    capset.size() + CAPABILITY_SET_TYPE_FIELD_SIZE + CAPABILITY_SET_LENGTH_FIELD_SIZE
                )?);
                capset.encode(dst)?;
            }
            CapabilitySet::MultiFragmentUpdate(capset) => {
                dst.write_u16(CapabilitySetType::MultiFragmentUpdate.as_u16());
                dst.write_u16(cast_length!(
                    "len",
                    capset.size() + CAPABILITY_SET_TYPE_FIELD_SIZE + CAPABILITY_SET_LENGTH_FIELD_SIZE
                )?);
                capset.encode(dst)?;
            }
            CapabilitySet::LargePointer(capset) => {
                dst.write_u16(CapabilitySetType::LargePointer.as_u16());
                dst.write_u16(cast_length!(
                    "len",
                    capset.size() + CAPABILITY_SET_TYPE_FIELD_SIZE + CAPABILITY_SET_LENGTH_FIELD_SIZE
                )?);
                capset.encode(dst)?;
            }
            CapabilitySet::FrameAcknowledge(capset) => {
                dst.write_u16(CapabilitySetType::FrameAcknowledge.as_u16());
                dst.write_u16(cast_length!(
                    "len",
                    capset.size() + CAPABILITY_SET_TYPE_FIELD_SIZE + CAPABILITY_SET_LENGTH_FIELD_SIZE
                )?);
                capset.encode(dst)?;
            }
            _ => {
                let (capability_set_type, capability_set_buffer) = match self {
                    CapabilitySet::Control(buffer) => (CapabilitySetType::Control, buffer),
                    CapabilitySet::WindowActivation(buffer) => (CapabilitySetType::WindowActivation, buffer),
                    CapabilitySet::Share(buffer) => (CapabilitySetType::Share, buffer),
                    CapabilitySet::Font(buffer) => (CapabilitySetType::Font, buffer),
                    CapabilitySet::BitmapCacheHostSupport(buffer) => {
                        (CapabilitySetType::BitmapCacheHostSupport, buffer)
                    }
                    CapabilitySet::DesktopComposition(buffer) => (CapabilitySetType::DesktopComposition, buffer),
                    CapabilitySet::ColorCache(buffer) => (CapabilitySetType::ColorCache, buffer),
                    CapabilitySet::DrawNineGridCache(buffer) => (CapabilitySetType::DrawNineGridCache, buffer),
                    CapabilitySet::DrawGdiPlus(buffer) => (CapabilitySetType::DrawGdiPlus, buffer),
                    CapabilitySet::Rail(buffer) => (CapabilitySetType::Rail, buffer),
                    CapabilitySet::WindowList(buffer) => (CapabilitySetType::WindowList, buffer),
                    CapabilitySet::BitmapCacheV3(buffer) => (CapabilitySetType::BitmapCacheV3CodecID, buffer),
                    // Structured variants are routed through the outer match's
                    // specific arms above this block and cannot reach this
                    // inner match. Listing them explicitly (instead of using
                    // `_ =>`) makes a future addition to `CapabilitySet` a
                    // compile error here until the new variant is routed in
                    // this `Encode` impl. PR #1313 (BitmapCacheV3 encoder
                    // `unreachable!()` reached on decoder-accepted input)
                    // demonstrated why a runtime catch-all is the wrong shape
                    // for this match.
                    CapabilitySet::General(_)
                    | CapabilitySet::Bitmap(_)
                    | CapabilitySet::Order(_)
                    | CapabilitySet::BitmapCache(_)
                    | CapabilitySet::BitmapCacheRev2(_)
                    | CapabilitySet::Pointer(_)
                    | CapabilitySet::Sound(_)
                    | CapabilitySet::Input(_)
                    | CapabilitySet::Brush(_)
                    | CapabilitySet::GlyphCache(_)
                    | CapabilitySet::OffscreenBitmapCache(_)
                    | CapabilitySet::VirtualChannel(_)
                    | CapabilitySet::MultiFragmentUpdate(_)
                    | CapabilitySet::LargePointer(_)
                    | CapabilitySet::SurfaceCommands(_)
                    | CapabilitySet::BitmapCodecs(_)
                    | CapabilitySet::FrameAcknowledge(_) => {
                        unreachable!("structured variant routed to raw-buffer encoder arm")
                    }
                };

                dst.write_u16(capability_set_type.as_u16());
                dst.write_u16(cast_length!(
                    "len",
                    capability_set_buffer.len() + CAPABILITY_SET_TYPE_FIELD_SIZE + CAPABILITY_SET_LENGTH_FIELD_SIZE
                )?);
                dst.write_slice(capability_set_buffer);
            }
        };
        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
            + match self {
                CapabilitySet::General(capset) => capset.size(),
                CapabilitySet::Bitmap(capset) => capset.size(),
                CapabilitySet::Order(capset) => capset.size(),
                CapabilitySet::BitmapCache(capset) => capset.size(),
                CapabilitySet::BitmapCacheRev2(capset) => capset.size(),
                CapabilitySet::Pointer(capset) => capset.size(),
                CapabilitySet::Sound(capset) => capset.size(),
                CapabilitySet::Input(capset) => capset.size(),
                CapabilitySet::Brush(capset) => capset.size(),
                CapabilitySet::GlyphCache(capset) => capset.size(),
                CapabilitySet::OffscreenBitmapCache(capset) => capset.size(),
                CapabilitySet::VirtualChannel(capset) => capset.size(),
                CapabilitySet::SurfaceCommands(capset) => capset.size(),
                CapabilitySet::BitmapCodecs(capset) => capset.size(),
                CapabilitySet::MultiFragmentUpdate(capset) => capset.size(),
                CapabilitySet::LargePointer(capset) => capset.size(),
                CapabilitySet::FrameAcknowledge(capset) => capset.size(),
                CapabilitySet::Control(buffer)
                | CapabilitySet::WindowActivation(buffer)
                | CapabilitySet::Share(buffer)
                | CapabilitySet::Font(buffer)
                | CapabilitySet::BitmapCacheHostSupport(buffer)
                | CapabilitySet::DesktopComposition(buffer)
                | CapabilitySet::ColorCache(buffer)
                | CapabilitySet::DrawNineGridCache(buffer)
                | CapabilitySet::DrawGdiPlus(buffer)
                | CapabilitySet::Rail(buffer)
                | CapabilitySet::WindowList(buffer)
                | CapabilitySet::BitmapCacheV3(buffer) => buffer.len(),
            }
    }
}

impl<'de> Decode<'de> for CapabilitySet {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let capability_set_type_raw = src.read_u16();
        let capability_set_type = CapabilitySetType::from_u16(capability_set_type_raw).ok_or_else(|| {
            unsupported_value_err!(
                "capabilitySetType",
                format!("invalid capability set type: {}", capability_set_type_raw)
            )
        })?;

        let length = usize::from(src.read_u16());

        if length < CAPABILITY_SET_TYPE_FIELD_SIZE + CAPABILITY_SET_LENGTH_FIELD_SIZE {
            return Err(invalid_field_err!("len", "invalid capability set length"));
        }

        let buffer_length = length - CAPABILITY_SET_TYPE_FIELD_SIZE - CAPABILITY_SET_LENGTH_FIELD_SIZE;
        ensure_size!(in: src, size: buffer_length);
        let capability_set_buffer = src.read_slice(buffer_length);

        match capability_set_type {
            CapabilitySetType::General => Ok(CapabilitySet::General(decode(capability_set_buffer)?)),
            CapabilitySetType::Bitmap => Ok(CapabilitySet::Bitmap(decode(capability_set_buffer)?)),
            CapabilitySetType::Order => Ok(CapabilitySet::Order(decode(capability_set_buffer)?)),
            CapabilitySetType::BitmapCache => Ok(CapabilitySet::BitmapCache(decode(capability_set_buffer)?)),
            CapabilitySetType::BitmapCacheRev2 => Ok(CapabilitySet::BitmapCacheRev2(decode(capability_set_buffer)?)),
            CapabilitySetType::Pointer => Ok(CapabilitySet::Pointer(decode(capability_set_buffer)?)),
            CapabilitySetType::Sound => Ok(CapabilitySet::Sound(decode(capability_set_buffer)?)),
            CapabilitySetType::Input => Ok(CapabilitySet::Input(decode(capability_set_buffer)?)),
            CapabilitySetType::Brush => Ok(CapabilitySet::Brush(decode(capability_set_buffer)?)),
            CapabilitySetType::GlyphCache => Ok(CapabilitySet::GlyphCache(decode(capability_set_buffer)?)),
            CapabilitySetType::OffscreenBitmapCache => {
                Ok(CapabilitySet::OffscreenBitmapCache(decode(capability_set_buffer)?))
            }
            CapabilitySetType::VirtualChannel => Ok(CapabilitySet::VirtualChannel(decode(capability_set_buffer)?)),
            CapabilitySetType::SurfaceCommands => Ok(CapabilitySet::SurfaceCommands(decode(capability_set_buffer)?)),
            CapabilitySetType::BitmapCodecs => Ok(CapabilitySet::BitmapCodecs(decode(capability_set_buffer)?)),

            CapabilitySetType::Control => Ok(CapabilitySet::Control(capability_set_buffer.into())),
            CapabilitySetType::WindowActivation => Ok(CapabilitySet::WindowActivation(capability_set_buffer.into())),
            CapabilitySetType::Share => Ok(CapabilitySet::Share(capability_set_buffer.into())),
            CapabilitySetType::Font => Ok(CapabilitySet::Font(capability_set_buffer.into())),
            CapabilitySetType::BitmapCacheHostSupport => {
                Ok(CapabilitySet::BitmapCacheHostSupport(capability_set_buffer.into()))
            }
            CapabilitySetType::DesktopComposition => {
                Ok(CapabilitySet::DesktopComposition(capability_set_buffer.into()))
            }
            CapabilitySetType::MultiFragmentUpdate => {
                Ok(CapabilitySet::MultiFragmentUpdate(decode(capability_set_buffer)?))
            }
            CapabilitySetType::LargePointer => Ok(CapabilitySet::LargePointer(decode(capability_set_buffer)?)),
            CapabilitySetType::ColorCache => Ok(CapabilitySet::ColorCache(capability_set_buffer.into())),
            CapabilitySetType::DrawNineGridCache => Ok(CapabilitySet::DrawNineGridCache(capability_set_buffer.into())),
            CapabilitySetType::DrawGdiPlus => Ok(CapabilitySet::DrawGdiPlus(capability_set_buffer.into())),
            CapabilitySetType::Rail => Ok(CapabilitySet::Rail(capability_set_buffer.into())),
            CapabilitySetType::WindowList => Ok(CapabilitySet::WindowList(capability_set_buffer.into())),
            CapabilitySetType::FrameAcknowledge => Ok(CapabilitySet::FrameAcknowledge(decode(capability_set_buffer)?)),
            CapabilitySetType::BitmapCacheV3CodecID => Ok(CapabilitySet::BitmapCacheV3(capability_set_buffer.into())),
        }
    }
}

#[repr(u16)]
#[derive(Copy, Clone, Debug, FromPrimitive)]
enum CapabilitySetType {
    General = 0x01,
    Bitmap = 0x02,
    Order = 0x03,
    BitmapCache = 0x04,
    Control = 0x05,
    BitmapCacheV3CodecID = 0x06,
    WindowActivation = 0x07,
    Pointer = 0x08,
    Share = 0x09,
    ColorCache = 0x0a,
    Sound = 0x0c,
    Input = 0x0d,
    Font = 0x0e,
    Brush = 0x0f,
    GlyphCache = 0x10,
    OffscreenBitmapCache = 0x11,
    BitmapCacheHostSupport = 0x12,
    BitmapCacheRev2 = 0x13,
    VirtualChannel = 0x14,
    DrawNineGridCache = 0x15,
    DrawGdiPlus = 0x16,
    Rail = 0x17,
    WindowList = 0x18,
    DesktopComposition = 0x19,
    MultiFragmentUpdate = 0x1a,
    LargePointer = 0x1b,
    SurfaceCommands = 0x1c,
    BitmapCodecs = 0x1d,
    FrameAcknowledge = 0x1e,
}

impl CapabilitySetType {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u16(self) -> u16 {
        self as u16
    }
}
