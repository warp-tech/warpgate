use core::{fmt, iter};

use bit_field::BitField as _;
use bitflags::bitflags;
use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, ensure_fixed_part_size, invalid_field_err,
};
use ironrdp_dvc::DvcEncode;
use ironrdp_pdu::gcc::Monitor;
use ironrdp_pdu::geometry::ExclusiveRectangle;
use ironrdp_pdu::{DecodeError, cast_length, ensure_size, read_padding, write_padding};
use tracing::warn;

use super::{Color, PixelFormat, Point};

const RDPGFX_CMDID_WIRETOSURFACE_1: u16 = 0x0001;
const RDPGFX_CMDID_WIRETOSURFACE_2: u16 = 0x0002;
const RDPGFX_CMDID_DELETEENCODINGCONTEXT: u16 = 0x0003;
const RDPGFX_CMDID_SOLIDFILL: u16 = 0x0004;
const RDPGFX_CMDID_SURFACETOSURFACE: u16 = 0x0005;
const RDPGFX_CMDID_SURFACETOCACHE: u16 = 0x0006;
const RDPGFX_CMDID_CACHETOSURFACE: u16 = 0x0007;
const RDPGFX_CMDID_EVICTCACHEENTRY: u16 = 0x0008;
const RDPGFX_CMDID_CREATESURFACE: u16 = 0x0009;
const RDPGFX_CMDID_DELETESURFACE: u16 = 0x000a;
const RDPGFX_CMDID_STARTFRAME: u16 = 0x000b;
const RDPGFX_CMDID_ENDFRAME: u16 = 0x000c;
const RDPGFX_CMDID_FRAMEACKNOWLEDGE: u16 = 0x000d;
const RDPGFX_CMDID_RESETGRAPHICS: u16 = 0x000e;
const RDPGFX_CMDID_MAPSURFACETOOUTPUT: u16 = 0x000f;
const RDPGFX_CMDID_CACHEIMPORTOFFER: u16 = 0x0010;
const RDPGFX_CMDID_CACHEIMPORTREPLY: u16 = 0x0011;
const RDPGFX_CMDID_CAPSADVERTISE: u16 = 0x0012;
const RDPGFX_CMDID_CAPSCONFIRM: u16 = 0x0013;
const RDPGFX_CMDID_MAPSURFACETOWINDOW: u16 = 0x0015;
const RDPGFX_CMDID_QOEFRAMEACKNOWLEDGE: u16 = 0x0016;
const RDPGFX_CMDID_MAPSURFACETOSCALEDOUTPUT: u16 = 0x0017;
const RDPGFX_CMDID_MAPSURFACETOSCALEDWINDOW: u16 = 0x0018;

const MAX_RESET_GRAPHICS_WIDTH_HEIGHT: u32 = 32_766;
const MONITOR_COUNT_MAX: u32 = 16;
const RESET_GRAPHICS_PDU_SIZE: usize = 340 - GfxPdu::FIXED_PART_SIZE;

/// Display Pipeline Virtual Channel message (PDU prefixed with `RDPGFX_HEADER`)
///
/// INVARIANTS: size of encoded inner PDU is always less than `u32::MAX - Self::FIXED_PART_SIZE`
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GfxPdu {
    WireToSurface1(WireToSurface1Pdu),
    WireToSurface2(WireToSurface2Pdu),
    DeleteEncodingContext(DeleteEncodingContextPdu),
    SolidFill(SolidFillPdu),
    SurfaceToSurface(SurfaceToSurfacePdu),
    SurfaceToCache(SurfaceToCachePdu),
    CacheToSurface(CacheToSurfacePdu),
    EvictCacheEntry(EvictCacheEntryPdu),
    CreateSurface(CreateSurfacePdu),
    DeleteSurface(DeleteSurfacePdu),
    StartFrame(StartFramePdu),
    EndFrame(EndFramePdu),
    FrameAcknowledge(FrameAcknowledgePdu),
    ResetGraphics(ResetGraphicsPdu),
    MapSurfaceToOutput(MapSurfaceToOutputPdu),
    CacheImportOffer(CacheImportOfferPdu),
    CacheImportReply(CacheImportReplyPdu),
    CapabilitiesAdvertise(CapabilitiesAdvertisePdu),
    CapabilitiesConfirm(CapabilitiesConfirmPdu),
    MapSurfaceToWindow(MapSurfaceToWindowPdu),
    QoeFrameAcknowledge(QoeFrameAcknowledgePdu),
    MapSurfaceToScaledOutput(MapSurfaceToScaledOutputPdu),
    MapSurfaceToScaledWindow(MapSurfaceToScaledWindowPdu),
}

/// 2.2.1.5 RDPGFX_HEADER
///
/// [2.2.1.5]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/ed075b10-168d-4f56-8348-4029940d7959>
impl GfxPdu {
    const NAME: &'static str = "RDPGFX_HEADER";

    const FIXED_PART_SIZE: usize = 2 /* CmdId */ + 2 /* flags */ + 4 /* Length */;
}

impl Encode for GfxPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        let (cmdid, payload_length) = match self {
            GfxPdu::WireToSurface1(pdu) => (RDPGFX_CMDID_WIRETOSURFACE_1, pdu.size()),
            GfxPdu::WireToSurface2(pdu) => (RDPGFX_CMDID_WIRETOSURFACE_2, pdu.size()),
            GfxPdu::DeleteEncodingContext(pdu) => (RDPGFX_CMDID_DELETEENCODINGCONTEXT, pdu.size()),
            GfxPdu::SolidFill(pdu) => (RDPGFX_CMDID_SOLIDFILL, pdu.size()),
            GfxPdu::SurfaceToSurface(pdu) => (RDPGFX_CMDID_SURFACETOSURFACE, pdu.size()),
            GfxPdu::SurfaceToCache(pdu) => (RDPGFX_CMDID_SURFACETOCACHE, pdu.size()),
            GfxPdu::CacheToSurface(pdu) => (RDPGFX_CMDID_CACHETOSURFACE, pdu.size()),
            GfxPdu::EvictCacheEntry(pdu) => (RDPGFX_CMDID_EVICTCACHEENTRY, pdu.size()),
            GfxPdu::CreateSurface(pdu) => (RDPGFX_CMDID_CREATESURFACE, pdu.size()),
            GfxPdu::DeleteSurface(pdu) => (RDPGFX_CMDID_DELETESURFACE, pdu.size()),
            GfxPdu::StartFrame(pdu) => (RDPGFX_CMDID_STARTFRAME, pdu.size()),
            GfxPdu::EndFrame(pdu) => (RDPGFX_CMDID_ENDFRAME, pdu.size()),
            GfxPdu::FrameAcknowledge(pdu) => (RDPGFX_CMDID_FRAMEACKNOWLEDGE, pdu.size()),
            GfxPdu::ResetGraphics(pdu) => (RDPGFX_CMDID_RESETGRAPHICS, pdu.size()),
            GfxPdu::MapSurfaceToOutput(pdu) => (RDPGFX_CMDID_MAPSURFACETOOUTPUT, pdu.size()),
            GfxPdu::CacheImportOffer(pdu) => (RDPGFX_CMDID_CACHEIMPORTOFFER, pdu.size()),
            GfxPdu::CacheImportReply(pdu) => (RDPGFX_CMDID_CACHEIMPORTREPLY, pdu.size()),
            GfxPdu::CapabilitiesAdvertise(pdu) => (RDPGFX_CMDID_CAPSADVERTISE, pdu.size()),
            GfxPdu::CapabilitiesConfirm(pdu) => (RDPGFX_CMDID_CAPSCONFIRM, pdu.size()),
            GfxPdu::MapSurfaceToWindow(pdu) => (RDPGFX_CMDID_MAPSURFACETOWINDOW, pdu.size()),
            GfxPdu::QoeFrameAcknowledge(pdu) => (RDPGFX_CMDID_QOEFRAMEACKNOWLEDGE, pdu.size()),
            GfxPdu::MapSurfaceToScaledOutput(pdu) => (RDPGFX_CMDID_MAPSURFACETOSCALEDOUTPUT, pdu.size()),
            GfxPdu::MapSurfaceToScaledWindow(pdu) => (RDPGFX_CMDID_MAPSURFACETOSCALEDWINDOW, pdu.size()),
        };

        // This will never overflow as per invariants.
        #[expect(clippy::arithmetic_side_effects, reason = "guaranteed by GfxPdu invariants")]
        let pdu_size = payload_length + Self::FIXED_PART_SIZE;

        // Write `RDPGFX_HEADER` fields.
        dst.write_u16(cmdid);
        dst.write_u16(0); /* flags */
        #[expect(clippy::unwrap_used, reason = "pdu_size bounded by GfxPdu invariants")]
        dst.write_u32(pdu_size.try_into().unwrap());

        match self {
            GfxPdu::WireToSurface1(pdu) => pdu.encode(dst),
            GfxPdu::WireToSurface2(pdu) => pdu.encode(dst),
            GfxPdu::DeleteEncodingContext(pdu) => pdu.encode(dst),
            GfxPdu::SolidFill(pdu) => pdu.encode(dst),
            GfxPdu::SurfaceToSurface(pdu) => pdu.encode(dst),
            GfxPdu::SurfaceToCache(pdu) => pdu.encode(dst),
            GfxPdu::CacheToSurface(pdu) => pdu.encode(dst),
            GfxPdu::EvictCacheEntry(pdu) => pdu.encode(dst),
            GfxPdu::CreateSurface(pdu) => pdu.encode(dst),
            GfxPdu::DeleteSurface(pdu) => pdu.encode(dst),
            GfxPdu::StartFrame(pdu) => pdu.encode(dst),
            GfxPdu::EndFrame(pdu) => pdu.encode(dst),
            GfxPdu::FrameAcknowledge(pdu) => pdu.encode(dst),
            GfxPdu::ResetGraphics(pdu) => pdu.encode(dst),
            GfxPdu::MapSurfaceToOutput(pdu) => pdu.encode(dst),
            GfxPdu::CacheImportOffer(pdu) => pdu.encode(dst),
            GfxPdu::CacheImportReply(pdu) => pdu.encode(dst),
            GfxPdu::CapabilitiesAdvertise(pdu) => pdu.encode(dst),
            GfxPdu::CapabilitiesConfirm(pdu) => pdu.encode(dst),
            GfxPdu::MapSurfaceToWindow(pdu) => pdu.encode(dst),
            GfxPdu::QoeFrameAcknowledge(pdu) => pdu.encode(dst),
            GfxPdu::MapSurfaceToScaledOutput(pdu) => pdu.encode(dst),
            GfxPdu::MapSurfaceToScaledWindow(pdu) => pdu.encode(dst),
        }?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        // As per invariants: This will never overflow.
        #[expect(clippy::arithmetic_side_effects, reason = "guaranteed by GfxPdu invariants")]
        let size = Self::FIXED_PART_SIZE
            + match self {
                GfxPdu::WireToSurface1(pdu) => pdu.size(),
                GfxPdu::WireToSurface2(pdu) => pdu.size(),
                GfxPdu::DeleteEncodingContext(pdu) => pdu.size(),
                GfxPdu::SolidFill(pdu) => pdu.size(),
                GfxPdu::SurfaceToSurface(pdu) => pdu.size(),
                GfxPdu::SurfaceToCache(pdu) => pdu.size(),
                GfxPdu::CacheToSurface(pdu) => pdu.size(),
                GfxPdu::EvictCacheEntry(pdu) => pdu.size(),
                GfxPdu::CreateSurface(pdu) => pdu.size(),
                GfxPdu::DeleteSurface(pdu) => pdu.size(),
                GfxPdu::StartFrame(pdu) => pdu.size(),
                GfxPdu::EndFrame(pdu) => pdu.size(),
                GfxPdu::FrameAcknowledge(pdu) => pdu.size(),
                GfxPdu::ResetGraphics(pdu) => pdu.size(),
                GfxPdu::MapSurfaceToOutput(pdu) => pdu.size(),
                GfxPdu::CacheImportOffer(pdu) => pdu.size(),
                GfxPdu::CacheImportReply(pdu) => pdu.size(),
                GfxPdu::CapabilitiesAdvertise(pdu) => pdu.size(),
                GfxPdu::CapabilitiesConfirm(pdu) => pdu.size(),
                GfxPdu::MapSurfaceToWindow(pdu) => pdu.size(),
                GfxPdu::QoeFrameAcknowledge(pdu) => pdu.size(),
                GfxPdu::MapSurfaceToScaledOutput(pdu) => pdu.size(),
                GfxPdu::MapSurfaceToScaledWindow(pdu) => pdu.size(),
            };

        size
    }
}

impl DvcEncode for GfxPdu {}

impl<'de> Decode<'de> for GfxPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        // Read `RDPGFX_HEADER` fields.
        let cmdid = src.read_u16();
        let flags = src.read_u16(); /* flags */
        if flags != 0 {
            warn!(?flags, "invalid GFX flag");
        }
        let pdu_length = src.read_u32();

        #[expect(clippy::unwrap_used, reason = "FIXED_PART_SIZE is a small constant")]
        let _payload_length = pdu_length
            .checked_sub(Self::FIXED_PART_SIZE.try_into().unwrap())
            .ok_or_else(|| invalid_field_err!("Length", "GFX PDU length is too small"))?;

        match cmdid {
            RDPGFX_CMDID_WIRETOSURFACE_1 => {
                let pdu = WireToSurface1Pdu::decode(src)?;
                Ok(GfxPdu::WireToSurface1(pdu))
            }
            RDPGFX_CMDID_WIRETOSURFACE_2 => {
                let pdu = WireToSurface2Pdu::decode(src)?;
                Ok(GfxPdu::WireToSurface2(pdu))
            }
            RDPGFX_CMDID_DELETEENCODINGCONTEXT => {
                let pdu = DeleteEncodingContextPdu::decode(src)?;
                Ok(GfxPdu::DeleteEncodingContext(pdu))
            }
            RDPGFX_CMDID_SOLIDFILL => {
                let pdu = SolidFillPdu::decode(src)?;
                Ok(GfxPdu::SolidFill(pdu))
            }
            RDPGFX_CMDID_SURFACETOSURFACE => {
                let pdu = SurfaceToSurfacePdu::decode(src)?;
                Ok(GfxPdu::SurfaceToSurface(pdu))
            }
            RDPGFX_CMDID_SURFACETOCACHE => {
                let pdu = SurfaceToCachePdu::decode(src)?;
                Ok(GfxPdu::SurfaceToCache(pdu))
            }
            RDPGFX_CMDID_CACHETOSURFACE => {
                let pdu = CacheToSurfacePdu::decode(src)?;
                Ok(GfxPdu::CacheToSurface(pdu))
            }
            RDPGFX_CMDID_EVICTCACHEENTRY => {
                let pdu = EvictCacheEntryPdu::decode(src)?;
                Ok(GfxPdu::EvictCacheEntry(pdu))
            }
            RDPGFX_CMDID_CREATESURFACE => {
                let pdu = CreateSurfacePdu::decode(src)?;
                Ok(GfxPdu::CreateSurface(pdu))
            }
            RDPGFX_CMDID_DELETESURFACE => {
                let pdu = DeleteSurfacePdu::decode(src)?;
                Ok(GfxPdu::DeleteSurface(pdu))
            }
            RDPGFX_CMDID_STARTFRAME => {
                let pdu = StartFramePdu::decode(src)?;
                Ok(GfxPdu::StartFrame(pdu))
            }
            RDPGFX_CMDID_ENDFRAME => {
                let pdu = EndFramePdu::decode(src)?;
                Ok(GfxPdu::EndFrame(pdu))
            }
            RDPGFX_CMDID_FRAMEACKNOWLEDGE => {
                let pdu = FrameAcknowledgePdu::decode(src)?;
                Ok(GfxPdu::FrameAcknowledge(pdu))
            }
            RDPGFX_CMDID_RESETGRAPHICS => {
                let pdu = ResetGraphicsPdu::decode(src)?;
                Ok(GfxPdu::ResetGraphics(pdu))
            }
            RDPGFX_CMDID_MAPSURFACETOOUTPUT => {
                let pdu = MapSurfaceToOutputPdu::decode(src)?;
                Ok(GfxPdu::MapSurfaceToOutput(pdu))
            }
            RDPGFX_CMDID_CACHEIMPORTOFFER => {
                let pdu = CacheImportOfferPdu::decode(src)?;
                Ok(GfxPdu::CacheImportOffer(pdu))
            }
            RDPGFX_CMDID_CACHEIMPORTREPLY => {
                let pdu = CacheImportReplyPdu::decode(src)?;
                Ok(GfxPdu::CacheImportReply(pdu))
            }
            RDPGFX_CMDID_CAPSADVERTISE => {
                let pdu = CapabilitiesAdvertisePdu::decode(src)?;
                Ok(GfxPdu::CapabilitiesAdvertise(pdu))
            }
            RDPGFX_CMDID_CAPSCONFIRM => {
                let pdu = CapabilitiesConfirmPdu::decode(src)?;
                Ok(GfxPdu::CapabilitiesConfirm(pdu))
            }
            RDPGFX_CMDID_MAPSURFACETOWINDOW => {
                let pdu = MapSurfaceToWindowPdu::decode(src)?;
                Ok(GfxPdu::MapSurfaceToWindow(pdu))
            }
            RDPGFX_CMDID_QOEFRAMEACKNOWLEDGE => {
                let pdu = QoeFrameAcknowledgePdu::decode(src)?;
                Ok(GfxPdu::QoeFrameAcknowledge(pdu))
            }
            RDPGFX_CMDID_MAPSURFACETOSCALEDOUTPUT => {
                let pdu = MapSurfaceToScaledOutputPdu::decode(src)?;
                Ok(GfxPdu::MapSurfaceToScaledOutput(pdu))
            }
            RDPGFX_CMDID_MAPSURFACETOSCALEDWINDOW => {
                let pdu = MapSurfaceToScaledWindowPdu::decode(src)?;
                Ok(GfxPdu::MapSurfaceToScaledWindow(pdu))
            }
            _ => Err(invalid_field_err!("Type", "Unknown GFX PDU type")),
        }
    }
}

/// 2.2.2.1 RDPGFX_WIRE_TO_SURFACE_PDU_1
///
/// `destination_rectangle` is an [`ExclusiveRectangle`] because MS-RDPEGFX
/// 2.2.1.4.1 RDPGFX_RECT16 specifies `right` and `bottom` as exclusive
/// (one-past-end), matching FreeRDP and the Windows reference clients.
///
/// [2.2.2.1]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/fb919fce-cc97-4d2b-8cf5-a737a00ef1a6>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, PartialEq, Eq)]
pub struct WireToSurface1Pdu {
    pub surface_id: u16,
    pub codec_id: Codec1Type,
    pub pixel_format: PixelFormat,
    pub destination_rectangle: ExclusiveRectangle,
    pub bitmap_data: Vec<u8>,
}

impl fmt::Debug for WireToSurface1Pdu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireToSurface1Pdu")
            .field("surface_id", &self.surface_id)
            .field("codec_id", &self.codec_id)
            .field("pixel_format", &self.pixel_format)
            .field("destination_rectangle", &self.destination_rectangle)
            .field("bitmap_data_length", &self.bitmap_data.len())
            .finish()
    }
}

impl WireToSurface1Pdu {
    const NAME: &'static str = "WireToSurface1Pdu";

    const FIXED_PART_SIZE: usize = 2 /* SurfaceId */ + 2 /* CodecId */ + 1 /* PixelFormat */ + ExclusiveRectangle::ENCODED_SIZE /* Dest */ + 4 /* BitmapDataLen */;
}

impl Encode for WireToSurface1Pdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u16(self.surface_id);
        dst.write_u16(self.codec_id.into());
        dst.write_u8(self.pixel_format.into());
        self.destination_rectangle.encode(dst)?;
        dst.write_u32(cast_length!("BitmapDataLen", self.bitmap_data.len())?);
        dst.write_slice(&self.bitmap_data);
        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.bitmap_data.len()
    }
}

impl<'a> Decode<'a> for WireToSurface1Pdu {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let surface_id = src.read_u16();
        let codec_id = Codec1Type::try_from(src.read_u16())?;
        let pixel_format = PixelFormat::try_from(src.read_u8())?;
        let destination_rectangle = ExclusiveRectangle::decode(src)?;
        let bitmap_data_length = cast_length!("BitmapDataLen", src.read_u32())?;

        ensure_size!(in: src, size: bitmap_data_length);
        let bitmap_data = src.read_slice(bitmap_data_length).to_vec();

        Ok(Self {
            surface_id,
            codec_id,
            pixel_format,
            destination_rectangle,
            bitmap_data,
        })
    }
}

/// 2.2.2.2 RDPGFX_WIRE_TO_SURFACE_PDU_2
///
/// [2.2.2.2]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/49ccafc7-e025-4293-9650-dcae1b7b9e84>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, PartialEq, Eq)]
pub struct WireToSurface2Pdu {
    pub surface_id: u16,
    pub codec_id: Codec2Type,
    pub codec_context_id: u32,
    pub pixel_format: PixelFormat,
    pub bitmap_data: Vec<u8>,
}

impl fmt::Debug for WireToSurface2Pdu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireToSurface2Pdu")
            .field("surface_id", &self.surface_id)
            .field("codec_id", &self.codec_id)
            .field("codec_context_id", &self.codec_context_id)
            .field("pixel_format", &self.pixel_format)
            .field("bitmap_data_length", &self.bitmap_data.len())
            .finish()
    }
}

impl WireToSurface2Pdu {
    const NAME: &'static str = "WireToSurface2Pdu";

    const FIXED_PART_SIZE: usize = 2 /* SurfaceId */ + 2 /* CodecId */ + 4 /* ContextId */ + 1 /* PixelFormat */ + 4 /* BitmapDataLen */;
}

impl Encode for WireToSurface2Pdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u16(self.surface_id);
        dst.write_u16(self.codec_id.into());
        dst.write_u32(self.codec_context_id);
        dst.write_u8(self.pixel_format.into());
        dst.write_u32(cast_length!("BitmapDataLen", self.bitmap_data.len())?);
        dst.write_slice(&self.bitmap_data);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.bitmap_data.len()
    }
}

impl<'a> Decode<'a> for WireToSurface2Pdu {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let surface_id = src.read_u16();
        let codec_id = Codec2Type::try_from(src.read_u16())?;
        let codec_context_id = src.read_u32();
        let pixel_format = PixelFormat::try_from(src.read_u8())?;
        let bitmap_data_length = cast_length!("BitmapDataLen", src.read_u32())?;

        ensure_size!(in: src, size: bitmap_data_length);
        let bitmap_data = src.read_slice(bitmap_data_length).to_vec();

        Ok(Self {
            surface_id,
            codec_id,
            codec_context_id,
            pixel_format,
            bitmap_data,
        })
    }
}

/// 2.2.2.3 RDPGFX_DELETE_ENCODING_CONTEXT_PDU
///
/// [2.2.2.3]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/0dfc9708-847a-4bf0-829a-481e7b826d6d>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteEncodingContextPdu {
    pub surface_id: u16,
    pub codec_context_id: u32,
}

impl DeleteEncodingContextPdu {
    const NAME: &'static str = "DeleteEncodingContextPdu";

    const FIXED_PART_SIZE: usize = 2 /* SurfaceId */ + 4 /* CodecContextId */;
}

impl Encode for DeleteEncodingContextPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(self.surface_id);
        dst.write_u32(self.codec_context_id);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'a> Decode<'a> for DeleteEncodingContextPdu {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let surface_id = src.read_u16();
        let codec_context_id = src.read_u32();

        Ok(Self {
            surface_id,
            codec_context_id,
        })
    }
}

/// 2.2.2.4 RDPGFX_SOLID_FILL_PDU
///
/// [2.2.2.4]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/d696ab07-fd47-42f6-a601-c8b6fae26577>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolidFillPdu {
    pub surface_id: u16,
    pub fill_pixel: Color,
    /// Filled regions; each is an exclusive `RDPGFX_RECT16` per
    /// MS-RDPEGFX 2.2.1.4.1 (`right` / `bottom` are one-past-end).
    pub rectangles: Vec<ExclusiveRectangle>,
}

impl SolidFillPdu {
    const NAME: &'static str = "SolidFillPdu";

    const FIXED_PART_SIZE: usize = 2 /* SurfaceId */ + Color::FIXED_PART_SIZE /* Color */ + 2 /* RectCount */;
}

impl Encode for SolidFillPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u16(self.surface_id);
        self.fill_pixel.encode(dst)?;
        dst.write_u16(cast_length!("nRect", self.rectangles.len())?);

        for rectangle in self.rectangles.iter() {
            rectangle.encode(dst)?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.rectangles.iter().map(|r| r.size()).sum::<usize>()
    }
}

impl<'a> Decode<'a> for SolidFillPdu {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let surface_id = src.read_u16();
        let fill_pixel = Color::decode(src)?;
        let rectangles_count = src.read_u16();

        ensure_size!(in: src, size: usize::from(rectangles_count) * ExclusiveRectangle::ENCODED_SIZE);
        let rectangles = iter::repeat_with(|| ExclusiveRectangle::decode(src))
            .take(usize::from(rectangles_count))
            .collect::<Result<_, _>>()?;

        Ok(Self {
            surface_id,
            fill_pixel,
            rectangles,
        })
    }
}

/// 2.2.2.5 RDPGFX_SURFACE_TO_SURFACE_PDU
///
/// [2.2.2.5]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/0b19d058-fff0-43e5-8671-8c4186d60529>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceToSurfacePdu {
    pub source_surface_id: u16,
    pub destination_surface_id: u16,
    /// Source region; an exclusive `RDPGFX_RECT16` per MS-RDPEGFX 2.2.1.4.1
    /// (`right` / `bottom` are one-past-end).
    pub source_rectangle: ExclusiveRectangle,
    pub destination_points: Vec<Point>,
}

impl SurfaceToSurfacePdu {
    const NAME: &'static str = "SurfaceToSurfacePdu";

    const FIXED_PART_SIZE: usize = 2 /* SourceId */ + 2 /* DestId */ + ExclusiveRectangle::ENCODED_SIZE /* SourceRect */ + 2 /* DestPointsCount */;
}

impl Encode for SurfaceToSurfacePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u16(self.source_surface_id);
        dst.write_u16(self.destination_surface_id);
        self.source_rectangle.encode(dst)?;

        dst.write_u16(cast_length!("DestinationPoints", self.destination_points.len())?);
        for rectangle in self.destination_points.iter() {
            rectangle.encode(dst)?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.destination_points.iter().map(|r| r.size()).sum::<usize>()
    }
}

impl<'a> Decode<'a> for SurfaceToSurfacePdu {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let source_surface_id = src.read_u16();
        let destination_surface_id = src.read_u16();
        let source_rectangle = ExclusiveRectangle::decode(src)?;
        let destination_points_count = src.read_u16();

        let destination_points = iter::repeat_with(|| Point::decode(src))
            .take(usize::from(destination_points_count))
            .collect::<Result<_, _>>()?;

        Ok(Self {
            source_surface_id,
            destination_surface_id,
            source_rectangle,
            destination_points,
        })
    }
}

/// 2.2.2.6 RDPGFX_SURFACE_TO_CACHE_PDU
///
/// [2.2.2.6]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/01108b9f-a888-4e5c-b790-42d5c5985998>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceToCachePdu {
    pub surface_id: u16,
    pub cache_key: u64,
    pub cache_slot: u16,
    /// Source region; an exclusive `RDPGFX_RECT16` per MS-RDPEGFX 2.2.1.4.1
    /// (`right` / `bottom` are one-past-end).
    pub source_rectangle: ExclusiveRectangle,
}

impl SurfaceToCachePdu {
    const NAME: &'static str = "SurfaceToCachePdu";

    const FIXED_PART_SIZE: usize = 2 /* SurfaceId */ + 8 /* CacheKey */ + 2 /* CacheSlot */ + ExclusiveRectangle::ENCODED_SIZE /* SourceRect */;
}

impl Encode for SurfaceToCachePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(self.surface_id);
        dst.write_u64(self.cache_key);
        dst.write_u16(self.cache_slot);
        self.source_rectangle.encode(dst)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'a> Decode<'a> for SurfaceToCachePdu {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let surface_id = src.read_u16();
        let cache_key = src.read_u64();
        let cache_slot = src.read_u16();
        let source_rectangle = ExclusiveRectangle::decode(src)?;

        Ok(Self {
            surface_id,
            cache_key,
            cache_slot,
            source_rectangle,
        })
    }
}

/// 2.2.2.7 RDPGFX_CACHE_TO_SURFACE_PDU
///
/// [2.2.2.7]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/78c00bcd-f5cb-4c33-8d6c-f4cd50facfab>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheToSurfacePdu {
    pub cache_slot: u16,
    pub surface_id: u16,
    pub destination_points: Vec<Point>,
}

impl CacheToSurfacePdu {
    const NAME: &'static str = "CacheToSurfacePdu";

    const FIXED_PART_SIZE: usize = 2 /* cache_slot */ + 2 /* surface_id */ + 2 /* npoints */;
}

impl Encode for CacheToSurfacePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u16(self.cache_slot);
        dst.write_u16(self.surface_id);
        dst.write_u16(cast_length!("npoints", self.destination_points.len())?);
        for point in self.destination_points.iter() {
            point.encode(dst)?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.destination_points.iter().map(|p| p.size()).sum::<usize>()
    }
}

impl<'de> Decode<'de> for CacheToSurfacePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let cache_slot = src.read_u16();
        let surface_id = src.read_u16();
        let destination_points_count = src.read_u16();

        let destination_points = iter::repeat_with(|| Point::decode(src))
            .take(usize::from(destination_points_count))
            .collect::<Result<_, _>>()?;

        Ok(Self {
            cache_slot,
            surface_id,
            destination_points,
        })
    }
}

/// 2.2.2.8 RDPGFX_EVICT_CACHE_ENTRY_PDU
///
/// [2.2.2.8]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/9dd32c5c-fabc-497b-81be-776fa581a4f6>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvictCacheEntryPdu {
    pub cache_slot: u16,
}

impl EvictCacheEntryPdu {
    const NAME: &'static str = "EvictCacheEntryPdu";

    const FIXED_PART_SIZE: usize = 2;
}

impl Encode for EvictCacheEntryPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(self.cache_slot);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'a> Decode<'a> for EvictCacheEntryPdu {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let cache_slot = src.read_u16();

        Ok(Self { cache_slot })
    }
}

/// 2.2.2.9 RDPGFX_CREATE_SURFACE_PDU
///
/// [2.2.2.9]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/9dd32c5c-fabc-497b-81be-776fa581a4f6>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSurfacePdu {
    pub surface_id: u16,
    pub width: u16,
    pub height: u16,
    pub pixel_format: PixelFormat,
}

impl CreateSurfacePdu {
    const NAME: &'static str = "CreateSurfacePdu";

    const FIXED_PART_SIZE: usize = 2 /* SurfaceId */ + 2 /* Width */ + 2 /* Height */ + 1 /* PixelFormat */;
}

impl Encode for CreateSurfacePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(self.surface_id);
        dst.write_u16(self.width);
        dst.write_u16(self.height);
        dst.write_u8(self.pixel_format.into());

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'a> Decode<'a> for CreateSurfacePdu {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let surface_id = src.read_u16();
        let width = src.read_u16();
        let height = src.read_u16();
        let pixel_format = PixelFormat::try_from(src.read_u8())?;

        Ok(Self {
            surface_id,
            width,
            height,
            pixel_format,
        })
    }
}

/// 2.2.2.10 RDPGFX_DELETE_SURFACE_PDU
///
/// [2.2.2.10]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/8079ae0e-8775-4525-aaf5-ebeef913402c>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteSurfacePdu {
    pub surface_id: u16,
}

impl DeleteSurfacePdu {
    const NAME: &'static str = "DeleteSurfacePdu";

    const FIXED_PART_SIZE: usize = 2 /* SurfaceId */;
}

impl Encode for DeleteSurfacePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(self.surface_id);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'a> Decode<'a> for DeleteSurfacePdu {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let surface_id = src.read_u16();

        Ok(Self { surface_id })
    }
}

/// 2.2.2.11 RDPGFX_START_FRAME_PDU
///
/// [2.2.2.11]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/9849fa1a-f896-4abe-9fd4-b7761f56b42c>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartFramePdu {
    pub timestamp: Timestamp,
    pub frame_id: u32,
}

impl StartFramePdu {
    const NAME: &'static str = "StartFramePdu";

    const FIXED_PART_SIZE: usize = Timestamp::FIXED_PART_SIZE + 4 /* FrameId */;
}

impl Encode for StartFramePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        self.timestamp.encode(dst)?;
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

impl<'a> Decode<'a> for StartFramePdu {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let timestamp = Timestamp::decode(src)?;
        let frame_id = src.read_u32();

        Ok(Self { timestamp, frame_id })
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Timestamp {
    pub milliseconds: u16,
    pub seconds: u8,
    pub minutes: u8,
    pub hours: u16,
}

// Manual `Arbitrary` impl: the encoder packs the four fields into a single u32 via
// `set_bits` (milliseconds: 10 bits, seconds: 6 bits, minutes: 6 bits, hours: 10 bits).
// `derive(Arbitrary)` would generate the full `u8` / `u16` range, but `set_bits` panics
// when the value exceeds the requested bit width. Mask each field to its wire-allowed
// range so fuzz inputs always round-trip through `Encode`.
#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Timestamp {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            milliseconds: u.arbitrary::<u16>()? & 0x03FF, // 10 bits
            seconds: u.arbitrary::<u8>()? & 0x3F,         // 6 bits
            minutes: u.arbitrary::<u8>()? & 0x3F,         // 6 bits
            hours: u.arbitrary::<u16>()? & 0x03FF,        // 10 bits
        })
    }
}

impl Timestamp {
    const NAME: &'static str = "GfxTimestamp";

    const FIXED_PART_SIZE: usize = 4;
}

impl Encode for Timestamp {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        let mut timestamp: u32 = 0;

        timestamp.set_bits(..10, u32::from(self.milliseconds));
        timestamp.set_bits(10..16, u32::from(self.seconds));
        timestamp.set_bits(16..22, u32::from(self.minutes));
        timestamp.set_bits(22.., u32::from(self.hours));

        dst.write_u32(timestamp);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'a> Decode<'a> for Timestamp {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let timestamp = src.read_u32();

        // All these bit extractions are bounded by the bit ranges specified,
        // so the conversions will never fail
        #[expect(clippy::unwrap_used, reason = "bit field extraction bounded by range")]
        let milliseconds = timestamp.get_bits(..10).try_into().unwrap();
        #[expect(clippy::unwrap_used, reason = "bit field extraction bounded by range")]
        let seconds = timestamp.get_bits(10..16).try_into().unwrap();
        #[expect(clippy::unwrap_used, reason = "bit field extraction bounded by range")]
        let minutes = timestamp.get_bits(16..22).try_into().unwrap();
        #[expect(clippy::unwrap_used, reason = "bit field extraction bounded by range")]
        let hours = timestamp.get_bits(22..).try_into().unwrap();

        Ok(Self {
            milliseconds,
            seconds,
            minutes,
            hours,
        })
    }
}

/// 2.2.2.12 RDPGFX_END_FRAME_PDU
///
/// [2.2.2.12]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/413b5449-efc7-429c-8764-fa8d005800d3>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndFramePdu {
    pub frame_id: u32,
}

impl EndFramePdu {
    const NAME: &'static str = "EndFramePdu";

    const FIXED_PART_SIZE: usize = 4;
}

impl Encode for EndFramePdu {
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

impl<'a> Decode<'a> for EndFramePdu {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let frame_id = src.read_u32();

        Ok(Self { frame_id })
    }
}

/// 2.2.2.13 RDPGFX_FRAME_ACKNOWLEDGE_PDU
///
/// [2.2.2.13]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/0241e258-77ef-4a58-b426-5039ed6296ce>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameAcknowledgePdu {
    pub queue_depth: QueueDepth,
    pub frame_id: u32,
    pub total_frames_decoded: u32,
}

impl FrameAcknowledgePdu {
    const NAME: &'static str = "FrameAcknowledgePdu";

    const FIXED_PART_SIZE: usize = 4 /* QueueDepth */ + 4 /* FrameId */ + 4 /* TotalFramesDecoded */;
}

impl Encode for FrameAcknowledgePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u32(self.queue_depth.to_u32());
        dst.write_u32(self.frame_id);
        dst.write_u32(self.total_frames_decoded);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'a> Decode<'a> for FrameAcknowledgePdu {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let queue_depth = QueueDepth::from_u32(src.read_u32());
        let frame_id = src.read_u32();
        let total_frames_decoded = src.read_u32();

        Ok(Self {
            queue_depth,
            frame_id,
            total_frames_decoded,
        })
    }
}

#[repr(u32)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum QueueDepth {
    Unavailable,
    AvailableBytes(u32),
    Suspend,
}

impl QueueDepth {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0x0000_0000 => Self::Unavailable,
            0x0000_0001..=0xFFFF_FFFE => Self::AvailableBytes(v),
            0xFFFF_FFFF => Self::Suspend,
        }
    }

    pub fn to_u32(self) -> u32 {
        match self {
            Self::Unavailable => 0x0000_0000,
            Self::AvailableBytes(v) => v,
            Self::Suspend => 0xFFFF_FFFF,
        }
    }
}

/// 2.2.2.14 RDPGFX_RESET_GRAPHICS_PDU
///
/// [2.2.2.14]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/60c8841c-3288-473b-82c3-340e24f51f98>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetGraphicsPdu {
    pub width: u32,
    pub height: u32,
    pub monitors: Vec<Monitor>,
}

impl ResetGraphicsPdu {
    const NAME: &'static str = "ResetGraphicsPdu";

    const FIXED_PART_SIZE: usize = 4 /* Width */ + 4 /* Height */ + 4 /* nMonitors */;

    fn padding_size(&self) -> usize {
        RESET_GRAPHICS_PDU_SIZE - Self::FIXED_PART_SIZE - self.monitors.iter().map(|m| m.size()).sum::<usize>()
    }
}

impl Encode for ResetGraphicsPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u32(self.width);
        dst.write_u32(self.height);
        dst.write_u32(cast_length!("nMonitors", self.monitors.len())?);

        for monitor in self.monitors.iter() {
            monitor.encode(dst)?;
        }

        write_padding!(dst, self.padding_size());

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.monitors.iter().map(|m| m.size()).sum::<usize>() + self.padding_size()
    }
}

impl<'a> Decode<'a> for ResetGraphicsPdu {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let width = src.read_u32();
        if width > MAX_RESET_GRAPHICS_WIDTH_HEIGHT {
            return Err(invalid_field_err!("width", "invalid reset graphics width"));
        }

        let height = src.read_u32();
        if height > MAX_RESET_GRAPHICS_WIDTH_HEIGHT {
            return Err(invalid_field_err!("height", "invalid reset graphics height"));
        }

        let monitor_count = src.read_u32();
        if monitor_count > MONITOR_COUNT_MAX {
            return Err(invalid_field_err!(
                "monitor_count",
                "invalid reset graphics monitor count"
            ));
        }

        #[expect(clippy::as_conversions, reason = "monitor_count validated above")]
        let monitors = iter::repeat_with(|| Monitor::decode(src))
            .take(monitor_count as usize)
            .collect::<Result<Vec<_>, _>>()?;

        let pdu = Self {
            width,
            height,
            monitors,
        };

        read_padding!(src, pdu.padding_size());

        Ok(pdu)
    }
}

/// 2.2.2.15 RDPGFX_MAP_SURFACE_TO_OUTPUT_PDU
///
/// [2.2.2.15]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/a1c6ff83-c385-4ad6-9437-f17697cc001c>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapSurfaceToOutputPdu {
    pub surface_id: u16,
    pub output_origin_x: u32,
    pub output_origin_y: u32,
}

impl MapSurfaceToOutputPdu {
    const NAME: &'static str = "MapSurfaceToOutputPdu";

    const FIXED_PART_SIZE: usize = 2 /* surfaceId */ + 2 /* reserved */ + 4 /* OutOriginX */ + 4 /* OutOriginY */;
}

impl Encode for MapSurfaceToOutputPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(self.surface_id);
        dst.write_u16(0); // reserved
        dst.write_u32(self.output_origin_x);
        dst.write_u32(self.output_origin_y);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'a> Decode<'a> for MapSurfaceToOutputPdu {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let surface_id = src.read_u16();
        let _reserved = src.read_u16();
        let output_origin_x = src.read_u32();
        let output_origin_y = src.read_u32();

        Ok(Self {
            surface_id,
            output_origin_x,
            output_origin_y,
        })
    }
}

/// 2.2.2.16 RDPGFX_CACHE_IMPORT_OFFER_PDU
///
/// [2.2.2.16]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/890f0077-dedb-4b22-8b20-ea69b9cfcacd>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheImportOfferPdu {
    pub cache_entries: Vec<CacheEntryMetadata>,
}

impl CacheImportOfferPdu {
    const NAME: &'static str = "CacheImportOfferPdu";

    const FIXED_PART_SIZE: usize = 2 /* Count */;
}

impl Encode for CacheImportOfferPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u16(cast_length!("Count", self.cache_entries.len())?);

        for e in self.cache_entries.iter() {
            e.encode(dst)?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.cache_entries.iter().map(|e| e.size()).sum::<usize>()
    }
}

impl<'a> Decode<'a> for CacheImportOfferPdu {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let entries_count = src.read_u16();

        let cache_entries = iter::repeat_with(|| CacheEntryMetadata::decode(src))
            .take(usize::from(entries_count))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { cache_entries })
    }
}

/// 2.2.2.17 RDPGFX_CACHE_IMPORT_REPLY_PDU
///
/// [2.2.2.17]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/0c4d88f8-50dc-465a-ab00-88a3fe0ec3c5>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheImportReplyPdu {
    pub cache_slots: Vec<u16>,
}

impl CacheImportReplyPdu {
    const NAME: &'static str = "CacheImportReplyPdu";

    const FIXED_PART_SIZE: usize = 2 /* Count */;
}

impl Encode for CacheImportReplyPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u16(cast_length!("Count", self.cache_slots.len())?);

        for cache_slot in self.cache_slots.iter() {
            dst.write_u16(*cache_slot);
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.cache_slots.iter().map(|_| 2).sum::<usize>()
    }
}

impl<'a> Decode<'a> for CacheImportReplyPdu {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let entries_count = src.read_u16();
        ensure_size!(in: src, size: 2 * usize::from(entries_count));

        let cache_slots = iter::repeat_with(|| src.read_u16())
            .take(usize::from(entries_count))
            .collect();

        Ok(Self { cache_slots })
    }
}

/// 2.2.2.16.1 RDPGFX_CACHE_ENTRY_METADATA
///
/// [2.2.2.16.1]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/486dc290-96f9-4219-98c2-e371e23fa0d6>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheEntryMetadata {
    pub cache_key: u64,
    pub bitmap_len: u32,
}

impl CacheEntryMetadata {
    const NAME: &'static str = "CacheEntryMetadata";

    const FIXED_PART_SIZE: usize = 8 /* cache_key */ + 4 /* bitmap_len */;
}

impl Encode for CacheEntryMetadata {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u64(self.cache_key);
        dst.write_u32(self.bitmap_len);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'a> Decode<'a> for CacheEntryMetadata {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let cache_key = src.read_u64();
        let bitmap_len = src.read_u32();

        Ok(Self { cache_key, bitmap_len })
    }
}

/// 2.2.2.18 RDPGFX_CAPS_ADVERTISE_PDU
///
/// [2.2.2.18]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/9cc3cf56-148d-44bf-9dea-5f5e6970c00f>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitiesAdvertisePdu(pub Vec<RawCapabilitySet>);

impl CapabilitiesAdvertisePdu {
    const NAME: &'static str = "CapabilitiesAdvertisePdu";

    const FIXED_PART_SIZE: usize  = 2 /* Count */;

    /// Build the PDU from a list of typed capability sets.
    pub fn from_typed(caps: &[CapabilitySet]) -> Self {
        Self(caps.iter().map(RawCapabilitySet::from).collect())
    }
}

impl Encode for CapabilitiesAdvertisePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u16(cast_length!("Count", self.0.len())?);

        for capability_set in self.0.iter() {
            capability_set.encode(dst)?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.0.iter().map(|c| c.size()).sum::<usize>()
    }
}

impl<'a> Decode<'a> for CapabilitiesAdvertisePdu {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let capabilities_count = cast_length!("Count", src.read_u16())?;

        ensure_size!(in: src, size: capabilities_count * RawCapabilitySet::FIXED_PART_SIZE);

        let capabilities = iter::repeat_with(|| RawCapabilitySet::decode(src))
            .take(capabilities_count)
            .collect::<Result<_, _>>()?;

        Ok(Self(capabilities))
    }
}

/// 2.2.2.19 RDPGFX_CAPS_CONFIRM_PDU
///
/// [2.2.2.19]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/4d1ced69-49ea-47dd-98d6-4b220f30db36>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitiesConfirmPdu(pub RawCapabilitySet);

impl CapabilitiesConfirmPdu {
    const NAME: &'static str = "CapabilitiesConfirmPdu";

    const FIXED_PART_SIZE: usize = 0;

    /// Build the PDU from a typed capability set.
    pub fn from_typed(cap: &CapabilitySet) -> Self {
        Self(RawCapabilitySet::from(cap))
    }
}

impl Encode for CapabilitiesConfirmPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        self.0.encode(dst)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        self.0.size()
    }
}

impl<'a> Decode<'a> for CapabilitiesConfirmPdu {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let cap = RawCapabilitySet::decode(src)?;

        Ok(Self(cap))
    }
}

/// 2.2.1.6 RDPGFX_CAPSET — lossless wire-level representation.
///
/// Stores the original `version` alongside the raw body bytes (`data`). This
/// is what [`CapabilitiesAdvertisePdu`] and [`CapabilitiesConfirmPdu`] hold on
/// the wire, ensuring that `m == encode(decode(m))` even when this build does
/// not recognize the advertised version.
///
/// Use [`Self::parsed`] to obtain a typed [`CapabilitySet`] when the version
/// is known to this build.
///
/// [2.2.1.6]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/82e6dd00-914d-4dcc-bd17-985e1268ffb7>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCapabilitySet {
    pub version: CapabilityVersion,
    pub data: Vec<u8>,
}

impl RawCapabilitySet {
    const NAME: &'static str = "GfxCapabilitySet";

    const FIXED_PART_SIZE: usize = 4 /* version */ + 4 /* capsDataLength */;

    pub fn new(version: CapabilityVersion, data: Vec<u8>) -> Self {
        Self { version, data }
    }

    /// Parse the body into a typed [`CapabilitySet`] when the version is one
    /// this build recognizes. Returns `Ok(None)` for unknown versions, leaving
    /// the raw bytes available via [`Self::data`].
    pub fn parsed(&self) -> DecodeResult<Option<CapabilitySet>> {
        let mut cur = ReadCursor::new(&self.data);
        let cap = match self.version {
            CapabilityVersion::V8 => {
                ensure_size!(in: cur, size: 4);
                CapabilitySet::V8 {
                    flags: CapabilitiesV8Flags::from_bits_retain(cur.read_u32()),
                }
            }
            CapabilityVersion::V8_1 => {
                ensure_size!(in: cur, size: 4);
                CapabilitySet::V8_1 {
                    flags: CapabilitiesV81Flags::from_bits_retain(cur.read_u32()),
                }
            }
            CapabilityVersion::V10 => {
                ensure_size!(in: cur, size: 4);
                CapabilitySet::V10 {
                    flags: CapabilitiesV10Flags::from_bits_retain(cur.read_u32()),
                }
            }
            CapabilityVersion::V10_1 => {
                ensure_size!(in: cur, size: 16);
                cur.read_u128();
                CapabilitySet::V10_1
            }
            CapabilityVersion::V10_2 => {
                ensure_size!(in: cur, size: 4);
                CapabilitySet::V10_2 {
                    flags: CapabilitiesV10Flags::from_bits_retain(cur.read_u32()),
                }
            }
            CapabilityVersion::V10_3 => {
                ensure_size!(in: cur, size: 4);
                CapabilitySet::V10_3 {
                    flags: CapabilitiesV103Flags::from_bits_retain(cur.read_u32()),
                }
            }
            CapabilityVersion::V10_4 => {
                ensure_size!(in: cur, size: 4);
                CapabilitySet::V10_4 {
                    flags: CapabilitiesV104Flags::from_bits_retain(cur.read_u32()),
                }
            }
            CapabilityVersion::V10_5 => {
                ensure_size!(in: cur, size: 4);
                CapabilitySet::V10_5 {
                    flags: CapabilitiesV104Flags::from_bits_retain(cur.read_u32()),
                }
            }
            CapabilityVersion::V10_6 => {
                ensure_size!(in: cur, size: 4);
                CapabilitySet::V10_6 {
                    flags: CapabilitiesV104Flags::from_bits_retain(cur.read_u32()),
                }
            }
            CapabilityVersion::V10_6_ERR => {
                ensure_size!(in: cur, size: 4);
                CapabilitySet::V10_6Err {
                    flags: CapabilitiesV104Flags::from_bits_retain(cur.read_u32()),
                }
            }
            CapabilityVersion::V10_7 => {
                ensure_size!(in: cur, size: 4);
                CapabilitySet::V10_7 {
                    flags: CapabilitiesV107Flags::from_bits_retain(cur.read_u32()),
                }
            }
            _ => return Ok(None),
        };

        Ok(Some(cap))
    }
}

impl Encode for RawCapabilitySet {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u32(self.version.into());
        dst.write_u32(cast_length!("dataLength", self.data.len())?);
        dst.write_slice(&self.data);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.data.len()
    }
}

impl<'de> Decode<'de> for RawCapabilitySet {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let version = CapabilityVersion(src.read_u32());
        let data_length: usize = cast_length!("dataLength", src.read_u32())?;

        ensure_size!(in: src, size: data_length);
        let data = src.read_slice(data_length).to_vec();

        // Tolerate capability versions this build doesn't recognize instead of
        // failing the whole PDU. A strict error here would abort decoding of
        // the entire CapabilitiesAdvertise during EGFX negotiation, which can
        // prevent a connection from being established at all when a client
        // advertises a capset version outside the set enumerated in
        // `CapabilityVersion`. Preserving the raw bytes lets
        // negotiation complete so the server can still select a mutually
        // supported version. Use `RawCapabilitySet::parsed` to obtain a typed
        // view when needed.
        Ok(Self { version, data })
    }
}

/// 2.2.1.6 RDPGFX_CAPSET — typed view of a [`RawCapabilitySet`] body.
///
/// Holds only versions this build knows how to interpret. Obtained from
/// [`RawCapabilitySet::parsed`], which returns `None` for unknown versions.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilitySet {
    V8 { flags: CapabilitiesV8Flags },
    V8_1 { flags: CapabilitiesV81Flags },
    V10 { flags: CapabilitiesV10Flags },
    V10_1,
    V10_2 { flags: CapabilitiesV10Flags },
    V10_3 { flags: CapabilitiesV103Flags },
    V10_4 { flags: CapabilitiesV104Flags },
    V10_5 { flags: CapabilitiesV104Flags },
    V10_6 { flags: CapabilitiesV104Flags },
    V10_6Err { flags: CapabilitiesV104Flags },
    V10_7 { flags: CapabilitiesV107Flags },
}

impl CapabilitySet {
    /// Wire `version` field corresponding to this typed variant.
    pub fn version(&self) -> CapabilityVersion {
        match self {
            CapabilitySet::V8 { .. } => CapabilityVersion::V8,
            CapabilitySet::V8_1 { .. } => CapabilityVersion::V8_1,
            CapabilitySet::V10 { .. } => CapabilityVersion::V10,
            CapabilitySet::V10_1 => CapabilityVersion::V10_1,
            CapabilitySet::V10_2 { .. } => CapabilityVersion::V10_2,
            CapabilitySet::V10_3 { .. } => CapabilityVersion::V10_3,
            CapabilitySet::V10_4 { .. } => CapabilityVersion::V10_4,
            CapabilitySet::V10_5 { .. } => CapabilityVersion::V10_5,
            CapabilitySet::V10_6 { .. } => CapabilityVersion::V10_6,
            CapabilitySet::V10_6Err { .. } => CapabilityVersion::V10_6_ERR,
            CapabilitySet::V10_7 { .. } => CapabilityVersion::V10_7,
        }
    }

    /// Size of the body bytes (no version/length header).
    fn body_size(&self) -> usize {
        match self {
            CapabilitySet::V10_1 => 16,
            CapabilitySet::V8 { .. }
            | CapabilitySet::V8_1 { .. }
            | CapabilitySet::V10 { .. }
            | CapabilitySet::V10_2 { .. }
            | CapabilitySet::V10_3 { .. }
            | CapabilitySet::V10_4 { .. }
            | CapabilitySet::V10_5 { .. }
            | CapabilitySet::V10_6 { .. }
            | CapabilitySet::V10_6Err { .. }
            | CapabilitySet::V10_7 { .. } => 4,
        }
    }

    /// Serialize just the body bytes (no version/length header).
    fn write_body(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.body_size());
        match self {
            CapabilitySet::V8 { flags } => dst.write_u32(flags.bits()),
            CapabilitySet::V8_1 { flags } => dst.write_u32(flags.bits()),
            CapabilitySet::V10 { flags } => dst.write_u32(flags.bits()),
            CapabilitySet::V10_1 => dst.write_u128(0),
            CapabilitySet::V10_2 { flags } => dst.write_u32(flags.bits()),
            CapabilitySet::V10_3 { flags } => dst.write_u32(flags.bits()),
            CapabilitySet::V10_4 { flags } => dst.write_u32(flags.bits()),
            CapabilitySet::V10_5 { flags } => dst.write_u32(flags.bits()),
            CapabilitySet::V10_6 { flags } => dst.write_u32(flags.bits()),
            CapabilitySet::V10_6Err { flags } => dst.write_u32(flags.bits()),
            CapabilitySet::V10_7 { flags } => dst.write_u32(flags.bits()),
        }
        Ok(())
    }
}

impl From<&CapabilitySet> for RawCapabilitySet {
    fn from(cap: &CapabilitySet) -> Self {
        let mut data = vec![0u8; cap.body_size()];
        let mut cur = WriteCursor::new(&mut data);
        cap.write_body(&mut cur)
            .expect("buffer is sized to body_size; write cannot fail");
        Self {
            version: cap.version(),
            data,
        }
    }
}

/// Capability set version, as advertised in 2.2.1.6 RDPGFX_CAPSET.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct CapabilityVersion(pub u32);

impl CapabilityVersion {
    pub const V8: Self = Self(0x8_0004);
    pub const V8_1: Self = Self(0x8_0105);
    pub const V10: Self = Self(0xa_0002);
    pub const V10_1: Self = Self(0xa_0100);
    pub const V10_2: Self = Self(0xa_0200);
    pub const V10_3: Self = Self(0xa_0301);
    pub const V10_4: Self = Self(0xa_0400);
    pub const V10_5: Self = Self(0xa_0502);
    pub const V10_6: Self = Self(0xa_0600); // [MS-RDPEGFX-errata]
    pub const V10_6_ERR: Self = Self(0xa_0601); // defined similar to FreeRDP to maintain best compatibility
    pub const V10_7: Self = Self(0xa_0701);

    /// Returns `true` if this version matches one of the constants defined on
    /// `CapabilityVersion`, i.e. one this build knows how to decode into a
    /// dedicated `CapabilitySet` variant.
    #[must_use]
    pub fn is_known(self) -> bool {
        matches!(
            self,
            Self::V8
                | Self::V8_1
                | Self::V10
                | Self::V10_1
                | Self::V10_2
                | Self::V10_3
                | Self::V10_4
                | Self::V10_5
                | Self::V10_6
                | Self::V10_6_ERR
                | Self::V10_7
        )
    }
}

impl From<CapabilityVersion> for u32 {
    fn from(value: CapabilityVersion) -> Self {
        value.0
    }
}

bitflags! {
    /// 2.2.3.1 RDPGFX_CAPSET_VERSION8
    ///
    /// [2.2.3.1] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/027dd8eb-a066-42e8-ad65-2e0314c4dce5
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct CapabilitiesV8Flags: u32  {
        const THIN_CLIENT = 0x1;
        const SMALL_CACHE = 0x2;

        const _ = !0;
    }
}

bitflags! {
    /// 2.2.3.2 RDPGFX_CAPSET_VERSION81
    ///
    /// [2.2.3.2] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/487e57cc-cd16-44c4-add8-60b84bf6d9e4
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct CapabilitiesV81Flags: u32  {
        const THIN_CLIENT = 0x01;
        const SMALL_CACHE = 0x02;
        const AVC420_ENABLED = 0x10;

        const _ = !0;
    }
}

bitflags! {
    /// 2.2.3.3 RDPGFX_CAPSET_VERSION10
    ///
    /// [2.2.3.3] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/d1899912-2b84-4e0d-9e6d-da0fd25d14bc
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct CapabilitiesV10Flags: u32 {
        const SMALL_CACHE = 0x02;
        const AVC_DISABLED = 0x20;

        const _ = !0;
    }
}

// 2.2.3.4 RDPGFX_CAPSET_VERSION101
//
// [2.2.3.4] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/5985e67e-4080-49a7-85e3-eb3ba0653ff6
// reserved

// 2.2.3.5 RDPGFX_CAPSET_VERSION102
//
// [2.2.3.5] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/a73e87d5-10c3-4d3f-b00c-fd5579570a0b
//same as v10

bitflags! {
    /// 2.2.3.6 RDPGFX_CAPSET_VERSION103
    ///
    /// [2.2.3.6] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/a73e87d5-10c3-4d3f-b00c-fd5579570a0b
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct CapabilitiesV103Flags: u32  {
        const AVC_DISABLED = 0x20;
        const AVC_THIN_CLIENT = 0x40;

        const _ = !0;
    }
}

bitflags! {
    /// 2.2.3.7 RDPGFX_CAPSET_VERSION104
    ///
    /// [2.2.3.7] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/be5ea8da-44db-478d-b55c-d42d82f11d26
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct CapabilitiesV104Flags: u32  {
        const SMALL_CACHE = 0x02;
        const AVC_DISABLED = 0x20;
        const AVC_THIN_CLIENT = 0x40;

        const _ = !0;
    }
}

// 2.2.3.8 RDPGFX_CAPSET_VERSION105
//
// [2.2.3.8] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/8fc20f1e-e63e-4b13-a546-22fba213ad83
// same as v104

// 2.2.3.9 RDPGFX_CAPSET_VERSION106
//
// [2.2.3.9] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/8d489900-e903-4778-bb83-691c5ab719d5
// same as v104

bitflags! {
    /// 2.2.3.10 RDPGFX_CAPSET_VERSION107
    ///
    /// [2.2.3.10] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/ba94595b-04de-4fbd-8ee4-89d8ff8f5cf1
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct CapabilitiesV107Flags: u32  {
        const SMALL_CACHE = 0x02;
        const AVC_DISABLED = 0x20;
        const AVC_THIN_CLIENT = 0x40;
        const SCALEDMAP_DISABLE = 0x80;

        const _ = !0;
    }
}

/// 2.2.2.20 RDPGFX_MAP_SURFACE_TO_WINDOW_PDU
///
/// [2.2.2.20]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/2ec1357c-ee65-4d9b-89f3-8fc49348c92a>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapSurfaceToWindowPdu {
    pub surface_id: u16,
    pub window_id: u64,
    pub mapped_width: u32,
    pub mapped_height: u32,
}

impl MapSurfaceToWindowPdu {
    const NAME: &'static str = "MapSurfaceToWindowPdu";

    const FIXED_PART_SIZE: usize = 2 /* SurfaceId */ + 8 /* WindowId */ + 4 /* MappedWidth */ + 4 /* MappedHeight */;
}

impl Encode for MapSurfaceToWindowPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u16(self.surface_id);
        dst.write_u64(self.window_id);
        dst.write_u32(self.mapped_width);
        dst.write_u32(self.mapped_height);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'a> Decode<'a> for MapSurfaceToWindowPdu {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let surface_id = src.read_u16();
        let window_id = src.read_u64();
        let mapped_width = src.read_u32();
        let mapped_height = src.read_u32();

        Ok(Self {
            surface_id,
            window_id,
            mapped_width,
            mapped_height,
        })
    }
}

/// 2.2.2.21 RDPGFX_QOE_FRAME_ACKNOWLEDGE_PDU
///
/// [2.2.2.21]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/17aaf205-23fe-467f-a629-447f428fdda0>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QoeFrameAcknowledgePdu {
    pub frame_id: u32,
    pub timestamp: u32,
    pub time_diff_se: u16,
    pub time_diff_dr: u16,
}

impl QoeFrameAcknowledgePdu {
    const NAME: &'static str = "QoeFrameAcknowledgePdu";

    const FIXED_PART_SIZE: usize = 4 /* FrameId */ + 4 /* timestamp */ + 2 /* diffSE */ + 2 /* diffDR */;
}

impl Encode for QoeFrameAcknowledgePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u32(self.frame_id);
        dst.write_u32(self.timestamp);
        dst.write_u16(self.time_diff_se);
        dst.write_u16(self.time_diff_dr);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'a> Decode<'a> for QoeFrameAcknowledgePdu {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let frame_id = src.read_u32();
        let timestamp = src.read_u32();
        let time_diff_se = src.read_u16();
        let time_diff_dr = src.read_u16();

        Ok(Self {
            frame_id,
            timestamp,
            time_diff_se,
            time_diff_dr,
        })
    }
}

/// 2.2.2.22 RDPGFX_MAP_SURFACE_TO_SCALED_OUTPUT_PDU
///
/// [2.2.2.22]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/6fbddd3f-0a87-4e83-9936-eb3a46fdfdea>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapSurfaceToScaledOutputPdu {
    pub surface_id: u16,
    pub output_origin_x: u32,
    pub output_origin_y: u32,
    pub target_width: u32,
    pub target_height: u32,
}

impl MapSurfaceToScaledOutputPdu {
    const NAME: &'static str = "MapSurfaceToScaledOutputPdu";

    const FIXED_PART_SIZE: usize = 2 /* SurfaceId */ + 2 /* reserved */ + 4 /* oox */ + 4 /* ooy */ + 4 /* targetWidth */ + 4 /* targetHeight */;
}

impl Encode for MapSurfaceToScaledOutputPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u16(self.surface_id);
        dst.write_u16(0); // reserved
        dst.write_u32(self.output_origin_x);
        dst.write_u32(self.output_origin_y);
        dst.write_u32(self.target_width);
        dst.write_u32(self.target_height);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'a> Decode<'a> for MapSurfaceToScaledOutputPdu {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let surface_id = src.read_u16();
        let _reserved = src.read_u16();
        let output_origin_x = src.read_u32();
        let output_origin_y = src.read_u32();
        let target_width = src.read_u32();
        let target_height = src.read_u32();

        Ok(Self {
            surface_id,
            output_origin_x,
            output_origin_y,
            target_width,
            target_height,
        })
    }
}

/// 2.2.2.23 RDPGFX_MAP_SURFACE_TO_SCALED_WINDOW_PDU
///
/// [2.2.2.23]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapSurfaceToScaledWindowPdu {
    pub surface_id: u16,
    pub window_id: u64,
    pub mapped_width: u32,
    pub mapped_height: u32,
    pub target_width: u32,
    pub target_height: u32,
}

impl MapSurfaceToScaledWindowPdu {
    const NAME: &'static str = "MapSurfaceToScaledWindowPdu";

    const FIXED_PART_SIZE: usize = 2 /* SurfaceId */ + 8 /* WindowId */ + 4 /* MappedWidth */ + 4 /* MappedHeight */ + 4 /* TargetWidth */ + 4 /* TargetHeight */;
}

impl Encode for MapSurfaceToScaledWindowPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u16(self.surface_id);
        dst.write_u64(self.window_id);
        dst.write_u32(self.mapped_width);
        dst.write_u32(self.mapped_height);
        dst.write_u32(self.target_width);
        dst.write_u32(self.target_height);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'a> Decode<'a> for MapSurfaceToScaledWindowPdu {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let surface_id = src.read_u16();
        let window_id = src.read_u64();
        let mapped_width = src.read_u32();
        let mapped_height = src.read_u32();
        let target_width = src.read_u32();
        let target_height = src.read_u32();

        Ok(Self {
            surface_id,
            window_id,
            mapped_width,
            mapped_height,
            target_width,
            target_height,
        })
    }
}

#[repr(u16)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Codec1Type {
    Uncompressed = 0x0,
    RemoteFx = 0x3,
    ClearCodec = 0x8,
    Planar = 0xa,
    Avc420 = 0xb,
    Alpha = 0xc,
    Avc444 = 0xe,
    Avc444v2 = 0xf,
}

impl TryFrom<u16> for Codec1Type {
    type Error = DecodeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0 => Ok(Codec1Type::Uncompressed),
            0x3 => Ok(Codec1Type::RemoteFx),
            0x8 => Ok(Codec1Type::ClearCodec),
            0xa => Ok(Codec1Type::Planar),
            0xb => Ok(Codec1Type::Avc420),
            0xc => Ok(Codec1Type::Alpha),
            0xe => Ok(Codec1Type::Avc444),
            0xf => Ok(Codec1Type::Avc444v2),
            _ => Err(invalid_field_err!("Codec1Type", "invalid codec type")),
        }
    }
}

impl From<Codec1Type> for u16 {
    #[expect(clippy::as_conversions, reason = "repr(u16) enum discriminant")]
    fn from(value: Codec1Type) -> Self {
        value as u16
    }
}

#[repr(u16)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Codec2Type {
    RemoteFxProgressive = 0x9,
}

impl TryFrom<u16> for Codec2Type {
    type Error = DecodeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x9 => Ok(Codec2Type::RemoteFxProgressive),
            _ => Err(invalid_field_err!("Codec2Type", "invalid codec type")),
        }
    }
}

impl From<Codec2Type> for u16 {
    #[expect(clippy::as_conversions, reason = "repr(u16) enum discriminant")]
    fn from(value: Codec2Type) -> Self {
        value as u16
    }
}
