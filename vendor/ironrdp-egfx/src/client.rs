//! Client-side EGFX implementation
//!
//! This module provides client-side support for the Graphics Pipeline Extension
//! ([MS-RDPEGFX]), including H.264 AVC420 decode and surface management.
//!
//! # Protocol Compliance
//!
//! This implementation follows MS-RDPEGFX client requirements:
//!
//! - **Capability Negotiation**: Advertises V8 through V10.7 ([2.2.3])
//! - **Surface Management**: Tracks server-created surfaces ([3.3.1.6])
//! - **Frame Acknowledgment**: Sends `FrameAcknowledge` after `EndFrame` ([3.3.5.12])
//! - **Codec Dispatch**: Routes `WireToSurface1` by `codec_id` ([3.3.5.2])
//!
//! # Architecture
//!
//! ```text
//! Server                                  Client
//!    |                                       |
//!    |--- CapabilitiesConfirm -------------->|
//!    |--- ResetGraphics -------------------->|
//!    |--- CreateSurface -------------------->|
//!    |--- MapSurfaceToOutput --------------->|
//!    |                                       |
//!    |  (For each frame:)                    |
//!    |--- StartFrame ----------------------->|
//!    |--- WireToSurface1 (H.264) ----------->|  -> H264Decoder::decode()
//!    |--- EndFrame ------------------------->|  -> FrameAcknowledge
//!    |                                       |
//!    |<---------- FrameAcknowledge ----------|
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use ironrdp_egfx::client::{GraphicsPipelineClient, GraphicsPipelineHandler, BitmapUpdate};
//! use ironrdp_egfx::decode::H264Decoder;
//!
//! struct MyHandler;
//!
//! impl GraphicsPipelineHandler for MyHandler {
//!     fn on_bitmap_updated(&mut self, update: &BitmapUpdate) {
//!         // Render decoded bitmap to screen
//!     }
//! }
//!
//! let client = GraphicsPipelineClient::new(Box::new(MyHandler), None);
//! ```
//!
//! [MS-RDPEGFX]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/da5c75f9-cd99-450c-98c4-014a496942b0
//! [2.2.3]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/b5e09f90-6dde-47ca-8ec1-7dcdd5dc70b0
//! [3.3.1.6]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/83cb08ff-c97f-4d08-b834-7aa69cdea6c5
//! [3.3.5.2]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/90aba3e3-d4a8-4af1-b1bb-a94e2313bbf0
//! [3.3.5.12]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/e3c80bff-3e4e-4e65-b7c2-c2cd6b1fb4f5

use std::collections::BTreeMap;

use ironrdp_core::{Decode as _, ReadCursor, impl_as_any};
use ironrdp_dvc::{DvcClientProcessor, DvcMessage, DvcProcessor};
use ironrdp_graphics::zgfx;
use ironrdp_pdu::geometry::{ExclusiveRectangle, Rectangle as _};
use ironrdp_pdu::{PduResult, decode_cursor, decode_err, pdu_other_err};
use tracing::{debug, trace, warn};

use crate::CHANNEL_NAME;
use crate::decode::H264Decoder;
use crate::pdu::{
    Avc420BitmapStream, CacheImportReplyPdu, CacheToSurfacePdu, CapabilitiesAdvertisePdu, CapabilitiesV8Flags,
    CapabilitiesV81Flags, CapabilitiesV107Flags, CapabilitySet, Codec1Type, DeleteEncodingContextPdu,
    EvictCacheEntryPdu, FrameAcknowledgePdu, GfxPdu, MapSurfaceToScaledOutputPdu, MapSurfaceToScaledWindowPdu,
    MapSurfaceToWindowPdu, PixelFormat, QueueDepth, RawCapabilitySet, SolidFillPdu, SurfaceToCachePdu,
    SurfaceToSurfacePdu, WireToSurface2Pdu,
};

/// Max capacity to keep for decompressed buffer when cleared.
const MAX_DECOMPRESSED_BUFFER_CAPACITY: usize = 16384; // 16 KiB

// ============================================================================
// Surface Management
// ============================================================================

/// Client-side surface state
///
/// Per [MS-RDPEGFX 3.3.1.6], the client maintains an "Offscreen Surfaces
/// ADM element" tracking surfaces created by the server.
///
/// [MS-RDPEGFX 3.3.1.6]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/83cb08ff-c97f-4d08-b834-7aa69cdea6c5
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Surface {
    /// Surface identifier (assigned by server)
    pub id: u16,
    /// Surface width in pixels
    pub width: u16,
    /// Surface height in pixels
    pub height: u16,
    /// Pixel format
    pub pixel_format: PixelFormat,
    /// Whether this surface is mapped to an output
    pub is_mapped: bool,
    /// Output X origin (if mapped)
    pub output_origin_x: u32,
    /// Output Y origin (if mapped)
    pub output_origin_y: u32,
}

// ============================================================================
// Codec Capabilities
// ============================================================================

/// Codec capabilities determined from negotiated capability set
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct CodecCapabilities {
    /// AVC420 (H.264 4:2:0) is available
    pub avc420: bool,
    /// AVC444 (H.264 4:4:4) is available
    pub avc444: bool,
    /// Small cache mode
    pub small_cache: bool,
    /// Thin client mode
    pub thin_client: bool,
}

impl CodecCapabilities {
    fn from_capability_set(cap: &CapabilitySet) -> Self {
        // Mirrors the server-side extraction logic
        match cap {
            CapabilitySet::V8 { flags } => Self {
                avc420: false,
                avc444: false,
                small_cache: flags.contains(CapabilitiesV8Flags::SMALL_CACHE),
                thin_client: flags.contains(CapabilitiesV8Flags::THIN_CLIENT),
            },
            CapabilitySet::V8_1 { flags } => Self {
                avc420: flags.contains(CapabilitiesV81Flags::AVC420_ENABLED),
                avc444: false,
                small_cache: flags.contains(CapabilitiesV81Flags::SMALL_CACHE),
                thin_client: flags.contains(CapabilitiesV81Flags::THIN_CLIENT),
            },
            CapabilitySet::V10 { flags } | CapabilitySet::V10_2 { flags } => Self {
                avc420: !flags.contains(crate::pdu::CapabilitiesV10Flags::AVC_DISABLED),
                avc444: !flags.contains(crate::pdu::CapabilitiesV10Flags::AVC_DISABLED),
                small_cache: flags.contains(crate::pdu::CapabilitiesV10Flags::SMALL_CACHE),
                thin_client: false,
            },
            CapabilitySet::V10_1 => Self {
                avc420: true,
                avc444: true,
                small_cache: false,
                thin_client: false,
            },
            CapabilitySet::V10_3 { flags } => Self {
                avc420: !flags.contains(crate::pdu::CapabilitiesV103Flags::AVC_DISABLED),
                avc444: !flags.contains(crate::pdu::CapabilitiesV103Flags::AVC_DISABLED),
                small_cache: false,
                thin_client: flags.contains(crate::pdu::CapabilitiesV103Flags::AVC_THIN_CLIENT),
            },
            CapabilitySet::V10_4 { flags }
            | CapabilitySet::V10_5 { flags }
            | CapabilitySet::V10_6 { flags }
            | CapabilitySet::V10_6Err { flags } => Self {
                avc420: !flags.contains(crate::pdu::CapabilitiesV104Flags::AVC_DISABLED),
                avc444: !flags.contains(crate::pdu::CapabilitiesV104Flags::AVC_DISABLED),
                small_cache: flags.contains(crate::pdu::CapabilitiesV104Flags::SMALL_CACHE),
                thin_client: flags.contains(crate::pdu::CapabilitiesV104Flags::AVC_THIN_CLIENT),
            },
            CapabilitySet::V10_7 { flags } => Self {
                avc420: !flags.contains(CapabilitiesV107Flags::AVC_DISABLED),
                avc444: !flags.contains(CapabilitiesV107Flags::AVC_DISABLED),
                small_cache: flags.contains(CapabilitiesV107Flags::SMALL_CACHE),
                thin_client: flags.contains(CapabilitiesV107Flags::AVC_THIN_CLIENT),
            },
        }
    }
}

// ============================================================================
// Bitmap Update
// ============================================================================

/// Decoded bitmap data for a surface region
///
/// Delivered to [`GraphicsPipelineHandler::on_bitmap_updated`] when
/// a `WireToSurface1` PDU is processed with decoded pixel data.
#[derive(Debug)]
#[non_exhaustive]
pub struct BitmapUpdate {
    /// Surface this update applies to
    pub surface_id: u16,
    /// Destination rectangle within the surface (exclusive `right`/`bottom`)
    pub destination_rectangle: ExclusiveRectangle,
    /// Codec that produced this update
    pub codec_id: Codec1Type,
    /// RGBA pixel data (4 bytes per pixel), row-major
    ///
    /// Dimensions match `width * height * 4` bytes.
    /// May be empty if decode was skipped (no decoder configured).
    pub data: Vec<u8>,
    /// Width of the decoded data in pixels
    pub width: u16,
    /// Height of the decoded data in pixels
    pub height: u16,
}

// ============================================================================
// Handler Trait
// ============================================================================

/// Handler trait for client-side EGFX events
///
/// Implement this trait to receive decoded bitmap data and surface
/// lifecycle notifications from the EGFX pipeline.
///
/// All methods have default no-op implementations so you only need
/// to override the ones relevant to your use case.
pub trait GraphicsPipelineHandler: Send {
    /// Returns the capability sets to advertise to the server
    ///
    /// The default advertises V10.7 (AVC420+AVC444), V8.1 (AVC420 only),
    /// and V8 (no AVC) as fallback.
    ///
    /// Note: AVC-capable versions are automatically filtered out at
    /// advertisement time if no H.264 decoder is configured on the
    /// [`GraphicsPipelineClient`]. If all returned sets require AVC
    /// and no decoder is available, a V8-only fallback is used.
    fn capabilities(&self) -> Vec<CapabilitySet> {
        vec![
            CapabilitySet::V10_7 {
                flags: CapabilitiesV107Flags::SMALL_CACHE,
            },
            CapabilitySet::V8_1 {
                flags: CapabilitiesV81Flags::AVC420_ENABLED | CapabilitiesV81Flags::SMALL_CACHE,
            },
            CapabilitySet::V8 {
                flags: CapabilitiesV8Flags::SMALL_CACHE,
            },
        ]
    }

    /// Called when the server confirms negotiated capabilities
    fn on_capabilities_confirmed(&mut self, _caps: &CapabilitySet) {}

    /// Called when the server resets the graphics output buffer
    fn on_reset_graphics(&mut self, _width: u32, _height: u32) {}

    /// Called when a surface is created by the server
    fn on_surface_created(&mut self, _surface: &Surface) {}

    /// Called when a surface is deleted by the server
    fn on_surface_deleted(&mut self, _surface_id: u16) {}

    /// Called when a surface is mapped to an output position
    fn on_surface_mapped(&mut self, _surface_id: u16, _origin_x: u32, _origin_y: u32) {}

    /// Called when decoded bitmap data is available for a surface
    ///
    /// This is the primary output path. The `update` contains the
    /// surface ID, destination rectangle, and RGBA pixel data.
    fn on_bitmap_updated(&mut self, _update: &BitmapUpdate) {}

    /// Called when a logical frame is complete
    ///
    /// All bitmap updates between the corresponding `StartFrame`
    /// and this notification belong to the same logical frame.
    fn on_frame_complete(&mut self, _frame_id: u32) {}

    /// Called when the EGFX channel is closed
    fn on_close(&mut self) {}

    // ========================================================================
    // Additional PDU handlers (server→client)
    // ========================================================================

    /// Called when the server fills a surface region with a solid color
    ///
    /// Per [MS-RDPEGFX 3.3.5.4].
    ///
    /// [MS-RDPEGFX 3.3.5.4]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/d696ab07-fd47-42f6-a601-c8b6fae26577
    fn on_solid_fill(&mut self, _pdu: &SolidFillPdu) {}

    /// Called when the server copies pixels between surfaces
    ///
    /// Per [MS-RDPEGFX 3.3.5.5].
    ///
    /// [MS-RDPEGFX 3.3.5.5]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/0b19d058-fff0-43e5-8671-8c4186d60529
    fn on_surface_to_surface(&mut self, _pdu: &SurfaceToSurfacePdu) {}

    /// Called when the server caches a surface region
    ///
    /// Per [MS-RDPEGFX 3.3.5.6].
    ///
    /// [MS-RDPEGFX 3.3.5.6]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/01108b9f-a888-4e5c-b790-42d5c5985998
    fn on_surface_to_cache(&mut self, _pdu: &SurfaceToCachePdu) {}

    /// Called when the server renders cached content to a surface
    ///
    /// Per [MS-RDPEGFX 3.3.5.7].
    ///
    /// [MS-RDPEGFX 3.3.5.7]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/78c00bcd-f5cb-4c33-8d6c-f4cd50facfab
    fn on_cache_to_surface(&mut self, _pdu: &CacheToSurfacePdu) {}

    /// Called when the server evicts a cache entry
    ///
    /// Per [MS-RDPEGFX 3.3.5.8].
    ///
    /// [MS-RDPEGFX 3.3.5.8]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/9dd32c5c-fabc-497b-81be-776fa581a4f6
    fn on_evict_cache_entry(&mut self, _pdu: &EvictCacheEntryPdu) {}

    /// Called when the server maps a surface to a RAIL window
    ///
    /// Per [MS-RDPEGFX 2.2.2.20].
    ///
    /// [MS-RDPEGFX 2.2.2.20]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/2ec1357c-ee65-4d9b-89f3-8fc49348c92a
    fn on_map_surface_to_window(&mut self, _pdu: &MapSurfaceToWindowPdu) {}

    /// Called when the server maps a surface to a scaled output
    ///
    /// Per [MS-RDPEGFX 2.2.2.22].
    ///
    /// [MS-RDPEGFX 2.2.2.22]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/3fcc3e63-e5a2-4b18-a572-26bbeb87b3aa
    fn on_map_surface_to_scaled_output(&mut self, _pdu: &MapSurfaceToScaledOutputPdu) {}

    /// Called when the server maps a surface to a scaled RAIL window
    ///
    /// Per [MS-RDPEGFX 2.2.2.23].
    ///
    /// [MS-RDPEGFX 2.2.2.23]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/22fc0ec7-38ce-4d9d-ad6d-93a0e9f3c38c
    fn on_map_surface_to_scaled_window(&mut self, _pdu: &MapSurfaceToScaledWindowPdu) {}

    /// Called for progressive codec (RFX Progressive) bitmap data
    ///
    /// Per [MS-RDPEGFX 3.3.5.3].
    ///
    /// [MS-RDPEGFX 3.3.5.3]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/e6dbb3a7-3de0-44a5-a1ee-9de90f75e7e0
    fn on_wire_to_surface2(&mut self, _pdu: &WireToSurface2Pdu) {}

    /// Called when the server deletes a progressive encoding context
    ///
    /// Per [MS-RDPEGFX 2.2.2.3].
    ///
    /// [MS-RDPEGFX 2.2.2.3]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/bd0c64d4-07b3-47e5-9f7b-ba5c14a3a2e2
    fn on_delete_encoding_context(&mut self, _pdu: &DeleteEncodingContextPdu) {}

    /// Called when the server replies to a cache import offer
    ///
    /// Per [MS-RDPEGFX 2.2.2.17].
    ///
    /// [MS-RDPEGFX 2.2.2.17]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/7c7a0a5d-50c1-44b9-a2e7-44b47ce1e49d
    fn on_cache_import_reply(&mut self, _pdu: &CacheImportReplyPdu) {}

    /// Called for PDUs that have no specific handler
    ///
    /// This is a catch-all for any GfxPdu variant not matched above.
    fn on_unhandled_pdu(&mut self, _pdu: &GfxPdu) {}
}

// ============================================================================
// Client State Machine
// ============================================================================

/// Client state machine states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientState {
    /// Waiting for server `CapabilitiesConfirm`
    WaitingForConfirm,
    /// Channel is active, processing frames
    Active,
    /// Channel has been closed
    Closed,
}

// ============================================================================
// Graphics Pipeline Client
// ============================================================================

/// Client for the Graphics Pipeline Virtual Channel (EGFX)
///
/// This client handles capability negotiation, surface tracking,
/// H.264 AVC420 decode, and frame acknowledgment per [MS-RDPEGFX].
///
/// [MS-RDPEGFX]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/da5c75f9-cd99-450c-98c4-014a496942b0
pub struct GraphicsPipelineClient {
    handler: Box<dyn GraphicsPipelineHandler>,
    h264_decoder: Option<Box<dyn H264Decoder>>,

    decompressor: zgfx::Decompressor,
    decompressed_buffer: Vec<u8>,

    state: ClientState,
    negotiated_caps: Option<CapabilitySet>,
    codec_caps: CodecCapabilities,

    surfaces: BTreeMap<u16, Surface>,
    current_frame_id: Option<u32>,
    frames_queued: u32,
    total_frames_decoded: u32,
}

impl GraphicsPipelineClient {
    /// Create a new `GraphicsPipelineClient`
    ///
    /// If `h264_decoder` is `None`, AVC420 frames are logged and skipped.
    pub fn new(handler: Box<dyn GraphicsPipelineHandler>, h264_decoder: Option<Box<dyn H264Decoder>>) -> Self {
        Self {
            handler,
            h264_decoder,
            decompressor: zgfx::Decompressor::new(),
            decompressed_buffer: Vec::new(),
            state: ClientState::WaitingForConfirm,
            negotiated_caps: None,
            codec_caps: CodecCapabilities::default(),
            surfaces: BTreeMap::new(),
            current_frame_id: None,
            frames_queued: 0,
            total_frames_decoded: 0,
        }
    }

    // ========================================================================
    // State Queries
    // ========================================================================

    /// Check if the client has completed capability negotiation
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state == ClientState::Active
    }

    /// Get the negotiated capability set
    #[must_use]
    pub fn negotiated_capabilities(&self) -> Option<&CapabilitySet> {
        self.negotiated_caps.as_ref()
    }

    /// Get codec capabilities determined from negotiation
    #[must_use]
    pub fn codec_capabilities(&self) -> &CodecCapabilities {
        &self.codec_caps
    }

    /// Get a surface by ID
    #[must_use]
    pub fn get_surface(&self, surface_id: u16) -> Option<&Surface> {
        self.surfaces.get(&surface_id)
    }

    /// Get the total number of frames decoded
    #[must_use]
    pub fn total_frames_decoded(&self) -> u32 {
        self.total_frames_decoded
    }

    // ========================================================================
    // PDU Handlers
    // ========================================================================

    fn handle_pdu(&mut self, pdu: GfxPdu) -> PduResult<Vec<DvcMessage>> {
        match pdu {
            GfxPdu::CapabilitiesConfirm(confirm) => {
                self.handle_capabilities_confirm(confirm.0);
                Ok(vec![])
            }
            GfxPdu::ResetGraphics(reset) => {
                self.handle_reset_graphics(reset.width, reset.height);
                Ok(vec![])
            }
            GfxPdu::CreateSurface(create) => {
                self.handle_create_surface(create.surface_id, create.width, create.height, create.pixel_format);
                Ok(vec![])
            }
            GfxPdu::DeleteSurface(delete) => {
                self.handle_delete_surface(delete.surface_id);
                Ok(vec![])
            }
            GfxPdu::MapSurfaceToOutput(map) => {
                self.handle_map_surface(map.surface_id, map.output_origin_x, map.output_origin_y);
                Ok(vec![])
            }
            GfxPdu::StartFrame(start) => {
                self.current_frame_id = Some(start.frame_id);
                self.frames_queued = self.frames_queued.saturating_add(1);
                trace!(frame_id = start.frame_id, "StartFrame");
                Ok(vec![])
            }
            GfxPdu::WireToSurface1(wire) => {
                self.handle_wire_to_surface1(wire)?;
                Ok(vec![])
            }
            GfxPdu::WireToSurface2(pdu) => {
                trace!("WireToSurface2 (progressive codec)");
                self.handler.on_wire_to_surface2(&pdu);
                Ok(vec![])
            }
            GfxPdu::EndFrame(end) => self.handle_end_frame(end.frame_id),

            // Surface operations
            GfxPdu::SolidFill(pdu) => {
                trace!(surface_id = pdu.surface_id, "SolidFill");
                self.handler.on_solid_fill(&pdu);
                Ok(vec![])
            }
            GfxPdu::SurfaceToSurface(pdu) => {
                trace!(
                    src = pdu.source_surface_id,
                    dst = pdu.destination_surface_id,
                    "SurfaceToSurface"
                );
                self.handler.on_surface_to_surface(&pdu);
                Ok(vec![])
            }

            // Cache operations
            GfxPdu::SurfaceToCache(pdu) => {
                trace!(
                    surface_id = pdu.surface_id,
                    cache_slot = pdu.cache_slot,
                    "SurfaceToCache"
                );
                self.handler.on_surface_to_cache(&pdu);
                Ok(vec![])
            }
            GfxPdu::CacheToSurface(pdu) => {
                trace!(
                    cache_slot = pdu.cache_slot,
                    surface_id = pdu.surface_id,
                    "CacheToSurface"
                );
                self.handler.on_cache_to_surface(&pdu);
                Ok(vec![])
            }
            GfxPdu::EvictCacheEntry(pdu) => {
                trace!(cache_slot = pdu.cache_slot, "EvictCacheEntry");
                self.handler.on_evict_cache_entry(&pdu);
                Ok(vec![])
            }
            GfxPdu::CacheImportReply(pdu) => {
                trace!("CacheImportReply");
                self.handler.on_cache_import_reply(&pdu);
                Ok(vec![])
            }

            // Surface mapping variants
            GfxPdu::MapSurfaceToWindow(pdu) => {
                trace!(
                    surface_id = pdu.surface_id,
                    window_id = pdu.window_id,
                    "MapSurfaceToWindow"
                );
                self.handler.on_map_surface_to_window(&pdu);
                Ok(vec![])
            }
            GfxPdu::MapSurfaceToScaledOutput(pdu) => {
                trace!(surface_id = pdu.surface_id, "MapSurfaceToScaledOutput");
                self.handler.on_map_surface_to_scaled_output(&pdu);
                Ok(vec![])
            }
            GfxPdu::MapSurfaceToScaledWindow(pdu) => {
                trace!(surface_id = pdu.surface_id, "MapSurfaceToScaledWindow");
                self.handler.on_map_surface_to_scaled_window(&pdu);
                Ok(vec![])
            }

            // Progressive codec context management
            GfxPdu::DeleteEncodingContext(pdu) => {
                trace!(
                    surface_id = pdu.surface_id,
                    codec_context_id = pdu.codec_context_id,
                    "DeleteEncodingContext"
                );
                self.handler.on_delete_encoding_context(&pdu);
                Ok(vec![])
            }

            // Catch-all for any remaining PDUs
            other => {
                self.handler.on_unhandled_pdu(&other);
                Ok(vec![])
            }
        }
    }

    fn handle_capabilities_confirm(&mut self, cap: RawCapabilitySet) {
        // Server confirms a single capability set. If we cannot interpret it
        // (unknown version, or malformed body), we still transition to Active
        // to avoid hanging the session, but we keep `negotiated_caps` empty
        // and skip the typed callback so consumers don't observe a confirm
        // they can't reason about.
        let cap = match cap.parsed() {
            Ok(Some(typed)) => typed,
            Ok(None) => {
                warn!(
                    version = cap.version.0,
                    "Server confirmed an unknown EGFX capability version; proceeding with defaults"
                );
                self.state = ClientState::Active;
                return;
            }
            Err(e) => {
                warn!(error = %e, "Failed to parse server's EGFX capabilities confirmation");
                self.state = ClientState::Active;
                return;
            }
        };

        self.codec_caps = CodecCapabilities::from_capability_set(&cap);
        self.state = ClientState::Active;
        let cap = self.negotiated_caps.insert(cap);

        debug!(
            avc420 = self.codec_caps.avc420,
            avc444 = self.codec_caps.avc444,
            "EGFX capabilities confirmed"
        );

        self.handler.on_capabilities_confirmed(cap);
    }

    fn handle_reset_graphics(&mut self, width: u32, height: u32) {
        // Per spec, ResetGraphics implicitly destroys all surfaces
        self.surfaces.clear();

        // Reset frame tracking state so subsequent FrameAcknowledge PDUs
        // don't report stale queue depth from a previous stream.
        // Capability state (negotiated_caps, codec_caps) is NOT reset here:
        // per spec, capabilities are negotiated via CapabilitiesConfirm before
        // ResetGraphics, and a ResetGraphics does not re-negotiate capabilities.
        self.current_frame_id = None;
        self.frames_queued = 0;

        // Reset decoder state for new stream
        if let Some(ref mut decoder) = self.h264_decoder {
            decoder.reset();
        }

        debug!(width, height, "Graphics reset");
        self.handler.on_reset_graphics(width, height);
    }

    fn handle_create_surface(&mut self, surface_id: u16, width: u16, height: u16, pixel_format: PixelFormat) {
        if width == 0 || height == 0 {
            warn!(surface_id, width, height, "Ignoring CreateSurface with zero dimensions");
            return;
        }

        let surface = Surface {
            id: surface_id,
            width,
            height,
            pixel_format,
            is_mapped: false,
            output_origin_x: 0,
            output_origin_y: 0,
        };

        debug!(surface_id, width, height, ?pixel_format, "Surface created");
        self.handler.on_surface_created(&surface);
        self.surfaces.insert(surface_id, surface);
    }

    fn handle_delete_surface(&mut self, surface_id: u16) {
        if self.surfaces.remove(&surface_id).is_some() {
            debug!(surface_id, "Surface deleted");
            self.handler.on_surface_deleted(surface_id);
        } else {
            warn!(surface_id, "DeleteSurface for unknown surface");
        }
    }

    fn handle_map_surface(&mut self, surface_id: u16, origin_x: u32, origin_y: u32) {
        if let Some(surface) = self.surfaces.get_mut(&surface_id) {
            surface.is_mapped = true;
            surface.output_origin_x = origin_x;
            surface.output_origin_y = origin_y;
            debug!(surface_id, origin_x, origin_y, "Surface mapped to output");
            self.handler.on_surface_mapped(surface_id, origin_x, origin_y);
        } else {
            warn!(surface_id, "MapSurfaceToOutput for unknown surface");
        }
    }

    fn handle_wire_to_surface1(&mut self, pdu: crate::pdu::WireToSurface1Pdu) -> PduResult<()> {
        let surface = self
            .surfaces
            .get(&pdu.surface_id)
            .ok_or_else(|| pdu_other_err!("unknown surface in WireToSurface1"))?;

        // Validate rectangle ordering (left <= right, top <= bottom)
        let rect = &pdu.destination_rectangle;
        if rect.left > rect.right || rect.top > rect.bottom {
            warn!(
                left = rect.left,
                top = rect.top,
                right = rect.right,
                bottom = rect.bottom,
                "invalid destination rectangle ordering"
            );
            return Err(pdu_other_err!("invalid destination rectangle ordering"));
        }

        // Validate destination rectangle against surface bounds. The rectangle
        // uses exclusive `right`/`bottom`, so a full-surface update has
        // `right == surface.width` and `bottom == surface.height`, which is valid.
        if rect.right > surface.width || rect.bottom > surface.height {
            warn!(
                surface_id = pdu.surface_id,
                rect_right = rect.right,
                rect_bottom = rect.bottom,
                surface_width = surface.width,
                surface_height = surface.height,
                "WireToSurface1 destination rectangle exceeds surface bounds"
            );
        }

        match pdu.codec_id {
            Codec1Type::Avc420 => {
                self.decode_avc420(pdu.surface_id, &pdu.destination_rectangle, &pdu.bitmap_data)?;
            }
            Codec1Type::Avc444 | Codec1Type::Avc444v2 => {
                debug!("AVC444 codec not yet implemented, forwarding to handler");
                self.handler.on_unhandled_pdu(&GfxPdu::WireToSurface1(pdu));
            }
            Codec1Type::Uncompressed => {
                self.handle_uncompressed(pdu);
            }
            _ => {
                trace!(codec_id = ?pdu.codec_id, "Forwarding unsupported codec to handler");
                self.handler.on_unhandled_pdu(&GfxPdu::WireToSurface1(pdu));
            }
        }

        Ok(())
    }

    fn decode_avc420(&mut self, surface_id: u16, dest_rect: &ExclusiveRectangle, bitmap_data: &[u8]) -> PduResult<()> {
        let mut cursor = ReadCursor::new(bitmap_data);
        let stream = Avc420BitmapStream::decode(&mut cursor).map_err(|e| decode_err!(e))?;

        let Some(ref mut decoder) = self.h264_decoder else {
            debug!("No H.264 decoder configured, skipping AVC420 frame");
            return Ok(());
        };

        let frame = decoder
            .decode(stream.data)
            .map_err(|e| pdu_other_err!("H.264 decode", source: e))?;

        let dest_width = dest_rect.width();
        let dest_height = dest_rect.height();

        // Decoded frame must be at least as large as the destination rectangle.
        // Larger is expected (macroblock alignment) and handled by cropping.
        // Smaller means the server sent mismatched dimensions.
        if frame.width() < u32::from(dest_width) || frame.height() < u32::from(dest_height) {
            warn!(
                frame_width = frame.width(),
                frame_height = frame.height(),
                dest_width,
                dest_height,
                "decoded frame smaller than destination rectangle"
            );
            return Err(pdu_other_err!("decoded frame smaller than destination rectangle"));
        }

        let cropped_data = crop_decoded_frame(frame.data(), frame.width(), frame.height(), dest_width, dest_height);

        let update = BitmapUpdate {
            surface_id,
            destination_rectangle: dest_rect.clone(),
            codec_id: Codec1Type::Avc420,
            data: cropped_data,
            width: dest_width,
            height: dest_height,
        };

        self.handler.on_bitmap_updated(&update);
        Ok(())
    }

    fn handle_uncompressed(&mut self, pdu: crate::pdu::WireToSurface1Pdu) {
        let dest_width = pdu.destination_rectangle.width();
        let dest_height = pdu.destination_rectangle.height();

        // Convert wire-format pixels to RGBA.
        // BitmapUpdate.data is always RGBA8888 regardless of codec -- this is
        // the convention so that handlers get a uniform pixel format.
        // Uncompressed wire format is 32-bit LE (0xAARRGGBB → bytes [B, G, R, A]).
        let rgba_data = convert_uncompressed_to_rgba(&pdu.bitmap_data);

        let update = BitmapUpdate {
            surface_id: pdu.surface_id,
            destination_rectangle: pdu.destination_rectangle,
            codec_id: Codec1Type::Uncompressed,
            data: rgba_data,
            width: dest_width,
            height: dest_height,
        };

        self.handler.on_bitmap_updated(&update);
    }

    #[expect(clippy::as_conversions, reason = "Box<GfxPdu> to Box<dyn DvcEncode> coercion")]
    fn handle_end_frame(&mut self, frame_id: u32) -> PduResult<Vec<DvcMessage>> {
        self.total_frames_decoded = self.total_frames_decoded.wrapping_add(1);
        self.current_frame_id = None;
        self.frames_queued = self.frames_queued.saturating_sub(1);

        self.handler.on_frame_complete(frame_id);

        // Per [3.3.5.12]: client MUST send FrameAcknowledge after EndFrame
        let ack = GfxPdu::FrameAcknowledge(FrameAcknowledgePdu {
            queue_depth: QueueDepth::from_u32(self.frames_queued),
            frame_id,
            total_frames_decoded: self.total_frames_decoded,
        });

        trace!(frame_id, "Sending FrameAcknowledge");
        Ok(vec![Box::new(ack) as DvcMessage])
    }
}

impl_as_any!(GraphicsPipelineClient);

impl DvcProcessor for GraphicsPipelineClient {
    fn channel_name(&self) -> &str {
        CHANNEL_NAME
    }

    fn start(&mut self, _channel_id: u32) -> PduResult<Vec<DvcMessage>> {
        let caps = if self.h264_decoder.is_some() {
            self.handler.capabilities()
        } else {
            // No H.264 decoder: filter out capability sets that imply AVC support.
            // Only keep sets that work without a decoder (V8 without AVC flags).
            let filtered: Vec<CapabilitySet> = self
                .handler
                .capabilities()
                .into_iter()
                .filter(|cap| !CodecCapabilities::from_capability_set(cap).avc420)
                .collect();

            if filtered.is_empty() {
                // All handler caps required AVC; fall back to V8-only
                debug!("No H.264 decoder and all capabilities require AVC; falling back to V8");
                vec![CapabilitySet::V8 {
                    flags: CapabilitiesV8Flags::SMALL_CACHE,
                }]
            } else {
                filtered
            }
        };

        let pdu = GfxPdu::CapabilitiesAdvertise(CapabilitiesAdvertisePdu::from_typed(&caps));

        #[expect(clippy::as_conversions, reason = "Box<GfxPdu> to Box<dyn DvcEncode> coercion")]
        Ok(vec![Box::new(pdu) as DvcMessage])
    }

    fn close(&mut self, _channel_id: u32) {
        self.state = ClientState::Closed;
        self.handler.on_close();
    }

    fn process(&mut self, _channel_id: u32, payload: &[u8]) -> PduResult<Vec<DvcMessage>> {
        // ZGFX decompress
        self.decompressed_buffer.clear();
        self.decompressed_buffer.shrink_to(MAX_DECOMPRESSED_BUFFER_CAPACITY);
        self.decompressor
            .decompress(payload, &mut self.decompressed_buffer)
            .map_err(|e| decode_err!(e))?;

        // Decode all PDUs first (cursor borrows decompressed_buffer)
        let mut pdus = Vec::new();
        {
            let mut cursor = ReadCursor::new(self.decompressed_buffer.as_slice());
            while !cursor.is_empty() {
                let pdu: GfxPdu = decode_cursor(&mut cursor).map_err(|e| decode_err!(e))?;
                pdus.push(pdu);
            }
        }

        // Process decoded PDUs
        let mut responses: Vec<DvcMessage> = Vec::new();
        for pdu in pdus {
            let pdu_responses = self.handle_pdu(pdu)?;
            responses.extend(pdu_responses);
        }

        Ok(responses)
    }
}

impl DvcClientProcessor for GraphicsPipelineClient {}

// ============================================================================
// Frame Cropping
// ============================================================================

/// Convert uncompressed 32bpp little-endian pixels to RGBA8888
///
/// The wire format for uncompressed graphics is 0xAARRGGBB in a 32-bit
/// little-endian word, which corresponds to bytes [B, G, R, A]. This
/// reorders to [R, G, B, 0xFF], treating all pixels as fully opaque.
fn convert_uncompressed_to_rgba(src: &[u8]) -> Vec<u8> {
    let mut dst = Vec::with_capacity(src.len());
    for pixel in src.chunks_exact(4) {
        let b = pixel[0];
        let g = pixel[1];
        let r = pixel[2];
        dst.extend_from_slice(&[r, g, b, 0xFF]);
    }
    dst
}

/// Crop a decoded RGBA frame to target dimensions
///
/// H.264 frames are macroblock-aligned (16x16), so decoded frames
/// may be larger than the destination rectangle. This function
/// extracts the top-left region matching the target size.
fn crop_decoded_frame(
    data: &[u8],
    decoded_width: u32,
    decoded_height: u32,
    target_width: u16,
    target_height: u16,
) -> Vec<u8> {
    let tw = u32::from(target_width);
    let th = u32::from(target_height);

    if decoded_width == 0 || decoded_height == 0 || tw == 0 || th == 0 {
        return Vec::new();
    }

    // If dimensions match, return as-is
    if decoded_width == tw && decoded_height == th {
        return data.to_vec();
    }

    let src_stride = decoded_width.saturating_mul(4);
    let dst_stride = tw.saturating_mul(4);
    let rows = th.min(decoded_height);

    #[expect(clippy::as_conversions, reason = "product of u32 values bounded by frame dimensions")]
    let mut cropped = Vec::with_capacity((dst_stride as usize).saturating_mul(rows as usize));

    for row in 0..rows {
        #[expect(clippy::as_conversions, reason = "row * src_stride bounded by frame size")]
        let src_start = (row.saturating_mul(src_stride)) as usize;
        #[expect(clippy::as_conversions, reason = "bounded by frame dimensions")]
        let copy_len = dst_stride.min(src_stride) as usize;
        let src_end = src_start.saturating_add(copy_len);
        if src_end <= data.len() {
            cropped.extend_from_slice(&data[src_start..src_end]);
        }
    }

    #[expect(clippy::as_conversions, reason = "dst_stride * rows bounded by frame dimensions")]
    let expected_len = (dst_stride as usize).saturating_mul(rows as usize);
    if cropped.len() < expected_len {
        tracing::warn!(
            expected = expected_len,
            actual = cropped.len(),
            "Decoded frame data truncated during crop"
        );
    }

    cropped
}

/// Unit tests that require access to private fields (state, surfaces, frame tracking).
/// Integration tests exercising the public DVC API are in ironrdp-testsuite-core/tests/egfx/client.rs.
#[cfg(test)]
mod tests {
    use super::*;

    struct TestHandler;
    impl GraphicsPipelineHandler for TestHandler {
        fn on_capabilities_confirmed(&mut self, _caps: &CapabilitySet) {}
        fn on_reset_graphics(&mut self, _width: u32, _height: u32) {}
        fn on_surface_created(&mut self, _surface: &Surface) {}
        fn on_surface_deleted(&mut self, _surface_id: u16) {}
        fn on_surface_mapped(&mut self, _surface_id: u16, _x: u32, _y: u32) {}
        fn on_bitmap_updated(&mut self, _update: &BitmapUpdate) {}
        fn on_frame_complete(&mut self, _frame_id: u32) {}
        fn on_close(&mut self) {}
        fn on_unhandled_pdu(&mut self, _pdu: &GfxPdu) {}
    }

    #[test]
    fn state_transitions() {
        let mut client = GraphicsPipelineClient::new(Box::new(TestHandler), None);

        assert_eq!(client.state, ClientState::WaitingForConfirm);
        assert!(!client.is_active());

        let _ = client.handle_pdu(GfxPdu::CapabilitiesConfirm(
            crate::pdu::CapabilitiesConfirmPdu::from_typed(&CapabilitySet::V8 {
                flags: CapabilitiesV8Flags::empty(),
            }),
        ));
        assert_eq!(client.state, ClientState::Active);
        assert!(client.is_active());

        client.close(0);
        assert_eq!(client.state, ClientState::Closed);
        assert!(!client.is_active());
    }

    #[test]
    fn reset_graphics_clears_surfaces_and_frame_tracking() {
        let mut client = GraphicsPipelineClient::new(Box::new(TestHandler), None);

        let _ = client.handle_pdu(GfxPdu::CreateSurface(crate::pdu::CreateSurfacePdu {
            surface_id: 1,
            width: 100,
            height: 100,
            pixel_format: PixelFormat::XRgb,
        }));
        assert_eq!(client.surfaces.len(), 1);

        // Simulate mid-stream state
        let _ = client.handle_pdu(GfxPdu::StartFrame(crate::pdu::StartFramePdu {
            timestamp: crate::pdu::Timestamp {
                milliseconds: 0,
                seconds: 0,
                minutes: 0,
                hours: 0,
            },
            frame_id: 42,
        }));
        assert!(client.current_frame_id.is_some());
        assert_eq!(client.frames_queued, 1);

        let _ = client.handle_pdu(GfxPdu::ResetGraphics(crate::pdu::ResetGraphicsPdu {
            width: 1920,
            height: 1080,
            monitors: vec![],
        }));

        assert!(client.surfaces.is_empty(), "surfaces should be cleared");
        assert!(client.current_frame_id.is_none(), "frame_id should be reset");
        assert_eq!(client.frames_queued, 0, "frame queue should be reset");
    }

    #[test]
    fn crop_decoded_frame_identity() {
        let data = vec![0xFFu8; 4 * 4 * 4];
        let cropped = crop_decoded_frame(&data, 4, 4, 4, 4);
        assert_eq!(cropped.len(), data.len());
    }

    #[test]
    fn crop_decoded_frame_macroblock_alignment() {
        // H.264 encodes 1920x1080 as 1920x1088 (rounded to 16-pixel macroblock boundary)
        let data = vec![0xAAu8; 1920 * 1088 * 4];
        let cropped = crop_decoded_frame(&data, 1920, 1088, 1920, 1080);
        assert_eq!(cropped.len(), 1920 * 1080 * 4);
    }

    #[test]
    fn convert_uncompressed_bgrx_to_rgba() {
        // Wire format: [B, G, R, A] per pixel (0xAARRGGBB little-endian)
        let wire_pixels = vec![
            0x00, 0x80, 0xFF, 0xCC, // B=0, G=128, R=255, A=204
            0x10, 0x20, 0x30, 0x40, // B=16, G=32, R=48, A=64
        ];
        let rgba = convert_uncompressed_to_rgba(&wire_pixels);
        // Expected: [R, G, B, 0xFF] per pixel (alpha forced to opaque)
        assert_eq!(rgba, vec![0xFF, 0x80, 0x00, 0xFF, 0x30, 0x20, 0x10, 0xFF]);
    }
}
