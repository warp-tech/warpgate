//! Server-side EGFX implementation
//!
//! This module provides complete server-side support for the Graphics Pipeline Extension
//! (MS-RDPEGFX), enabling H.264 AVC420/AVC444 video streaming to RDP clients.
//!
//! # Protocol Compliance
//!
//! This implementation follows MS-RDPEGFX specification requirements:
//!
//! - **Capability Negotiation**: Supports V8, V8.1, V10, V10.1-V10.7
//! - **Surface Management**: Multi-surface support with proper lifecycle
//! - **Frame Flow Control**: Tracks unacknowledged frames per spec
//! - **Codec Support**: AVC420, AVC444, with extensibility for others
//!
//! # Architecture
//!
//! The server follows this message flow:
//!
//! ```text
//! Client                                  Server
//!    |                                       |
//!    |--- CapabilitiesAdvertise ------------>|
//!    |                                       | (negotiate capabilities)
//!    |<----------- CapabilitiesConfirm ------|
//!    |<----------- ResetGraphics ------------|
//!    |<----------- CreateSurface ------------|
//!    |<----------- MapSurfaceToOutput -------|
//!    |                                       |
//!    |  (For each frame:)                    |
//!    |<----------- StartFrame ---------------|
//!    |<----------- WireToSurface1/2 ---------|  (H.264 data)
//!    |<----------- EndFrame -----------------|
//!    |                                       |
//!    |--- FrameAcknowledge ----------------->|  (flow control)
//!    |--- QoeFrameAcknowledge -------------->|  (optional, V10+)
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use ironrdp_egfx::server::{GraphicsPipelineServer, GraphicsPipelineHandler};
//!
//! struct MyHandler;
//!
//! impl GraphicsPipelineHandler for MyHandler {
//!     fn capabilities_advertise(&mut self, caps: &CapabilitiesAdvertisePdu) {
//!         // Client sent capabilities
//!     }
//!
//!     fn on_ready(&mut self, negotiated: &CapabilitySet) {
//!         // Server is ready to send frames
//!     }
//! }
//!
//! let server = GraphicsPipelineServer::new(Box::new(MyHandler));
//! ```

use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use ironrdp_core::{Encode, EncodeResult, WriteCursor, decode, impl_as_any};
use ironrdp_dvc::{DvcEncode, DvcMessage, DvcProcessor, DvcServerProcessor};
use ironrdp_graphics::zgfx::{CompressionMode, Compressor, compress_and_wrap_egfx, wrap_uncompressed};
use ironrdp_pdu::gcc::Monitor;
use ironrdp_pdu::geometry::ExclusiveRectangle;
use ironrdp_pdu::{PduResult, decode_err};
use tracing::{debug, trace, warn};

use crate::CHANNEL_NAME;
use crate::pdu::{
    Avc420BitmapStream, Avc420Region, Avc444BitmapStream, CacheImportOfferPdu, CacheImportReplyPdu,
    CapabilitiesAdvertisePdu, CapabilitiesConfirmPdu, CapabilitiesV8Flags, CapabilitiesV10Flags, CapabilitiesV81Flags,
    CapabilitiesV103Flags, CapabilitiesV104Flags, CapabilitiesV107Flags, CapabilitySet, Codec1Type, Codec2Type,
    CreateSurfacePdu, DeleteSurfacePdu, Encoding, EndFramePdu, FrameAcknowledgePdu, GfxPdu, MapSurfaceToOutputPdu,
    PixelFormat, QoeFrameAcknowledgePdu, ResetGraphicsPdu, StartFramePdu, Timestamp, WireToSurface1Pdu,
    WireToSurface2Pdu, encode_avc420_bitmap_stream,
};

// ============================================================================
// Constants
// ============================================================================

/// Default maximum frames in flight before applying backpressure
const DEFAULT_MAX_FRAMES_IN_FLIGHT: u32 = 3;

/// Special queue depth value indicating client has disabled acknowledgments
const SUSPEND_FRAME_ACK_QUEUE_DEPTH: u32 = 0xFFFFFFFF;

/// Pre-encoded ZGFX-wrapped bytes for DVC transmission.
///
/// `Encode::encode()` takes `&self`, but ZGFX wrapping is done in `drain_output()`
/// where `&mut self` is available. This type holds the already-wrapped bytes.
struct ZgfxWrappedBytes {
    bytes: Vec<u8>,
    pdu_name: &'static str,
}

impl Encode for ZgfxWrappedBytes {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_slice(&self.bytes);
        Ok(())
    }

    fn name(&self) -> &'static str {
        self.pdu_name
    }

    fn size(&self) -> usize {
        self.bytes.len()
    }
}

impl DvcEncode for ZgfxWrappedBytes {}

// ============================================================================
// Surface Management
// ============================================================================

/// Surface state tracked by server
///
/// Per MS-RDPEGFX, the server maintains an "Offscreen Surfaces ADM element"
/// which is a list of surfaces created on the client.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Surface {
    /// Surface identifier (unique per session)
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

impl Surface {
    fn new(id: u16, width: u16, height: u16, pixel_format: PixelFormat) -> Self {
        Self {
            id,
            width,
            height,
            pixel_format,
            is_mapped: false,
            output_origin_x: 0,
            output_origin_y: 0,
        }
    }
}

/// Multi-surface management
///
/// Implements the "Offscreen Surfaces ADM element" from MS-RDPEGFX.
#[derive(Debug, Default)]
pub struct Surfaces {
    surfaces: HashMap<u16, Surface>,
    next_surface_id: u16,
}

impl Surfaces {
    /// Create a new surface manager
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a new surface ID
    pub fn allocate_id(&mut self) -> u16 {
        let id = self.next_surface_id;
        debug_assert!(!self.surfaces.contains_key(&id), "surface ID {id} already in use");
        self.next_surface_id = self.next_surface_id.wrapping_add(1);
        id
    }

    /// Register a surface
    pub fn insert(&mut self, surface: Surface) {
        self.surfaces.insert(surface.id, surface);
    }

    /// Remove a surface
    pub fn remove(&mut self, surface_id: u16) -> Option<Surface> {
        self.surfaces.remove(&surface_id)
    }

    /// Get a surface by ID
    pub fn get(&self, surface_id: u16) -> Option<&Surface> {
        self.surfaces.get(&surface_id)
    }

    /// Get a mutable surface by ID
    pub fn get_mut(&mut self, surface_id: u16) -> Option<&mut Surface> {
        self.surfaces.get_mut(&surface_id)
    }

    /// Check if a surface exists
    pub fn contains(&self, surface_id: u16) -> bool {
        self.surfaces.contains_key(&surface_id)
    }

    /// Get all surface IDs
    pub fn surface_ids(&self) -> impl Iterator<Item = u16> + '_ {
        self.surfaces.keys().copied()
    }

    /// Clear all surfaces
    pub fn clear(&mut self) {
        self.surfaces.clear();
    }

    /// Number of surfaces
    pub fn len(&self) -> usize {
        self.surfaces.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.surfaces.is_empty()
    }
}

// ============================================================================
// Frame Tracking
// ============================================================================

/// Information about a frame awaiting acknowledgment
///
/// Per MS-RDPEGFX, the server maintains an "Unacknowledged Frames ADM element"
/// which tracks frames sent but not yet acknowledged.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FrameInfo {
    /// Frame identifier
    pub frame_id: u32,
    /// Frame timestamp
    pub timestamp: Timestamp,
    /// When the frame was sent
    pub sent_at: Instant,
    /// Approximate size in bytes
    pub size_bytes: usize,
}

/// Quality of Experience metrics from client
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct QoeMetrics {
    /// Frame ID this relates to
    pub frame_id: u32,
    /// Client timestamp when decode started
    pub timestamp: u32,
    /// Time difference for serial encode (microseconds)
    pub time_diff_se: u16,
    /// Time difference for decode and render (microseconds)
    pub time_diff_dr: u16,
}

// ============================================================================
// QoE Statistics
// ============================================================================

/// Accumulated Quality of Experience statistics.
///
/// Tracks client-reported decode/render timing from [2.2.2.13] QoE Frame
/// Acknowledge PDUs and server-measured round-trip latency from frame
/// acknowledgments. Statistics are accumulated over the lifetime of the
/// EGFX channel.
///
/// Use [`GraphicsPipelineServer::qoe_snapshot()`] to query current values.
///
/// [2.2.2.13]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/40c1ada9-db39-407b-a760-fca4b3e9cc35
#[derive(Debug)]
struct QoeCollector {
    /// Total QoE reports received from client.
    total_reports: u64,

    /// Most recent client decode+render time (microseconds).
    latest_decode_render_us: u16,

    /// Exponential moving average of decode+render time (microseconds).
    avg_decode_render_us: f32,

    /// Minimum decode+render time observed (microseconds).
    min_decode_render_us: u16,

    /// Maximum decode+render time observed (microseconds).
    max_decode_render_us: u16,

    /// Total round-trip latency samples (frame send to ack receive).
    total_rtt_samples: u64,

    /// Exponential moving average of round-trip latency (milliseconds).
    avg_rtt_ms: f32,

    /// Minimum round-trip latency observed (milliseconds).
    min_rtt_ms: f32,

    /// Maximum round-trip latency observed (milliseconds).
    max_rtt_ms: f32,

    /// Total encoded bytes across all acknowledged frames.
    total_bytes_sent: u64,

    /// Total frames acknowledged (for average frame size calculation).
    total_frames_acked: u64,

    /// Number of times a frame send was blocked by backpressure.
    backpressure_count: u64,
}

/// EMA smoothing factor. Balances responsiveness to recent values against
/// stability. 0.1 means ~10-sample effective window.
const QOE_EMA_ALPHA: f32 = 0.1;

impl QoeCollector {
    fn new() -> Self {
        Self {
            total_reports: 0,
            latest_decode_render_us: 0,
            avg_decode_render_us: 0.0,
            min_decode_render_us: u16::MAX,
            max_decode_render_us: 0,
            total_rtt_samples: 0,
            avg_rtt_ms: 0.0,
            min_rtt_ms: f32::MAX,
            max_rtt_ms: 0.0,
            total_bytes_sent: 0,
            total_frames_acked: 0,
            backpressure_count: 0,
        }
    }

    /// Record a QoE report from the client.
    fn record_qoe(&mut self, metrics: &QoeMetrics) {
        let dr = metrics.time_diff_dr;

        self.latest_decode_render_us = dr;
        self.min_decode_render_us = self.min_decode_render_us.min(dr);
        self.max_decode_render_us = self.max_decode_render_us.max(dr);

        if self.total_reports == 0 {
            self.avg_decode_render_us = f32::from(dr);
        } else {
            self.avg_decode_render_us =
                self.avg_decode_render_us * (1.0 - QOE_EMA_ALPHA) + f32::from(dr) * QOE_EMA_ALPHA;
        }

        self.total_reports += 1;
    }

    /// Record an acknowledged frame's size for bandwidth tracking.
    #[expect(
        clippy::as_conversions,
        reason = "usize to u64 is lossless on all supported platforms (32/64-bit)"
    )]
    fn record_frame_ack(&mut self, size_bytes: usize) {
        self.total_bytes_sent += size_bytes as u64;
        self.total_frames_acked += 1;
    }

    /// Record a backpressure event (frame send blocked by full queue).
    fn record_backpressure(&mut self) {
        self.backpressure_count += 1;
    }

    /// Record a round-trip latency measurement from a frame acknowledgment.
    fn record_rtt(&mut self, rtt: core::time::Duration) {
        let rtt_ms = rtt.as_secs_f32() * 1000.0;

        self.min_rtt_ms = self.min_rtt_ms.min(rtt_ms);
        self.max_rtt_ms = self.max_rtt_ms.max(rtt_ms);

        if self.total_rtt_samples == 0 {
            self.avg_rtt_ms = rtt_ms;
        } else {
            self.avg_rtt_ms = self.avg_rtt_ms * (1.0 - QOE_EMA_ALPHA) + rtt_ms * QOE_EMA_ALPHA;
        }

        self.total_rtt_samples += 1;
    }

    /// Produce a point-in-time snapshot of accumulated statistics.
    fn snapshot(&self) -> QoeSnapshot {
        QoeSnapshot {
            total_qoe_reports: self.total_reports,
            latest_decode_render_us: self.latest_decode_render_us,
            avg_decode_render_us: self.avg_decode_render_us,
            min_decode_render_us: if self.total_reports == 0 {
                0
            } else {
                self.min_decode_render_us
            },
            max_decode_render_us: self.max_decode_render_us,
            total_rtt_samples: self.total_rtt_samples,
            avg_rtt_ms: self.avg_rtt_ms,
            min_rtt_ms: if self.total_rtt_samples == 0 {
                0.0
            } else {
                self.min_rtt_ms
            },
            max_rtt_ms: self.max_rtt_ms,
            total_bytes_sent: self.total_bytes_sent,
            avg_frame_size_bytes: if self.total_frames_acked == 0 {
                0
            } else {
                self.total_bytes_sent / self.total_frames_acked
            },
            backpressure_count: self.backpressure_count,
        }
    }

    /// Reset all accumulated statistics.
    fn clear(&mut self) {
        *self = Self::new();
    }
}

impl Default for QoeCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Point-in-time snapshot of QoE statistics.
///
/// Returned by [`GraphicsPipelineServer::qoe_snapshot()`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct QoeSnapshot {
    /// Total QoE reports received from client.
    pub total_qoe_reports: u64,

    /// Most recent client decode+render time (microseconds).
    pub latest_decode_render_us: u16,

    /// Exponential moving average of decode+render time (microseconds).
    pub avg_decode_render_us: f32,

    /// Minimum decode+render time observed (microseconds).
    pub min_decode_render_us: u16,

    /// Maximum decode+render time observed (microseconds).
    pub max_decode_render_us: u16,

    /// Total round-trip latency samples.
    pub total_rtt_samples: u64,

    /// Exponential moving average of round-trip latency (milliseconds).
    pub avg_rtt_ms: f32,

    /// Minimum round-trip latency observed (milliseconds).
    pub min_rtt_ms: f32,

    /// Maximum round-trip latency observed (milliseconds).
    pub max_rtt_ms: f32,

    /// Total encoded bytes across all acknowledged frames.
    pub total_bytes_sent: u64,

    /// Average frame size in bytes (total_bytes_sent / frames acknowledged).
    pub avg_frame_size_bytes: u64,

    /// Number of times a frame send was blocked by backpressure.
    ///
    /// High values indicate the client cannot keep up with the server's
    /// frame rate. Useful for adaptive encoding decisions and thin client
    /// detection.
    pub backpressure_count: u64,
}

// ============================================================================
// Frame Tracking
// ============================================================================

/// Frame tracking for flow control
///
/// Implements the "Unacknowledged Frames ADM element" from MS-RDPEGFX.
#[derive(Debug)]
pub struct FrameTracker {
    /// Frames sent but not yet acknowledged
    unacknowledged: HashMap<u32, FrameInfo>,
    /// Last reported client queue depth
    client_queue_depth: u32,
    /// Whether client has suspended acknowledgments
    ack_suspended: bool,
    /// Next frame ID to assign
    next_frame_id: u32,
    /// Maximum frames in flight before backpressure
    max_in_flight: u32,
    /// Total frames sent
    total_sent: u64,
    /// Total frames acknowledged
    total_acked: u64,
}

impl Default for FrameTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameTracker {
    /// Create a new frame tracker
    pub fn new() -> Self {
        Self {
            unacknowledged: HashMap::new(),
            client_queue_depth: 0,
            ack_suspended: false,
            next_frame_id: 0,
            max_in_flight: DEFAULT_MAX_FRAMES_IN_FLIGHT,
            total_sent: 0,
            total_acked: 0,
        }
    }

    /// Set maximum frames in flight
    pub fn set_max_in_flight(&mut self, max: u32) {
        self.max_in_flight = max;
    }

    /// Allocate a new frame ID and track it
    pub fn begin_frame(&mut self, timestamp: Timestamp) -> u32 {
        let frame_id = self.next_frame_id;
        self.next_frame_id = self.next_frame_id.wrapping_add(1);

        self.unacknowledged.insert(
            frame_id,
            FrameInfo {
                frame_id,
                timestamp,
                sent_at: Instant::now(),
                size_bytes: 0,
            },
        );

        self.total_sent += 1;
        frame_id
    }

    /// Update frame size after encoding
    pub fn set_frame_size(&mut self, frame_id: u32, size_bytes: usize) {
        if let Some(info) = self.unacknowledged.get_mut(&frame_id) {
            info.size_bytes = size_bytes;
        }
    }

    /// Handle frame acknowledgment from client
    pub fn acknowledge(&mut self, frame_id: u32, queue_depth: u32) -> Option<FrameInfo> {
        if queue_depth == SUSPEND_FRAME_ACK_QUEUE_DEPTH {
            self.ack_suspended = true;
            self.client_queue_depth = 0;
        } else {
            self.ack_suspended = false;
            self.client_queue_depth = queue_depth;
        }

        let info = self.unacknowledged.remove(&frame_id);
        if info.is_some() {
            self.total_acked += 1;
        }
        info
    }

    /// Number of frames in flight
    #[expect(
        clippy::cast_possible_truncation,
        clippy::as_conversions,
        reason = "frame count will never exceed u32::MAX"
    )]
    pub fn in_flight(&self) -> u32 {
        self.unacknowledged.len() as u32
    }

    /// Check if backpressure should be applied
    pub fn should_backpressure(&self) -> bool {
        !self.ack_suspended && self.in_flight() >= self.max_in_flight
    }

    /// Get client queue depth
    pub fn client_queue_depth(&self) -> u32 {
        self.client_queue_depth
    }

    /// Check if acknowledgments are suspended
    pub fn is_ack_suspended(&self) -> bool {
        self.ack_suspended
    }

    /// Get total frames sent
    pub fn total_sent(&self) -> u64 {
        self.total_sent
    }

    /// Get total frames acknowledged
    pub fn total_acked(&self) -> u64 {
        self.total_acked
    }

    /// Clear all tracking state
    pub fn clear(&mut self) {
        self.unacknowledged.clear();
        self.client_queue_depth = 0;
        self.ack_suspended = false;
    }
}

// ============================================================================
// Capability Negotiation
// ============================================================================

/// Codec capabilities determined from negotiation
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
    /// Extract codec capabilities from a capability set
    fn from_capability_set(cap: &CapabilitySet) -> Self {
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
                avc420: !flags.contains(CapabilitiesV10Flags::AVC_DISABLED),
                avc444: !flags.contains(CapabilitiesV10Flags::AVC_DISABLED),
                small_cache: flags.contains(CapabilitiesV10Flags::SMALL_CACHE),
                thin_client: false,
            },
            CapabilitySet::V10_1 => Self {
                avc420: true,
                avc444: true,
                small_cache: false,
                thin_client: false,
            },
            CapabilitySet::V10_3 { flags } => Self {
                // V10.3 lacks SMALL_CACHE flag
                avc420: !flags.contains(CapabilitiesV103Flags::AVC_DISABLED),
                avc444: !flags.contains(CapabilitiesV103Flags::AVC_DISABLED),
                small_cache: false,
                thin_client: flags.contains(CapabilitiesV103Flags::AVC_THIN_CLIENT),
            },
            CapabilitySet::V10_4 { flags }
            | CapabilitySet::V10_5 { flags }
            | CapabilitySet::V10_6 { flags }
            | CapabilitySet::V10_6Err { flags } => Self {
                avc420: !flags.contains(CapabilitiesV104Flags::AVC_DISABLED),
                avc444: !flags.contains(CapabilitiesV104Flags::AVC_DISABLED),
                small_cache: flags.contains(CapabilitiesV104Flags::SMALL_CACHE),
                thin_client: flags.contains(CapabilitiesV104Flags::AVC_THIN_CLIENT),
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

/// Priority order for capability negotiation (highest to lowest)
fn capability_priority(cap: &CapabilitySet) -> u32 {
    match cap {
        CapabilitySet::V10_7 { .. } => 12,
        CapabilitySet::V10_6Err { .. } => 11,
        CapabilitySet::V10_6 { .. } => 10,
        CapabilitySet::V10_5 { .. } => 9,
        CapabilitySet::V10_4 { .. } => 8,
        CapabilitySet::V10_3 { .. } => 7,
        CapabilitySet::V10_2 { .. } => 6,
        CapabilitySet::V10_1 => 5,
        CapabilitySet::V10 { .. } => 4,
        CapabilitySet::V8_1 { .. } => 3,
        CapabilitySet::V8 { .. } => 2,
    }
}

/// Negotiate the best capability set between client and server
fn negotiate_capabilities(client_caps: &[CapabilitySet], server_caps: &[CapabilitySet]) -> Option<CapabilitySet> {
    let mut server_sorted: Vec<_> = server_caps.iter().collect();
    server_sorted.sort_by_key(|cap| core::cmp::Reverse(capability_priority(cap)));

    for server_cap in server_sorted {
        for client_cap in client_caps {
            if core::mem::discriminant(client_cap) == core::mem::discriminant(server_cap) {
                return Some(intersect_flags(client_cap, server_cap));
            }
        }
    }

    None
}

/// Intersect flags for matching capability set versions
fn intersect_flags(client: &CapabilitySet, server: &CapabilitySet) -> CapabilitySet {
    match (client, server) {
        (CapabilitySet::V8 { flags: cf }, CapabilitySet::V8 { flags: sf }) => CapabilitySet::V8 { flags: *cf & *sf },
        (CapabilitySet::V8_1 { flags: cf }, CapabilitySet::V8_1 { flags: sf }) => {
            CapabilitySet::V8_1 { flags: *cf & *sf }
        }
        (CapabilitySet::V10 { flags: cf }, CapabilitySet::V10 { flags: sf }) => CapabilitySet::V10 { flags: *cf & *sf },
        (CapabilitySet::V10_2 { flags: cf }, CapabilitySet::V10_2 { flags: sf }) => {
            CapabilitySet::V10_2 { flags: *cf & *sf }
        }
        (CapabilitySet::V10_3 { flags: cf }, CapabilitySet::V10_3 { flags: sf }) => {
            CapabilitySet::V10_3 { flags: *cf & *sf }
        }
        (CapabilitySet::V10_4 { flags: cf }, CapabilitySet::V10_4 { flags: sf }) => {
            CapabilitySet::V10_4 { flags: *cf & *sf }
        }
        (CapabilitySet::V10_5 { flags: cf }, CapabilitySet::V10_5 { flags: sf }) => {
            CapabilitySet::V10_5 { flags: *cf & *sf }
        }
        (CapabilitySet::V10_6 { flags: cf }, CapabilitySet::V10_6 { flags: sf }) => {
            CapabilitySet::V10_6 { flags: *cf & *sf }
        }
        (CapabilitySet::V10_6Err { flags: cf }, CapabilitySet::V10_6Err { flags: sf }) => {
            CapabilitySet::V10_6Err { flags: *cf & *sf }
        }
        (CapabilitySet::V10_7 { flags: cf }, CapabilitySet::V10_7 { flags: sf }) => {
            CapabilitySet::V10_7 { flags: *cf & *sf }
        }
        // V10_1 has no flags; mismatched variants return server as-is.
        _ => server.clone(),
    }
}

// ============================================================================
// Handler Trait
// ============================================================================

/// Handler trait for server-side EGFX events
///
/// Implement this trait to receive callbacks when the EGFX channel state changes
/// or when client messages are received.
pub trait GraphicsPipelineHandler: Send {
    /// Called when the client advertises its capabilities
    ///
    /// This is informational - the server will automatically negotiate
    /// based on [`preferred_capabilities()`](Self::preferred_capabilities).
    fn capabilities_advertise(&mut self, pdu: &CapabilitiesAdvertisePdu);

    /// Called when the EGFX channel is ready to send frames
    ///
    /// At this point, capability negotiation is complete.
    /// The handler should create surfaces and start sending frames.
    fn on_ready(&mut self, negotiated: &CapabilitySet);

    /// Called when a frame has been acknowledged by the client
    ///
    /// `total_frames_decoded` is the client's running decoded-frame count
    /// (MS-RDPEGFX 2.2.2.13), for decode-backlog flow control.
    fn on_frame_ack(&mut self, frame_id: u32, queue_depth: u32, total_frames_decoded: u32) {
        let _ = frame_id;
        let _ = queue_depth;
        let _ = total_frames_decoded;
    }

    /// Called when QoE metrics are received from client (V10+)
    fn on_qoe_metrics(&mut self, _metrics: QoeMetrics) {}

    /// Called when a surface is created
    fn on_surface_created(&mut self, _surface: &Surface) {}

    /// Called when a surface is deleted
    fn on_surface_deleted(&mut self, _surface_id: u16) {}

    /// Called when the EGFX channel is closed
    fn on_close(&mut self) {}

    /// Returns the server's preferred capabilities
    ///
    /// Override this to customize codec support. The default enables
    /// AVC420/AVC444 with V10.7 and V8.1 as fallback.
    fn preferred_capabilities(&self) -> Vec<CapabilitySet> {
        vec![
            CapabilitySet::V10_7 {
                flags: CapabilitiesV107Flags::SMALL_CACHE,
            },
            CapabilitySet::V10 {
                flags: CapabilitiesV10Flags::SMALL_CACHE,
            },
            CapabilitySet::V8_1 {
                flags: CapabilitiesV81Flags::AVC420_ENABLED | CapabilitiesV81Flags::SMALL_CACHE,
            },
            CapabilitySet::V8 {
                flags: CapabilitiesV8Flags::SMALL_CACHE,
            },
        ]
    }

    /// Returns the maximum frames in flight before backpressure
    fn max_frames_in_flight(&self) -> u32 {
        DEFAULT_MAX_FRAMES_IN_FLIGHT
    }

    /// Called when client offers to import cached bitmaps
    ///
    /// Return the list of cache slot IDs to accept.
    /// Default rejects all (returns empty).
    fn on_cache_import_offer(&mut self, _offer: &CacheImportOfferPdu) -> Vec<u16> {
        vec![]
    }
}

// ============================================================================
// Server State Machine
// ============================================================================

/// Server state machine states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerState {
    /// Waiting for client CapabilitiesAdvertise
    WaitingForCapabilities,
    /// Channel is ready, can send frames
    Ready,
    /// Performing a resize operation
    Resizing,
    /// Channel has been closed
    Closed,
}

// ============================================================================
// Graphics Pipeline Server
// ============================================================================

/// Server for the Graphics Pipeline Virtual Channel (EGFX)
///
/// This server handles capability negotiation, surface management,
/// and H.264 frame transmission to RDP clients per MS-RDPEGFX specification.
pub struct GraphicsPipelineServer {
    handler: Box<dyn GraphicsPipelineHandler>,

    state: ServerState,
    negotiated_caps: Option<CapabilitySet>,
    codec_caps: CodecCapabilities,

    surfaces: Surfaces,
    frames: FrameTracker,
    qoe: QoeCollector,

    output_width: u16,
    output_height: u16,
    /// MS-RDPEGFX requires ResetGraphics before any CreateSurface
    reset_graphics_sent: bool,
    output_queue: VecDeque<GfxPdu>,

    /// Stored from DvcProcessor::start() for proactive frame encoding
    channel_id: Option<u32>,

    /// ZGFX compressor state (history buffer shared across frames)
    zgfx_compressor: Compressor,
    /// Whether to compress EGFX output with ZGFX
    compression_mode: CompressionMode,
}

/// Payload for a single tile within a mixed-codec frame.
///
/// Each variant corresponds to a different EGFX codec. Used with
/// [`GraphicsPipelineServer::send_mixed_frame()`] to pack multiple codec
/// types into a single `StartFrame`/`EndFrame` pair.
///
/// Marked `#[non_exhaustive]` so future EGFX codec additions (for example,
/// Avc444 or hardware-accelerated paths) can land without a SemVer break
/// for downstream consumers that pattern-match on this enum.
#[non_exhaustive]
pub enum MixedTilePayload {
    /// Lossless ClearCodec tile (text, UI elements, icons).
    /// `bitmap_data` is a pre-encoded ClearCodec bitmap stream.
    /// `destination` uses `ExclusiveRectangle` to match the spec-defined
    /// `WireToSurface1Pdu.destination_rectangle` field type (MS-RDPEGFX
    /// 2.2.1.4.1: right/bottom are exclusive).
    ClearCodec {
        destination: ExclusiveRectangle,
        bitmap_data: Vec<u8>,
    },
    /// RemoteFX Progressive tile (photos, gradients).
    /// `progressive_data` is a valid progressive block stream.
    RemoteFxProgressive {
        codec_context_id: u32,
        progressive_data: Vec<u8>,
    },
    /// H.264 AVC420 tile (video, high-motion content).
    Avc420 {
        regions: Vec<Avc420Region>,
        h264_data: Vec<u8>,
    },
}

impl GraphicsPipelineServer {
    /// Create a new GraphicsPipelineServer
    pub fn new(handler: Box<dyn GraphicsPipelineHandler>) -> Self {
        let max_frames = handler.max_frames_in_flight();
        let mut frames = FrameTracker::new();
        frames.set_max_in_flight(max_frames);

        Self {
            handler,
            state: ServerState::WaitingForCapabilities,
            negotiated_caps: None,
            codec_caps: CodecCapabilities::default(),
            surfaces: Surfaces::new(),
            frames,
            qoe: QoeCollector::new(),
            output_width: 0,
            output_height: 0,
            reset_graphics_sent: false,
            output_queue: VecDeque::new(),
            channel_id: None,
            zgfx_compressor: Compressor::new(),
            compression_mode: CompressionMode::Never,
        }
    }

    /// Create a server with ZGFX compression enabled for output.
    ///
    /// When `compression_mode` is `Auto` or `Always`, `drain_output()` will
    /// compress PDUs before ZGFX wrapping, reducing bandwidth at the cost
    /// of CPU. The compressor maintains a sliding history window across
    /// frames for back-reference efficiency.
    pub fn with_compression(handler: Box<dyn GraphicsPipelineHandler>, compression_mode: CompressionMode) -> Self {
        let mut server = Self::new(handler);
        server.compression_mode = compression_mode;
        server
    }

    /// Set desktop output dimensions for ResetGraphics.
    ///
    /// Call before `create_surface()` when the desktop size differs from
    /// the surface size (e.g. 16-pixel alignment padding).
    pub fn set_output_dimensions(&mut self, width: u16, height: u16) {
        self.output_width = width;
        self.output_height = height;
    }

    /// DVC channel ID assigned by DRDYNVC.
    ///
    /// Returns `None` before the channel has been started.
    #[must_use]
    pub fn channel_id(&self) -> Option<u32> {
        self.channel_id
    }

    // ========================================================================
    // State Queries
    // ========================================================================

    /// Check if the server is ready to send frames
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.state == ServerState::Ready
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

    /// Check if AVC420 (H.264 4:2:0) is available
    #[must_use]
    pub fn supports_avc420(&self) -> bool {
        self.codec_caps.avc420
    }

    /// Check if AVC444 (H.264 4:4:4) is available
    #[must_use]
    pub fn supports_avc444(&self) -> bool {
        self.codec_caps.avc444
    }

    /// Get the graphics output buffer dimensions
    #[must_use]
    pub fn output_dimensions(&self) -> (u16, u16) {
        (self.output_width, self.output_height)
    }

    // ========================================================================
    // Surface Management
    // ========================================================================

    /// Create a new surface
    ///
    /// Queues CreateSurface PDU and returns the surface ID.
    /// Returns `None` if not ready.
    pub fn create_surface(&mut self, width: u16, height: u16) -> Option<u16> {
        self.create_surface_with_format(width, height, PixelFormat::XRgb)
    }

    /// Create a new surface with specific pixel format
    pub fn create_surface_with_format(&mut self, width: u16, height: u16, pixel_format: PixelFormat) -> Option<u16> {
        if self.state != ServerState::Ready && self.state != ServerState::Resizing {
            return None;
        }

        // MS-RDPEGFX: ResetGraphics MUST precede any CreateSurface.
        // Auto-send on first surface creation if not explicitly sent via resize().
        if !self.reset_graphics_sent {
            let desktop_width = if self.output_width > 0 {
                self.output_width
            } else {
                width
            };
            let desktop_height = if self.output_height > 0 {
                self.output_height
            } else {
                height
            };

            self.output_queue.push_back(GfxPdu::ResetGraphics(ResetGraphicsPdu {
                width: u32::from(desktop_width),
                height: u32::from(desktop_height),
                monitors: Vec::new(),
            }));

            self.output_width = desktop_width;
            self.output_height = desktop_height;
            self.reset_graphics_sent = true;
        }

        let surface_id = self.surfaces.allocate_id();
        let surface = Surface::new(surface_id, width, height, pixel_format);

        self.output_queue.push_back(GfxPdu::CreateSurface(CreateSurfacePdu {
            surface_id,
            width,
            height,
            pixel_format,
        }));

        self.handler.on_surface_created(&surface);
        self.surfaces.insert(surface);

        debug!(surface_id, width, height, ?pixel_format, "Created surface");
        Some(surface_id)
    }

    /// Delete a surface
    ///
    /// Queues DeleteSurface PDU. Returns `false` if surface doesn't exist.
    pub fn delete_surface(&mut self, surface_id: u16) -> bool {
        if self.surfaces.remove(surface_id).is_none() {
            return false;
        }

        self.output_queue
            .push_back(GfxPdu::DeleteSurface(DeleteSurfacePdu { surface_id }));

        self.handler.on_surface_deleted(surface_id);
        debug!(surface_id, "Deleted surface");
        true
    }

    /// Map a surface to the graphics output buffer
    pub fn map_surface_to_output(&mut self, surface_id: u16, origin_x: u32, origin_y: u32) -> bool {
        let Some(surface) = self.surfaces.get_mut(surface_id) else {
            return false;
        };

        surface.is_mapped = true;
        surface.output_origin_x = origin_x;
        surface.output_origin_y = origin_y;

        self.output_queue
            .push_back(GfxPdu::MapSurfaceToOutput(MapSurfaceToOutputPdu {
                surface_id,
                output_origin_x: origin_x,
                output_origin_y: origin_y,
            }));

        debug!(surface_id, origin_x, origin_y, "Mapped surface to output");
        true
    }

    /// Get a surface by ID
    #[must_use]
    pub fn get_surface(&self, surface_id: u16) -> Option<&Surface> {
        self.surfaces.get(surface_id)
    }

    /// Get all surface IDs
    pub fn surface_ids(&self) -> impl Iterator<Item = u16> + '_ {
        self.surfaces.surface_ids()
    }

    // ========================================================================
    // Resize Handling
    // ========================================================================

    /// Resize the graphics output buffer
    ///
    /// This initiates a resize sequence:
    /// 1. Sends ResetGraphics with new dimensions
    /// 2. Deletes existing surfaces
    /// 3. Transitions to Ready state
    ///
    /// After calling this, create new surfaces for the new dimensions.
    pub fn resize(&mut self, width: u16, height: u16) {
        self.resize_with_monitors(width, height, Vec::new());
    }

    /// Resize with explicit monitor configuration
    pub fn resize_with_monitors(&mut self, width: u16, height: u16, monitors: Vec<Monitor>) {
        if self.state != ServerState::Ready {
            debug!("Cannot resize: not in Ready state");
            return;
        }

        // RDPGFX_RESET_GRAPHICS_PDU is fixed at 340 bytes, limiting to 16 monitors.
        if monitors.len() > 16 {
            warn!(
                count = monitors.len(),
                "Too many monitors for ResetGraphicsPdu (max 16)"
            );
            return;
        }

        debug!(width, height, monitors = monitors.len(), "Initiating resize");

        self.state = ServerState::Resizing;
        self.output_width = width;
        self.output_height = height;

        let surface_ids: Vec<_> = self.surfaces.surface_ids().collect();
        for id in surface_ids {
            self.delete_surface(id);
        }

        self.frames.clear();

        self.output_queue.push_back(GfxPdu::ResetGraphics(ResetGraphicsPdu {
            width: u32::from(width),
            height: u32::from(height),
            monitors,
        }));

        self.reset_graphics_sent = true;
        self.state = ServerState::Ready;
    }

    // ========================================================================
    // Flow Control
    // ========================================================================

    /// Check if backpressure should be applied
    ///
    /// Returns `true` if too many frames are in flight and the caller
    /// should drop or delay new frames.
    #[must_use]
    pub fn should_backpressure(&self) -> bool {
        self.frames.should_backpressure()
    }

    /// Get the number of frames currently in flight (awaiting ACK)
    #[must_use]
    pub fn frames_in_flight(&self) -> u32 {
        self.frames.in_flight()
    }

    /// Get the last reported client queue depth
    #[must_use]
    pub fn client_queue_depth(&self) -> u32 {
        self.frames.client_queue_depth()
    }

    /// Set the maximum frames in flight before backpressure
    pub fn set_max_frames_in_flight(&mut self, max: u32) {
        self.frames.set_max_in_flight(max);
    }

    // ========================================================================
    // QoE Statistics
    // ========================================================================

    /// Get a snapshot of accumulated Quality of Experience statistics.
    ///
    /// Returns `None` if no QoE reports have been received and no
    /// round-trip latency samples have been measured.
    ///
    /// QoE reports are sent by clients that support [2.2.2.13] QoE Frame
    /// Acknowledge PDUs (V10.4+). Round-trip latency is measured for all
    /// EGFX versions from frame send to acknowledgment.
    ///
    /// [2.2.2.13]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/40c1ada9-db39-407b-a760-fca4b3e9cc35
    #[must_use]
    pub fn qoe_snapshot(&self) -> Option<QoeSnapshot> {
        if self.qoe.total_reports == 0 && self.qoe.total_rtt_samples == 0 {
            return None;
        }
        Some(self.qoe.snapshot())
    }

    /// Reset accumulated QoE statistics.
    ///
    /// Useful when starting a new measurement window (e.g., after a resize).
    pub fn reset_qoe(&mut self) {
        self.qoe.clear();
    }

    // ========================================================================
    // Frame Sending
    // ========================================================================

    /// Convert timestamp in milliseconds to Timestamp struct
    #[expect(
        clippy::as_conversions,
        reason = "arithmetic results bounded and fit in target types"
    )]
    fn make_timestamp(timestamp_ms: u32) -> Timestamp {
        Timestamp {
            milliseconds: (timestamp_ms % 1000) as u16,
            seconds: ((timestamp_ms / 1000) % 60) as u8,
            minutes: ((timestamp_ms / 60000) % 60) as u8,
            hours: ((timestamp_ms / 3600000) % 24) as u16,
        }
    }

    /// Compute bounding rectangle from regions.
    ///
    /// Avc420Region uses inclusive bounds; the wire format (RDPGFX_RECT16) is
    /// exclusive, so the returned ExclusiveRectangle adds 1 to the max right
    /// and bottom of the inclusive bounding box.
    fn compute_dest_rect(regions: &[Avc420Region], default_width: u16, default_height: u16) -> ExclusiveRectangle {
        if let Some(first) = regions.first() {
            let mut left = first.left;
            let mut top = first.top;
            let mut right = first.right;
            let mut bottom = first.bottom;

            for r in regions.iter().skip(1) {
                left = left.min(r.left);
                top = top.min(r.top);
                right = right.max(r.right);
                bottom = bottom.max(r.bottom);
            }

            ExclusiveRectangle {
                left,
                top,
                right: right.saturating_add(1),
                bottom: bottom.saturating_add(1),
            }
        } else {
            ExclusiveRectangle {
                left: 0,
                top: 0,
                right: default_width,
                bottom: default_height,
            }
        }
    }

    /// Queue an H.264 AVC420 frame for transmission
    ///
    /// Returns `Some(frame_id)` if queued, `None` if backpressure is active,
    /// server not ready, or AVC420 not supported.
    pub fn send_avc420_frame(
        &mut self,
        surface_id: u16,
        h264_data: &[u8],
        regions: &[Avc420Region],
        timestamp_ms: u32,
    ) -> Option<u32> {
        if !self.is_ready() {
            return None;
        }
        if !self.supports_avc420() {
            return None;
        }
        if self.should_backpressure() {
            self.qoe.record_backpressure();
            return None;
        }

        let surface = self.surfaces.get(surface_id)?;

        let timestamp = Self::make_timestamp(timestamp_ms);
        let frame_id = self.frames.begin_frame(timestamp);

        let encoded_stream = encode_avc420_bitmap_stream(regions, h264_data);
        let target_rect = Self::compute_dest_rect(regions, surface.width, surface.height);

        // MS-RDPEGFX requires three-PDU sequence per frame
        self.output_queue
            .push_back(GfxPdu::StartFrame(StartFramePdu { timestamp, frame_id }));

        self.output_queue.push_back(GfxPdu::WireToSurface1(WireToSurface1Pdu {
            surface_id,
            codec_id: Codec1Type::Avc420,
            pixel_format: surface.pixel_format,
            destination_rectangle: target_rect,
            bitmap_data: encoded_stream,
        }));

        self.output_queue.push_back(GfxPdu::EndFrame(EndFramePdu { frame_id }));

        Some(frame_id)
    }

    /// Queue an H.264 AVC444 frame for transmission
    ///
    /// AVC444 uses two streams: luma (Y) and chroma (UV). Set `chroma_data` to
    /// `None` for luma-only transmission.
    ///
    /// Returns `Some(frame_id)` if queued, `None` if not supported or backpressured.
    pub fn send_avc444_frame(
        &mut self,
        surface_id: u16,
        luma_data: &[u8],
        luma_regions: &[Avc420Region],
        chroma_data: Option<&[u8]>,
        chroma_regions: Option<&[Avc420Region]>,
        timestamp_ms: u32,
    ) -> Option<u32> {
        if !self.is_ready() {
            return None;
        }
        if !self.supports_avc444() {
            return None;
        }
        if self.should_backpressure() {
            self.qoe.record_backpressure();
            return None;
        }

        let surface = self.surfaces.get(surface_id)?;

        let timestamp = Self::make_timestamp(timestamp_ms);
        let frame_id = self.frames.begin_frame(timestamp);

        let luma_rectangles: Vec<_> = luma_regions.iter().map(Avc420Region::to_rectangle).collect();
        let luma_quant_vals: Vec<_> = luma_regions.iter().map(Avc420Region::to_quant_quality).collect();

        let stream1 = Avc420BitmapStream {
            rectangles: luma_rectangles,
            quant_qual_vals: luma_quant_vals,
            data: luma_data,
        };

        let (encoding, stream2) = if let (Some(chroma), Some(chroma_regs)) = (chroma_data, chroma_regions) {
            let chroma_rectangles: Vec<_> = chroma_regs.iter().map(Avc420Region::to_rectangle).collect();
            let chroma_quant_vals: Vec<_> = chroma_regs.iter().map(Avc420Region::to_quant_quality).collect();

            (
                Encoding::LUMA_AND_CHROMA,
                Some(Avc420BitmapStream {
                    rectangles: chroma_rectangles,
                    quant_qual_vals: chroma_quant_vals,
                    data: chroma,
                }),
            )
        } else {
            (Encoding::LUMA, None)
        };

        let avc444_stream = Avc444BitmapStream {
            encoding,
            stream1,
            stream2,
        };

        let encoded_stream = encode_avc444_bitmap_stream(&avc444_stream);
        let target_rect = Self::compute_dest_rect(luma_regions, surface.width, surface.height);

        self.output_queue
            .push_back(GfxPdu::StartFrame(StartFramePdu { timestamp, frame_id }));

        self.output_queue.push_back(GfxPdu::WireToSurface1(WireToSurface1Pdu {
            surface_id,
            codec_id: Codec1Type::Avc444,
            pixel_format: surface.pixel_format,
            destination_rectangle: target_rect,
            bitmap_data: encoded_stream,
        }));

        self.output_queue.push_back(GfxPdu::EndFrame(EndFramePdu { frame_id }));

        Some(frame_id)
    }

    /// Queue an uncompressed bitmap frame for transmission via EGFX
    ///
    /// Sends raw pixel data through `WireToSurface1` with `Codec1Type::Uncompressed`.
    /// Used for V8 clients that support EGFX but not H.264 (AVC420/AVC444).
    ///
    /// The `bitmap_data` should be in the surface's pixel format (typically XRGB).
    ///
    /// Returns `Some(frame_id)` if queued, `None` if not ready or backpressured.
    pub fn send_uncompressed_frame(
        &mut self,
        surface_id: u16,
        bitmap_data: &[u8],
        dest_width: u16,
        dest_height: u16,
        timestamp_ms: u32,
    ) -> Option<u32> {
        if !self.is_ready() {
            return None;
        }
        if self.should_backpressure() {
            self.qoe.record_backpressure();
            return None;
        }

        let surface = self.surfaces.get(surface_id)?;

        let timestamp = Self::make_timestamp(timestamp_ms);
        let frame_id = self.frames.begin_frame(timestamp);

        let dest_rect = ExclusiveRectangle {
            left: 0,
            top: 0,
            right: dest_width,
            bottom: dest_height,
        };

        self.output_queue
            .push_back(GfxPdu::StartFrame(StartFramePdu { timestamp, frame_id }));

        self.output_queue.push_back(GfxPdu::WireToSurface1(WireToSurface1Pdu {
            surface_id,
            codec_id: Codec1Type::Uncompressed,
            pixel_format: surface.pixel_format,
            destination_rectangle: dest_rect,
            bitmap_data: bitmap_data.to_vec(),
        }));

        self.output_queue.push_back(GfxPdu::EndFrame(EndFramePdu { frame_id }));

        Some(frame_id)
    }

    /// Queue a RemoteFX Progressive frame for transmission.
    ///
    /// Progressive frames use `WireToSurface2Pdu` with a pre-encoded progressive
    /// block stream as the bitmap payload. The `codec_context_id` associates
    /// this data with persistent tile state on the client.
    ///
    /// The `progressive_data` must be a valid progressive block stream
    /// (SYNC + CONTEXT + FRAME_BEGIN + REGION + FRAME_END) as produced by
    /// `ironrdp_pdu::codecs::rfx::progressive::encode_progressive_stream()`.
    ///
    /// Returns `Some(frame_id)` if queued, `None` if not ready or backpressured.
    pub fn send_remotefx_progressive_frame(
        &mut self,
        surface_id: u16,
        codec_context_id: u32,
        progressive_data: Vec<u8>,
        timestamp_ms: u32,
    ) -> Option<u32> {
        if !self.is_ready() {
            return None;
        }
        if self.should_backpressure() {
            return None;
        }

        let surface = self.surfaces.get(surface_id)?;

        let timestamp = Self::make_timestamp(timestamp_ms);
        let frame_id = self.frames.begin_frame(timestamp);

        self.output_queue
            .push_back(GfxPdu::StartFrame(StartFramePdu { timestamp, frame_id }));

        self.output_queue.push_back(GfxPdu::WireToSurface2(WireToSurface2Pdu {
            surface_id,
            codec_id: Codec2Type::RemoteFxProgressive,
            codec_context_id,
            pixel_format: surface.pixel_format,
            bitmap_data: progressive_data,
        }));

        self.output_queue.push_back(GfxPdu::EndFrame(EndFramePdu { frame_id }));

        Some(frame_id)
    }

    // ========================================================================
    // Mixed-Codec Frame Support
    // ========================================================================

    /// Queue a mixed-codec frame containing tiles encoded with different codecs.
    ///
    /// This is the core of multi-codec EGFX: a single frame update can contain
    /// ClearCodec tiles (lossless text), Progressive tiles (photos), and H.264
    /// tiles (video), all sent between one `StartFrame`/`EndFrame` pair.
    ///
    /// This matches how Azure VDI achieves its visual quality — each tile uses
    /// the codec best suited to its content type.
    ///
    /// Returns `Some(frame_id)` if queued, `None` if not ready or backpressured.
    pub fn send_mixed_frame(
        &mut self,
        surface_id: u16,
        tiles: Vec<MixedTilePayload>,
        timestamp_ms: u32,
    ) -> Option<u32> {
        if !self.is_ready() {
            return None;
        }
        if self.should_backpressure() {
            return None;
        }
        if tiles.is_empty() {
            return None;
        }

        let surface = self.surfaces.get(surface_id)?;
        let pixel_format = surface.pixel_format;

        let timestamp = Self::make_timestamp(timestamp_ms);
        let frame_id = self.frames.begin_frame(timestamp);

        self.output_queue
            .push_back(GfxPdu::StartFrame(StartFramePdu { timestamp, frame_id }));

        for tile in tiles {
            match tile {
                MixedTilePayload::ClearCodec {
                    destination,
                    bitmap_data,
                } => {
                    self.output_queue.push_back(GfxPdu::WireToSurface1(WireToSurface1Pdu {
                        surface_id,
                        codec_id: Codec1Type::ClearCodec,
                        pixel_format,
                        destination_rectangle: destination,
                        bitmap_data,
                    }));
                }
                MixedTilePayload::RemoteFxProgressive {
                    codec_context_id,
                    progressive_data,
                } => {
                    self.output_queue.push_back(GfxPdu::WireToSurface2(WireToSurface2Pdu {
                        surface_id,
                        codec_id: Codec2Type::RemoteFxProgressive,
                        codec_context_id,
                        pixel_format,
                        bitmap_data: progressive_data,
                    }));
                }
                MixedTilePayload::Avc420 { regions, h264_data } => {
                    let encoded_stream = encode_avc420_bitmap_stream(&regions, &h264_data);
                    let target_rect = Self::compute_dest_rect(&regions, surface.width, surface.height);

                    self.output_queue.push_back(GfxPdu::WireToSurface1(WireToSurface1Pdu {
                        surface_id,
                        codec_id: Codec1Type::Avc420,
                        pixel_format,
                        destination_rectangle: target_rect,
                        bitmap_data: encoded_stream,
                    }));
                }
            }
        }

        self.output_queue.push_back(GfxPdu::EndFrame(EndFramePdu { frame_id }));

        Some(frame_id)
    }

    // ========================================================================
    // Output Management
    // ========================================================================

    /// Drain the output queue, ZGFX-wrapping each PDU for DVC transmission.
    ///
    /// Each `GfxPdu` is encoded to bytes then wrapped in uncompressed ZGFX
    /// segment format. Windows clients expect this wrapping on the EGFX DVC.
    ///
    /// # Panics
    ///
    /// Panics if a `GfxPdu` fails to encode. This indicates a bug in the PDU
    /// encoding logic, not a runtime condition.
    #[expect(clippy::as_conversions, reason = "Box<T> to Box<dyn Trait> coercion")]
    pub fn drain_output(&mut self) -> Vec<DvcMessage> {
        let mode = self.compression_mode;
        let pdus: Vec<_> = self.output_queue.drain(..).collect();

        pdus.into_iter()
            .map(|pdu| {
                let pdu_name = pdu.name();
                let pdu_size = pdu.size();
                let mut pdu_bytes = vec![0u8; pdu_size];
                let mut cursor = WriteCursor::new(&mut pdu_bytes);
                pdu.encode(&mut cursor).expect("GfxPdu encoding should not fail");

                let wrapped = match mode {
                    CompressionMode::Never => wrap_uncompressed(&pdu_bytes),
                    _ => compress_and_wrap_egfx(&pdu_bytes, &mut self.zgfx_compressor, mode)
                        .unwrap_or_else(|_| wrap_uncompressed(&pdu_bytes)),
                };
                trace!(pdu_name, pdu_size, wrapped = wrapped.len(), mode = ?mode, "ZGFX output");

                Box::new(ZgfxWrappedBytes {
                    bytes: wrapped,
                    pdu_name,
                }) as DvcMessage
            })
            .collect()
    }

    /// Check if there are pending PDUs to send
    #[must_use]
    pub fn has_pending_output(&self) -> bool {
        !self.output_queue.is_empty()
    }

    // ========================================================================
    // Internal Message Handlers
    // ========================================================================

    fn handle_capabilities_advertise(&mut self, pdu: CapabilitiesAdvertisePdu) {
        self.handler.capabilities_advertise(&pdu);
        let server_caps = self.handler.preferred_capabilities();

        // Parse client raw caps into typed. Silently skip unknown versions for
        // negotiation purposes (the raw form is still observable in `pdu`), but
        // treat parse failures for known versions as malformed input instead of
        // negotiating as if the client never advertised them.
        let mut client_caps = Vec::with_capacity(pdu.0.len());
        for raw in &pdu.0 {
            match raw.parsed() {
                Ok(Some(cap)) => client_caps.push(cap),
                Ok(None) => {}
                Err(e) => {
                    warn!(error = ?e, "Received malformed client capability set; aborting capability negotiation");
                    return;
                }
            }
        }

        // When no version overlaps with server preferences, confirm the client's
        // highest-priority capability to avoid confirming a version the client
        // did not advertise.
        let negotiated = negotiate_capabilities(&client_caps, &server_caps).unwrap_or_else(|| {
            warn!("No capability match with server preferences, selecting client's highest version");
            let mut client_sorted = client_caps.clone();
            client_sorted.sort_by_key(|cap| core::cmp::Reverse(capability_priority(cap)));
            client_sorted.into_iter().next().unwrap_or(CapabilitySet::V8 {
                flags: CapabilitiesV8Flags::empty(),
            })
        });

        self.codec_caps = CodecCapabilities::from_capability_set(&negotiated);
        self.state = ServerState::Ready;
        let negotiated = self.negotiated_caps.insert(negotiated);

        self.output_queue
            .push_back(GfxPdu::CapabilitiesConfirm(CapabilitiesConfirmPdu::from_typed(
                negotiated,
            )));

        self.handler.on_ready(negotiated);
    }

    fn handle_frame_acknowledge(&mut self, pdu: FrameAcknowledgePdu) {
        let queue_depth = pdu.queue_depth.to_u32();

        if let Some(info) = self.frames.acknowledge(pdu.frame_id, queue_depth) {
            let rtt = info.sent_at.elapsed();
            self.qoe.record_rtt(rtt);
            self.qoe.record_frame_ack(info.size_bytes);
            trace!(frame_id = pdu.frame_id, latency = ?rtt);
        }

        self.handler
            .on_frame_ack(pdu.frame_id, queue_depth, pdu.total_frames_decoded);
    }

    fn handle_qoe_frame_acknowledge(&mut self, pdu: QoeFrameAcknowledgePdu) {
        let metrics = QoeMetrics {
            frame_id: pdu.frame_id,
            timestamp: pdu.timestamp,
            time_diff_se: pdu.time_diff_se,
            time_diff_dr: pdu.time_diff_dr,
        };

        self.qoe.record_qoe(&metrics);
        self.handler.on_qoe_metrics(metrics);
    }

    fn handle_cache_import_offer(&mut self, pdu: CacheImportOfferPdu) {
        let accepted = self.handler.on_cache_import_offer(&pdu);

        self.output_queue
            .push_back(GfxPdu::CacheImportReply(CacheImportReplyPdu { cache_slots: accepted }));
    }
}

impl_as_any!(GraphicsPipelineServer);

impl DvcProcessor for GraphicsPipelineServer {
    fn channel_name(&self) -> &str {
        CHANNEL_NAME
    }

    fn start(&mut self, channel_id: u32) -> PduResult<Vec<DvcMessage>> {
        self.channel_id = Some(channel_id);
        debug!(channel_id, "EGFX channel started");
        Ok(vec![])
    }

    fn close(&mut self, _channel_id: u32) {
        debug!("EGFX channel closed");
        self.state = ServerState::Closed;
        self.reset_graphics_sent = false;
        self.handler.on_close();
    }

    fn process(&mut self, _channel_id: u32, payload: &[u8]) -> PduResult<Vec<DvcMessage>> {
        let pdu = decode(payload).map_err(|e| decode_err!(e))?;

        match pdu {
            GfxPdu::CapabilitiesAdvertise(pdu) => {
                self.handle_capabilities_advertise(pdu);
            }
            GfxPdu::FrameAcknowledge(pdu) => {
                self.handle_frame_acknowledge(pdu);
            }
            GfxPdu::QoeFrameAcknowledge(pdu) => {
                self.handle_qoe_frame_acknowledge(pdu);
            }
            GfxPdu::CacheImportOffer(pdu) => {
                self.handle_cache_import_offer(pdu);
            }
            _ => {
                warn!(?pdu, "Unhandled client GFX PDU");
            }
        }

        Ok(self.drain_output())
    }
}

impl DvcServerProcessor for GraphicsPipelineServer {}

// ============================================================================
// AVC444 Encoding Helper
// ============================================================================

/// Encode an AVC444 bitmap stream to bytes
fn encode_avc444_bitmap_stream(stream: &Avc444BitmapStream<'_>) -> Vec<u8> {
    use ironrdp_pdu::Encode as _;

    let size = stream.size();
    let mut buf = vec![0u8; size];
    let mut cursor = WriteCursor::new(&mut buf);

    stream
        .encode(&mut cursor)
        .expect("encode_avc444_bitmap_stream: encoding failed");

    buf
}
