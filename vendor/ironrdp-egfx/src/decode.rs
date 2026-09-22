//! Codec decoder traits for client-side EGFX processing
//!
//! This module provides pluggable decoder traits that allow consumers
//! to bring their own codec implementations (e.g., openh264, ffmpeg,
//! hardware decoders). The traits are designed for core tier: no I/O,
//! `Send` only. They are intended for use in `std` environments;
//! `no_std` + `alloc` support is not currently guaranteed.
//!
//! # Protocol Context
//!
//! H.264 data arrives inside [RFX_AVC420_BITMAP_STREAM][1] payloads
//! within `RDPGFX_WIRE_TO_SURFACE_PDU_1` messages. The NAL units
//! are in AVC format (4-byte big-endian length prefix per NAL unit),
//! not Annex B (start code prefix).
//!
//! [1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/d65c3f9c-2088-4302-90c0-53adc0e11a78

use core::fmt;

// ============================================================================
// Decoded Frame
// ============================================================================

/// Decoded bitmap frame from an H.264 decoder
///
/// Contains RGBA pixel data for a decoded H.264 frame.
/// The pixel data is in RGBA format (4 bytes per pixel),
/// row-major, top-to-bottom, left-to-right.
#[derive(Clone)]
#[non_exhaustive]
pub struct DecodedFrame {
    data: Vec<u8>,
    width: u32,
    height: u32,
}

impl DecodedFrame {
    #[expect(
        clippy::as_conversions,
        reason = "usize to u64 is lossless on all supported platforms (32/64-bit)"
    )]
    pub fn new(data: Vec<u8>, width: u32, height: u32) -> Self {
        debug_assert_eq!(
            data.len() as u64,
            u64::from(width).saturating_mul(u64::from(height)).saturating_mul(4),
            "DecodedFrame buffer must be RGBA8888 (width * height * 4 bytes)",
        );
        Self { data, width, height }
    }

    /// RGBA pixel data (4 bytes per pixel).
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Frame width in pixels.
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Frame height in pixels.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Consume the frame and return the owned RGBA buffer.
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }
}

impl fmt::Debug for DecodedFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecodedFrame")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("data_len", &self.data.len())
            .finish()
    }
}

// ============================================================================
// Decoder Error
// ============================================================================

/// Error type for decoder operations
#[derive(Debug)]
#[non_exhaustive]
pub struct DecoderError {
    context: String,
    source: Option<Box<dyn core::error::Error + Send + Sync>>,
}

impl DecoderError {
    /// Create a decoder error with a source error
    pub fn new(context: impl Into<String>, source: impl core::error::Error + Send + Sync + 'static) -> Self {
        Self {
            context: context.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Create a decoder error with only a message
    pub fn msg(context: impl Into<String>) -> Self {
        Self {
            context: context.into(),
            source: None,
        }
    }
}

impl fmt::Display for DecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "decoder error: {}", self.context)?;
        if let Some(ref source) = self.source {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}

impl core::error::Error for DecoderError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        self.source.as_deref().map(|e| {
            let err: &(dyn core::error::Error + 'static) = e;
            err
        })
    }
}

/// Result type for decoder operations
pub type DecoderResult<T> = Result<T, DecoderError>;

// ============================================================================
// H.264 Decoder Trait
// ============================================================================

/// Trait for H.264 (AVC) decoders
///
/// Implement this trait to provide H.264 decode capability to the
/// EGFX client. The decoder receives AVC-format NAL units (length-prefixed,
/// not Annex B) from `RFX_AVC420_BITMAP_STREAM` payloads.
///
/// # Thread Safety
///
/// Implementations must be `Send` to work with the DVC framework.
///
/// # Example
///
/// ```ignore
/// use ironrdp_egfx::decode::{H264Decoder, DecodedFrame, DecoderResult};
///
/// struct MyH264Decoder { /* ... */ }
///
/// impl H264Decoder for MyH264Decoder {
///     fn decode(&mut self, data: &[u8]) -> DecoderResult<DecodedFrame> {
///         // Decode H.264 NAL units to RGBA
///         todo!()
///     }
/// }
/// ```
pub trait H264Decoder: Send {
    /// Decode AVC-format H.264 NAL units (4-byte BE length prefix, not Annex B)
    /// into an RGBA bitmap.
    ///
    /// Frame dimensions may exceed the destination rectangle due to
    /// macroblock alignment (16x16). The caller crops to fit.
    fn decode(&mut self, data: &[u8]) -> DecoderResult<DecodedFrame>;

    /// Reset the decoder state
    ///
    /// Called when surfaces are reset (e.g., on `ResetGraphics`).
    /// The decoder should drop any internal state and prepare for
    /// a new stream.
    fn reset(&mut self) {
        // Default: no-op
    }
}

// ============================================================================
// OpenH264 Implementation
// ============================================================================

#[cfg(feature = "openh264")]
mod openh264_impl {
    use tracing::warn;

    use super::{DecodedFrame, DecoderError, DecoderResult, H264Decoder};

    /// H.264 decoder backed by Cisco's OpenH264 library
    ///
    /// This decoder converts AVC-format NAL units to Annex B format
    /// (as required by OpenH264), decodes to YUV420p, then converts
    /// to RGBA for the client pipeline.
    ///
    /// # Feature Gates
    ///
    /// Two construction paths are available depending on the feature flags:
    ///
    /// - `openh264-bundled`: compiles OpenH264 from source at build time.
    ///   Use [`OpenH264Decoder::new()`] to construct.
    ///
    /// - `openh264-libloading`: loads a prebuilt Cisco OpenH264 binary at
    ///   runtime. Use [`OpenH264Decoder::from_library_path()`] to construct.
    ///   The library is verified against known Cisco release hashes.
    pub struct OpenH264Decoder {
        decoder: openh264::decoder::Decoder,
        annex_b_buffer: Vec<u8>,
    }

    impl OpenH264Decoder {
        /// Create a decoder using the bundled (source-compiled) OpenH264 library
        ///
        /// This compiles OpenH264 C code at build time. The resulting binary
        /// has no patent coverage from Cisco's license agreement.
        #[cfg(feature = "openh264-bundled")]
        pub fn new() -> DecoderResult<Self> {
            let decoder = openh264::decoder::Decoder::new()
                .map_err(|e| DecoderError::new("failed to create OpenH264 decoder", e))?;

            Ok(Self {
                decoder,
                annex_b_buffer: Vec::new(),
            })
        }

        /// Create a decoder using a dynamically loaded OpenH264 library
        ///
        /// `library_path` should point to a Cisco OpenH264 prebuilt binary,
        /// which is verified against known Cisco release hashes before loading.
        /// Cisco's prebuilt binaries carry patent coverage under their license.
        #[cfg(feature = "openh264-libloading")]
        pub fn from_library_path(library_path: &std::path::Path) -> DecoderResult<Self> {
            let api = openh264::OpenH264API::from_blob_path(library_path)
                .map_err(|e| DecoderError::new("failed to load OpenH264 library", e))?;
            let decoder = openh264::decoder::Decoder::with_api_config(api, Default::default())
                .map_err(|e| DecoderError::new("failed to create OpenH264 decoder", e))?;

            Ok(Self {
                decoder,
                annex_b_buffer: Vec::new(),
            })
        }

        /// Convert AVC format (4-byte BE length prefix) to Annex B (start codes)
        fn avc_to_annex_b(&mut self, data: &[u8]) {
            self.annex_b_buffer.clear();
            let mut offset = 0;

            while offset + 4 <= data.len() {
                let nal_len = u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);

                #[expect(clippy::as_conversions, reason = "NAL length from wire format")]
                let nal_len = nal_len as usize;
                offset += 4;

                // Use checked addition to prevent overflow on malicious input
                let Some(end) = offset.checked_add(nal_len) else {
                    warn!(nal_len, offset, "AVC NAL length overflow, discarding remaining data");
                    break;
                };
                if end > data.len() {
                    warn!(
                        nal_len,
                        offset,
                        data_len = data.len(),
                        "AVC NAL extends beyond buffer, discarding remaining data"
                    );
                    break;
                }

                // Annex B start code
                self.annex_b_buffer.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
                self.annex_b_buffer.extend_from_slice(&data[offset..offset + nal_len]);
                offset += nal_len;
            }
        }
    }

    impl H264Decoder for OpenH264Decoder {
        fn decode(&mut self, data: &[u8]) -> DecoderResult<DecodedFrame> {
            self.avc_to_annex_b(data);

            let yuv = self
                .decoder
                .decode(&self.annex_b_buffer)
                .map_err(|e| DecoderError::new("OpenH264 decode failed", e))?
                .ok_or_else(|| DecoderError::msg("OpenH264 returned no picture"))?;

            let (width, height) = openh264::formats::YUVSource::dimensions(&yuv);

            #[expect(
                clippy::as_conversions,
                clippy::cast_possible_truncation,
                reason = "H.264 frame dimensions are always within u32 range"
            )]
            let (w32, h32) = (width as u32, height as u32);

            let rgba_size = width
                .checked_mul(height)
                .and_then(|s| s.checked_mul(4))
                .ok_or_else(|| DecoderError::msg("frame dimensions too large for RGBA allocation"))?;
            let mut rgba = vec![0u8; rgba_size];
            yuv.write_rgba8(&mut rgba);

            Ok(DecodedFrame::new(rgba, w32, h32))
        }

        fn reset(&mut self) {
            // Recreate decoder from source when available
            #[cfg(feature = "openh264-bundled")]
            match openh264::decoder::Decoder::new() {
                Ok(new_decoder) => self.decoder = new_decoder,
                Err(e) => warn!("Failed to reset OpenH264 decoder, reusing existing state: {e}"),
            }
            // In libloading-only mode, we don't have the library path stored,
            // so we can't recreate. The existing decoder handles new SPS/PPS
            // transparently when the next I-frame arrives.
        }
    }
}

#[cfg(feature = "openh264")]
pub use openh264_impl::OpenH264Decoder;

#[cfg(test)]
mod tests {
    use super::DecodedFrame;

    #[test]
    fn getters_return_constructor_inputs() {
        let data = vec![0u8; 2 * 3 * 4];
        let frame = DecodedFrame::new(data.clone(), 2, 3);
        assert_eq!(frame.data(), data.as_slice());
        assert_eq!(frame.width(), 2);
        assert_eq!(frame.height(), 3);
    }

    #[test]
    fn into_data_yields_owned_buffer() {
        let data = vec![0xAAu8; 4 * 4 * 4];
        let frame = DecodedFrame::new(data.clone(), 4, 4);
        assert_eq!(frame.into_data(), data);
    }
}
