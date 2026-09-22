//! Server-side H.264 encoding for the graphics pipeline.
//!
//! This module is the encode-side twin of [`crate::decode`]: it defines the
//! [`H264Encoder`] trait that servers implement (or plug a backend into) to
//! produce the H.264 payloads consumed by
//! `GraphicsPipelineServer::send_avc420_frame`, plus an optional
//! OpenH264-backed reference implementation behind the `openh264` feature.

use core::fmt;

// ============================================================================
// Encoder Input
// ============================================================================

/// A borrowed RGBA frame handed to an H.264 encoder.
///
/// The buffer is tightly packed RGBA8888, `width * height * 4` bytes, matching
/// the pixel layout [`crate::decode::DecodedFrame`] produces on the decode
/// side. Both dimensions must be even (H.264 4:2:0 chroma subsampling);
/// callers typically pad to 16-pixel macroblock alignment and let the
/// destination rectangle crop, exactly as the decode side does in reverse.
#[derive(Clone, Copy)]
pub struct EncodeFrame<'a> {
    /// Tightly packed RGBA8888 pixel data, `width * height * 4` bytes.
    pub data: &'a [u8],
    /// Frame width in pixels. Must be even.
    pub width: u32,
    /// Frame height in pixels. Must be even.
    pub height: u32,
}

impl fmt::Debug for EncodeFrame<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncodeFrame")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("data_len", &self.data.len())
            .finish()
    }
}

/// Result type for encoder operations
pub type EncoderResult<T> = Result<T, EncoderError>;

// ============================================================================
// H.264 Encoder Trait
// ============================================================================

/// Trait for H.264 (AVC) encoders
///
/// Implement this trait to provide H.264 encode capability to an EGFX
/// server. The encoder produces an ITU-T H.264 Annex B bitstream (start
/// codes, with SPS/PPS emitted in-band on IDR frames), which is the format
/// `RFX_AVC420_BITMAP_STREAM` carries on the wire ([MS-RDPEGFX] 2.2.4.4)
/// and which `GraphicsPipelineServer::send_avc420_frame` forwards
/// unmodified.
///
/// # Thread Safety
///
/// Implementations must be `Send` to cross the server's task boundaries.
///
/// # Example
///
/// ```ignore
/// use ironrdp_egfx::encode::{EncodeFrame, EncoderResult, H264Encoder};
///
/// struct MyH264Encoder { /* ... */ }
///
/// impl H264Encoder for MyH264Encoder {
///     fn encode(&mut self, frame: EncodeFrame<'_>) -> EncoderResult<Vec<u8>> {
///         // Encode RGBA to an Annex B H.264 bitstream
///         todo!()
///     }
/// }
/// ```
pub trait H264Encoder: Send {
    /// Encode one RGBA frame into an ITU-T H.264 Annex B bitstream.
    ///
    /// The returned bytes are ready for
    /// `GraphicsPipelineServer::send_avc420_frame`. An empty return value is
    /// valid and means the encoder produced no output for this frame (some
    /// backends skip unchanged input); callers should simply not send a
    /// frame in that case.
    fn encode(&mut self, frame: EncodeFrame<'_>) -> EncoderResult<Vec<u8>>;

    /// Request that the next encoded frame is an IDR (key) frame.
    ///
    /// Servers call this when the client needs a clean decode entry point,
    /// for example after a mid-session capability re-advertise or when a new
    /// consumer attaches. The default is a no-op for backends without
    /// key-frame control.
    fn request_key_frame(&mut self) {
        // Default: no-op
    }

    /// Reset the encoder state
    ///
    /// Called when surfaces are reset (e.g., on `ResetGraphics`). The
    /// encoder should drop temporal references so the next frame decodes
    /// without prior state.
    fn reset(&mut self) {
        // Default: no-op
    }
}

// ============================================================================
// OpenH264 Implementation
// ============================================================================

#[cfg(feature = "openh264")]
mod openh264_impl {
    use super::{EncodeFrame, EncoderError, EncoderResult, H264Encoder};

    /// H.264 encoder backed by Cisco's OpenH264 library
    ///
    /// This encoder converts RGBA input to YUV 4:2:0 and produces an Annex B
    /// bitstream with in-band SPS/PPS, suitable for
    /// `GraphicsPipelineServer::send_avc420_frame` as-is.
    ///
    /// # Feature Gates
    ///
    /// Two construction paths are available depending on the feature flags:
    ///
    /// - `openh264-bundled`: compiles OpenH264 from source at build time.
    ///   Use [`OpenH264Encoder::new()`] to construct.
    ///
    /// - `openh264-libloading`: loads a prebuilt Cisco OpenH264 binary at
    ///   runtime. Use [`OpenH264Encoder::from_library_path()`] to construct.
    ///   The library is verified against known Cisco release hashes.
    pub struct OpenH264Encoder {
        encoder: openh264::encoder::Encoder,
    }

    impl OpenH264Encoder {
        /// Create an encoder using the bundled (source-compiled) OpenH264 library
        ///
        /// This compiles OpenH264 C code at build time. The resulting binary
        /// has no patent coverage from Cisco's license agreement.
        #[cfg(feature = "openh264-bundled")]
        pub fn new() -> EncoderResult<Self> {
            let encoder = openh264::encoder::Encoder::new()
                .map_err(|e| EncoderError::new("failed to create OpenH264 encoder", e))?;

            Ok(Self { encoder })
        }

        /// Create an encoder using a dynamically loaded OpenH264 library
        ///
        /// `library_path` should point to a Cisco OpenH264 prebuilt binary,
        /// which is verified against known Cisco release hashes before loading.
        /// Cisco's prebuilt binaries carry patent coverage under their license.
        #[cfg(feature = "openh264-libloading")]
        pub fn from_library_path(library_path: &std::path::Path) -> EncoderResult<Self> {
            let api = openh264::OpenH264API::from_blob_path(library_path)
                .map_err(|e| EncoderError::new("failed to load OpenH264 library", e))?;
            let encoder = openh264::encoder::Encoder::with_api_config(api, openh264::encoder::EncoderConfig::default())
                .map_err(|e| EncoderError::new("failed to create OpenH264 encoder", e))?;

            Ok(Self { encoder })
        }
    }

    impl H264Encoder for OpenH264Encoder {
        fn encode(&mut self, frame: EncodeFrame<'_>) -> EncoderResult<Vec<u8>> {
            if frame.width == 0 || frame.height == 0 || frame.width % 2 != 0 || frame.height % 2 != 0 {
                return Err(EncoderError::msg("frame dimensions must be non-zero and even"));
            }

            let width = usize::try_from(frame.width).map_err(|e| EncoderError::new("frame width", e))?;
            let height = usize::try_from(frame.height).map_err(|e| EncoderError::new("frame height", e))?;

            let expected_len = width
                .checked_mul(height)
                .and_then(|s| s.checked_mul(4))
                .ok_or_else(|| EncoderError::msg("frame dimensions overflow"))?;
            if frame.data.len() != expected_len {
                return Err(EncoderError::msg("frame buffer length does not match dimensions"));
            }

            let rgba = openh264::formats::RgbaSliceU8::new(frame.data, (width, height));
            let yuv = openh264::formats::YUVBuffer::from_rgb_source(rgba);

            let bitstream = self
                .encoder
                .encode(&yuv)
                .map_err(|e| EncoderError::new("OpenH264 encode failed", e))?;

            Ok(bitstream.to_vec())
        }

        fn request_key_frame(&mut self) {
            self.encoder.force_intra_frame();
        }

        fn reset(&mut self) {
            // OpenH264 has no full reset; forcing an IDR drops temporal
            // references, so the next frame decodes without prior state.
            self.encoder.force_intra_frame();
        }
    }
}

#[cfg(feature = "openh264")]
pub use openh264_impl::OpenH264Encoder;

// ============================================================================
// Encoder Error
// ============================================================================

/// Error type for encoder operations
#[derive(Debug)]
#[non_exhaustive]
pub struct EncoderError {
    context: String,
    source: Option<Box<dyn core::error::Error + Send + Sync>>,
}

impl EncoderError {
    /// Create an encoder error with a source error
    pub fn new(context: impl Into<String>, source: impl core::error::Error + Send + Sync + 'static) -> Self {
        Self {
            context: context.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Create an encoder error with only a message
    pub fn msg(context: impl Into<String>) -> Self {
        Self {
            context: context.into(),
            source: None,
        }
    }
}

impl fmt::Display for EncoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "encoder error: {}", self.context)?;
        if let Some(ref source) = self.source {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}

impl core::error::Error for EncoderError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        self.source.as_deref().map(|e| {
            let err: &(dyn core::error::Error + 'static) = e;
            err
        })
    }
}

#[cfg(all(test, feature = "openh264-bundled"))]
mod tests {
    use super::*;
    use crate::decode::H264Decoder as _;

    /// Round-trip through the reference encoder and the reference decoder,
    /// crossing the documented format boundary explicitly: the encoder
    /// produces Annex B (the wire format), the decoder consumes AVC
    /// length-prefixed input, and `pdu::annex_b_to_avc` is the bridge.
    ///
    /// Run with: `cargo test -p ironrdp-egfx --features openh264-bundled`
    #[test]
    fn openh264_encode_decode_round_trip() {
        const W: u32 = 64;
        const H: u32 = 64;

        let mut rgba = vec![0u8; (W * H * 4) as usize];
        for y in 0..H {
            for x in 0..W {
                let i = ((y * W + x) * 4) as usize;
                rgba[i] = (x * 4) as u8;
                rgba[i + 1] = (y * 4) as u8;
                rgba[i + 2] = 0x80;
                rgba[i + 3] = 0xff;
            }
        }

        let mut encoder = OpenH264Encoder::new().expect("bundled encoder");
        encoder.request_key_frame();
        let annex_b = encoder
            .encode(EncodeFrame {
                data: &rgba,
                width: W,
                height: H,
            })
            .expect("encode");

        assert!(!annex_b.is_empty());
        // Annex B starts with a 3- or 4-byte start code.
        assert!(annex_b.starts_with(&[0, 0, 0, 1]) || annex_b.starts_with(&[0, 0, 1]));

        let avc = crate::pdu::annex_b_to_avc(&annex_b);
        let mut decoder = crate::decode::OpenH264Decoder::new().expect("bundled decoder");
        let frame = decoder.decode(&avc).expect("decode");

        assert!(frame.width() >= W);
        assert!(frame.height() >= H);
    }

    #[test]
    fn rejects_odd_dimensions_and_bad_lengths() {
        let mut encoder = OpenH264Encoder::new().expect("bundled encoder");

        let buf = vec![0u8; 63 * 64 * 4];
        assert!(
            encoder
                .encode(EncodeFrame {
                    data: &buf,
                    width: 63,
                    height: 64,
                })
                .is_err()
        );

        let buf = vec![0u8; 8];
        assert!(
            encoder
                .encode(EncodeFrame {
                    data: &buf,
                    width: 64,
                    height: 64,
                })
                .is_err()
        );
    }
}
