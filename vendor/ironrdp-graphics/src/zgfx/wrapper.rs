//! ZGFX Segment Wrapper
//!
//! Provides utilities to wrap data in ZGFX segment structure for transmission over
//! DVC channels. Supports both uncompressed wrapping (data sent as-is) and compressed
//! wrapping (data already ZGFX-compressed by [`super::Compressor`]).
//!
//! # Specification
//!
//! Per MS-RDPEGFX section 2.2.1.1, ZGFX segments use RDP8 (0x04) compression type.
//! The COMPRESSED flag (0x02) distinguishes raw from compressed payloads.
//!
//! ## Single Segment Format
//!
//! ```text
//! Descriptor (1 byte): 0xE0 (ZGFX_SEGMENTED_SINGLE)
//! Flags (1 byte): 0x04 (RDP8 type, not compressed)
//! Data: Raw data bytes
//! ```
//!
//! ## Multipart Segment Format (for data > 65535 bytes)
//!
//! ```text
//! Descriptor (1 byte): 0xE1 (ZGFX_SEGMENTED_MULTIPART)
//! SegmentCount (2 bytes LE): Number of segments
//! UncompressedSize (4 bytes LE): Total data size
//! For each segment:
//!   Size (4 bytes LE): Segment size including flags byte
//!   Flags (1 byte): 0x04 (RDP8 type, not compressed)
//!   Data: Segment data bytes
//! ```

use byteorder::{LittleEndian, WriteBytesExt as _};

/// ZGFX descriptor for single segment
const ZGFX_SEGMENTED_SINGLE: u8 = 0xE0;

/// ZGFX descriptor for multipart segments
const ZGFX_SEGMENTED_MULTIPART: u8 = 0xE1;

/// RDP8 compression type (lower 4 bits of flags byte)
const ZGFX_PACKET_COMPR_TYPE_RDP8: u8 = 0x04;

/// COMPRESSED flag (upper 4 bits of flags byte)
const ZGFX_PACKET_COMPRESSED: u8 = 0x02;

/// Maximum size for a single ZGFX segment (65535 bytes)
pub(crate) const ZGFX_SEGMENTED_MAXSIZE: usize = 65535;

/// Wrap data in ZGFX segment structure (uncompressed)
///
/// This creates a spec-compliant ZGFX packet that clients can process,
/// but doesn't actually compress the data. The COMPRESSED flag (0x02)
/// is NOT set, indicating to the client to use the data directly.
///
/// # Arguments
///
/// * `data` - Raw data to wrap (typically EGFX PDU bytes)
///
/// # Returns
///
/// ZGFX-wrapped data ready for transmission over DVC channel
///
/// # Examples
///
/// ```
/// use ironrdp_graphics::zgfx::wrap_uncompressed;
///
/// let egfx_pdu_bytes = vec![0x01, 0x02, 0x03, 0x04];
/// let wrapped = wrap_uncompressed(&egfx_pdu_bytes);
///
/// // Wrapped data has 2-byte overhead for small data
/// assert_eq!(wrapped.len(), egfx_pdu_bytes.len() + 2);
/// assert_eq!(wrapped[0], 0xE0);  // Single segment descriptor
/// assert_eq!(wrapped[1], 0x04);  // RDP8 type, not compressed
/// ```
pub fn wrap_uncompressed(data: &[u8]) -> Vec<u8> {
    if data.len() <= ZGFX_SEGMENTED_MAXSIZE {
        wrap_single_segment(data, false)
    } else {
        wrap_multipart_segments(data, false)
    }
}

/// Wrap already-compressed data in a single ZGFX segment
///
/// The COMPRESSED flag is set, telling the client to decompress using ZGFX.
///
/// Only single-segment wrapping is supported for compressed data because a ZGFX
/// compressed bitstream cannot be split at arbitrary byte boundaries -- each segment
/// must be an independently decodable stream. If multi-segment compressed output is
/// needed, the compressor must emit pre-segmented output.
///
/// # Panics
///
/// Panics if `compressed_data` exceeds [`ZGFX_SEGMENTED_MAXSIZE`] (65535 bytes).
pub fn wrap_compressed(compressed_data: &[u8]) -> Vec<u8> {
    assert!(
        compressed_data.len() <= ZGFX_SEGMENTED_MAXSIZE,
        "compressed data ({} bytes) exceeds single-segment limit ({}); \
         the compressor must emit pre-segmented output for larger payloads",
        compressed_data.len(),
        ZGFX_SEGMENTED_MAXSIZE,
    );

    wrap_single_segment(compressed_data, true)
}

/// Wrap data in a single ZGFX segment
///
/// # Arguments
///
/// * `data` - Data to wrap
/// * `compressed` - Whether the data is already ZGFX-compressed
fn wrap_single_segment(data: &[u8], compressed: bool) -> Vec<u8> {
    let mut output = Vec::with_capacity(data.len() + 2);

    // Descriptor
    output.push(ZGFX_SEGMENTED_SINGLE);

    // Flags: RDP8 type + optional COMPRESSED flag
    // Lower 4 bits = compression type, upper 4 bits = flags
    let flags = if compressed {
        ZGFX_PACKET_COMPR_TYPE_RDP8 | (ZGFX_PACKET_COMPRESSED << 4)
    } else {
        ZGFX_PACKET_COMPR_TYPE_RDP8
    };
    output.push(flags);

    // Data (raw or compressed)
    output.extend_from_slice(data);

    output
}

/// Wrap data in multiple ZGFX segments
///
/// # Arguments
///
/// * `data` - Data to wrap
/// * `compressed` - Whether the data is already ZGFX-compressed
fn wrap_multipart_segments(data: &[u8], compressed: bool) -> Vec<u8> {
    let segment_count = data.len().div_ceil(ZGFX_SEGMENTED_MAXSIZE);

    // Header: descriptor(1) + count(2) + uncompressed_size(4)
    // Per segment: size(4) + flags(1) + data
    let mut output = Vec::with_capacity(data.len() + 7 + segment_count * 5);

    output.push(ZGFX_SEGMENTED_MULTIPART);

    output
        .write_u16::<LittleEndian>(u16::try_from(segment_count).expect("segment count exceeds u16"))
        .expect("write to Vec cannot fail");

    output
        .write_u32::<LittleEndian>(u32::try_from(data.len()).expect("data exceeds u32"))
        .expect("write to Vec cannot fail");

    for segment in data.chunks(ZGFX_SEGMENTED_MAXSIZE) {
        // Segment size (includes flags byte) - max ZGFX_SEGMENTED_MAXSIZE + 1
        output
            .write_u32::<LittleEndian>(u32::try_from(segment.len() + 1).expect("segment size exceeds u32"))
            .expect("write to Vec cannot fail");

        // Flags: RDP8 type + optional COMPRESSED flag
        let flags = if compressed {
            ZGFX_PACKET_COMPR_TYPE_RDP8 | (ZGFX_PACKET_COMPRESSED << 4)
        } else {
            ZGFX_PACKET_COMPR_TYPE_RDP8
        };
        output.push(flags);

        // Segment data
        output.extend_from_slice(segment);
    }

    output
}

#[cfg(test)]
#[expect(clippy::as_conversions, reason = "test assertions use as for clarity")]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_small_data() {
        let data = b"Hello, ZGFX!";
        let wrapped = wrap_uncompressed(data);

        // Should be: descriptor(1) + flags(1) + data
        assert_eq!(wrapped.len(), data.len() + 2);
        assert_eq!(wrapped[0], 0xE0); // Single segment
        assert_eq!(wrapped[1], 0x04); // RDP8, not compressed
        assert_eq!(&wrapped[2..], data);
    }

    #[test]
    fn test_wrap_empty_data() {
        let data = b"";
        let wrapped = wrap_uncompressed(data);

        assert_eq!(wrapped.len(), 2);
        assert_eq!(wrapped[0], 0xE0);
        assert_eq!(wrapped[1], 0x04);
    }

    #[test]
    fn test_wrap_max_single_segment() {
        let data = vec![0xAB; 65535]; // Exactly at limit
        let wrapped = wrap_uncompressed(&data);

        assert_eq!(wrapped[0], 0xE0); // Should still be single segment
        assert_eq!(wrapped.len(), 65535 + 2);
    }

    #[test]
    fn test_wrap_large_data() {
        let data = vec![0xCD; 100000]; // 100KB > 65KB limit
        let wrapped = wrap_uncompressed(&data);

        assert_eq!(wrapped[0], 0xE1); // Multipart

        // Parse header
        let segment_count = u16::from_le_bytes([wrapped[1], wrapped[2]]) as usize;
        assert_eq!(segment_count, 2); // 100KB / 65KB = 2 segments

        let uncompressed_size = u32::from_le_bytes([wrapped[3], wrapped[4], wrapped[5], wrapped[6]]) as usize;
        assert_eq!(uncompressed_size, 100000);

        // Verify first segment
        let seg1_size = u32::from_le_bytes([wrapped[7], wrapped[8], wrapped[9], wrapped[10]]) as usize;
        assert_eq!(seg1_size, 65536); // 65535 data + 1 flags
        assert_eq!(wrapped[11], 0x04); // Flags

        // Verify second segment starts at correct offset
        let seg2_offset = 7 + 4 + seg1_size;
        let seg2_size = u32::from_le_bytes([
            wrapped[seg2_offset],
            wrapped[seg2_offset + 1],
            wrapped[seg2_offset + 2],
            wrapped[seg2_offset + 3],
        ]) as usize;
        assert_eq!(seg2_size, 100000 - 65535 + 1); // Remaining data + 1 flags
        assert_eq!(wrapped[seg2_offset + 4], 0x04); // Flags
    }

    #[test]
    fn test_round_trip_with_decompressor() {
        use super::super::Decompressor;

        let data = b"Test data for ZGFX round-trip verification";
        let wrapped = wrap_uncompressed(data);

        // Verify decompressor can handle it
        let mut decompressor = Decompressor::new();
        let mut output = Vec::new();
        decompressor.decompress(&wrapped, &mut output).unwrap();

        assert_eq!(&output, data);
    }

    #[test]
    fn test_round_trip_large_data() {
        use super::super::Decompressor;

        // Test with data that requires multiple segments
        let data = vec![0x42; 150000];
        let wrapped = wrap_uncompressed(&data);

        let mut decompressor = Decompressor::new();
        let mut output = Vec::new();
        decompressor.decompress(&wrapped, &mut output).unwrap();

        assert_eq!(output, data);
    }

    #[test]
    fn test_wrap_compressed_single_segment() {
        let fake_compressed = vec![0xFF; 128];
        let wrapped = wrap_compressed(&fake_compressed);

        assert_eq!(wrapped[0], 0xE0); // Single segment
        assert_eq!(wrapped[1], 0x24); // RDP8 (0x04) | COMPRESSED (0x02 << 4)
        assert_eq!(&wrapped[2..], &*fake_compressed);
    }

    #[test]
    #[should_panic(expected = "exceeds single-segment limit")]
    fn test_wrap_compressed_rejects_oversized() {
        let too_large = vec![0xFF; ZGFX_SEGMENTED_MAXSIZE + 1];
        wrap_compressed(&too_large);
    }

    #[test]
    fn test_wrap_typical_egfx_pdu() {
        // Simulate a typical EGFX CapabilitiesConfirm PDU (44 bytes)
        let egfx_caps_confirm = vec![0x13, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00]; // Simplified header
        let wrapped = wrap_uncompressed(&egfx_caps_confirm);

        assert_eq!(wrapped[0], 0xE0); // Single segment
        assert_eq!(wrapped[1], 0x04); // Not compressed
        assert_eq!(wrapped.len(), egfx_caps_confirm.len() + 2);
    }

    #[test]
    fn test_wrap_typical_h264_frame() {
        // Simulate a typical 85KB H.264 frame
        let h264_frame = vec![0x00; 85000];
        let wrapped = wrap_uncompressed(&h264_frame);

        assert_eq!(wrapped[0], 0xE1); // Multipart (> 65KB)

        // Should produce 2 segments
        let segment_count = u16::from_le_bytes([wrapped[1], wrapped[2]]);
        assert_eq!(segment_count, 2);
    }

    #[test]
    fn test_wrap_compressed_data() {
        use crate::zgfx::Compressor;

        let mut compressor = Compressor::new();
        let data = b"Test data with some patterns for compression";

        let compressed = compressor.compress(data).unwrap();
        let wrapped = wrap_compressed(&compressed);

        // Should have COMPRESSED flag set
        assert_eq!(wrapped[0], 0xE0); // Single segment
        assert_eq!(wrapped[1], 0x24); // 0x04 (RDP8) | (0x02 << 4) = 0x24

        use crate::zgfx::Decompressor;
        let mut decompressor = Decompressor::new();
        let mut output = Vec::new();
        decompressor.decompress(&wrapped, &mut output).unwrap();

        assert_eq!(&output, data);
    }

    #[test]
    fn test_compress_and_wrap_full_pipeline() {
        use crate::zgfx::{Compressor, Decompressor};

        let mut compressor = Compressor::new();
        let data = b"This is test data that will be compressed using ZGFX algorithm and then wrapped";

        let compressed_data = compressor.compress(data).unwrap();
        let wrapped = wrap_compressed(&compressed_data);

        let mut decompressor = Decompressor::new();
        let mut output = Vec::new();
        decompressor.decompress(&wrapped, &mut output).unwrap();

        assert_eq!(&output, data);
    }
}
