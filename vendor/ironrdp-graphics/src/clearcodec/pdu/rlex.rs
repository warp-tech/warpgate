//! ClearCodec RLEX subcodec ([MS-RDPEGFX] 2.2.4.1.1.3.1.3).
//!
//! RLEX is a palette-indexed RLE codec with gradient "suite" encoding.
//! It encodes each pixel as a pair: a "run" of repeated color followed
//! by a "suite" (sequential palette walk from startIndex to stopIndex).

use ironrdp_core::{DecodeResult, ReadCursor, ensure_size, invalid_field_err};

/// Maximum palette size per spec.
pub const MAX_PALETTE_COUNT: u8 = 127;

/// A decoded RLEX segment (run + suite).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RlexSegment {
    /// Palette index to repeat for the run portion.
    pub start_index: u8,
    /// Last palette index in the suite walk.
    pub stop_index: u8,
    /// Number of pixels in the run (repeated start color).
    pub run_length: u32,
}

/// Decoded RLEX data: palette + segments.
#[derive(Debug, Clone)]
pub struct RlexData {
    /// BGR palette entries (3 bytes each).
    pub palette: Vec<[u8; 3]>,
    /// Sequence of run+suite segments.
    pub segments: Vec<RlexSegment>,
}

/// Decode RLEX subcodec data.
///
/// The data format:
/// ```text
/// paletteCount(u8) | paletteEntries[paletteCount * 3 bytes BGR]
/// segments[]: packed bit fields
/// ```
///
/// Bit widths derived from palette count:
/// - `stop_index_bits = floor(log2(palette_count - 1)) + 1`
/// - `suite_depth_bits = 8 - stop_index_bits`
pub fn decode_rlex(data: &[u8]) -> DecodeResult<RlexData> {
    let mut src = ReadCursor::new(data);

    ensure_size!(ctx: "RlexPalette", in: src, size: 1);
    let palette_count = src.read_u8();

    if palette_count == 0 {
        return Err(invalid_field_err!("paletteCount", "palette count is 0"));
    }

    if palette_count > MAX_PALETTE_COUNT {
        return Err(invalid_field_err!("paletteCount", "palette count exceeds 127"));
    }

    let palette_byte_count = usize::from(palette_count) * 3;
    ensure_size!(ctx: "RlexPalette", in: src, size: palette_byte_count);

    let mut palette = Vec::with_capacity(usize::from(palette_count));
    for _ in 0..palette_count {
        let b = src.read_u8();
        let g = src.read_u8();
        let r = src.read_u8();
        palette.push([b, g, r]);
    }

    // Compute bit widths
    let stop_index_bits = if palette_count <= 1 {
        // Edge case: only 1 palette entry
        0
    } else {
        bit_length(u32::from(palette_count - 1))
    };
    let suite_depth_bits = 8u8.saturating_sub(stop_index_bits);

    // Decode segments from remaining bytes
    let mut segments = Vec::new();
    let remaining = src.len();

    if stop_index_bits == 0 {
        // Single palette entry: no stop/suite bits, only run lengths
        // Each byte is a run length factor for palette[0]
        decode_single_palette_segments(&mut src, &mut segments)?;
    } else {
        decode_multi_palette_segments(
            remaining,
            &mut src,
            stop_index_bits,
            suite_depth_bits,
            palette_count,
            &mut segments,
        )?;
    }

    Ok(RlexData { palette, segments })
}

fn decode_single_palette_segments(src: &mut ReadCursor<'_>, segments: &mut Vec<RlexSegment>) -> DecodeResult<()> {
    while !src.is_empty() {
        let run_length = decode_run_length(src)?;
        segments.push(RlexSegment {
            start_index: 0,
            stop_index: 0,
            run_length,
        });
    }
    Ok(())
}

fn decode_multi_palette_segments(
    _remaining: usize,
    src: &mut ReadCursor<'_>,
    stop_index_bits: u8,
    suite_depth_bits: u8,
    palette_count: u8,
    segments: &mut Vec<RlexSegment>,
) -> DecodeResult<()> {
    let stop_mask = (1u8 << stop_index_bits) - 1;
    let depth_mask = (1u8 << suite_depth_bits) - 1;

    while !src.is_empty() {
        let packed = src.read_u8();
        let stop_index = packed & stop_mask;
        let suite_depth = (packed >> stop_index_bits) & depth_mask;

        if stop_index >= palette_count {
            return Err(invalid_field_err!("rlexStopIndex", "stop_index exceeds palette count"));
        }

        // MS-RDPEGFX 2.2.4.1.1.3.1.1.2: startIndex is stopIndex - suiteDepth and is itself a
        // palette entry, so a depth reaching below entry 0 describes no valid suite. Clamping
        // it would render a shorter suite than the stream asked for instead of rejecting it.
        let start_index = stop_index
            .checked_sub(suite_depth)
            .ok_or_else(|| invalid_field_err!("rlexSuiteDepth", "suite depth exceeds stop index"))?;

        let run_length = decode_run_length(src)?;

        segments.push(RlexSegment {
            start_index,
            stop_index,
            run_length,
        });
    }

    Ok(())
}

/// Decode a variable-length run length value.
/// Uses the same variable-length scheme as the residual layer.
fn decode_run_length(src: &mut ReadCursor<'_>) -> DecodeResult<u32> {
    ensure_size!(ctx: "RlexRunLength", in: src, size: 1);
    let factor1 = src.read_u8();

    if factor1 < 0xFF {
        return Ok(u32::from(factor1));
    }

    ensure_size!(ctx: "RlexRunLength", in: src, size: 2);
    let factor2 = src.read_u16();

    if factor2 < 0xFFFF {
        return Ok(u32::from(factor2));
    }

    ensure_size!(ctx: "RlexRunLength", in: src, size: 4);
    Ok(src.read_u32())
}

/// Compute the number of bits needed to represent a value (floor(log2(n)) + 1).
fn bit_length(n: u32) -> u8 {
    if n == 0 {
        return 0;
    }
    // Result is 1..=32 for non-zero n, always fits in u8
    u8::try_from(32 - n.leading_zeros()).expect("bit length of u32 always fits in u8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_length_values() {
        assert_eq!(bit_length(0), 0);
        assert_eq!(bit_length(1), 1);
        assert_eq!(bit_length(2), 2);
        assert_eq!(bit_length(3), 2);
        assert_eq!(bit_length(4), 3);
        assert_eq!(bit_length(7), 3);
        assert_eq!(bit_length(126), 7);
    }

    #[test]
    fn decode_rlex_two_palette() {
        // palette_count=2, palette=[black, white]
        // stop_index_bits = bit_length(1) = 1
        // suite_depth_bits = 8 - 1 = 7
        let mut data = Vec::new();
        data.push(2); // palette_count
        data.extend_from_slice(&[0x00, 0x00, 0x00]); // black BGR
        data.extend_from_slice(&[0xFF, 0xFF, 0xFF]); // white BGR
        // Segment: packed byte, stop_index=0 (1 bit), suite_depth=0 (7 bits), run=5
        data.push(0x00); // packed: stop=0, depth=0
        data.push(5); // run_length=5
        // Segment: stop_index=1, suite_depth=0, run=3
        data.push(0x01); // packed: stop=1, depth=0
        data.push(3); // run_length=3

        let rlex = decode_rlex(&data).unwrap();
        assert_eq!(rlex.palette.len(), 2);
        assert_eq!(rlex.segments.len(), 2);
        assert_eq!(rlex.segments[0].stop_index, 0);
        assert_eq!(rlex.segments[0].run_length, 5);
        assert_eq!(rlex.segments[1].stop_index, 1);
        assert_eq!(rlex.segments[1].run_length, 3);
    }

    #[test]
    fn reject_zero_palette() {
        let data = [0x00]; // palette_count = 0
        assert!(decode_rlex(&data).is_err());
    }

    #[test]
    fn reject_too_large_palette() {
        let data = [128]; // palette_count = 128 > 127
        assert!(decode_rlex(&data).is_err());
    }

    #[test]
    fn reject_stop_index_beyond_palette() {
        // palette_count=2, stop_index_bits=1, so valid stop_index is 0 or 1.
        // Craft a packed byte with stop_index=1 (valid) then one with stop_index
        // that exceeds palette_count by using a 4-palette setup where the mask
        // allows index 3 but only 2 entries exist.
        //
        // palette_count=2, stop_index_bits = bit_length(1) = 1, stop_mask = 0x01
        // Maximum stop_index from 1 bit = 1, which equals palette_count-1. Valid.
        // So use palette_count=3 instead: stop_index_bits = bit_length(2) = 2,
        // stop_mask = 0x03. Maximum stop_index = 3, but palette only has 3 entries
        // (indices 0..2). stop_index=3 is invalid.
        let mut data = Vec::new();
        data.push(3); // palette_count
        data.extend_from_slice(&[0, 0, 0]); // palette[0]
        data.extend_from_slice(&[1, 1, 1]); // palette[1]
        data.extend_from_slice(&[2, 2, 2]); // palette[2]
        // packed byte: stop_index=3 (bits 1:0), suite_depth=0 (bits 7:2)
        data.push(0x03);
        data.push(1); // run_length
        assert!(decode_rlex(&data).is_err());
    }

    /// MS-RDPEGFX 2.2.4.1.1.3.1.1.2: startIndex is stopIndex - suiteDepth and must itself be a
    /// palette entry, so a suite reaching below entry 0 has no valid start.
    #[test]
    fn reject_suite_depth_past_palette_start() {
        // palette_count=3 gives stop_index_bits=2 (mask 0x03) and suite_depth_bits=6 (mask 0x3F).
        // packed=0x04 is stop_index=0 with suite_depth=1, so startIndex would be -1.
        let mut data = Vec::new();
        data.push(3); // palette_count
        data.extend_from_slice(&[0, 0, 0]); // palette[0]
        data.extend_from_slice(&[1, 1, 1]); // palette[1]
        data.extend_from_slice(&[2, 2, 2]); // palette[2]
        data.push(0x04); // packed: stop_index=0, suite_depth=1
        data.push(5); // run_length
        assert!(decode_rlex(&data).is_err());
    }

    #[test]
    fn suite_depth_within_palette_sets_start_index() {
        // Same layout, but packed=0x06 is stop_index=2 with suite_depth=1, so the suite spans
        // palette entries 1 through 2. This is the valid counterpart of the case above and
        // guards against rejecting legal depths.
        let mut data = Vec::new();
        data.push(3); // palette_count
        data.extend_from_slice(&[0, 0, 0]); // palette[0]
        data.extend_from_slice(&[1, 1, 1]); // palette[1]
        data.extend_from_slice(&[2, 2, 2]); // palette[2]
        data.push(0x06); // packed: stop_index=2, suite_depth=1
        data.push(5); // run_length

        let rlex = decode_rlex(&data).unwrap();
        assert_eq!(rlex.segments.len(), 1);
        assert_eq!(rlex.segments[0].start_index, 1);
        assert_eq!(rlex.segments[0].stop_index, 2);
        assert_eq!(rlex.segments[0].run_length, 5);
    }
}
