//! ClearCodec Layer 1: Residual (BGR RLE) ([MS-RDPEGFX] 2.2.4.1.1.1).
//!
//! The residual layer encodes the background of the bitmap as a sequence of
//! run-length-encoded BGR pixel runs. This forms the base layer onto which
//! bands and subcodec regions are composited.

use ironrdp_core::{DecodeResult, ReadCursor, ensure_size};

/// A single BGR run-length segment.
///
/// The run length uses a variable-length encoding:
/// - `factor1 < 0xFF`: run = factor1
/// - `factor1 == 0xFF && factor2 < 0xFFFF`: run = factor2
/// - `factor1 == 0xFF && factor2 == 0xFFFF`: run = factor3
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RgbRunSegment {
    pub blue: u8,
    pub green: u8,
    pub red: u8,
    pub run_length: u32,
}

impl RgbRunSegment {
    const NAME: &'static str = "RgbRunSegment";

    /// Minimum segment size: 3 bytes color + 1 byte factor1.
    const MIN_SIZE: usize = 4;
}

/// Decode all residual run segments from the residual layer data.
///
/// Returns the sequence of run segments. The caller is responsible for
/// expanding them into a pixel buffer of `width * height` pixels.
pub fn decode_residual_layer(data: &[u8]) -> DecodeResult<Vec<RgbRunSegment>> {
    let mut segments = Vec::new();
    let mut src = ReadCursor::new(data);

    while src.len() >= RgbRunSegment::MIN_SIZE {
        let blue = src.read_u8();
        let green = src.read_u8();
        let red = src.read_u8();
        let factor1 = src.read_u8();

        let run_length = if factor1 < 0xFF {
            u32::from(factor1)
        } else {
            ensure_size!(ctx: RgbRunSegment::NAME, in: src, size: 2);
            let factor2 = src.read_u16();
            if factor2 < 0xFFFF {
                u32::from(factor2)
            } else {
                ensure_size!(ctx: RgbRunSegment::NAME, in: src, size: 4);
                src.read_u32()
            }
        };

        segments.push(RgbRunSegment {
            blue,
            green,
            red,
            run_length,
        });
    }

    Ok(segments)
}

/// Encode residual layer data from a sequence of BGR run segments.
///
/// Writes the variable-length encoded run segments into a Vec.
///
/// # Panics
///
/// Cannot panic. Internal `expect()` calls are guarded by range checks.
pub fn encode_residual_layer(segments: &[RgbRunSegment]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(segments.len() * 4);

    for seg in segments {
        buf.push(seg.blue);
        buf.push(seg.green);
        buf.push(seg.red);

        if seg.run_length < 0xFF {
            buf.push(u8::try_from(seg.run_length).expect("guarded by < 0xFF check"));
        } else if seg.run_length < 0xFFFF {
            buf.push(0xFF);
            buf.extend_from_slice(
                &u16::try_from(seg.run_length)
                    .expect("guarded by < 0xFFFF check")
                    .to_le_bytes(),
            );
        } else {
            buf.push(0xFF);
            buf.extend_from_slice(&0xFFFFu16.to_le_bytes());
            buf.extend_from_slice(&seg.run_length.to_le_bytes());
        }
    }

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_single_short_run() {
        // Blue=0x10, Green=0x20, Red=0x30, run=5
        let data = [0x10, 0x20, 0x30, 0x05];
        let segments = decode_residual_layer(&data).unwrap();
        assert_eq!(segments.len(), 1);
        assert_eq!(
            segments[0],
            RgbRunSegment {
                blue: 0x10,
                green: 0x20,
                red: 0x30,
                run_length: 5
            }
        );
    }

    #[test]
    fn decode_medium_run() {
        // run_length = 300 (0x012C), needs factor2
        let data = [0x00, 0x00, 0x00, 0xFF, 0x2C, 0x01];
        let segments = decode_residual_layer(&data).unwrap();
        assert_eq!(segments[0].run_length, 300);
    }

    #[test]
    fn decode_long_run() {
        // run_length = 70000 (0x00011170), needs factor3
        let data = [0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x70, 0x11, 0x01, 0x00];
        let segments = decode_residual_layer(&data).unwrap();
        assert_eq!(segments[0].run_length, 70000);
    }

    #[test]
    fn decode_multiple_segments() {
        // Two short runs
        let data = [
            0xFF, 0x00, 0x00, 0x03, // blue pixel, run=3
            0x00, 0xFF, 0x00, 0x02, // green pixel, run=2
        ];
        let segments = decode_residual_layer(&data).unwrap();
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].run_length, 3);
        assert_eq!(segments[1].run_length, 2);
    }

    #[test]
    fn round_trip_short() {
        let original = vec![
            RgbRunSegment {
                blue: 0xAA,
                green: 0xBB,
                red: 0xCC,
                run_length: 42,
            },
            RgbRunSegment {
                blue: 0x00,
                green: 0x00,
                red: 0x00,
                run_length: 0,
            },
        ];
        let encoded = encode_residual_layer(&original);
        let decoded = decode_residual_layer(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn round_trip_all_sizes() {
        let original = vec![
            RgbRunSegment {
                blue: 0,
                green: 0,
                red: 0,
                run_length: 100,
            }, // short
            RgbRunSegment {
                blue: 0,
                green: 0,
                red: 0,
                run_length: 1000,
            }, // medium
            RgbRunSegment {
                blue: 0,
                green: 0,
                red: 0,
                run_length: 100_000,
            }, // long
        ];
        let encoded = encode_residual_layer(&original);
        let decoded = decode_residual_layer(&encoded).unwrap();
        assert_eq!(decoded, original);
    }
}
