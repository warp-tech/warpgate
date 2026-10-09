use core::cmp;
use std::io::{Read as _, Write as _};

use byteorder::ReadBytesExt as _;
use ironrdp_core::WriteCursor;

/// Maximum possible segment size is 47 (run_length = 2, raw_bytes_count = 15), which is treated as
/// special mode segment, which repeats last decoded byte in scanline 32 + raw_bytes_count times
const MAX_DECODED_SEGMENT_SIZE: usize = 47;

#[derive(Debug)]
pub enum RleDecodeError {
    ReadCompressedData(std::io::Error),
    WriteDecompressedData(std::io::Error),
    InvalidSegmentHeader,
    SegmentDoNotFitScanline,
}

impl core::fmt::Display for RleDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RleDecodeError::ReadCompressedData(_error) => write!(f, "failed to read RLE-compressed data"),
            RleDecodeError::WriteDecompressedData(_error) => write!(f, "failed to write decompressed data"),
            RleDecodeError::InvalidSegmentHeader => write!(f, "invalid RLE segment header"),
            RleDecodeError::SegmentDoNotFitScanline => {
                write!(f, "decoded scanline segments length exceeds scanline length")
            }
        }
    }
}

impl core::error::Error for RleDecodeError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            RleDecodeError::ReadCompressedData(error) => Some(error),
            RleDecodeError::WriteDecompressedData(error) => Some(error),
            RleDecodeError::InvalidSegmentHeader => None,
            RleDecodeError::SegmentDoNotFitScanline => None,
        }
    }
}

#[derive(Debug)]
pub enum RleEncodeError {
    NotEnoughBytes,
    BufferTooSmall,
}

impl core::fmt::Display for RleEncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RleEncodeError::NotEnoughBytes => write!(f, "not enough data to compress"),
            RleEncodeError::BufferTooSmall => write!(f, "destination buffer is too small"),
        }
    }
}

impl core::error::Error for RleEncodeError {}

/// RLE-encoded color plane decoder implementation for RDP6 bitmap stream
#[derive(Debug)]
struct RlePlaneDecoder {
    /// RDP6 performs per-scanline encoding, therefore segment decoder require state reset
    /// for when each scanline is started (e.g. resetting last decoded byte value to 0)
    last_decoded_byte: u8,

    width: usize,
    height: usize,

    decoded_data: [u8; MAX_DECODED_SEGMENT_SIZE],
    decoded_data_len: usize,
}

impl RlePlaneDecoder {
    fn new(width: usize, height: usize) -> Self {
        Self {
            last_decoded_byte: 0,
            width,
            height,
            decoded_data: [0; MAX_DECODED_SEGMENT_SIZE],
            decoded_data_len: 0,
        }
    }

    fn decompress_next_segment(&mut self, mut src: &[u8]) -> Result<usize, RleDecodeError> {
        let control_byte = src.read_u8().map_err(RleDecodeError::ReadCompressedData)?;

        if control_byte == 0 {
            return Err(RleDecodeError::InvalidSegmentHeader);
        }

        let rle_bytes_field = control_byte & 0x0F;
        let raw_bytes_field = (control_byte >> 4) & 0x0F;

        let (run_length, raw_bytes_count) = match rle_bytes_field {
            1 => (16 + usize::from(raw_bytes_field), 0),
            2 => (32 + usize::from(raw_bytes_field), 0),
            rle_control => (usize::from(rle_control), usize::from(raw_bytes_field)),
        };

        self.decoded_data_len = raw_bytes_count + run_length;

        src.read_exact(&mut self.decoded_data[..raw_bytes_count])
            .map_err(RleDecodeError::ReadCompressedData)?;

        if raw_bytes_count > 0 {
            // save last decoded byte for the next segments decoding
            self.last_decoded_byte = self.decoded_data[raw_bytes_count - 1];
        }

        self.decoded_data[raw_bytes_count..self.decoded_data_len].fill(self.last_decoded_byte);

        Ok(raw_bytes_count + 1)
    }

    /// Decodes single RLE-encoded scanline, without performing delta transformation
    fn decode_scanline(&mut self, src: &[u8], mut dst: &mut [u8]) -> Result<usize, RleDecodeError> {
        let mut decoded_columns = 0;
        let mut read_bytes = 0;

        self.last_decoded_byte = 0;

        while decoded_columns < self.width {
            read_bytes += self.decompress_next_segment(&src[read_bytes..])?;

            if decoded_columns + self.decoded_data_len > self.width {
                return Err(RleDecodeError::SegmentDoNotFitScanline);
            }

            dst.write_all(&self.decoded_data[..self.decoded_data_len])
                .map_err(RleDecodeError::WriteDecompressedData)?;

            decoded_columns += self.decoded_data_len;
        }

        Ok(read_bytes)
    }

    /// Performs delta transformation as described in 3.1.9.2.3 of [MS-RDPEGDI]
    fn resolve_scanline_delta(prev_line: &[u8], current_scanline: &mut [u8]) {
        assert!(prev_line.len() == current_scanline.len());

        current_scanline
            .iter_mut()
            .zip(prev_line.iter())
            .for_each(|(dst, src)| {
                let delta = *dst;
                let value_above = *src;

                let transformed_delta = if delta % 2 == 1 {
                    255u8.wrapping_sub((delta.wrapping_sub(1)) >> 1)
                } else {
                    delta >> 1
                };

                *dst = value_above.wrapping_add(transformed_delta);
            });
    }

    fn decode(mut self, src: &[u8], dst: &mut [u8]) -> Result<usize, RleDecodeError> {
        let mut read_bytes = 0;

        read_bytes += self.decode_scanline(src, dst)?;

        let (mut prev_scanline, mut dst) = dst.split_at_mut(self.width);

        for _ in 1..self.height {
            let current_scanline = &mut dst[..self.width];

            read_bytes += self.decode_scanline(&src[read_bytes..], current_scanline)?;
            Self::resolve_scanline_delta(prev_scanline, current_scanline);

            (prev_scanline, dst) = dst.split_at_mut(self.width);
        }

        Ok(read_bytes)
    }
}

/// Performs decompression of 8bpp color plane into slice.
/// Slice must have enough space for decompressed data.
/// Size of data written to dst buffer is exactly equal to `width * height`.
///
/// Returns number of bytes consumed from src buffer.
pub(crate) fn decompress_8bpp_plane(
    src: &[u8],
    dst: &mut [u8],
    width: usize,
    height: usize,
) -> Result<usize, RleDecodeError> {
    RlePlaneDecoder::new(width, height).decode(src, dst)
}

struct RleEncoderScanlineIterator<I> {
    inner: core::iter::Enumerate<I>,
    width: usize,
    prev_scanline: Vec<u8>,
}

impl<I: Iterator> RleEncoderScanlineIterator<I> {
    fn new(width: usize, inner: I) -> Self {
        Self {
            width,
            inner: inner.enumerate(),
            prev_scanline: vec![0; width],
        }
    }

    fn delta_value(prev: u8, next: u8) -> u8 {
        let mut result = u8::try_from((i16::from(next) - i16::from(prev)) & 0xFF)
            .expect("masking with 0xFF ensures that the value fits into u8");

        // bit magic from 3.1.9.2.1 of [MS-RDPEGDI].
        if result < 128 {
            result <<= 1;
        } else {
            result = (255u8.wrapping_sub(result) << 1).wrapping_add(1);
        }

        result
    }
}

impl<I: Iterator<Item = u8>> Iterator for RleEncoderScanlineIterator<I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        let (idx, mut next) = self.inner.next()?;

        let prev = core::mem::replace(&mut self.prev_scanline[idx % self.width], next);
        if idx >= self.width {
            next = Self::delta_value(prev, next);
        }

        Some(next)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

#[derive(Debug)]
struct RlePlaneEncoder {
    width: usize,
    height: usize,
}

macro_rules! ensure_size {
    (dst: $buf:ident, size: $expected:expr) => {{
        let available = $buf.len();
        let needed = $expected;
        if !(needed <= available) {
            return Err(RleEncodeError::BufferTooSmall);
        }
    }};
}

impl RlePlaneEncoder {
    fn new(width: usize, height: usize) -> Self {
        Self { width, height }
    }

    fn encode(&self, mut src: impl Iterator<Item = u8>, dst: &mut WriteCursor<'_>) -> Result<usize, RleEncodeError> {
        let mut written = 0;

        for _ in 0..self.height {
            written += self.encode_scanline((&mut src).take(self.width), dst)?;
        }

        Ok(written)
    }

    fn encode_scanline(
        &self,
        mut src: impl Iterator<Item = u8>,
        dst: &mut WriteCursor<'_>,
    ) -> Result<usize, RleEncodeError> {
        let mut written = 0;
        let first = src.next().ok_or(RleEncodeError::NotEnoughBytes)?;

        let mut raw = vec![first];
        let mut seq = (first, 0);

        for byte in src {
            let (last, count) = seq;

            seq = if byte == last {
                (byte, count + 1)
            } else {
                match count {
                    3.. => {
                        written += self.encode_segment(&raw, count, dst)?;
                        raw.clear();
                    }
                    2 => raw.extend_from_slice(&[last, last]),
                    1 => raw.push(last),
                    _ => {}
                }

                raw.push(byte);

                (byte, 0)
            }
        }

        let (last, mut count) = seq;
        if count < 3 {
            raw.extend(vec![last; count]);
            count = 0;
        }

        written += self.encode_segment(&raw, count, dst)?;

        Ok(written)
    }

    fn encode_segment(&self, mut raw: &[u8], run: usize, dst: &mut WriteCursor<'_>) -> Result<usize, RleEncodeError> {
        if raw.is_empty() {
            return Err(RleEncodeError::NotEnoughBytes);
        }

        let mut extra_bytes = 0;

        while raw.len() > 15 {
            extra_bytes += self.encode_segment(&raw[0..15], 0, dst)?;
            raw = &raw[15..];
        }

        let raw_len = u8::try_from(raw.len()).expect("max value is guaranteed to be 15 due to the prior while loop");
        let run_capped = u8::try_from(cmp::min(run, 15)).expect("max value is guaranteed to be 15");

        let control = (raw_len << 4) + run_capped;

        ensure_size!(dst: dst, size: raw.len() + 1);

        dst.write_u8(control);
        dst.write_slice(raw);

        if run > 15 {
            let last = raw.last().expect("buffer cannot be empty");
            extra_bytes += self.encode_long_sequence(run - 15, *last, dst)?;
        }

        Ok(1 + raw.len() + extra_bytes)
    }

    fn encode_long_sequence(
        &self,
        mut run: usize,
        last: u8,
        dst: &mut WriteCursor<'_>,
    ) -> Result<usize, RleEncodeError> {
        let mut written = 0;

        while run >= 16 {
            ensure_size!(dst: dst, size: 1);

            let current = u8::try_from(cmp::min(run, MAX_DECODED_SEGMENT_SIZE))
                .expect("max value is guaranteed to be MAX_DECODED_SEGMENT_SIZE (47)");

            let c_raw_bytes = cmp::min(current / 16, 2);
            let n_run_length = current - c_raw_bytes * 16;

            let control = (n_run_length << 4) + c_raw_bytes;
            dst.write_u8(control);
            written += 1;

            run -= usize::from(current);
        }

        if run > 0 {
            match run {
                short @ 1..=3 => {
                    written += self.encode_segment(&vec![last; short], 0, dst)?;
                }
                long => {
                    written += self.encode_segment(&[last], long - 1, dst)?;
                }
            }
        }

        Ok(written)
    }
}

/// Performs compression of 8bpp color plane pixel stream into a buffer.
/// Pixel iterator must have at least width * height items.
/// Destination slice must have enough space for the compressed data.
///
/// Returns number of bytes written to the dst buffer.
pub(crate) fn compress_8bpp_plane(
    src: impl Iterator<Item = u8>,
    dst: &mut WriteCursor<'_>,
    width: usize,
    height: usize,
) -> Result<usize, RleEncodeError> {
    let iter = RleEncoderScanlineIterator::new(width, src);
    RlePlaneEncoder::new(width, height).encode(iter, dst)
}

#[cfg(test)]
#[expect(
    clippy::needless_raw_strings,
    reason = "the lint is disable to not interfere with expect! macro"
)]
mod tests {
    use expect_test::expect;

    use super::*;

    /// Performs decompression of 8bpp color plane into vector. Vector will be resized to fit decompressed data.
    fn decompress(src: &[u8], dst: &mut Vec<u8>, width: usize, height: usize) -> Result<usize, RleDecodeError> {
        // Ensure dest buffer have enough space for decompressed data
        dst.resize(width * height, 0);

        decompress_8bpp_plane(src, dst.as_mut_slice(), width, height)
    }

    fn compress(src: &[u8], dst: &mut [u8], width: usize, height: usize) -> Result<usize, RleEncodeError> {
        compress_8bpp_plane(src.iter().copied(), &mut WriteCursor::new(dst), width, height)
    }

    #[test]
    fn simple_encode() {
        // Example AAAABBCCCCCD from 3.1.9.2 of [MS-RDPEGDI].
        let src = [65, 65, 65, 65, 66, 66, 67, 67, 67, 67, 67, 68];

        let width = src.len();
        let height = 1usize;

        let expected = &[0x13, 65, 0x34, 66, 66, 67, 0x10, 68];

        let mut compressed = vec![0; 255];
        let len = compress(&src, &mut compressed, width, height).unwrap();

        assert_eq!(&compressed[..len], expected);
    }

    #[test]
    fn long_sequence_encode() {
        // Example from 3.1.9.2.2 of [MS-RDPEGDI].
        let src = [0x41u8; 100];

        let width = 100usize;
        let height = 1usize;

        let expected = &[0x1F, 0x41, 0xF2, 0x52];

        let mut compressed = vec![0; 255];
        let len = compress(&src, &mut compressed, width, height).unwrap();

        assert_eq!(&compressed[..len], expected);
    }

    #[test]
    fn multiline_encode() {
        // Example from 3.1.9.2.1 of [MS-RDPEGDI].
        let src = [
            255, 255, 255, 255, 254, 253, 254, 192, 132, 96, 75, 25, 253, 140, 62, 14, 135, 193,
        ];

        let width = 6usize;
        let height = 3usize;

        let expected = &[
            0x13, 0xFF, 0x20, 0xFE, 0xFD, 0x60, 0x01, 0x7D, 0xF5, 0xC2, 0x9A, 0x38, 0x60, 0x01, 0x67, 0x8B, 0xA3, 0x78,
            0xAF,
        ];

        let mut compressed = vec![0; 255];
        let len = compress(&src, &mut compressed, width, height).unwrap();

        assert_eq!(&compressed[..len], expected);
    }

    #[test]
    fn long_sequence_decode() {
        // Example from 3.1.9.2.2 of [MS-RDPEGDI].
        let src = [0x1F, 0x41, 0xF2, 0x52];

        let width = 100usize;
        let height = 1usize;

        let expected = &[0x41u8; 100];

        let mut actual = Vec::new();
        decompress(&src, &mut actual, width, height).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn multiline_decode() {
        // Example from 3.1.9.2.3 of [MS-RDPEGDI].
        let src = [
            0x13, 0xFF, 0x20, 0xFE, 0xFD, 0x60, 0x01, 0x7D, 0xF5, 0xC2, 0x9A, 0x38, 0x60, 0x01, 0x67, 0x8B, 0xA3, 0x78,
            0xAF,
        ];

        let width = 6usize;
        let height = 3usize;

        let expected = &[
            255, 255, 255, 255, 254, 253, 254, 192, 132, 96, 75, 25, 253, 140, 62, 14, 135, 193,
        ];

        let mut actual = Vec::new();
        decompress(&src, &mut actual, width, height).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn long_sequence_encode_decode() {
        // Example from 3.1.9.2.2 of [MS-RDPEGDI].
        let src = [0x41u8; 100];

        let width = 100usize;
        let height = 1usize;

        let mut compressed = vec![0; 255];
        let len = compress(&src, &mut compressed, width, height).unwrap();

        let mut actual = Vec::new();
        decompress(&compressed[..len], &mut actual, width, height).unwrap();

        assert_eq!(actual.as_slice(), src.as_slice());
    }

    #[test]
    fn complex_encode_decode() {
        let src = [
            19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 18, 18, 18, 19, 19, 18, 18, 18,
            18, 18, 18, 18, 18,
        ];

        let width = src.len();
        let height = 1usize;

        let mut compressed = vec![0; 255];
        let len = compress(&src, &mut compressed, width, height).unwrap();

        let mut actual = Vec::new();
        decompress(&compressed[..len], &mut actual, width, height).unwrap();

        assert_eq!(actual.as_slice(), src.as_slice());
    }

    #[test]
    fn multiline_encode_decode() {
        // Example from 3.1.9.2.3 of [MS-RDPEGDI].
        let src = [
            255, 255, 255, 255, 254, 253, 254, 192, 132, 96, 75, 25, 253, 140, 62, 14, 135, 193,
        ];

        let width = 6usize;
        let height = 3usize;

        let mut compressed = vec![0; 255];
        let len = compress(&src, &mut compressed, width, height).unwrap();

        let mut actual = Vec::new();
        decompress(&compressed[..len], &mut actual, width, height).unwrap();

        assert_eq!(actual.as_slice(), src.as_slice());
    }

    #[test]
    fn each_scanline_resets_last_decoded_byte() {
        let src = [0x17, 0xFF, 0x04, 0x40, 0x01, 0x02, 0x03, 0x04];

        let width = 8usize;
        let height = 2usize;

        let mut actual = Vec::new();

        let expected = &[
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 0, 253, 1,
        ];

        decompress(&src, &mut actual, width, height).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn segments_out_of_scanline_produce_error() {
        let src = [
            0x18, 0xFF, // Will produce 9 bytes which is out of bounds for 8x2 image
            0x04, 0x40, 0x01, 0x02, 0x03, 0x04,
        ];

        let width = 8usize;
        let height = 2usize;

        let mut actual = Vec::new();
        expect![[r#"
            Err(
                SegmentDoNotFitScanline,
            )
        "#]]
        .assert_debug_eq(&decompress(&src, &mut actual, width, height));

        // Same test, but fail on non-first line
        let src = [
            0x17, 0xFF, 0x18, 0xFF, // Will produce 9 bytes which is out of bounds for 8x2 image
        ];

        let width = 8usize;
        let height = 2usize;

        let mut actual = Vec::new();
        expect![[r#"
            Err(
                SegmentDoNotFitScanline,
            )
        "#]]
        .assert_debug_eq(&decompress(&src, &mut actual, width, height));
    }

    #[test]
    fn insufficient_raw_bytes_handled() {
        let src = [0x18]; // Actually require 1 more byte

        let width = 8usize;
        let height = 2usize;

        let mut actual = Vec::new();
        expect![[r#"
            Err(
                ReadCompressedData(
                    Error {
                        kind: UnexpectedEof,
                        message: "failed to fill whole buffer",
                    },
                ),
            )
        "#]]
        .assert_debug_eq(&decompress(&src, &mut actual, width, height));
    }

    #[test]
    fn empty_buffer_handled() {
        let src = [];

        let width = 8usize;
        let height = 2usize;

        let mut actual = Vec::new();
        expect![[r#"
            Err(
                ReadCompressedData(
                    Error {
                        kind: UnexpectedEof,
                        message: "failed to fill whole buffer",
                    },
                ),
            )
        "#]]
        .assert_debug_eq(&decompress(&src, &mut actual, width, height));
    }

    #[test]
    fn buffer_too_small_encode() {
        let src = [
            255, 255, 255, 255, 254, 253, 254, 192, 132, 96, 75, 25, 253, 140, 62, 14, 135, 193,
        ];

        let width = 6usize;
        let height = 3usize;

        let mut compressed = vec![0; 4];

        expect![[r#"
            Err(
                BufferTooSmall,
            )
        "#]]
        .assert_debug_eq(&compress(&src, &mut compressed, width, height));
    }

    #[test]
    fn not_enough_bytes_to_encode() {
        let src = [255, 255, 255, 255, 254, 253, 254, 192, 132, 96, 75, 25, 253];

        let width = 8usize;
        let height = 3usize;

        let mut compressed = vec![0; 255];

        expect![[r#"
            Err(
                NotEnoughBytes,
            )
        "#]]
        .assert_debug_eq(&compress(&src, &mut compressed, width, height));
    }

    #[test]
    fn too_small_dest_buffer_handled() {
        let src = [0x17, 0xFF, 0x04, 0x40, 0x01, 0x02, 0x03, 0x04];

        let width = 8usize;
        let height = 2usize;

        let mut actual = vec![0u8; 7];

        expect![[r#"
            Err(
                WriteDecompressedData(
                    Error {
                        kind: WriteZero,
                        message: "failed to write whole buffer",
                    },
                ),
            )
        "#]]
        .assert_debug_eq(&decompress_8bpp_plane(&src, &mut actual, width, height));

        // Check same failure mode, but on non-first line
    }
}
