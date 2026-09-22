//! ZGFX (RDP8) Bulk Data Compression

mod api;
mod circular_buffer;
mod compressor;
mod control_messages;
mod wrapper;

use std::io::{self, Write as _};
use std::sync::LazyLock;

pub use api::{CompressionMode, compress_and_wrap_egfx};
use bitvec::bits;
use bitvec::field::BitField as _;
use bitvec::order::Msb0;
use bitvec::slice::BitSlice;
use byteorder::WriteBytesExt as _;
pub use compressor::Compressor;
pub use wrapper::{wrap_compressed, wrap_uncompressed};

use self::circular_buffer::FixedCircularBuffer;
use self::control_messages::{BulkEncodedData, CompressionFlags, SegmentedDataPdu};
use crate::utils::Bits;

/// Sliding window size shared by compressor and decompressor.
pub(crate) const HISTORY_SIZE: usize = 2_500_000;

pub struct Decompressor {
    history: FixedCircularBuffer,
}

impl Decompressor {
    pub fn new() -> Self {
        Self {
            history: FixedCircularBuffer::new(HISTORY_SIZE),
        }
    }

    pub fn decompress(&mut self, input: &[u8], output: &mut Vec<u8>) -> Result<usize, ZgfxError> {
        let segmented_data = SegmentedDataPdu::from_buffer(input)?;

        match segmented_data {
            SegmentedDataPdu::Single(segment) => self.handle_segment(&segment, output),
            SegmentedDataPdu::Multipart {
                uncompressed_size,
                segments,
            } => {
                let mut bytes_written = 0;
                for segment in segments {
                    let written = self.handle_segment(&segment, output)?;
                    bytes_written += written;
                }

                if bytes_written != uncompressed_size {
                    Err(ZgfxError::InvalidDecompressedSize {
                        decompressed_size: bytes_written,
                        uncompressed_size,
                    })
                } else {
                    Ok(bytes_written)
                }
            }
        }
    }

    fn handle_segment(&mut self, segment: &BulkEncodedData<'_>, output: &mut Vec<u8>) -> Result<usize, ZgfxError> {
        if !segment.data.is_empty() {
            if segment.compression_flags.contains(CompressionFlags::COMPRESSED) {
                self.decompress_segment(segment.data, output)
            } else {
                self.history.write_all(segment.data)?;
                output.extend_from_slice(segment.data);

                Ok(segment.data.len())
            }
        } else {
            Ok(0)
        }
    }

    fn decompress_segment(&mut self, encoded_data: &[u8], output: &mut Vec<u8>) -> Result<usize, ZgfxError> {
        if encoded_data.is_empty() {
            return Ok(0);
        }

        let mut bits = BitSlice::from_slice(encoded_data);

        // The value of the last byte indicates the number of unused bits in the final byte
        bits = &bits
            [..8 * (encoded_data.len() - 1) - usize::from(*encoded_data.last().expect("encoded_data is not empty"))];
        let mut bits = Bits::new(bits);
        let mut bytes_written = 0;

        while !bits.is_empty() {
            let token = TOKEN_TABLE
                .iter()
                .find(|token| token.prefix == bits[..token.prefix.len()])
                .ok_or(ZgfxError::TokenBitsNotFound)?;
            let _prefix = bits.split_to(token.prefix.len());

            match token.ty {
                TokenType::NullLiteral => {
                    // The prefix value is encoded with a "0" prefix,
                    // then read 8 bits containing the byte to output.
                    let value = bits.split_to(8).load_be::<u8>();

                    self.history.write_u8(value)?;
                    output.push(value);
                    bytes_written += 1;
                }
                TokenType::Literal { literal_value } => {
                    self.history
                        .write_u8(literal_value)
                        .expect("circular buffer does not fail");
                    output.push(literal_value);
                    bytes_written += 1;
                }
                TokenType::Match {
                    distance_value_size,
                    distance_base,
                } => {
                    let written =
                        handle_match(&mut bits, distance_value_size, distance_base, &mut self.history, output)?;
                    bytes_written += written;
                }
            }
        }

        Ok(bytes_written)
    }
}

impl Default for Decompressor {
    fn default() -> Self {
        Self::new()
    }
}

fn handle_match(
    bits: &mut Bits<'_>,
    distance_value_size: usize,
    distance_base: u32,
    history: &mut FixedCircularBuffer,
    output: &mut Vec<u8>,
) -> Result<usize, ZgfxError> {
    // Each token has been assigned a different base distance
    // and number of additional value bits to be added to compute the full distance.

    let distance = usize::try_from(distance_base + bits.split_to(distance_value_size).load_be::<u32>())
        .map_err(|_| ZgfxError::InvalidIntegralConversion("token's full distance"))?;

    if distance == 0 {
        read_unencoded_bytes(bits, history, output).map_err(ZgfxError::from)
    } else {
        read_encoded_bytes(bits, distance, history, output)
    }
}

fn read_unencoded_bytes(
    bits: &mut Bits<'_>,
    history: &mut FixedCircularBuffer,
    output: &mut Vec<u8>,
) -> io::Result<usize> {
    // A match distance of zero is a special case,
    // which indicates that an unencoded run of bytes follows.
    // The count of bytes is encoded as a 15-bit value
    let length = bits.split_to(15).load_be::<usize>();

    if bits.remaining_bits_of_last_byte() > 0 {
        let pad_to_byte_boundary = 8 - bits.remaining_bits_of_last_byte();
        bits.split_to(pad_to_byte_boundary);
    }

    let unencoded_bits = bits.split_to(length * 8);

    // FIXME: not very efficient, but we need to rework the `Bits` helper and refactor a bit otherwise
    let unencoded_bits = unencoded_bits.to_bitvec();
    let unencoded_bytes = unencoded_bits.as_raw_slice();
    history.write_all(unencoded_bytes)?;
    output.extend_from_slice(unencoded_bytes);

    Ok(unencoded_bytes.len())
}

fn read_encoded_bytes(
    bits: &mut Bits<'_>,
    distance: usize,
    history: &mut FixedCircularBuffer,
    output: &mut Vec<u8>,
) -> Result<usize, ZgfxError> {
    // A match length prefix follows the token and indicates
    // how many additional bits will be needed to get the full length
    // (the number of bytes to be copied).

    let length_token_size = bits.leading_ones();
    bits.split_to(length_token_size + 1); // length token + zero bit

    let length = if length_token_size == 0 {
        // special case

        3
    } else {
        let length = bits.split_to(length_token_size + 1).load_be::<usize>();

        let length_token_size = u32::try_from(length_token_size)
            .map_err(|_| ZgfxError::InvalidIntegralConversion("length of the token size"))?;

        let base = 2usize.pow(length_token_size + 1);

        base + length
    };

    let output_length = output.len();
    history.read_with_offset(distance, length, output)?;
    history
        .write_all(&output[output_length..])
        .expect("circular buffer does not fail");

    Ok(length)
}

struct Token {
    prefix: &'static BitSlice<u8, Msb0>,
    ty: TokenType,
}

enum TokenType {
    NullLiteral,
    Literal {
        literal_value: u8,
    },
    Match {
        distance_value_size: usize,
        distance_base: u32,
    },
}

static TOKEN_TABLE: LazyLock<[Token; 40]> = LazyLock::new(|| {
    [
        Token {
            prefix: bits![static u8, Msb0; 0],
            ty: TokenType::NullLiteral,
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 1, 0, 0, 0],
            ty: TokenType::Literal { literal_value: 0x00 },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 1, 0, 0, 1],
            ty: TokenType::Literal { literal_value: 0x01 },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 1, 0, 1, 0, 0],
            ty: TokenType::Literal { literal_value: 0x02 },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 1, 0, 1, 0, 1],
            ty: TokenType::Literal { literal_value: 0x03 },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 1, 0, 1, 1, 0],
            ty: TokenType::Literal { literal_value: 0x0ff },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 1, 0, 1, 1, 1, 0],
            ty: TokenType::Literal { literal_value: 0x04 },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 1, 0, 1, 1, 1, 1],
            ty: TokenType::Literal { literal_value: 0x05 },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 1, 1, 0, 0, 0, 0],
            ty: TokenType::Literal { literal_value: 0x06 },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 1, 1, 0, 0, 0, 1],
            ty: TokenType::Literal { literal_value: 0x07 },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 1, 1, 0, 0, 1, 0],
            ty: TokenType::Literal { literal_value: 0x08 },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 1, 1, 0, 0, 1, 1],
            ty: TokenType::Literal { literal_value: 0x09 },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 1, 1, 0, 1, 0, 0],
            ty: TokenType::Literal { literal_value: 0x0a },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 1, 1, 0, 1, 0, 1],
            ty: TokenType::Literal { literal_value: 0x0b },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 1, 1, 0, 1, 1, 0],
            ty: TokenType::Literal { literal_value: 0x3a },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 1, 1, 0, 1, 1, 1],
            ty: TokenType::Literal { literal_value: 0x3b },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 1, 1, 1, 0, 0, 0],
            ty: TokenType::Literal { literal_value: 0x3c },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 1, 1, 1, 0, 0, 1],
            ty: TokenType::Literal { literal_value: 0x3d },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 1, 1, 1, 0, 1, 0],
            ty: TokenType::Literal { literal_value: 0x3e },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 1, 1, 1, 0, 1, 1],
            ty: TokenType::Literal { literal_value: 0x3f },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 1, 1, 1, 1, 0, 0],
            ty: TokenType::Literal { literal_value: 0x40 },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 1, 1, 1, 1, 0, 1],
            ty: TokenType::Literal { literal_value: 0x80 },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 1, 1, 1, 1, 1, 0, 0],
            ty: TokenType::Literal { literal_value: 0x0c },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 1, 1, 1, 1, 1, 0, 1],
            ty: TokenType::Literal { literal_value: 0x38 },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 1, 1, 1, 1, 1, 1, 0],
            ty: TokenType::Literal { literal_value: 0x39 },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 1, 1, 1, 1, 1, 1, 1],
            ty: TokenType::Literal { literal_value: 0x66 },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 0, 0, 0, 1],
            ty: TokenType::Match {
                distance_value_size: 5,
                distance_base: 0,
            },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 0, 0, 1, 0],
            ty: TokenType::Match {
                distance_value_size: 7,
                distance_base: 32,
            },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 0, 0, 1, 1],
            ty: TokenType::Match {
                distance_value_size: 9,
                distance_base: 160,
            },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 0, 1, 0, 0],
            ty: TokenType::Match {
                distance_value_size: 10,
                distance_base: 672,
            },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 0, 1, 0, 1],
            ty: TokenType::Match {
                distance_value_size: 12,
                distance_base: 1_696,
            },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 0, 1, 1, 0, 0],
            ty: TokenType::Match {
                distance_value_size: 14,
                distance_base: 5_792,
            },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 0, 1, 1, 0, 1],
            ty: TokenType::Match {
                distance_value_size: 15,
                distance_base: 22_176,
            },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 0, 1, 1, 1, 0, 0],
            ty: TokenType::Match {
                distance_value_size: 18,
                distance_base: 54_944,
            },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 0, 1, 1, 1, 0, 1],
            ty: TokenType::Match {
                distance_value_size: 20,
                distance_base: 317_088,
            },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 0, 1, 1, 1, 1, 0, 0],
            ty: TokenType::Match {
                distance_value_size: 20,
                distance_base: 1_365_664,
            },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 0, 1, 1, 1, 1, 0, 1],
            ty: TokenType::Match {
                distance_value_size: 21,
                distance_base: 2_414_240,
            },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 0, 1, 1, 1, 1, 1, 0, 0],
            ty: TokenType::Match {
                distance_value_size: 22,
                distance_base: 4_511_392,
            },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 0, 1, 1, 1, 1, 1, 0, 1],
            ty: TokenType::Match {
                distance_value_size: 23,
                distance_base: 8_705_696,
            },
        },
        Token {
            prefix: bits![static u8, Msb0; 1, 0, 1, 1, 1, 1, 1, 1, 0],
            ty: TokenType::Match {
                distance_value_size: 24,
                distance_base: 17_094_304,
            },
        },
    ]
});

#[derive(Debug)]
pub enum ZgfxError {
    IOError(io::Error),
    InvalidCompressionType,
    InvalidSegmentedDescriptor,
    InvalidDecompressedSize {
        decompressed_size: usize,
        uncompressed_size: usize,
    },
    TokenBitsNotFound,
    InvalidIntegralConversion(&'static str),
}

impl core::fmt::Display for ZgfxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::IOError(_error) => write!(f, "IO error"),
            Self::InvalidCompressionType => write!(f, "invalid compression type"),
            Self::InvalidSegmentedDescriptor => write!(f, "invalid segmented descriptor"),
            Self::InvalidDecompressedSize {
                decompressed_size,
                uncompressed_size,
            } => write!(
                f,
                "decompressed size of segments ({decompressed_size}) does not equal to uncompressed size ({uncompressed_size})",
            ),
            Self::TokenBitsNotFound => write!(f, "token bits not found"),
            Self::InvalidIntegralConversion(type_name) => {
                write!(f, "invalid `{type_name}`: out of range integral type conversion")
            }
        }
    }
}

impl core::error::Error for ZgfxError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::IOError(error) => Some(error),
            Self::InvalidCompressionType => None,
            Self::InvalidSegmentedDescriptor => None,
            Self::InvalidDecompressedSize { .. } => None,
            Self::TokenBitsNotFound => None,
            Self::InvalidIntegralConversion(_) => None,
        }
    }
}

impl From<io::Error> for ZgfxError {
    fn from(err: io::Error) -> Self {
        Self::IOError(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENCODED_ZGFX_SINGLE: [&[u8]; 5] = [
        include_bytes!("test_assets/encoded.0.bin"),
        include_bytes!("test_assets/encoded.1.bin"),
        include_bytes!("test_assets/encoded.2.bin"),
        include_bytes!("test_assets/encoded.3.bin"),
        include_bytes!("test_assets/encoded.4.bin"),
    ];

    const DECODED_ZGFX_SINGLE: [&[u8]; 5] = [
        include_bytes!("test_assets/decoded.0.bin"),
        include_bytes!("test_assets/decoded.1.bin"),
        include_bytes!("test_assets/decoded.2.bin"),
        include_bytes!("test_assets/decoded.3.bin"),
        include_bytes!("test_assets/decoded.4.bin"),
    ];

    #[test]
    fn zgfx_decompresses_multiple_single_pdus() {
        let pairs = ENCODED_ZGFX_SINGLE
            .iter()
            .copied()
            .zip(DECODED_ZGFX_SINGLE.iter().copied());
        let mut zgfx = Decompressor::new();
        let mut decompressed = Vec::with_capacity(pairs.clone().map(|(_, d)| d.len()).max().unwrap());
        for (i, (encode, decode)) in pairs.enumerate() {
            let bytes_written = zgfx.decompress(encode.as_ref(), &mut decompressed).unwrap();
            assert_eq!(decode.len(), bytes_written);
            assert_eq!(decompressed, *decode, "Failed to decompress encoded PDU #{i}");
            decompressed.clear();
        }
    }

    #[test]
    fn zgfx_decompresses_only_one_literal() {
        let buffer = [0b1100_1000, 0x03];
        let expected = vec![0x01];

        let mut zgfx = Decompressor::new();
        let mut decompressed = Vec::with_capacity(expected.len());
        zgfx.decompress_segment(buffer.as_ref(), &mut decompressed).unwrap();
        assert_eq!(decompressed, expected);
    }

    #[test]
    fn zgfx_decompresses_one_literal_with_null_prefix() {
        let buffer = [0b0011_0010, 0b1000_0000, 0x07];
        let expected = vec![0x65];

        let mut zgfx = Decompressor::new();
        let mut decompressed = Vec::with_capacity(expected.len());
        zgfx.decompress_segment(buffer.as_ref(), &mut decompressed).unwrap();
        assert_eq!(decompressed, expected);
    }

    #[test]
    fn zgfx_decompresses_only_multiple_literals() {
        let buffer = [0b1100_1110, 0b1001_1011, 0b0001_1001, 0b0100_0000, 0x06];
        let expected = vec![0x01, 0x02, 0xff, 0x65];

        let mut zgfx = Decompressor::new();
        let mut decompressed = Vec::with_capacity(expected.len());
        zgfx.decompress_segment(buffer.as_ref(), &mut decompressed).unwrap();
        assert_eq!(decompressed, expected);
    }

    #[test]
    fn zgfx_decompresses_one_literal_with_one_match_distance_1() {
        let buffer = [0b0011_0010, 0b1100_0100, 0b0011_0000, 0x1];
        let expected = vec![0x65; 1 + 4]; // literal (1) + match repeated 4 (length) + 0 times

        let mut zgfx = Decompressor::new();
        let mut decompressed = Vec::with_capacity(expected.len());
        zgfx.decompress_segment(buffer.as_ref(), &mut decompressed).unwrap();
        assert_eq!(decompressed, expected);
    }

    #[test]
    fn zgfx_decompresses_three_literals_with_one_match_distance_3_length_57() {
        let buffer = [
            0b0010_0000,
            0b1001_0000,
            0b1000_1000,
            0b0111_0001,
            0b0001_1111,
            0b1011_0010,
            0x1,
        ];
        let expected = "ABC".repeat(20);
        let expected = expected.as_bytes();

        let mut zgfx = Decompressor::new();
        let mut decompressed = Vec::with_capacity(expected.len());
        zgfx.decompress_segment(buffer.as_ref(), &mut decompressed).unwrap();
        assert_eq!(decompressed, expected);
    }

    #[test]
    fn zgfx_decompresses_one_match_with_match_unencoded_bytes() {
        let expected = "The quick brown fox jumps over the lazy dog".as_bytes();
        let mut buffer = vec![0b1000_1000, 0b0000_0000, 0b00010101, 0b1000_0000];
        buffer.extend_from_slice(expected);
        buffer.extend_from_slice(&[0x00]); // no bits unused

        let mut zgfx = Decompressor::new();
        let mut decompressed = Vec::with_capacity(expected.len());
        zgfx.decompress_segment(buffer.as_ref(), &mut decompressed).unwrap();
        assert_eq!(decompressed, expected);
    }

    #[test]
    fn zgfx_decompresses_multiple_literals_with_match_in_center_with_not_compressed() {
        let buffer = [
            0xE1, // DEBLOCK_MULTIPART
            0x03, 0x00, // 3 segments
            0x2B, 0x00, 0x00, 0x00, // 0x0000002B total bytes uncompressed
            0x11, 0x00, 0x00, 0x00, // first segment is the next 17 bytes:
            0x04, // type 4, not PACKET_COMPRESSED
            0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6B, 0x20, 0x62, 0x72, 0x6F, 0x77, 0x6E,
            0x20, // "The quick brown "
            0x0E, 0x00, 0x00, 0x00, // second segment is the next 14 bytes:
            0x04, // type 4, not PACKET_COMPRESSED
            0x66, 0x6F, 0x78, 0x20, 0x6A, 0x75, 0x6D, 0x70, 0x73, 0x20, 0x6F, 0x76, 0x65, // "fox jumps ove"
            0x10, 0x00, 0x00, 0x00, // third segment is the next 16 bytes
            0x24, // type 4 + PACKET_COMPRESSED
            0x39, 0x08, 0x0E, 0x91, 0xF8, 0xD8, 0x61, 0x3D, 0x1E, 0x44, 0x06, 0x43, 0x79, 0x9C, // encoded:
            // 0 01110010 = literal 0x72 = "r"
            // 0 00100000 = literal 0x20 = " "
            // 0 01110100 = literal 0x74 = "t"
            //
            // 10001 11111 0 = match, distance = 31, length = 3 "he "
            //
            // 0 01101100 = literal 0x6C = "l"
            // 0 01100001 = literal 0x61 = "a"
            // 0 01111010 = literal 0x7A = "z"
            // 0 01111001 = literal 0x79 = "y"
            // 0 00100000 = literal 0x20 = " "
            // 0 01100100 = literal 0x64 = "d"
            // 0 01101111 = literal 0x6F = "o"
            // 0 01100111 = literal 0x67 = "g"
            0x02, // ignore last two bits of 0x9C byte
        ];
        let expected = "The quick brown fox jumps over the lazy dog".as_bytes();

        let mut zgfx = Decompressor::new();
        let mut decompressed = Vec::with_capacity(expected.len());
        let bytes_written = zgfx.decompress(buffer.as_ref(), &mut decompressed).unwrap();
        assert_eq!(expected.len(), bytes_written);
        assert_eq!(decompressed, expected, "\n{decompressed:x?} != \n{expected:x?}");
    }

    #[test]
    fn zgfx_decompresses_single_match_unencoded_block() {
        let buffer = [
            0xe0, 0x04, 0x13, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x01, 0x06, 0x0a, 0x00, 0x04, 0x00, 0x00, 0x00,
            0x20, 0x00, 0x00, 0x00,
        ];
        let expected = vec![
            0x13, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x01, 0x06, 0x0a, 0x00, 0x04, 0x00, 0x00, 0x00, 0x20, 0x00,
            0x00, 0x00,
        ];

        let mut zgfx = Decompressor::new();
        let mut decompressed = Vec::with_capacity(expected.len());
        let bytes_written = zgfx.decompress(buffer.as_ref(), &mut decompressed).unwrap();
        assert_eq!(expected.len(), bytes_written);
        assert_eq!(decompressed, expected);
    }

    #[test]
    fn zgfx_decompresses_unencoded_block_without_padding() {
        let buffer = [0b1110_0101, 0b0001_0000, 0b0000_0000, 0b00000001, 0b1111_0000, 0x0];
        let expected = vec![0x08, 0xf0];

        let mut zgfx = Decompressor::new();
        let mut decompressed = Vec::with_capacity(expected.len());
        zgfx.decompress_segment(buffer.as_ref(), &mut decompressed).unwrap();
        assert_eq!(decompressed, expected);
    }
}
