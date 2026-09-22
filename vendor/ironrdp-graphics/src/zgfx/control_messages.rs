use bit_field::BitField as _;
use bitflags::bitflags;
use byteorder::{LittleEndian, ReadBytesExt as _};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive as _;

use super::ZgfxError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SegmentedDataPdu<'a> {
    Single(BulkEncodedData<'a>),
    Multipart {
        uncompressed_size: usize,
        segments: Vec<BulkEncodedData<'a>>,
    },
}

impl<'a> SegmentedDataPdu<'a> {
    pub(crate) fn from_buffer(mut buffer: &'a [u8]) -> Result<Self, ZgfxError> {
        let descriptor =
            SegmentedDescriptor::from_u8(buffer.read_u8()?).ok_or(ZgfxError::InvalidSegmentedDescriptor)?;

        match descriptor {
            SegmentedDescriptor::Single => Ok(SegmentedDataPdu::Single(BulkEncodedData::from_buffer(buffer)?)),
            SegmentedDescriptor::Multipart => {
                let segment_count = usize::from(buffer.read_u16::<LittleEndian>()?);
                let uncompressed_size = usize::try_from(buffer.read_u32::<LittleEndian>()?)
                    .map_err(|_| ZgfxError::InvalidIntegralConversion("segments uncompressed size"))?;

                let mut segments = Vec::with_capacity(segment_count);
                for _ in 0..segment_count {
                    let size = usize::try_from(buffer.read_u32::<LittleEndian>()?)
                        .map_err(|_| ZgfxError::InvalidIntegralConversion("segment data size"))?;
                    let (segment_data, new_buffer) = buffer.split_at(size);
                    buffer = new_buffer;

                    segments.push(BulkEncodedData::from_buffer(segment_data)?);
                }

                Ok(SegmentedDataPdu::Multipart {
                    uncompressed_size,
                    segments,
                })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BulkEncodedData<'a> {
    pub(crate) compression_flags: CompressionFlags,
    pub(crate) data: &'a [u8],
}

impl<'a> BulkEncodedData<'a> {
    pub(crate) fn from_buffer(mut buffer: &'a [u8]) -> Result<Self, ZgfxError> {
        let compression_type_and_flags = buffer.read_u8()?;
        let _compression_type = CompressionType::from_u8(compression_type_and_flags.get_bits(..4))
            .ok_or(ZgfxError::InvalidCompressionType)?;
        let compression_flags = CompressionFlags::from_bits_retain(compression_type_and_flags.get_bits(4..));

        Ok(Self {
            compression_flags,
            data: buffer,
        })
    }
}

#[derive(Debug, Copy, Clone, PartialEq, FromPrimitive)]
enum SegmentedDescriptor {
    Single = 0xe0,
    Multipart = 0xe1,
}

#[derive(Debug, Copy, Clone, PartialEq, FromPrimitive)]
enum CompressionType {
    Rdp8 = 0x4,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct CompressionFlags: u8 {
        const COMPRESSED = 0x2;

        const _ = !0;
    }
}

#[cfg(test)]
mod test {
    use std::sync::LazyLock;

    use super::*;

    const SINGLE_SEGMENTED_DATA_PDU_BUFFER: [u8; 17] = [
        0xe0, // descriptor
        0x24, // flags and compression type
        0x09, 0xe3, 0x18, 0x0a, 0x44, 0x8d, 0x37, 0xf4, 0xc6, 0xe8, 0xa0, 0x20, 0xc6, 0x30, 0x01, // data
    ];

    const MULTIPART_SEGMENTED_DATA_PDU_BUFFER: [u8; 66] = [
        0xE1, // descriptor
        0x03, 0x00, // segment count
        0x2B, 0x00, 0x00, 0x00, // uncompressed size
        0x11, 0x00, 0x00, 0x00, // size of the first segment
        0x04, // the first segment: flags and compression type
        0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6B, 0x20, 0x62, 0x72, 0x6F, 0x77, 0x6E,
        0x20, // the first segment: data
        0x0E, 0x00, 0x00, 0x00, // size of the second segment
        0x04, // the second segment: flags and compression type
        0x66, 0x6F, 0x78, 0x20, 0x6A, 0x75, 0x6D, 0x70, 0x73, 0x20, 0x6F, 0x76, 0x65, // the second segment: data
        0x10, 0x00, 0x00, 0x00, // size of the third segment
        0x24, // the third segment: flags and compression type
        0x39, 0x08, 0x0E, 0x91, 0xF8, 0xD8, 0x61, 0x3D, 0x1E, 0x44, 0x06, 0x43, 0x79, 0x9C,
        0x02, // the third segment: data
    ];

    static SINGLE_SEGMENTED_DATA_PDU: LazyLock<SegmentedDataPdu<'static>> = LazyLock::new(|| {
        SegmentedDataPdu::Single(BulkEncodedData {
            compression_flags: CompressionFlags::COMPRESSED,
            data: &SINGLE_SEGMENTED_DATA_PDU_BUFFER[2..],
        })
    });
    static MULTIPART_SEGMENTED_DATA_PDU: LazyLock<SegmentedDataPdu<'static>> =
        LazyLock::new(|| SegmentedDataPdu::Multipart {
            uncompressed_size: 0x2B,
            segments: vec![
                BulkEncodedData {
                    compression_flags: CompressionFlags::empty(),
                    data: &MULTIPART_SEGMENTED_DATA_PDU_BUFFER[12..12 + 16],
                },
                BulkEncodedData {
                    compression_flags: CompressionFlags::empty(),
                    data: &MULTIPART_SEGMENTED_DATA_PDU_BUFFER[33..33 + 13],
                },
                BulkEncodedData {
                    compression_flags: CompressionFlags::COMPRESSED,
                    data: &MULTIPART_SEGMENTED_DATA_PDU_BUFFER[51..],
                },
            ],
        });

    #[test]
    fn from_buffer_correctly_parses_zgfx_single_segmented_data_pdu() {
        let buffer = SINGLE_SEGMENTED_DATA_PDU_BUFFER.as_ref();

        assert_eq!(
            *SINGLE_SEGMENTED_DATA_PDU,
            SegmentedDataPdu::from_buffer(buffer).unwrap()
        );
    }

    #[test]
    fn from_buffer_correctly_parses_zgfx_multipart_segmented_data_pdu() {
        let buffer = MULTIPART_SEGMENTED_DATA_PDU_BUFFER.as_ref();

        assert_eq!(
            *MULTIPART_SEGMENTED_DATA_PDU,
            SegmentedDataPdu::from_buffer(buffer).unwrap()
        );
    }
}
