use std::sync::LazyLock;

use ironrdp_core::{decode, encode};

use super::*;

const BITMAP_BUFFER: [u8; 114] = [
    0x01, 0x00, // Bitmap update type = must be PDATETYPE_BITMAP (0x0001)
    0x01, 0x00, // Number of rectangles = 1
    // Rectangle
    0x00, 0x07, // Left bound of the rectangle = 1792
    0x00, 0x04, // Top bound of the rectangle = 1024
    0x3f, 0x07, // Right bound of the rectangle = 1855
    0x37, 0x04, // Bottom bound of the rectangle = 1079
    0x40, 0x00, // The width of the rectangle = 64
    0x38, 0x00, // The height of the rectangle = 56
    0x10, 0x00, // The color depth of the rectangle data in bits-per-pixel = 16
    0x01,
    // The flag which describes the format of the bitmap data:
    // BITMAP_COMPRESSION | !NO_BITMAP_COMPRESSION_HDR => bitmapComprHdr is present
    0x00, // The size in bytes of the data in CompressedDataHeader and bitmap_data = 92
    0x5c, 0x00, // CompressedDataHeader
    0x00, 0x00, // FirstRowSize, must be set to 0x0000 = 0
    0x50, 0x00, // MainBodySize - size in bytes of the compressed bitmap data = 80
    0x1c, 0x00, // ScanWidth - width of the bitmap in pixels(must be divisible by 4) = 28
    // UncompressedSize - size in bytes of the bitmap data after it has been decompressed = 4
    0x04, 0x00, // Bitmap data
    0x21, 0x00, 0x21, 0x00, 0x01, 0x00, 0x20, 0x09, 0x84, 0x21, 0x00, 0x21, 0x00, 0x21, 0x00, 0x12, 0x00, 0x10, 0xd8,
    0x20, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x1e, 0x21, 0x00, 0x00, 0xa8, 0x83, 0x21, 0x00,
    0x55, 0xad, 0xff, 0xff, 0x45, 0x29, 0x7a, 0xce, 0xa3, 0x10, 0x0e, 0x82, 0x45, 0x29, 0x7a, 0xce, 0xd5, 0x82, 0x10,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x80, 0x0e, 0x45, 0x29, 0x9e, 0xf7, 0xff, 0xff, 0x9e, 0xf7, 0x45, 0x29, 0x21, 0x00,
    0x55, 0xad, 0x10, 0x10, 0xa8, 0xd8, 0x60, 0x12,
];

static BITMAP: LazyLock<BitmapUpdateData<'static>> = LazyLock::new(|| BitmapUpdateData {
    rectangles: {
        let vec = vec![BitmapData {
            rectangle: InclusiveRectangle {
                left: 1792,
                top: 1024,
                right: 1855,
                bottom: 1079,
            },
            width: 64,
            height: 56,
            bits_per_pixel: 16,
            compression_flags: Compression::BITMAP_COMPRESSION,
            compressed_data_header: Some(CompressedDataHeader {
                main_body_size: 80,
                scan_width: 28,
                uncompressed_size: 4,
            }),
            bitmap_data: &BITMAP_BUFFER[30..],
        }];
        vec
    },
});

#[test]
fn from_buffer_bitmap_data_parsses_correctly() {
    let actual = decode::<BitmapUpdateData<'_>>(BITMAP_BUFFER.as_ref()).unwrap();
    assert_eq!(*BITMAP, actual);
}

#[test]
fn to_buffer_bitmap_data_serializes_correctly() {
    let expected = BITMAP_BUFFER.as_ref();
    let mut buffer = vec![0; expected.len()];
    encode(&*BITMAP, buffer.as_mut_slice()).unwrap();
    assert_eq!(expected, buffer.as_slice());
}

#[test]
fn bitmap_data_length_is_correct() {
    let actual = decode::<BitmapUpdateData<'_>>(BITMAP_BUFFER.as_ref()).unwrap();
    let actual = actual.rectangles.first().unwrap().bitmap_data.len();
    assert_eq!(BITMAP_BUFFER[30..].len(), actual)
}
