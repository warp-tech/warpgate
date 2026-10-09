//! ClearCodec Layer 3: Subcodecs ([MS-RDPEGFX] 2.2.4.1.1.3).
//!
//! The subcodec layer encodes rectangular regions using one of three methods:
//! raw BGR pixels, NSCodec, or RLEX. Each subcodec region specifies its
//! position, dimensions, and the codec used to compress its bitmap data.

use ironrdp_core::{DecodeResult, ReadCursor, cast_length, ensure_size, invalid_field_err};

/// Subcodec identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SubcodecId {
    /// Uncompressed BGR pixels.
    Raw = 0x00,
    /// NSCodec bitmap compression (MS-RDPNSC).
    NsCodec = 0x01,
    /// Palette-indexed RLE with gradient suite encoding.
    Rlex = 0x02,
}

impl SubcodecId {
    fn from_u8(val: u8) -> DecodeResult<Self> {
        match val {
            0x00 => Ok(Self::Raw),
            0x01 => Ok(Self::NsCodec),
            0x02 => Ok(Self::Rlex),
            _ => Err(invalid_field_err!("subCodecId", "unknown subcodec ID")),
        }
    }
}

/// A decoded subcodec region.
#[derive(Debug, Clone)]
pub struct Subcodec<'a> {
    pub x_start: u16,
    pub y_start: u16,
    pub width: u16,
    pub height: u16,
    pub codec_id: SubcodecId,
    /// Raw bitmap data for this region, interpreted according to `codec_id`.
    pub bitmap_data: &'a [u8],
}

impl Subcodec<'_> {
    const NAME: &'static str = "ClearCodecSubcodec";

    /// Header: 4 x u16 + u32 + u8 = 13 bytes.
    const HEADER_SIZE: usize = 13;
}

/// Decode all subcodec regions from the subcodec layer data.
pub fn decode_subcodec_layer<'a>(data: &'a [u8]) -> DecodeResult<Vec<Subcodec<'a>>> {
    let mut regions = Vec::new();
    let mut src = ReadCursor::new(data);

    while src.len() >= Subcodec::HEADER_SIZE {
        let region = decode_single_subcodec(&mut src)?;
        regions.push(region);
    }

    Ok(regions)
}

fn decode_single_subcodec<'a>(src: &mut ReadCursor<'a>) -> DecodeResult<Subcodec<'a>> {
    ensure_size!(ctx: Subcodec::NAME, in: src, size: Subcodec::HEADER_SIZE);

    let x_start = src.read_u16();
    let y_start = src.read_u16();
    let width = src.read_u16();
    let height = src.read_u16();
    let bitmap_data_byte_count: usize = cast_length!("bitmapDataByteCount", src.read_u32())?;
    let codec_id_raw = src.read_u8();
    let codec_id = SubcodecId::from_u8(codec_id_raw)?;

    if width == 0 || height == 0 {
        return Err(invalid_field_err!("dimensions", "subcodec region has zero dimension"));
    }

    ensure_size!(ctx: Subcodec::NAME, in: src, size: bitmap_data_byte_count);
    let bitmap_data = src.read_slice(bitmap_data_byte_count);

    Ok(Subcodec {
        x_start,
        y_start,
        width,
        height,
        codec_id,
        bitmap_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_raw_subcodec() {
        // Region at (10, 20), 2x2 pixels, raw BGR = 12 bytes
        let mut data = Vec::new();
        data.extend_from_slice(&10u16.to_le_bytes()); // x_start
        data.extend_from_slice(&20u16.to_le_bytes()); // y_start
        data.extend_from_slice(&2u16.to_le_bytes()); // width
        data.extend_from_slice(&2u16.to_le_bytes()); // height
        data.extend_from_slice(&12u32.to_le_bytes()); // bitmapDataByteCount = 2*2*3 = 12
        data.push(0x00); // subCodecId = Raw
        // 4 pixels BGR
        data.extend_from_slice(&[0xFF, 0x00, 0x00]); // blue
        data.extend_from_slice(&[0x00, 0xFF, 0x00]); // green
        data.extend_from_slice(&[0x00, 0x00, 0xFF]); // red
        data.extend_from_slice(&[0xFF, 0xFF, 0xFF]); // white

        let regions = decode_subcodec_layer(&data).unwrap();
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].x_start, 10);
        assert_eq!(regions[0].y_start, 20);
        assert_eq!(regions[0].width, 2);
        assert_eq!(regions[0].height, 2);
        assert_eq!(regions[0].codec_id, SubcodecId::Raw);
        assert_eq!(regions[0].bitmap_data.len(), 12);
    }

    #[test]
    fn reject_zero_dimensions() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u16.to_le_bytes()); // x_start
        data.extend_from_slice(&0u16.to_le_bytes()); // y_start
        data.extend_from_slice(&0u16.to_le_bytes()); // width = 0 (invalid)
        data.extend_from_slice(&1u16.to_le_bytes()); // height
        data.extend_from_slice(&0u32.to_le_bytes()); // bitmapDataByteCount
        data.push(0x00); // subCodecId
        assert!(decode_subcodec_layer(&data).is_err());
    }

    #[test]
    fn reject_unknown_subcodec() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.push(0x03); // unknown subcodec
        assert!(decode_subcodec_layer(&data).is_err());
    }

    #[test]
    fn decode_multiple_subcodecs() {
        let mut data = Vec::new();
        // First region: 1x1 raw
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&3u32.to_le_bytes());
        data.push(0x00); // Raw
        data.extend_from_slice(&[0xFF, 0xFF, 0xFF]);

        // Second region: 1x1 RLEX (minimal: palette_count=1 + run)
        data.extend_from_slice(&5u16.to_le_bytes());
        data.extend_from_slice(&5u16.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&5u32.to_le_bytes());
        data.push(0x02); // RLEX
        data.push(1); // palette_count
        data.extend_from_slice(&[0x00, 0x00, 0x00]); // palette entry
        data.push(1); // run_length

        let regions = decode_subcodec_layer(&data).unwrap();
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].codec_id, SubcodecId::Raw);
        assert_eq!(regions[1].codec_id, SubcodecId::Rlex);
    }

    #[test]
    fn decode_empty_layer() {
        let regions = decode_subcodec_layer(&[]).unwrap();
        assert!(regions.is_empty());
    }
}
