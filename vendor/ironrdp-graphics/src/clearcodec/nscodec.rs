//! NSCodec payload decoding for ClearCodec layer-three regions.
//!
//! ClearCodec embeds an NSCodec Compressed Bitmap Stream ([MS-RDPNSC] 2.2.2) directly inside a positioned subcodec region ([MS-RDPEGFX] 2.2.4.1.1.3.1).
//! Unlike the classic bitmap-update transport, which wraps the stream in Extended Bitmap Data ([MS-RDPBCGR] 2.2.9.2.1.1), the containing subcodec supplies its dimensions.

use ironrdp_core::{DecodeResult, invalid_field_err};

const HEADER_SIZE: usize = 4 /* LumaPlaneByteCount */
    + 4 /* OrangeChromaPlaneByteCount */
    + 4 /* GreenChromaPlaneByteCount */
    + 4 /* AlphaPlaneByteCount */
    + 1 /* ColorLossLevel */
    + 1 /* ChromaSubsamplingLevel */
    + 2 /* Reserved */;
const RLE_END_DATA_SIZE: usize = 4;

/// Decode an NSCodec compressed bitmap stream into top-down BGRA pixels.
///
/// The stream uses AYCoCg planes, optionally with 4:2:0 chroma subsampling.
pub(super) fn decode(data: &[u8], width: u16, height: u16) -> DecodeResult<Vec<u8>> {
    #![allow(clippy::similar_names, reason = "Co and Cg are protocol-defined plane names")]

    if data.len() < HEADER_SIZE {
        return Err(invalid_field_err!(
            "bitmapData",
            "NSCodec stream is shorter than its header"
        ));
    }

    let luma_len = usize::try_from(u32::from_le_bytes(data[0..4].try_into().expect("4-byte slice")))
        .map_err(|_| invalid_field_err!("lumaPlaneByteCount", "length does not fit in usize"))?;
    let co_len = usize::try_from(u32::from_le_bytes(data[4..8].try_into().expect("4-byte slice")))
        .map_err(|_| invalid_field_err!("orangeChromaPlaneByteCount", "length does not fit in usize"))?;
    let cg_len = usize::try_from(u32::from_le_bytes(data[8..12].try_into().expect("4-byte slice")))
        .map_err(|_| invalid_field_err!("greenChromaPlaneByteCount", "length does not fit in usize"))?;
    let alpha_len = usize::try_from(u32::from_le_bytes(data[12..16].try_into().expect("4-byte slice")))
        .map_err(|_| invalid_field_err!("alphaPlaneByteCount", "length does not fit in usize"))?;
    let color_loss_level = data[16];
    let chroma_subsampling = data[17];

    if !(1..=7).contains(&color_loss_level) {
        return Err(invalid_field_err!("colorLossLevel", "must be in the range 1-7"));
    }
    if chroma_subsampling > 1 {
        return Err(invalid_field_err!("chromaSubsamplingLevel", "must be 0 or 1"));
    }
    if luma_len == 0 || co_len == 0 || cg_len == 0 {
        return Err(invalid_field_err!(
            "planeByteCount",
            "luma and chroma planes must be present"
        ));
    }

    let w = usize::from(width);
    let h = usize::from(height);
    let pixel_count = w
        .checked_mul(h)
        .ok_or_else(|| invalid_field_err!("dimensions", "width * height overflow"))?;
    let (luma_width, chroma_width, chroma_height) = if chroma_subsampling == 0 {
        (w, w, h)
    } else {
        let padded_luma_width = w
            .checked_add(7)
            .ok_or_else(|| invalid_field_err!("dimensions", "padded luma width overflow"))?
            / 8
            * 8;
        let padded_luma_height = h
            .checked_add(1)
            .ok_or_else(|| invalid_field_err!("dimensions", "padded luma height overflow"))?
            / 2
            * 2;
        (padded_luma_width, padded_luma_width / 2, padded_luma_height / 2)
    };
    let luma_size = luma_width
        .checked_mul(h)
        .ok_or_else(|| invalid_field_err!("dimensions", "luma plane size overflow"))?;
    let chroma_size = chroma_width
        .checked_mul(chroma_height)
        .ok_or_else(|| invalid_field_err!("dimensions", "chroma plane size overflow"))?;

    let payload_len = luma_len
        .checked_add(co_len)
        .and_then(|len| len.checked_add(cg_len))
        .and_then(|len| len.checked_add(alpha_len))
        .ok_or_else(|| invalid_field_err!("planeByteCount", "combined plane length overflow"))?;
    let stream_len = HEADER_SIZE
        .checked_add(payload_len)
        .ok_or_else(|| invalid_field_err!("planeByteCount", "combined plane length overflow"))?;
    if data.len() != stream_len {
        return Err(invalid_field_err!(
            "bitmapData",
            "plane lengths do not match stream length"
        ));
    }

    let luma_end = HEADER_SIZE + luma_len;
    let co_end = luma_end + co_len;
    let cg_end = co_end + cg_len;
    let luma = decode_plane(&data[HEADER_SIZE..luma_end], luma_size, "lumaPlaneByteCount")?;
    let co = decode_plane(&data[luma_end..co_end], chroma_size, "orangeChromaPlaneByteCount")?;
    let cg = decode_plane(&data[co_end..cg_end], chroma_size, "greenChromaPlaneByteCount")?;
    let alpha = if alpha_len == 0 {
        None
    } else {
        Some(decode_plane(&data[cg_end..], pixel_count, "alphaPlaneByteCount")?)
    };

    let mut pixels = Vec::with_capacity(pixel_count * 4);
    for y in 0..h {
        for x in 0..w {
            let luma_index = y * luma_width + x;
            let chroma_index = if chroma_subsampling == 0 {
                y * chroma_width + x
            } else {
                (y / 2) * chroma_width + x / 2
            };
            let (red, green, blue) =
                ycocg_to_rgb(color_loss_level, luma[luma_index], co[chroma_index], cg[chroma_index]);

            pixels.extend_from_slice(&[blue, green, red, alpha.as_ref().map_or(0xFF, |plane| plane[y * w + x])]);
        }
    }

    Ok(pixels)
}

fn decode_plane(data: &[u8], expected_len: usize, field: &'static str) -> DecodeResult<Vec<u8>> {
    if data.len() > expected_len {
        return Err(invalid_field_err!(
            field,
            "compressed plane is larger than its raw size"
        ));
    }
    if data.len() == expected_len {
        return Ok(data.to_vec());
    }
    if data.len() < RLE_END_DATA_SIZE {
        return Err(invalid_field_err!(field, "RLE plane is missing its four-byte EndData"));
    }

    let segments_end = data.len() - RLE_END_DATA_SIZE;
    let mut decoded = Vec::with_capacity(expected_len);
    let mut offset = 0;
    while offset < segments_end {
        let value = data[offset];
        offset += 1;

        let run_len = if offset < segments_end && data[offset] == value {
            offset += 1;
            if offset == segments_end {
                return Err(invalid_field_err!(field, "RLE run is missing its length factor"));
            }

            let factor = data[offset];
            offset += 1;
            if factor == u8::MAX {
                if segments_end - offset < 4 {
                    return Err(invalid_field_err!(field, "long RLE run is missing its length factor"));
                }
                let length = usize::try_from(u32::from_le_bytes(
                    data[offset..offset + 4].try_into().expect("4-byte slice"),
                ))
                .map_err(|_| invalid_field_err!(field, "long RLE run length does not fit in usize"))?;
                offset += 4;
                length
            } else {
                usize::from(factor) + 2
            }
        } else {
            1
        };

        let new_len = decoded
            .len()
            .checked_add(run_len)
            .ok_or_else(|| invalid_field_err!(field, "RLE output length overflow"))?;
        if new_len > expected_len {
            return Err(invalid_field_err!(field, "RLE output exceeds plane size"));
        }
        decoded.resize(new_len, value);
    }

    decoded.extend_from_slice(&data[segments_end..]);
    if decoded.len() != expected_len {
        return Err(invalid_field_err!(field, "RLE output does not fill plane size"));
    }

    Ok(decoded)
}

fn ycocg_to_rgb(color_loss_level: u8, luma: u8, co: u8, cg: u8) -> (u8, u8, u8) {
    // Combine color-loss recovery (MS-RDPEGDI 3.1.9.1.4) and the AYCoCg inverse
    // transform (MS-RDPEGDI 3.1.9.1.2) without a lossy intermediate division.
    // This is the integer form used by the RDP6 bitmap decoder.
    let chroma_shift = color_loss_level - 1;
    let co = i16::from(co.wrapping_shl(u32::from(chroma_shift)).cast_signed());
    let cg = i16::from(cg.wrapping_shl(u32::from(chroma_shift)).cast_signed());
    let luma = i16::from(luma);
    let t = luma - cg;

    (clamp_u8(t + co), clamp_u8(luma + cg), clamp_u8(t - co))
}

fn clamp_u8(value: i16) -> u8 {
    u8::try_from(value.clamp(0, 255)).expect("value is clamped to u8 range")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(luma: &[u8], co: &[u8], cg: &[u8], alpha: &[u8], color_loss_level: u8, subsampled: bool) -> Vec<u8> {
        let mut data = Vec::with_capacity(HEADER_SIZE + luma.len() + co.len() + cg.len() + alpha.len());
        for plane in [luma, co, cg, alpha] {
            data.extend_from_slice(
                &u32::try_from(plane.len())
                    .expect("test plane length fits")
                    .to_le_bytes(),
            );
        }
        data.extend_from_slice(&[color_loss_level, u8::from(subsampled), 0, 0]);
        data.extend_from_slice(luma);
        data.extend_from_slice(co);
        data.extend_from_slice(cg);
        data.extend_from_slice(alpha);
        data
    }

    #[test]
    fn decodes_raw_opaque_black_pixel() {
        let data = stream(&[0], &[0], &[0], &[0xFF], 3, false);
        assert_eq!(decode(&data, 1, 1).unwrap(), [0, 0, 0, 0xFF]);
    }

    #[test]
    fn decodes_rle_plane_with_raw_end_data() {
        let plane = decode_plane(&[0x33, 0x33, 0x02, 1, 2, 3, 4], 8, "test").unwrap();
        assert_eq!(plane, [0x33, 0x33, 0x33, 0x33, 1, 2, 3, 4]);
    }

    #[test]
    fn decodes_rle_luma_plane() {
        let data = stream(&[0x33, 0x33, 0x02, 1, 2, 3, 4], &[0; 8], &[0; 8], &[], 1, false);
        let pixels = decode(&data, 4, 2).unwrap();
        let luma = [0x33, 0x33, 0x33, 0x33, 1, 2, 3, 4];

        for (pixel, luma) in pixels.chunks_exact(4).zip(luma) {
            assert_eq!(pixel, [luma, luma, luma, 0xFF]);
        }
    }

    #[test]
    fn decodes_long_rle_run() {
        let mut compressed = vec![0x55, 0x55, 0xFF];
        compressed.extend_from_slice(&296u32.to_le_bytes());
        compressed.extend_from_slice(&[1, 2, 3, 4]);
        let plane = decode_plane(&compressed, 300, "test").unwrap();
        assert_eq!(&plane[..296], &[0x55; 296]);
        assert_eq!(&plane[296..], &[1, 2, 3, 4]);
    }

    #[test]
    fn rejects_rle_overrun() {
        assert!(decode_plane(&[0x33, 0x33, 0x04, 1, 2, 3, 4], 9, "test").is_err());
    }

    #[test]
    fn rejects_invalid_header() {
        assert!(decode(&[], 1, 1).is_err());
    }

    #[test]
    fn rejects_invalid_color_loss_level() {
        let data = stream(&[0], &[0], &[0], &[], 0, false);
        assert!(decode(&data, 1, 1).is_err());
    }

    #[test]
    fn rejects_truncated_payload() {
        let mut data = stream(&[0], &[0], &[0], &[], 1, false);
        data.pop();
        assert!(decode(&data, 1, 1).is_err());
    }

    #[test]
    fn decodes_subsampled_padded_planes() {
        // A 3x3 image with padded 8x3 luma and 4x2 chroma planes. The decoder
        // must address only the original 3x3 image area.
        let data = stream(&[100; 24], &[0; 8], &[0; 8], &[0xFF; 9], 3, true);
        let pixels = decode(&data, 3, 3).unwrap();
        assert_eq!(pixels.len(), 3 * 3 * 4);
        assert!(pixels.chunks_exact(4).all(|pixel| pixel == [100, 100, 100, 0xFF]));
    }

    #[test]
    fn decodes_no_alpha_bgra_without_channel_swap() {
        let data = stream(&[100], &[10], &[0], &[], 1, false);
        assert_eq!(decode(&data, 1, 1).unwrap(), [90, 100, 110, 0xFF]);
    }

    #[test]
    fn restores_chroma_in_a_wrapping_signed_byte() {
        let data = stream(&[93], &[40], &[63], &[], 3, false);
        assert_eq!(decode(&data, 1, 1).unwrap(), [193, 89, 1, 0xFF]);
    }
}
