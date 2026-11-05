/// Builds the 1 bpp AND mask for a 32 bpp pointer from the XOR data's alpha channel.
///
/// MS-RDPBCGR 2.2.9.1.1.4.4 makes the AND mask part of every color pointer. For a
/// 32 bpp pointer the alpha channel already carries the transparency, so the mask
/// sets a bit for each fully transparent pixel and clears it elsewhere, which is
/// what a Windows server sends. Each scan line is padded to a 2-byte boundary, and
/// rows are in the same order as `xor_mask`, since clients read both masks with
/// the same row order.
///
/// Some clients drop a 32 bpp pointer whose AND mask is empty and keep showing their
/// default arrow; Windows App for macOS is one. mstsc and FreeRDP accept it.
pub(super) fn and_mask_from_alpha(xor_mask: &[u8], width: u16, height: u16) -> Vec<u8> {
    let width = usize::from(width);
    let height = usize::from(height);
    let stride = width.div_ceil(16) * 2;
    let mut mask = vec![0u8; stride * height];

    for (row_idx, row) in xor_mask.chunks_exact(width * 4).take(height).enumerate() {
        for (col_idx, pixel) in row.chunks_exact(4).enumerate() {
            if pixel[3] == 0 {
                mask[row_idx * stride + col_idx / 8] |= 0x80 >> (col_idx % 8);
            }
        }
    }

    mask
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLEAR: [u8; 4] = [0x12, 0x34, 0x56, 0x00];
    const OPAQUE: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];
    const SHADOW: [u8; 4] = [0x00, 0x00, 0x00, 0x40];

    fn pixels(rows: &[&[[u8; 4]]]) -> Vec<u8> {
        rows.iter().flat_map(|row| row.iter().flatten().copied()).collect()
    }

    #[test]
    fn sets_a_bit_only_for_fully_transparent_pixels() {
        let xor = pixels(&[&[CLEAR, OPAQUE, SHADOW], &[OPAQUE, CLEAR, CLEAR]]);

        let mask = and_mask_from_alpha(&xor, 3, 2);

        // 3 pixels wide: one data byte, padded to two bytes per scan line.
        assert_eq!(mask, [0b1000_0000, 0, 0b0110_0000, 0]);
    }

    #[test]
    fn pads_each_scan_line_to_two_bytes() {
        for (width, stride) in [(1u16, 2), (16, 2), (17, 4), (32, 4), (33, 6)] {
            let xor = vec![0; usize::from(width) * 4 * 3];

            let mask = and_mask_from_alpha(&xor, width, 3);

            assert_eq!(mask.len(), stride * 3, "width {width}");
        }
    }

    #[test]
    fn marks_pixels_past_the_first_byte_of_a_scan_line() {
        let mut row = vec![OPAQUE; 10];
        row[9] = CLEAR;
        let xor = pixels(&[&row]);

        let mask = and_mask_from_alpha(&xor, 10, 1);

        assert_eq!(mask, [0, 0b0100_0000]);
    }
}
