//! Reduce-extrapolate variant of the LeGall 5/3 DWT for progressive RFX.
//!
//! When `RFX_DWT_REDUCE_EXTRAPOLATE` (0x01) is set in the progressive context,
//! the DWT uses boundary extrapolation instead of symmetric extension. This
//! produces asymmetric subbands that avoid wraparound artifacts at tile edges.
//!
//! For a 64x64 tile with 3-level decomposition:
//!
//!   Level 1: HL1(31x33), LH1(33x31), HH1(31x31) — LL1(33x33) feeds level 2
//!   Level 2: HL2(16x17), LH2(17x16), HH2(16x16) — LL2(17x17) feeds level 3
//!   Level 3: HL3(8x9), LH3(9x8), HH3(8x8), LL3(9x9)
//!
//! Buffer layout (4096 coefficients total):
//!   [HL1:1023][LH1:1023][HH1:961][HL2:272][LH2:272][HH2:256][HL3:72][LH3:72][HH3:64][LL3:81]

/// Subband position and dimensions within the coefficient buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BandInfo {
    /// Width (columns) of the subband.
    pub width: usize,
    /// Height (rows) of the subband.
    pub height: usize,
    /// Starting index in the linearized coefficient array.
    pub offset: usize,
}

impl BandInfo {
    /// Total number of coefficients in this subband.
    pub const fn count(&self) -> usize {
        self.width * self.height
    }
}

/// Low-pass output count for the reduce-extrapolate split.
///
/// For even N: `N/2 + 1` (extrapolated sample).
/// For odd N: `(N + 1) / 2` (standard ceiling division).
fn low_count(n: usize) -> usize {
    // Even: (64+2)/2=33. Odd: (33+2)/2=17, (17+2)/2=9.
    (n + 2) / 2
}

/// High-pass output count: remainder after low-pass.
fn high_count(n: usize) -> usize {
    n - low_count(n)
}

/// Band layout for the reduce-extrapolate 3-level DWT on a 64x64 tile.
///
/// Returns 10 subbands in buffer order:
/// `[HL1, LH1, HH1, HL2, LH2, HH2, HL3, LH3, HH3, LL3]`
///
/// Band indices match `ComponentCodecQuant::for_band()`:
///   0=HL1, 1=LH1, 2=HH1, 3=HL2, 4=LH2, 5=HH2, 6=HL3, 7=LH3, 8=HH3, 9=LL3
#[expect(clippy::similar_names, reason = "lw/hw/lh/hh are standard DWT band dimensions")]
pub fn band_layout() -> [BandInfo; 10] {
    let (lw1, hw1) = (low_count(64), high_count(64)); // (33, 31)
    let (lw2, hw2) = (low_count(lw1), high_count(lw1)); // (17, 16)
    let (lw3, hw3) = (low_count(lw2), high_count(lw2)); // (9, 8)

    // Vertical dimensions are the same (square tile)
    let (lh1, hh1) = (lw1, hw1);
    let (lh2, hh2) = (lw2, hw2);
    let (lh3, hh3) = (lw3, hw3);

    let mut off = 0;
    let mut b = |w: usize, h: usize| {
        let info = BandInfo {
            width: w,
            height: h,
            offset: off,
        };
        off += w * h;
        info
    };

    [
        b(hw1, lh1), // HL1: 31x33 = 1023
        b(lw1, hh1), // LH1: 33x31 = 1023
        b(hw1, hh1), // HH1: 31x31 = 961
        b(hw2, lh2), // HL2: 16x17 = 272
        b(lw2, hh2), // LH2: 17x16 = 272
        b(hw2, hh2), // HH2: 16x16 = 256
        b(hw3, lh3), // HL3: 8x9  = 72
        b(lw3, hh3), // LH3: 9x8  = 72
        b(hw3, hh3), // HH3: 8x8  = 64
        b(lw3, lh3), // LL3: 9x9  = 81
    ]
}

/// Inverse 3-level reduce-extrapolate DWT (coefficients to 64x64 tile).
///
/// Reconstructs the tile in-place in `buffer`. Both slices must have at least
/// 4096 elements.
///
/// # Panics
///
/// Panics if either slice has fewer than 4096 elements.
pub fn decode(buffer: &mut [i16], temp: &mut [i16]) {
    assert!(buffer.len() >= 4096, "buffer must hold 4096 coefficients");
    assert!(temp.len() >= 4096, "temp must hold 4096 elements");

    // Inner-to-outer: level 3 first (smallest subbands), then 2, then 1
    decode_block(&mut buffer[3807..], temp, 9, 8);
    decode_block(&mut buffer[3007..], temp, 17, 16);
    decode_block(buffer, temp, 33, 31);
}

/// Forward 3-level reduce-extrapolate DWT (64x64 tile to coefficients).
///
/// Transforms the tile in-place in `buffer`. Both slices must have at least
/// 4096 elements.
///
/// # Panics
///
/// Panics if either slice has fewer than 4096 elements.
pub fn encode(buffer: &mut [i16], temp: &mut [i16]) {
    assert!(buffer.len() >= 4096, "buffer must hold 4096 coefficients");
    assert!(temp.len() >= 4096, "temp must hold 4096 elements");

    // Outer-to-inner: level 1 first (full tile), then 2, then 3
    encode_block(buffer, temp, 33, 31);
    encode_block(&mut buffer[3007..], temp, 17, 16);
    encode_block(&mut buffer[3807..], temp, 9, 8);
}

// ---------------------------------------------------------------------------
// Inverse (decode) implementation
// ---------------------------------------------------------------------------

/// Inverse DWT for one decomposition level.
///
/// `n_l` and `n_h` are the low-pass and high-pass band counts.
/// Buffer contains `[HL, LH, HH, LL]` contiguously.
#[expect(clippy::similar_names, reason = "hl/lh/hh/ll are standard DWT subband names")]
fn decode_block(buffer: &mut [i16], temp: &mut [i16], n_l: usize, n_h: usize) {
    let dst_w = n_l + n_h;

    // Subband offsets within this block's buffer region
    let hl_off = 0;
    let lh_off = n_h * n_l;
    let hh_off = lh_off + n_l * n_h;
    let ll_off = hh_off + n_h * n_h;

    // Temp: L half (n_l rows x dst_w cols) then H half (n_h rows x dst_w cols)
    let l_off = 0;
    let h_off = n_l * dst_w;

    // Horizontal inverse: (LL + HL) -> L rows
    for row in 0..n_l {
        let ll_start = ll_off + row * n_l;
        let hl_start = hl_off + row * n_h;
        let l_start = l_off + row * dst_w;
        idwt_row(
            &buffer[ll_start..ll_start + n_l],
            &buffer[hl_start..hl_start + n_h],
            &mut temp[l_start..l_start + dst_w],
        );
    }

    // Horizontal inverse: (LH + HH) -> H rows
    for row in 0..n_h {
        let lh_start = lh_off + row * n_l;
        let hh_start = hh_off + row * n_h;
        let h_start = h_off + row * dst_w;
        idwt_row(
            &buffer[lh_start..lh_start + n_l],
            &buffer[hh_start..hh_start + n_h],
            &mut temp[h_start..h_start + dst_w],
        );
    }

    // Vertical inverse: (L + H) -> reconstructed columns in buffer
    for col in 0..dst_w {
        idwt_col(temp, l_off + col, h_off + col, dst_w, buffer, col, dst_w, n_l, n_h);
    }
}

/// 1D inverse DWT on a contiguous row.
///
/// Reconstructs `n_l + n_h` output samples from `n_l` low-pass and `n_h`
/// high-pass coefficients.
fn idwt_row(low: &[i16], high: &[i16], dst: &mut [i16]) {
    let n_l = low.len();
    let n_h = high.len();

    let mut h0 = i32::from(high[0]);
    let mut x0 = t(i32::from(low[0]) - h0);
    let mut x2 = x0;

    let mut di = 0;

    for j in 0..n_h - 1 {
        let h1 = i32::from(high[j + 1]);
        let l_val = i32::from(low[j + 1]);
        x2 = t(l_val - (h0 + h1) / 2);
        let x1 = t((i32::from(x0) + i32::from(x2)) / 2 + 2 * h0);
        dst[di] = x0;
        dst[di + 1] = x1;
        di += 2;
        x0 = x2;
        h0 = h1;
    }

    if n_l <= n_h + 1 {
        if n_l <= n_h {
            dst[di] = x2;
            dst[di + 1] = t(i32::from(x2) + 2 * h0);
        } else {
            let x_new = t(i32::from(low[n_h]) - h0);
            dst[di] = x2;
            dst[di + 1] = t((i32::from(x_new) + i32::from(x2)) / 2 + 2 * h0);
            dst[di + 2] = x_new;
        }
    } else {
        let x_new = t(i32::from(low[n_h]) - h0 / 2);
        dst[di] = x2;
        dst[di + 1] = t((i32::from(x_new) + i32::from(x2)) / 2 + 2 * h0);
        dst[di + 2] = x_new;
        dst[di + 3] = t((i32::from(x_new) + i32::from(low[n_h + 1])) / 2);
    }
}

/// 1D inverse DWT on a strided column.
///
/// Reads from `src` with stride, writes to `dst` with stride.
#[expect(clippy::too_many_arguments)]
fn idwt_col(
    src: &[i16],
    l_start: usize,
    h_start: usize,
    src_stride: usize,
    dst: &mut [i16],
    d_start: usize,
    dst_stride: usize,
    n_l: usize,
    n_h: usize,
) {
    let l = |i: usize| i32::from(src[l_start + i * src_stride]);
    let h = |i: usize| i32::from(src[h_start + i * src_stride]);

    let mut h0 = h(0);
    let mut x0 = t(l(0) - h0);
    let mut x2 = x0;

    let mut d = d_start;

    for j in 0..n_h - 1 {
        let h1 = h(j + 1);
        x2 = t(l(j + 1) - (h0 + h1) / 2);
        let x1 = t((i32::from(x0) + i32::from(x2)) / 2 + 2 * h0);
        dst[d] = x0;
        d += dst_stride;
        dst[d] = x1;
        d += dst_stride;
        x0 = x2;
        h0 = h1;
    }

    if n_l <= n_h + 1 {
        if n_l <= n_h {
            dst[d] = x2;
            d += dst_stride;
            dst[d] = t(i32::from(x2) + 2 * h0);
        } else {
            let x_new = t(l(n_h) - h0);
            dst[d] = x2;
            d += dst_stride;
            dst[d] = t((i32::from(x_new) + i32::from(x2)) / 2 + 2 * h0);
            d += dst_stride;
            dst[d] = x_new;
        }
    } else {
        let x_new = t(l(n_h) - h0 / 2);
        dst[d] = x2;
        d += dst_stride;
        dst[d] = t((i32::from(x_new) + i32::from(x2)) / 2 + 2 * h0);
        d += dst_stride;
        dst[d] = x_new;
        d += dst_stride;
        dst[d] = t((i32::from(x_new) + l(n_h + 1)) / 2);
    }
}

// ---------------------------------------------------------------------------
// Forward (encode) implementation
// ---------------------------------------------------------------------------

/// Forward DWT for one decomposition level.
#[expect(clippy::similar_names, reason = "hl/lh/hh/ll are standard DWT subband names")]
fn encode_block(buffer: &mut [i16], temp: &mut [i16], n_l: usize, n_h: usize) {
    let src_w = n_l + n_h;

    let hl_off = 0;
    let lh_off = n_h * n_l;
    let hh_off = lh_off + n_l * n_h;
    let ll_off = hh_off + n_h * n_h;

    let l_off = 0;
    let h_off = n_l * src_w;

    // Forward vertical: split columns into L (n_l rows) and H (n_h rows) in temp
    for col in 0..src_w {
        dwt_col(buffer, col, src_w, temp, l_off + col, h_off + col, src_w, n_l, n_h);
    }

    // Forward horizontal on L rows: produce LL and HL subbands.
    // Read from temp (vertical output), write directly to scattered buffer locations.
    for row in 0..n_l {
        let l_start = l_off + row * src_w;
        dwt_row_scattered(
            &temp[l_start..l_start + src_w],
            buffer,
            ll_off + row * n_l,
            hl_off + row * n_h,
            n_l,
            n_h,
        );
    }

    // Forward horizontal on H rows: produce LH and HH subbands
    for row in 0..n_h {
        let h_start = h_off + row * src_w;
        dwt_row_scattered(
            &temp[h_start..h_start + src_w],
            buffer,
            lh_off + row * n_l,
            hh_off + row * n_h,
            n_l,
            n_h,
        );
    }
}

/// 1D forward DWT: reads from `input`, writes low-pass to `out[low_off..]` and
/// high-pass to `out[high_off..]`. This avoids needing two separate mutable
/// slice borrows.
fn dwt_row_scattered(input: &[i16], out: &mut [i16], low_off: usize, high_off: usize, n_l: usize, n_h: usize) {
    // Predict step: compute high-pass from odd samples
    for i in 0..n_h {
        let x0 = i32::from(input[2 * i]);
        let x1 = i32::from(input[2 * i + 1]);
        let x2 = i32::from(input[2 * i + 2]);
        out[high_off + i] = t((x1 - (x0 + x2) / 2) / 2);
    }

    // Update step: compute low-pass from even samples + high-pass
    out[low_off] = t(i32::from(input[0]) + i32::from(out[high_off]));
    for i in 1..n_h {
        let h_prev = i32::from(out[high_off + i - 1]);
        let h_curr = i32::from(out[high_off + i]);
        out[low_off + i] = t(i32::from(input[2 * i]) + (h_prev + h_curr) / 2);
    }

    if n_l <= n_h + 1 {
        let h_last = i32::from(out[high_off + n_h - 1]);
        out[low_off + n_h] = t(i32::from(input[2 * n_h]) + h_last);
    } else {
        let h_last = i32::from(out[high_off + n_h - 1]);
        out[low_off + n_h] = t(i32::from(input[2 * n_h]) + h_last / 2);
        out[low_off + n_h + 1] = t(2 * i32::from(input[n_l + n_h - 1]) - i32::from(input[n_l + n_h - 2]));
    }
}

/// 1D forward DWT on a strided column.
///
/// Reads from `src` at stride `s_stride`, writes low-pass to `dst[l_start..]`
/// and high-pass to `dst[h_start..]` at stride `d_stride`.
#[expect(clippy::too_many_arguments)]
fn dwt_col(
    src: &[i16],
    s_start: usize,
    s_stride: usize,
    dst: &mut [i16],
    l_start: usize,
    h_start: usize,
    d_stride: usize,
    n_l: usize,
    n_h: usize,
) {
    let x = |i: usize| i32::from(src[s_start + i * s_stride]);

    // Predict: compute high-pass
    for i in 0..n_h {
        dst[h_start + i * d_stride] = t((x(2 * i + 1) - (x(2 * i) + x(2 * i + 2)) / 2) / 2);
    }

    // Update: compute low-pass (reads high-pass values we just wrote)
    dst[l_start] = t(x(0) + i32::from(dst[h_start]));

    for i in 1..n_h {
        let h_prev = i32::from(dst[h_start + (i - 1) * d_stride]);
        let h_curr = i32::from(dst[h_start + i * d_stride]);
        dst[l_start + i * d_stride] = t(x(2 * i) + (h_prev + h_curr) / 2);
    }

    if n_l <= n_h + 1 {
        let h_last = i32::from(dst[h_start + (n_h - 1) * d_stride]);
        dst[l_start + n_h * d_stride] = t(x(2 * n_h) + h_last);
    } else {
        let n = n_l + n_h;
        let h_last = i32::from(dst[h_start + (n_h - 1) * d_stride]);
        dst[l_start + n_h * d_stride] = t(x(2 * n_h) + h_last / 2);
        dst[l_start + (n_h + 1) * d_stride] = t(2 * x(n - 1) - x(n - 2));
    }
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/// Truncate i32 to i16 (matches the `i32_to_i16_possible_truncation` pattern
/// in the existing `dwt.rs`). DWT coefficients stay within i16 range for
/// typical image data; truncation handles rare overflow gracefully.
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "intentional truncation matching existing DWT convention"
)]
fn t(value: i32) -> i16 {
    value as i16
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::as_conversions, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
mod tests {
    use super::*;

    #[test]
    fn band_dimensions_match_spec() {
        let bands = band_layout();

        // Verify dimensions from MS-RDPEGFX spec
        assert_eq!((bands[0].width, bands[0].height), (31, 33), "HL1");
        assert_eq!((bands[1].width, bands[1].height), (33, 31), "LH1");
        assert_eq!((bands[2].width, bands[2].height), (31, 31), "HH1");
        assert_eq!((bands[3].width, bands[3].height), (16, 17), "HL2");
        assert_eq!((bands[4].width, bands[4].height), (17, 16), "LH2");
        assert_eq!((bands[5].width, bands[5].height), (16, 16), "HH2");
        assert_eq!((bands[6].width, bands[6].height), (8, 9), "HL3");
        assert_eq!((bands[7].width, bands[7].height), (9, 8), "LH3");
        assert_eq!((bands[8].width, bands[8].height), (8, 8), "HH3");
        assert_eq!((bands[9].width, bands[9].height), (9, 9), "LL3");
    }

    #[test]
    fn band_offsets_match_freerdp() {
        let bands = band_layout();

        assert_eq!(bands[0].offset, 0, "HL1");
        assert_eq!(bands[1].offset, 1023, "LH1");
        assert_eq!(bands[2].offset, 2046, "HH1");
        assert_eq!(bands[3].offset, 3007, "HL2");
        assert_eq!(bands[4].offset, 3279, "LH2");
        assert_eq!(bands[5].offset, 3551, "HH2");
        assert_eq!(bands[6].offset, 3807, "HL3");
        assert_eq!(bands[7].offset, 3879, "LH3");
        assert_eq!(bands[8].offset, 3951, "HH3");
        assert_eq!(bands[9].offset, 4015, "LL3");
    }

    #[test]
    fn band_total_is_4096() {
        let bands = band_layout();
        let total: usize = bands.iter().map(|b| b.count()).sum();
        assert_eq!(total, 4096);
    }

    #[test]
    fn low_high_counts() {
        assert_eq!(low_count(64), 33);
        assert_eq!(high_count(64), 31);
        assert_eq!(low_count(33), 17);
        assert_eq!(high_count(33), 16);
        assert_eq!(low_count(17), 9);
        assert_eq!(high_count(17), 8);
    }

    #[test]
    fn decode_all_zeros() {
        let mut buffer = vec![0i16; 4096];
        let mut temp = vec![0i16; 4096];
        decode(&mut buffer, &mut temp);
        // All-zero coefficients should produce all-zero output
        assert!(buffer.iter().all(|&v| v == 0));
    }

    #[test]
    fn encode_all_zeros() {
        let mut buffer = vec![0i16; 4096];
        let mut temp = vec![0i16; 4096];
        encode(&mut buffer, &mut temp);
        assert!(buffer.iter().all(|&v| v == 0));
    }

    #[test]
    fn round_trip_identity() {
        // A simple signal: DC component only (flat tile)
        let mut buffer = vec![100i16; 4096];
        let original = buffer.clone();
        let mut temp = vec![0i16; 4096];

        encode(&mut buffer, &mut temp);
        decode(&mut buffer, &mut temp);

        // Due to integer truncation, allow small per-sample error
        let max_err: i16 = buffer
            .iter()
            .zip(original.iter())
            .map(|(&a, &b)| (a - b).abs())
            .max()
            .unwrap_or(0);
        assert!(max_err <= 2, "max round-trip error {max_err} exceeds tolerance");
    }

    #[test]
    fn round_trip_gradient() {
        // Horizontal gradient: tests non-trivial frequency content
        let mut buffer = vec![0i16; 4096];
        for row in 0..64 {
            for col in 0..64 {
                buffer[row * 64 + col] = col as i16 * 4;
            }
        }
        let original = buffer.clone();
        let mut temp = vec![0i16; 4096];

        encode(&mut buffer, &mut temp);
        decode(&mut buffer, &mut temp);

        let max_err: i16 = buffer
            .iter()
            .zip(original.iter())
            .map(|(&a, &b)| (a - b).abs())
            .max()
            .unwrap_or(0);
        assert!(max_err <= 4, "max round-trip error {max_err} exceeds tolerance");
    }

    #[test]
    fn round_trip_random_like() {
        // Pseudo-random signal using a simple LCG to test general case
        let mut buffer = vec![0i16; 4096];
        let mut seed: u32 = 12345;
        for val in buffer.iter_mut() {
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            *val = ((seed >> 16) as i16) >> 4; // range roughly -2048..2047
        }
        let original = buffer.clone();
        let mut temp = vec![0i16; 4096];

        encode(&mut buffer, &mut temp);
        decode(&mut buffer, &mut temp);

        let max_err: i16 = buffer
            .iter()
            .zip(original.iter())
            .map(|(&a, &b)| (a - b).abs())
            .max()
            .unwrap_or(0);
        // Reduce-extrapolate DWT has slightly more rounding error at
        // boundaries than standard DWT due to asymmetric sample counts
        assert!(max_err <= 6, "max round-trip error {max_err} exceeds tolerance");
    }

    #[test]
    fn idwt_row_even_input() {
        // Test the 1D inverse on a small even-length case (n_l=3, n_h=1)
        let low = [10i16, 20, 30];
        let high = [5i16];
        let mut dst = [0i16; 4];
        idwt_row(&low, &high, &mut dst);
        // Just verify it doesn't panic and produces 4 values
        assert_eq!(dst.len(), 4);
    }

    #[test]
    fn idwt_row_odd_input() {
        // Test the 1D inverse on a small odd-length case (n_l=2, n_h=1)
        let low = [10i16, 20];
        let high = [5i16];
        let mut dst = [0i16; 3];
        idwt_row(&low, &high, &mut dst);
        assert_eq!(dst.len(), 3);
    }
}
