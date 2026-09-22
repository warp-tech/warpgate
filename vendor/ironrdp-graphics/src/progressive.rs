//! RemoteFX Progressive codec implementation ([MS-RDPEGFX] 2.2.4.2).
//!
//! This module implements the full progressive RemoteFX codec for both
//! client-side decode and server-side encode. The progressive codec delivers
//! screen updates in multiple passes: a coarse first pass followed by
//! refinement upgrade passes that progressively improve quality.
//!
//! # Architecture
//!
//! ## Decode pipeline (client)
//! - [`decode_first_pass`]: RLGR1 → LL3 delta decode → base dequantization →
//!   progressive dequantization → DAS sign capture
//! - [`decode_upgrade_pass`]: SRL/raw routing by DAS sign state → coefficient
//!   accumulation
//!
//! ## Encode pipeline (server)
//! - [`encode_first_pass`]: forward DWT → base quantization → progressive
//!   quantization → LL3 delta encode → RLGR1
//! - [`encode_upgrade_pass`]: per-band SRL + raw bit encoding for refinement
//! - [`rgba_to_ycbcr`]: ITU-R BT.601 color space conversion
//!
//! ## State management
//! - [`TileState`]: per-codec-context tile coefficient and DAS sign storage
//!   (~37 KB per tile)
//! - [`SurfaceTiles`]: lazily-allocated tile grid for a surface
//! - [`ProgressiveDecoder`]: high-level decoder maintaining per-context
//!   progressive state and surface-scoped sub-band references, wired into the
//!   EGFX `WireToSurface2Pdu` path
//!
//! # Progressive quantization
//!
//! Progressive regions use [`ComponentCodecQuant`] (different nibble ordering
//! from classic RFX `Quant`). Each quality level specifies a BitPos per band
//! that controls how many bits are transmitted. Higher BitPos means fewer bits
//! (coarser quality). Upgrade passes decrease BitPos, revealing more bits.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::collections::btree_map::Entry;

use ironrdp_core::invalid_field_err;
use ironrdp_pdu::codecs::rfx::EntropyAlgorithm;
use ironrdp_pdu::codecs::rfx::progressive::{ComponentCodecQuant, ProgressiveCodecQuant};

/// RFX_TILE_DIFFERENCE in TILE_SIMPLE and TILE_FIRST flags. Defined by IronRDP master in
/// `ironrdp_pdu::codecs::rfx::progressive`, which ironrdp-pdu 0.9.0 predates; drop this
/// copy and restore the import on re-vendor (see PATCHES.md).
const TILE_FLAG_DIFFERENCE: u8 = 0x01;
use ironrdp_pdu::geometry::{ExclusiveRectangle, InclusiveRectangle};

use crate::dwt_extrapolate::BandInfo;
use crate::rectangle_processing::Region;
use crate::rlgr::RlgrError;
use crate::srl::{self, SrlError};

/// Number of DWT coefficients per component in a 64x64 tile.
pub const COEFFICIENTS_PER_COMPONENT: usize = 4096;

/// Progressive tile dimension in pixels ([MS-RDPEGFX] 2.2.4.2.1.1: `tileSize` MUST be 0x0040).
pub const TILE_DIM: u16 = 64;

/// Bytes per pixel of decoded RGBA tile output.
pub const TILE_BYTES_PER_PIXEL: usize = 4;

type DecDwtQ = [[i16; COEFFICIENTS_PER_COMPONENT]; 3];
type SubBandDiffingTileKey = (u16, u16, u16);

/// Number of subbands in a 3-level DWT decomposition.
pub const NUM_BANDS: usize = 10;

/// DAS (Delta-Analysis State) values for tri-state sign tracking.
///
/// After the first pass, each coefficient position is classified:
/// - `SIGN_ZERO`: coefficient was zero (eligible for SRL upgrade)
/// - `SIGN_POSITIVE`: coefficient was positive (eligible for raw upgrade)
/// - `SIGN_NEGATIVE`: coefficient was negative (eligible for raw upgrade)
pub const SIGN_ZERO: i8 = 0;
pub const SIGN_POSITIVE: i8 = 1;
pub const SIGN_NEGATIVE: i8 = -1;

// ---------------------------------------------------------------------------
// First-pass decode (TILE_SIMPLE / TILE_FIRST)
// ---------------------------------------------------------------------------

/// Decode a first-pass component from RLGR1-encoded data.
///
/// Performs: RLGR1 decode -> LL3 delta decode -> progressive dequantization
/// -> sign capture -> base dequantization.
///
/// # Arguments
/// - `data`: RLGR1-encoded coefficient stream
/// - `base_quant`: base quantization values (from region quant table, `ComponentCodecQuant` format)
/// - `prog_quant`: progressive quantization BitPos values for this quality level
/// - `use_reduce_extrapolate`: whether to use asymmetric band sizes
/// - `coefficients`: output buffer for decoded coefficients (4096 i16)
/// - `sign`: output buffer for DAS sign state (4096 i8)
///
/// # Panics
///
/// Panics if `coefficients` or `sign` has fewer than 4096 elements.
///
/// # Errors
/// Returns `RlgrError` if RLGR decoding fails.
pub fn decode_first_pass(
    data: &[u8],
    base_quant: &ComponentCodecQuant,
    prog_quant: &ComponentCodecQuant,
    use_reduce_extrapolate: bool,
    coefficients: &mut [i16],
    sign: &mut [i8],
) -> Result<(), RlgrError> {
    assert!(coefficients.len() >= COEFFICIENTS_PER_COMPONENT);
    assert!(sign.len() >= COEFFICIENTS_PER_COMPONENT);

    decode_first_pass_to_dwtq(data, prog_quant, use_reduce_extrapolate, coefficients, sign)?;

    // Apply base dequantization only after the progressive reconstruction.
    dequantize_component_ccq(coefficients, base_quant, use_reduce_extrapolate);

    Ok(())
}

/// Decode a first progressive pass into the base-quantized DWT domain.
///
/// The resulting coefficients are `DecDwtQ` as specified by MS-RDPEGFX
/// section 3.3.8.2.1.1. They must retain their base quantization while
/// upgrade passes are accumulated.
fn decode_first_pass_to_dwtq(
    data: &[u8],
    prog_quant: &ComponentCodecQuant,
    use_reduce_extrapolate: bool,
    coefficients: &mut [i16],
    sign: &mut [i8],
) -> Result<(), RlgrError> {
    // Step 1: RLGR1 decode into coefficient buffer.
    crate::rlgr::decode(EntropyAlgorithm::Rlgr1, data, coefficients)?;

    // Step 2: LL3 differential decoding (reverse delta encoding on last subband).
    crate::subband_reconstruction::decode(&mut coefficients[ll3_offset(use_reduce_extrapolate)..]);

    // Step 3: Reconstruct DecDwtQ by multiplying by the progressive quantization factor.
    progressive_dequantize(coefficients, prog_quant, use_reduce_extrapolate);

    // Step 4: Capture sign state for subsequent upgrade passes.
    capture_sign(coefficients, sign);

    Ok(())
}

/// Decode an upgrade-pass component from SRL and raw data streams.
///
/// For each coefficient position:
/// - DAS = 0 (zero): decode from SRL stream, update DAS if non-zero
/// - DAS != 0 (non-zero): decode raw magnitude bits, accumulate
///
/// # Arguments
/// - `srl_data`: SRL-encoded stream for zero-DAS positions
/// - `raw_data`: raw bit stream for non-zero-DAS positions
/// - `prev_prog_quant`: BitPos values from previous quality level
/// - `curr_prog_quant`: BitPos values for this quality level
/// - `use_reduce_extrapolate`: whether to use asymmetric band sizes
/// - `coefficients`: coefficient buffer to accumulate into (modified in-place)
/// - `sign`: DAS sign buffer (modified in-place when zeros become non-zero)
///
/// # Panics
///
/// Panics if `coefficients` or `sign` has fewer than 4096 elements.
///
/// # Errors
///
/// Returns [`SrlError`] for a malformed or truncated SRL stream.
/// See MS-RDPEGFX section 3.3.8.2.1.2.
pub fn decode_upgrade_pass(
    srl_data: &[u8],
    raw_data: &[u8],
    prev_prog_quant: &ComponentCodecQuant,
    curr_prog_quant: &ComponentCodecQuant,
    use_reduce_extrapolate: bool,
    coefficients: &mut [i16],
    sign: &mut [i8],
) -> Result<(), SrlError> {
    assert!(coefficients.len() >= COEFFICIENTS_PER_COMPONENT);
    assert!(sign.len() >= COEFFICIENTS_PER_COMPONENT);

    let bands = get_band_layout(use_reduce_extrapolate);
    let zero_counts: [usize; NUM_BANDS] = core::array::from_fn(|band_idx| band_zero_count(sign, &bands[band_idx]));
    let has_srl_values = bands.iter().enumerate().any(|(band_idx, _)| {
        let num_bits = prev_prog_quant
            .for_band(band_idx)
            .saturating_sub(curr_prog_quant.for_band(band_idx));
        band_idx != NUM_BANDS - 1 && num_bits != 0 && zero_counts[band_idx] != 0
    });
    let mut srl_decoder = has_srl_values.then(|| srl::SrlDecoder::new(srl_data)).transpose()?;
    let mut srl_values = Vec::with_capacity(NUM_BANDS);

    for (band_idx, _) in bands.iter().enumerate() {
        let prev_bit_pos = prev_prog_quant.for_band(band_idx);
        let curr_bit_pos = curr_prog_quant.for_band(band_idx);

        // Number of raw bits per coefficient in this band
        let num_bits = prev_bit_pos.saturating_sub(curr_bit_pos);
        if num_bits == 0 {
            srl_values.push(Vec::new());
            continue;
        }

        if band_idx == NUM_BANDS - 1 {
            // LL3 entries are always decoded from the raw stream.
            srl_values.push(Vec::new());
            continue;
        }

        let zero_count = zero_counts[band_idx];
        let values = match srl_decoder.as_mut() {
            Some(decoder) => decoder.decode(zero_count, num_bits)?,
            None => Vec::new(),
        };
        srl_values.push(values);
    }

    let mut raw_reader = RawBitReader::new(raw_data);
    for (band_idx, band) in bands.iter().enumerate() {
        let prev_bit_pos = prev_prog_quant.for_band(band_idx);
        let curr_bit_pos = curr_prog_quant.for_band(band_idx);
        let num_bits = prev_bit_pos.saturating_sub(curr_bit_pos);
        if num_bits == 0 {
            continue;
        }

        let is_ll3 = band_idx == NUM_BANDS - 1;
        let mut srl_idx = 0;

        for i in 0..band.count() {
            let coeff_idx = band.offset + i;

            if !is_ll3 && sign[coeff_idx] == SIGN_ZERO {
                // Zero-DAS: get value from SRL stream
                let value = srl_values[band_idx][srl_idx];
                srl_idx += 1;

                if value != 0 {
                    // Coefficient transitions from zero to non-zero
                    let shifted = i32::from(value) << i32::from(curr_bit_pos);
                    coefficients[coeff_idx] = clamp_i16(i32::from(coefficients[coeff_idx]) + shifted);
                    sign[coeff_idx] = if value > 0 { SIGN_POSITIVE } else { SIGN_NEGATIVE };
                }
            } else {
                // Non-zero DAS: read raw magnitude bits
                let raw_mag = raw_reader.read_bits(u32::from(num_bits));

                if raw_mag != 0 {
                    // raw_mag fits in i32 (at most 2^15 from bit stream)
                    let mag_i32 = i32::try_from(raw_mag).unwrap_or(i32::MAX);
                    let shifted = mag_i32 << i32::from(curr_bit_pos);
                    if is_ll3 || sign[coeff_idx] == SIGN_POSITIVE {
                        // LL3 is always positive; positive DAS adds
                        coefficients[coeff_idx] = clamp_i16(i32::from(coefficients[coeff_idx]) + shifted);
                    } else {
                        // Negative DAS subtracts
                        coefficients[coeff_idx] = clamp_i16(i32::from(coefficients[coeff_idx]) - shifted);
                    }
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Progressive (de)quantization
// ---------------------------------------------------------------------------

/// Apply progressive dequantization: left-shift each band by its BitPos value.
///
/// For non-LL3 bands, this shifts the absolute value (preserving sign).
/// For LL3, this is a simple left shift (floor toward negative infinity).
fn progressive_dequantize(coefficients: &mut [i16], prog_quant: &ComponentCodecQuant, use_reduce_extrapolate: bool) {
    let bands = get_band_layout(use_reduce_extrapolate);

    for (band_idx, band) in bands.iter().enumerate() {
        let bit_pos = prog_quant.for_band(band_idx);
        if bit_pos == 0 {
            continue;
        }

        let is_ll3 = band_idx == 9;
        let start = band.offset;
        let end = start + band.count();

        if is_ll3 {
            // LL3: simple left shift (floor toward negative infinity)
            for coeff in &mut coefficients[start..end] {
                *coeff = clamp_i16(i32::from(*coeff) << i32::from(bit_pos));
            }
        } else {
            // Other bands: shift absolute value, preserve sign
            for coeff in &mut coefficients[start..end] {
                let val = i32::from(*coeff);
                if val >= 0 {
                    *coeff = clamp_i16(val << i32::from(bit_pos));
                } else {
                    *coeff = clamp_i16(-((-val) << i32::from(bit_pos)));
                }
            }
        }
    }
}

/// Apply progressive quantization: right-shift each band by its BitPos value.
///
/// Inverse of `progressive_dequantize`.
pub fn progressive_quantize(coefficients: &mut [i16], prog_quant: &ComponentCodecQuant, use_reduce_extrapolate: bool) {
    let bands = get_band_layout(use_reduce_extrapolate);

    for (band_idx, band) in bands.iter().enumerate() {
        let bit_pos = prog_quant.for_band(band_idx);
        if bit_pos == 0 {
            continue;
        }

        let is_ll3 = band_idx == 9;
        let start = band.offset;
        let end = start + band.count();

        if is_ll3 {
            // LL3: floor division (right shift)
            for coeff in &mut coefficients[start..end] {
                *coeff >>= bit_pos;
            }
        } else {
            // Other bands: truncation toward zero
            for coeff in &mut coefficients[start..end] {
                let val = i32::from(*coeff);
                if val >= 0 {
                    *coeff = clamp_i16(val >> i32::from(bit_pos));
                } else {
                    *coeff = clamp_i16(-((-val) >> i32::from(bit_pos)));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Server-side encode pipeline
// ---------------------------------------------------------------------------

/// Encode a first-pass component from spatial-domain coefficients.
///
/// Pipeline: forward DWT -> base quantization -> progressive quantization
/// -> LL3 delta encode -> RLGR1 encode.
///
/// Returns the number of bytes written to `output`.
///
/// # Arguments
/// - `coefficients`: spatial-domain coefficients (4096 i16, modified in-place)
/// - `output`: output buffer for RLGR1-encoded data
/// - `base_quant`: base quantization values
/// - `prog_quant`: progressive quantization BitPos values for this quality level
/// - `use_reduce_extrapolate`: DWT mode flag
///
/// # Panics
///
/// Panics if `coefficients` has fewer than 4096 elements.
///
/// # Errors
/// Returns `RlgrError` if RLGR encoding fails.
pub fn encode_first_pass(
    coefficients: &mut [i16],
    output: &mut [u8],
    base_quant: &ComponentCodecQuant,
    prog_quant: &ComponentCodecQuant,
    use_reduce_extrapolate: bool,
) -> Result<usize, RlgrError> {
    assert!(coefficients.len() >= COEFFICIENTS_PER_COMPONENT);

    let mut temp = [0i16; COEFFICIENTS_PER_COMPONENT];

    // Step 1: Forward DWT
    if use_reduce_extrapolate {
        crate::dwt_extrapolate::encode(coefficients, &mut temp);
    } else {
        crate::dwt::encode(coefficients, &mut temp);
    }

    // Step 2: Base quantization (scale by 2^(quant - 6))
    quantize_component_ccq(coefficients, base_quant, use_reduce_extrapolate);

    // Step 3: Progressive quantization (right-shift by BitPos)
    progressive_quantize(coefficients, prog_quant, use_reduce_extrapolate);

    // Step 4: LL3 delta encoding
    crate::subband_reconstruction::encode(&mut coefficients[ll3_offset(use_reduce_extrapolate)..]);

    // Step 5: RLGR1 entropy encode
    crate::rlgr::encode(EntropyAlgorithm::Rlgr1, coefficients, output)
}

/// Base quantization using `ComponentCodecQuant` (progressive format).
///
/// Each band is divided by `2^(quant_value - 6)` and rounded. This is the
/// scale specified by MS-RDPRFX section 3.1.8.1.5.
fn quantize_component_ccq(coefficients: &mut [i16], quant: &ComponentCodecQuant, use_reduce_extrapolate: bool) {
    let bands = get_band_layout(use_reduce_extrapolate);

    for (band_idx, band) in bands.iter().enumerate() {
        let q = quant.for_band(band_idx);
        let start = band.offset;
        let end = start + band.count();

        match q.cmp(&6) {
            core::cmp::Ordering::Greater => {
                let shift = q - 6;
                for coeff in &mut coefficients[start..end] {
                    *coeff = round_shift_right(*coeff, shift);
                }
            }
            core::cmp::Ordering::Less => {
                let shift = 6 - q;
                for coeff in &mut coefficients[start..end] {
                    *coeff = clamp_i16(i32::from(*coeff) << i32::from(shift));
                }
            }
            core::cmp::Ordering::Equal => {}
        }
    }
}

/// Compute the upgrade-pass data for a single component.
///
/// Given the previous and current progressive quantization, produces
/// SRL-encoded data (for zero-DAS positions) and raw bit data (for
/// non-zero DAS positions) representing the refinement.
///
/// # Arguments
/// - `coefficients`: current full-resolution DWT coefficients for this component
/// - `prev_coefficients`: coefficients as reconstructed from the previous pass
/// - `prev_prog_quant`: BitPos values from the previous pass
/// - `curr_prog_quant`: BitPos values for this upgrade pass
/// - `sign`: DAS sign array from the previous pass
/// - `use_reduce_extrapolate`: DWT mode flag
///
/// # Returns
/// A tuple of `(srl_data, raw_data)` byte vectors.
///
/// # Wire-format invariants (MS-RDPEGFX 3.2.8.1.5.2)
///
/// The non-zero-DAS raw-magnitude path uses `saturating_sub` to compute
/// `raw_mag = curr_q - prev_q`. Upgrade passes are *monotonic refinements*:
/// the encoder only adds magnitude bits, never subtracts. The decoder's
/// counterpart accumulates raw_mag onto the previously-decoded coefficient
/// with the DAS-determined sign (`+=` for SIGN_POSITIVE / LL3, `-=` for
/// SIGN_NEGATIVE), so a hypothetical signed delta would have no place in
/// the wire format. Switching this to a signed-delta encoding would break
/// wire compatibility with mstsc/FreeRDP — do not "fix" the saturating_sub.
///
/// The zero-DAS SRL path uses `clamp_i16(curr_shifted - prev_shifted)`. SRL
/// stream values are i16 by wire-format definition, so wider precision is
/// not available without a spec extension. The clamp is the wire-format
/// boundary, not a precision compromise.
pub fn encode_upgrade_pass(
    coefficients: &[i16],
    prev_coefficients: &[i16],
    prev_prog_quant: &ComponentCodecQuant,
    curr_prog_quant: &ComponentCodecQuant,
    sign: &[i8],
    use_reduce_extrapolate: bool,
) -> Result<(Vec<u8>, Vec<u8>), SrlError> {
    let bands = get_band_layout(use_reduce_extrapolate);
    let mut srl_encoder = srl::SrlEncoder::new();
    let mut has_srl_values = false;
    let mut raw_writer = RawBitWriter::new();

    for (band_idx, band) in bands.iter().enumerate() {
        let prev_bit_pos = prev_prog_quant.for_band(band_idx);
        let curr_bit_pos = curr_prog_quant.for_band(band_idx);

        let num_bits = prev_bit_pos.saturating_sub(curr_bit_pos);
        if num_bits == 0 {
            continue;
        }

        let mut band_srl_values = Vec::new();

        for i in 0..band.count() {
            let coeff_idx = band.offset + i;
            let is_ll3 = band_idx == NUM_BANDS - 1;

            if !is_ll3 && sign[coeff_idx] == SIGN_ZERO {
                // Zero-DAS: compute the refined value and encode via SRL
                let curr_shifted = i32::from(coefficients[coeff_idx]) >> i32::from(curr_bit_pos);
                let prev_shifted = i32::from(prev_coefficients[coeff_idx]) >> i32::from(curr_bit_pos);
                let delta = clamp_i16(curr_shifted - prev_shifted);
                band_srl_values.push(delta);
            } else {
                // Non-zero DAS: compute raw magnitude bits
                let curr_abs = i32::from(coefficients[coeff_idx]).unsigned_abs();
                let prev_abs = i32::from(prev_coefficients[coeff_idx]).unsigned_abs();

                let curr_q = curr_abs >> u32::from(curr_bit_pos);
                let prev_q = prev_abs >> u32::from(curr_bit_pos);
                let raw_mag = curr_q.saturating_sub(prev_q);

                raw_writer.write_bits(raw_mag, u32::from(num_bits));
            }
        }

        if !band_srl_values.is_empty() {
            srl_encoder.encode(&band_srl_values, num_bits)?;
            has_srl_values = true;
        }
    }

    let raw_data = raw_writer.finish();
    let srl_data = if has_srl_values {
        srl_encoder.finish()?
    } else {
        Vec::new()
    };
    Ok((srl_data, raw_data))
}

/// Encode RGBA pixels to spatial-domain i16 coefficients (RGB to YCbCr).
///
/// Performs ITU-R BT.601 RGB-to-YCbCr conversion on a 64x64 pixel tile.
/// Output is 3 buffers of 4096 i16 coefficients (Y, Cb, Cr) in tile order.
///
/// # Panics
///
/// Panics if `pixels` has fewer than 64 * 64 * 4 = 16384 bytes.
#[expect(clippy::similar_names)]
pub fn rgba_to_ycbcr(pixels: &[u8], y_out: &mut [i16], cb_out: &mut [i16], cr_out: &mut [i16]) {
    assert!(pixels.len() >= 64 * 64 * 4);
    assert!(y_out.len() >= COEFFICIENTS_PER_COMPONENT);
    assert!(cb_out.len() >= COEFFICIENTS_PER_COMPONENT);
    assert!(cr_out.len() >= COEFFICIENTS_PER_COMPONENT);

    for i in 0..64 * 64 {
        let off = i * 4;
        let r = i32::from(pixels[off]);
        let g = i32::from(pixels[off + 1]);
        let b = i32::from(pixels[off + 2]);

        // ITU-R BT.601: Y = 0.299R + 0.587G + 0.114B
        //               Cb = -0.169R - 0.331G + 0.500B
        //               Cr = 0.500R - 0.419G - 0.081B
        // Fixed-point with 16-bit precision
        let y = ((19595 * r + 38470 * g + 7471 * b + 32768) >> 16) - 128;
        let cb = (-11059 * r - 21709 * g + 32768 * b + 32768) >> 16;
        let cr = (32768 * r - 27439 * g - 5329 * b + 32768) >> 16;

        y_out[i] = clamp_i16(y);
        cb_out[i] = clamp_i16(cb);
        cr_out[i] = clamp_i16(cr);
    }
}

/// Base dequantization using `ComponentCodecQuant` (progressive-format quantization).
///
/// Each band is multiplied by `2^(quant_value - 6)` and rounded. Uses
/// `for_band()` to map band indices to quant values, which handles the
/// progressive nibble ordering.
fn dequantize_component_ccq(coefficients: &mut [i16], quant: &ComponentCodecQuant, use_reduce_extrapolate: bool) {
    let bands = get_band_layout(use_reduce_extrapolate);

    for (band_idx, band) in bands.iter().enumerate() {
        let q = quant.for_band(band_idx);
        let start = band.offset;
        let end = start + band.count();

        match q.cmp(&6) {
            core::cmp::Ordering::Greater => {
                let shift = q - 6;
                for coeff in &mut coefficients[start..end] {
                    *coeff = clamp_i16(i32::from(*coeff) << i32::from(shift));
                }
            }
            core::cmp::Ordering::Less => {
                let shift = 6 - q;
                for coeff in &mut coefficients[start..end] {
                    *coeff = round_shift_right(*coeff, shift);
                }
            }
            core::cmp::Ordering::Equal => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Sign capture
// ---------------------------------------------------------------------------

/// Capture the tri-state sign of each coefficient into the DAS array.
fn capture_sign(coefficients: &[i16], sign: &mut [i8]) {
    for (s, &c) in sign.iter_mut().zip(coefficients.iter()) {
        *s = match c.cmp(&0) {
            core::cmp::Ordering::Greater => SIGN_POSITIVE,
            core::cmp::Ordering::Less => SIGN_NEGATIVE,
            core::cmp::Ordering::Equal => SIGN_ZERO,
        };
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Get the band layout for the current DWT mode.
fn get_band_layout(use_reduce_extrapolate: bool) -> [BandInfo; NUM_BANDS] {
    if use_reduce_extrapolate {
        crate::dwt_extrapolate::band_layout()
    } else {
        standard_band_layout()
    }
}

/// Standard (non-extrapolate) band layout for a 64x64 tile.
/// Band sizes: 1024 each for level 1, 256 each for level 2, 64 each for level 3.
fn standard_band_layout() -> [BandInfo; NUM_BANDS] {
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
        b(32, 32), // HL1: 1024
        b(32, 32), // LH1: 1024
        b(32, 32), // HH1: 1024
        b(16, 16), // HL2: 256
        b(16, 16), // LH2: 256
        b(16, 16), // HH2: 256
        b(8, 8),   // HL3: 64
        b(8, 8),   // LH3: 64
        b(8, 8),   // HH3: 64
        b(8, 8),   // LL3: 64
    ]
}

/// Starting offset of the LL3 subband for delta decoding.
fn ll3_offset(use_reduce_extrapolate: bool) -> usize {
    if use_reduce_extrapolate {
        4015 // reduce-extrapolate: 9x9 = 81 coefficients at offset 4015
    } else {
        4032 // standard: 8x8 = 64 coefficients at offset 4032
    }
}

/// Count zero-DAS positions within a band.
fn band_zero_count(sign: &[i8], band: &BandInfo) -> usize {
    let start = band.offset;
    let end = start + band.count();
    sign[start..end].iter().filter(|&&s| s == SIGN_ZERO).count()
}

/// Clamp to u8 range (0-255).
#[expect(
    clippy::as_conversions,
    clippy::cast_sign_loss,
    reason = "value is clamped to 0..255 before cast"
)]
fn clamp_u8(value: i64) -> u8 {
    value.clamp(0, 255) as u8
}

/// ITU-R BT.601 YCbCr to RGB with 16-bit fixed point.
///
/// The samples come off the wire and can reach the full i16 range, where
/// the fixed-point products overflow i32. Widening keeps the arithmetic
/// exact for every input a tile can hold, and `clamp_u8` still bounds the
/// result.
fn ycbcr_to_rgb(y: i16, cb: i16, cr: i16) -> [u8; 3] {
    let y = i64::from(y) + 128;
    let cb = i64::from(cb);
    let cr = i64::from(cr);

    let r = y + ((cr * 91881 + 32768) >> 16);
    let g = y - ((cb * 22554 + cr * 46802 + 32768) >> 16);
    let b = y + ((cb * 116130 + 32768) >> 16);

    [clamp_u8(r), clamp_u8(g), clamp_u8(b)]
}

/// Clamp i32 to i16 range.
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "value is clamped to i16 range before cast"
)]
fn clamp_i16(value: i32) -> i16 {
    value.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16
}

/// Divide by a power of two using the base-quantization rounding rule.
fn round_shift_right(value: i16, shift: u8) -> i16 {
    debug_assert!(shift > 0);

    let half = 1i32 << (i32::from(shift) - 1);
    clamp_i16((i32::from(value) + half) >> i32::from(shift))
}

// ---------------------------------------------------------------------------
// Raw bit I/O for upgrade pass
// ---------------------------------------------------------------------------

/// Writes raw magnitude bits MSB-first to a byte stream.
///
/// Symmetric counterpart of [`RawBitReader`]. Callers are expected to pass
/// `count <= 32` to [`write_bits`](Self::write_bits); the upgrade-pass call
/// site bounds `count` by `prev_bit_pos - curr_bit_pos` which is at most a
/// few bits in practice. `count > 32` reads beyond `u32` width in the shift
/// expression, which is wrap-on-release / panic-on-debug — caller responsibility.
struct RawBitWriter {
    bytes: Vec<u8>,
    current: u8,
    bit_count: u8,
}

impl RawBitWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            current: 0,
            bit_count: 0,
        }
    }

    fn write_bit(&mut self, bit: bool) {
        self.current = (self.current << 1) | u8::from(bit);
        self.bit_count += 1;
        if self.bit_count >= 8 {
            self.bytes.push(self.current);
            self.current = 0;
            self.bit_count = 0;
        }
    }

    /// Write the low `count` bits of `value`, MSB-first. Caller must ensure
    /// `count <= 32` (see type-level docs).
    fn write_bits(&mut self, value: u32, count: u32) {
        debug_assert!(count <= 32, "RawBitWriter::write_bits count must be <= 32");
        for i in (0..count).rev() {
            self.write_bit((value >> i) & 1 != 0);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bit_count > 0 {
            self.current <<= 8 - self.bit_count;
            self.bytes.push(self.current);
        }
        self.bytes
    }
}

/// Reads raw magnitude bits MSB-first from a byte stream.
///
/// Past-end-of-stream reads return zero bits rather than an error: a
/// truncated `raw_data` produces zero coefficient magnitudes (no-op upgrade)
/// for the missing positions, matching the FreeRDP reference implementation's
/// tolerance for short truncation in this exact upgrade path.
///
/// Callers are expected to pass `count <= 32` to [`read_bits`](Self::read_bits);
/// the upgrade-pass call site bounds `count` by `prev_bit_pos - curr_bit_pos`
/// which is at most a few bits in practice.
struct RawBitReader<'a> {
    data: &'a [u8],
    byte_idx: usize,
    bit_idx: u8,
}

impl<'a> RawBitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_idx: 0,
            bit_idx: 0,
        }
    }

    /// Read `count` bits MSB-first into a `u32`. Bits past the end of the
    /// underlying stream read as zero.
    fn read_bits(&mut self, count: u32) -> u32 {
        let mut value = 0u32;
        for _ in 0..count {
            value = (value << 1) | u32::from(self.read_bit());
        }
        value
    }

    /// Read one bit. Returns `false` past end-of-stream by design (see
    /// type-level docs).
    fn read_bit(&mut self) -> bool {
        if self.byte_idx >= self.data.len() {
            return false;
        }
        let bit = (self.data[self.byte_idx] >> (7 - self.bit_idx)) & 1 != 0;
        self.bit_idx += 1;
        if self.bit_idx >= 8 {
            self.bit_idx = 0;
            self.byte_idx += 1;
        }
        bit
    }
}

// ---------------------------------------------------------------------------
// Tile state machine
// ---------------------------------------------------------------------------

/// Per-tile progressive state: coefficients, signs, and quality tracking.
///
/// Each tile in a progressive surface maintains this state across decode
/// passes. The first pass (TILE_SIMPLE or TILE_FIRST) initializes the
/// coefficients and signs; subsequent upgrade passes (TILE_UPGRADE)
/// accumulate refinement data.
///
/// Memory per tile: ~37 KB (24 KB coefficients + 12 KB signs + metadata).
pub struct TileState {
    /// Accumulated base-quantized DWT coefficients (`DecDwtQ`) per component (Y, Cb, Cr).
    pub coefficients: DecDwtQ,
    /// Tri-state sign tracking per component (DAS array).
    pub sign: [[i8; COEFFICIENTS_PER_COMPONENT]; 3],
    /// Progressive quantization BitPos from the last applied pass.
    pub prog_quant: [ComponentCodecQuant; 3],
    /// Base quantization indices (Y, Cb, Cr) into the region's quant table.
    pub quant_idx: [u8; 3],
    /// Base quantization tables (Y, Cb, Cr) used when reconstructing pixels.
    pub base_quant: [ComponentCodecQuant; 3],
    /// Progressive pass counter (0 = no data, 1 = first pass complete, 2+ = upgrade).
    pub pass: u16,
    /// Whether the tile was encoded as a difference tile.
    pub is_difference: bool,
    /// Last progressive quality byte (0xFF = full quality).
    pub quality: u8,
    /// Whether reduce-extrapolate DWT is used for this tile's context.
    pub use_reduce_extrapolate: bool,
}

struct FirstPassOptions {
    quant_idx: [u8; 3],
    quality: u8,
    use_reduce_extrapolate: bool,
}

impl TileState {
    /// Create a new tile with zeroed state.
    pub fn new() -> Self {
        Self {
            coefficients: [[0; COEFFICIENTS_PER_COMPONENT]; 3],
            sign: [[0; COEFFICIENTS_PER_COMPONENT]; 3],
            prog_quant: [ComponentCodecQuant::LOSSLESS; 3],
            quant_idx: [0; 3],
            base_quant: [ComponentCodecQuant {
                ll3: 6,
                hl3: 6,
                lh3: 6,
                hh3: 6,
                hl2: 6,
                lh2: 6,
                hh2: 6,
                hl1: 6,
                lh1: 6,
                hh1: 6,
            }; 3],
            pass: 0,
            is_difference: false,
            quality: 0,
            use_reduce_extrapolate: false,
        }
    }

    /// Decode a first-pass tile (TILE_SIMPLE or TILE_FIRST).
    ///
    /// Clears persistent progressive state and decodes three original-tile
    /// components from RLGR1 data.
    ///
    /// # Arguments
    /// - `component_data`: RLGR1-encoded data for [Y, Cb, Cr]
    /// - `base_quants`: base quantization values for [Y, Cb, Cr]
    /// - `prog_quants`: progressive quantization for [Y, Cb, Cr]
    /// - `quality`: progressive quality byte
    /// - `use_reduce_extrapolate`: DWT mode flag
    ///
    /// # Errors
    /// Returns `RlgrError` if any component's RLGR decode fails.
    pub fn decode_first(
        &mut self,
        component_data: [&[u8]; 3],
        base_quants: [&ComponentCodecQuant; 3],
        prog_quants: [ComponentCodecQuant; 3],
        quant_idx: [u8; 3],
        quality: u8,
        use_reduce_extrapolate: bool,
    ) -> Result<(), RlgrError> {
        self.decode_first_with_difference(
            component_data,
            base_quants,
            prog_quants,
            None,
            FirstPassOptions {
                quant_idx,
                quality,
                use_reduce_extrapolate,
            },
        )
    }

    /// Decode a first pass and add difference-tile deltas to a retained DWT
    /// reference.
    fn decode_first_with_difference(
        &mut self,
        component_data: [&[u8]; 3],
        base_quants: [&ComponentCodecQuant; 3],
        prog_quants: [ComponentCodecQuant; 3],
        reference: Option<&DecDwtQ>,
        options: FirstPassOptions,
    ) -> Result<(), RlgrError> {
        let mut coefficients = [[0; COEFFICIENTS_PER_COMPONENT]; 3];
        let mut sign = [[SIGN_ZERO; COEFFICIENTS_PER_COMPONENT]; 3];

        for c in 0..3 {
            decode_first_pass_to_dwtq(
                component_data[c],
                &prog_quants[c],
                options.use_reduce_extrapolate,
                &mut coefficients[c],
                &mut sign[c],
            )?;
        }

        if let Some(reference) = reference {
            for (component, reference_component) in coefficients.iter_mut().zip(reference.iter()) {
                for (coefficient, reference_coefficient) in component.iter_mut().zip(reference_component.iter()) {
                    *coefficient = coefficient.saturating_add(*reference_coefficient);
                }
            }
        }

        self.coefficients = coefficients;
        self.sign = sign;
        self.pass = 1;
        self.quality = options.quality;
        self.quant_idx = options.quant_idx;
        self.base_quant = [*base_quants[0], *base_quants[1], *base_quants[2]];
        self.use_reduce_extrapolate = options.use_reduce_extrapolate;
        self.is_difference = reference.is_some();
        self.prog_quant = prog_quants;

        Ok(())
    }

    /// Decode an upgrade-pass tile (TILE_UPGRADE).
    ///
    /// Accumulates refinement data into existing coefficients.
    /// On error, leaves the tile at its prior upgrade state.
    ///
    /// # Arguments
    /// - `srl_data`: SRL-encoded streams for [Y, Cb, Cr]
    /// - `raw_data`: raw bit streams for [Y, Cb, Cr]
    /// - `prog_quants`: progressive quantization for this upgrade level
    /// - `quality`: progressive quality byte for this pass
    pub fn decode_upgrade(
        &mut self,
        srl_data: [&[u8]; 3],
        raw_data: [&[u8]; 3],
        prog_quants: [ComponentCodecQuant; 3],
        quality: u8,
    ) -> Result<(), SrlError> {
        let prev_prog_quant = self.prog_quant;
        let mut coefficients = self.coefficients;
        let mut sign = self.sign;

        for c in 0..3 {
            decode_upgrade_pass(
                srl_data[c],
                raw_data[c],
                &prev_prog_quant[c],
                &prog_quants[c],
                self.use_reduce_extrapolate,
                &mut coefficients[c],
                &mut sign[c],
            )?;
        }

        self.coefficients = coefficients;
        self.sign = sign;
        self.prog_quant = prog_quants;
        self.quality = quality;
        self.pass = self.pass.saturating_add(1);

        Ok(())
    }

    /// Reconstruct the tile to spatial domain and write RGBA pixels.
    ///
    /// Applies base dequantization and inverse DWT to each component, then
    /// YCbCr-to-RGB color conversion. The pixel buffer receives 64x64 RGBA
    /// pixels (16384 bytes).
    ///
    /// # Panics
    ///
    /// Panics if `pixels` has fewer than 64 * 64 * 4 = 16384 bytes.
    #[expect(clippy::similar_names, reason = "y/cb/cr are standard YCbCr component names")]
    pub fn reconstruct_to_rgba(&self, pixels: &mut [u8]) {
        assert!(pixels.len() >= 64 * 64 * 4, "pixel buffer too small");

        // Copy coefficients to scratch buffers for in-place DWT
        let mut y_buf = self.coefficients[0];
        let mut cb_buf = self.coefficients[1];
        let mut cr_buf = self.coefficients[2];
        let mut temp = [0i16; COEFFICIENTS_PER_COMPONENT];

        // The progressive state remains in DecDwtQ form until all refinements are applied.
        dequantize_component_ccq(&mut y_buf, &self.base_quant[0], self.use_reduce_extrapolate);
        dequantize_component_ccq(&mut cb_buf, &self.base_quant[1], self.use_reduce_extrapolate);
        dequantize_component_ccq(&mut cr_buf, &self.base_quant[2], self.use_reduce_extrapolate);

        // Inverse DWT.
        if self.use_reduce_extrapolate {
            crate::dwt_extrapolate::decode(&mut y_buf, &mut temp);
            crate::dwt_extrapolate::decode(&mut cb_buf, &mut temp);
            crate::dwt_extrapolate::decode(&mut cr_buf, &mut temp);
        } else {
            let mut dwt_temp = [0i16; COEFFICIENTS_PER_COMPONENT];
            crate::dwt::decode(&mut y_buf, &mut dwt_temp);
            crate::dwt::decode(&mut cb_buf, &mut dwt_temp);
            crate::dwt::decode(&mut cr_buf, &mut dwt_temp);
        }

        // YCbCr to RGBA conversion.
        for i in 0..64 * 64 {
            let [r, g, b] = ycbcr_to_rgb(y_buf[i], cb_buf[i], cr_buf[i]);
            let off = i * 4;
            pixels[off] = r;
            pixels[off + 1] = g;
            pixels[off + 2] = b;
            pixels[off + 3] = 0xFF;
        }
    }
}

impl Default for TileState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Surface tile grid
// ---------------------------------------------------------------------------

/// Grid of progressive tiles for a single surface.
///
/// Manages tile state for a surface identified by its codec context ID.
/// Tiles are lazily allocated on first access to avoid upfront memory
/// cost for surfaces that only partially receive progressive updates.
pub struct SurfaceTiles {
    /// Width of the surface in tiles (ceildiv of pixel width by 64).
    pub tiles_wide: u16,
    /// Height of the surface in tiles.
    pub tiles_high: u16,
    /// Whether the associated context uses reduce-extrapolate DWT.
    pub use_reduce_extrapolate: bool,
    /// Tile storage, indexed by `y_idx * tiles_wide + x_idx`.
    /// `None` entries haven't received any progressive data yet.
    pub tiles: Vec<Option<Box<TileState>>>,
}

impl SurfaceTiles {
    /// Create a new tile grid for the given surface dimensions.
    ///
    /// Returns [`ProgressiveDecodeError::SurfaceTooLarge`] if either axis
    /// exceeds [`MAX_SURFACE_DIM`]. The check rejects only inputs that exceed
    /// the MS-RDPEGFX 2.2.2.14 normative ceiling (32766 px), so every
    /// spec-conformant surface is accepted.
    pub fn new(
        width_pixels: u16,
        height_pixels: u16,
        use_reduce_extrapolate: bool,
    ) -> Result<Self, ProgressiveDecodeError> {
        if width_pixels > MAX_SURFACE_DIM || height_pixels > MAX_SURFACE_DIM {
            return Err(ProgressiveDecodeError::SurfaceTooLarge {
                width: width_pixels,
                height: height_pixels,
            });
        }

        let tiles_wide = width_pixels.div_ceil(64);
        let tiles_high = height_pixels.div_ceil(64);
        let count = usize::from(tiles_wide) * usize::from(tiles_high);

        Ok(Self {
            tiles_wide,
            tiles_high,
            use_reduce_extrapolate,
            tiles: core::iter::repeat_with(|| None).take(count).collect(),
        })
    }

    /// Get or create the tile at the given grid position.
    ///
    /// Returns `None` if the coordinates are out of bounds.
    pub fn get_or_create(&mut self, x_idx: u16, y_idx: u16) -> Option<&mut TileState> {
        let idx = self.tile_index(x_idx, y_idx)?;
        let tile = self.tiles[idx].get_or_insert_with(|| {
            let mut t = Box::new(TileState::new());
            t.use_reduce_extrapolate = self.use_reduce_extrapolate;
            t
        });
        Some(tile)
    }

    /// Get the tile at the given grid position, if it exists.
    pub fn get(&self, x_idx: u16, y_idx: u16) -> Option<&TileState> {
        let idx = self.tile_index(x_idx, y_idx)?;
        self.tiles[idx].as_deref()
    }

    /// Reset all tiles (e.g., on context reset or surface resize).
    pub fn reset(&mut self) {
        for tile in &mut self.tiles {
            *tile = None;
        }
    }

    fn tile_index(&self, x_idx: u16, y_idx: u16) -> Option<usize> {
        if x_idx >= self.tiles_wide || y_idx >= self.tiles_high {
            return None;
        }
        Some(usize::from(y_idx) * usize::from(self.tiles_wide) + usize::from(x_idx))
    }
}

// ---------------------------------------------------------------------------
// Progressive decoder (EGFX integration)
// ---------------------------------------------------------------------------

/// Decoded tile pixel data for compositing onto a surface.
pub struct DecodedTile {
    /// Tile grid X coordinate (tile column).
    pub x_idx: u16,
    /// Tile grid Y coordinate (tile row).
    pub y_idx: u16,
    /// RGBA pixel data (64x64 = 16384 bytes).
    pub pixels: Vec<u8>,
    /// Surface-relative rectangles where this tile is visible, clipped to the
    /// Progressive REGION and surface bounds.
    pub update_rectangles: Vec<ExclusiveRectangle>,
}

/// Per-axis cap on surface dimensions, in pixels.
///
/// Per MS-RDPEGFX 2.2.2.14 RDPGFX_RESET_GRAPHICS_PDU, the normative maximum
/// allowed width and height are 32766 pixels. We round up to 32768 so that
/// the cap accepts every spec-conformant surface while bounding the
/// per-surface tile-grid allocation: at the cap the backing
/// `Vec<Option<Box<TileState>>>` is 512 * 512 = 262144 slots * 8 bytes per
/// slot = 2 MiB of pointer storage per surface before any tile is populated.
pub const MAX_SURFACE_DIM: u16 = 32768;

/// Maximum aggregate rectangle visits while clipping one progressive bitmap payload.
///
/// `Region::union_rectangle` scans the normalized rectangle list, and each
/// tile intersection scans that list again. Charging both operations bounds
/// server-controlled CPU and allocation amplification without rejecting a
/// large `numRects` solely because many rectangles collapse to a simple region.
const MAX_REGION_CLIPPING_WORK: usize = 1 << 20;

/// Error type for progressive decoding operations.
#[derive(Debug)]
pub enum ProgressiveDecodeError {
    /// PDU parsing failed.
    Pdu(ironrdp_core::DecodeError),
    /// RLGR decode failed within a tile.
    Rlgr(RlgrError),
    /// SRL decode failed within an upgrade tile.
    Srl(SrlError),
    /// The progressive stream is missing a required block.
    MissingBlock(&'static str),
    /// Tile coordinates are out of bounds for the surface.
    TileOutOfBounds { x_idx: u16, y_idx: u16 },
    /// Region references a quant index beyond the table.
    InvalidQuantIndex { index: usize, table_len: usize },
    /// A difference tile has no previously decoded state to use as its reference.
    MissingTileReference { x_idx: u16, y_idx: u16 },
    /// Surface dimensions exceed [`MAX_SURFACE_DIM`] per axis.
    SurfaceTooLarge { width: u16, height: u16 },
}

impl core::fmt::Display for ProgressiveDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Pdu(e) => write!(f, "progressive PDU decode: {e}"),
            Self::Rlgr(e) => write!(f, "progressive RLGR decode: {e}"),
            Self::Srl(e) => write!(f, "progressive srl decode: {e}"),
            Self::MissingBlock(name) => write!(f, "progressive stream missing {name} block"),
            Self::TileOutOfBounds { x_idx, y_idx } => {
                write!(f, "tile ({x_idx}, {y_idx}) out of surface bounds")
            }
            Self::InvalidQuantIndex { index, table_len } => {
                write!(f, "quant index {index} exceeds table length {table_len}")
            }
            Self::MissingTileReference { x_idx, y_idx } => {
                write!(f, "difference tile ({x_idx}, {y_idx}) has no retained reference")
            }
            Self::SurfaceTooLarge { width, height } => {
                write!(
                    f,
                    "surface dimensions {width}x{height} exceed per-axis cap of {MAX_SURFACE_DIM} \
                     (MS-RDPEGFX 2.2.2.14 normative ceiling: 32766)"
                )
            }
        }
    }
}

impl From<ironrdp_core::DecodeError> for ProgressiveDecodeError {
    fn from(e: ironrdp_core::DecodeError) -> Self {
        Self::Pdu(e)
    }
}

impl From<RlgrError> for ProgressiveDecodeError {
    fn from(e: RlgrError) -> Self {
        Self::Rlgr(e)
    }
}

impl From<SrlError> for ProgressiveDecodeError {
    fn from(e: SrlError) -> Self {
        Self::Srl(e)
    }
}

fn charge_region_clipping_work(used: &mut usize, units: usize) -> Result<(), ProgressiveDecodeError> {
    match (*used).checked_add(units) {
        Some(total) if total <= MAX_REGION_CLIPPING_WORK => {
            *used = total;
            Ok(())
        }
        _ => Err(ProgressiveDecodeError::Pdu(invalid_field_err!(
            "rects",
            "progressive REGION clipping work limit exceeded"
        ))),
    }
}

/// Per-context progressive state, identified by `(surface_id, codec_context_id)`.
struct ProgressiveContext {
    surface: SurfaceTiles,
}

/// High-level progressive bitmap decoder for EGFX WireToSurface2 processing.
///
/// Maintains per-context progressive state and surface-scoped sub-band
/// references across frames.
/// MS-RDPEGFX section 3.3.1.1 associates each codec context with a surface, so
/// two surfaces can reuse a codec context ID without sharing progressive state.
/// Feed it progressive bitmap data from `WireToSurface2Pdu.bitmap_data` and get
/// back decoded RGBA tiles for compositing. Call [`Self::begin_frame`] and
/// [`Self::end_frame`] around an RDPGFX frame so REGION blocks in separate
/// bitmap payloads can share tiles.
///
/// # Usage
///
/// ```ignore
/// let mut decoder = ProgressiveDecoder::new();
///
/// // On receiving WireToSurface2Pdu:
/// let tiles = decoder.decode_bitmap(
///     pdu.surface_id,
///     pdu.codec_context_id,
///     surface_width, surface_height,
///     &pdu.bitmap_data,
/// )?;
///
/// for tile in &tiles {
///     for rectangle in &tile.update_rectangles {
///         blit_tile_region(surface, tile.x_idx, tile.y_idx, rectangle, &tile.pixels);
///     }
/// }
/// ```
pub struct ProgressiveDecoder {
    contexts: BTreeMap<(u16, u32), ProgressiveContext>,
    references: BTreeMap<SubBandDiffingTileKey, DecDwtQ>,
    frame_tiles: BTreeMap<(u16, u32), BTreeSet<(u16, u16)>>,
    frame_active: bool,
    surface_context_flags: BTreeMap<u16, bool>,
}

impl ProgressiveDecoder {
    /// Create a new progressive decoder with no context state.
    pub fn new() -> Self {
        Self {
            contexts: BTreeMap::new(),
            references: BTreeMap::new(),
            frame_tiles: BTreeMap::new(),
            frame_active: false,
            surface_context_flags: BTreeMap::new(),
        }
    }

    /// Start an RDPGFX frame, resetting the set of tiles available to REGION blocks.
    pub fn begin_frame(&mut self) {
        self.frame_tiles.clear();
        self.frame_active = true;
    }

    /// Finish an RDPGFX frame and discard its transient tile references.
    pub fn end_frame(&mut self) {
        self.frame_tiles.clear();
        self.frame_active = false;
    }

    /// Decode a progressive bitmap stream from WireToSurface2Pdu.
    ///
    /// Parses the progressive block stream, updates per-tile state, and
    /// returns RGBA pixel data for each tile that was updated.
    ///
    /// # Arguments
    /// - `surface_id`: surface ID from the WireToSurface2Pdu
    /// - `codec_context_id`: context ID from the WireToSurface2Pdu
    /// - `surface_width`: surface width in pixels (for tile grid sizing)
    /// - `surface_height`: surface height in pixels
    /// - `bitmap_data`: raw progressive block stream from the PDU
    pub fn decode_bitmap(
        &mut self,
        surface_id: u16,
        codec_context_id: u32,
        surface_width: u16,
        surface_height: u16,
        bitmap_data: &[u8],
    ) -> Result<Vec<DecodedTile>, ProgressiveDecodeError> {
        use ironrdp_pdu::codecs::rfx::progressive::{ProgressiveBlock, decode_progressive_stream};

        let blocks = decode_progressive_stream(bitmap_data)?;

        // Extract the band-layout flag from the CONTEXT block when present.
        // Per MS-RDPEGFX 2.2.4.2 the SYNC + CONTEXT blocks establish a codec
        // context once (keyed by `(surface_id, codec_context_id)`) and are not
        // required to be
        // repeated on subsequent frames that reference the same context.
        // Real-world servers (xrdp, GNOME Remote Desktop) omit the CONTEXT
        // block on every frame after the first one that established the
        // context. The strict requirement rejected each of those frames with
        // `MissingBlock("CONTEXT")`, freezing the image on the coarse first
        // pass.
        //
        // Fall back to the value stored when the context was first created, then to the last
        // one this surface described: Windows opens a new codec context id mid-session,
        // deletes the previous one, and never repeats SYNC + CONTEXT, so a per-context lookup
        // alone rejects the new context. The retained value is scoped to its surface and
        // released with it. Only error when no source is available at all.
        let signalled = blocks.iter().find_map(|block| match block {
            ProgressiveBlock::Context(ctx) => Some(ctx.uses_reduce_extrapolate()),
            _ => None,
        });
        if let Some(flag) = signalled {
            self.surface_context_flags.insert(surface_id, flag);
        }
        let use_reduce_extrapolate = signalled
            .or_else(|| {
                self.contexts
                    .get(&(surface_id, codec_context_id))
                    .map(|c| c.surface.use_reduce_extrapolate)
            })
            .or_else(|| self.surface_context_flags.get(&surface_id).copied())
            .ok_or(ProgressiveDecodeError::MissingBlock("CONTEXT"))?;

        // Direct users of the decoder get one self-contained frame per call.
        // The EGFX client brackets multiple payloads with begin_frame/end_frame.
        if !self.frame_active {
            self.frame_tiles.clear();
        }

        let (contexts, references, all_frame_tiles) = (&mut self.contexts, &mut self.references, &mut self.frame_tiles);

        // Get or create the context for this (surface_id, codec_context_id).
        let context = match contexts.entry((surface_id, codec_context_id)) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => {
                let surface = SurfaceTiles::new(surface_width, surface_height, use_reduce_extrapolate)?;
                e.insert(ProgressiveContext { surface })
            }
        };

        // If surface dimensions changed, reallocate the codec-context tile grid.
        let expected_wide = surface_width.div_ceil(TILE_DIM);
        let expected_high = surface_height.div_ceil(TILE_DIM);
        let surface_resized =
            context.surface.tiles_wide != expected_wide || context.surface.tiles_high != expected_high;
        if surface_resized {
            context.surface = SurfaceTiles::new(surface_width, surface_height, use_reduce_extrapolate)?;
        }
        context.surface.use_reduce_extrapolate = use_reduce_extrapolate;

        let frame_tiles = all_frame_tiles.entry((surface_id, codec_context_id)).or_default();
        if surface_resized {
            frame_tiles.clear();
        }

        let mut decoded_tiles = Vec::new();
        let mut region_clipping_work = 0;

        // Process REGION blocks only inside the first FRAME_BEGIN/FRAME_END
        // pair in this bitmap stream. Codec state persists across RDPGFX
        // frames, while frame_tiles persists only across payloads in one frame.
        let mut in_frame = false;
        let mut frame_ended = false;
        for block in &blocks {
            let region = match block {
                ProgressiveBlock::FrameBegin(_) if !frame_ended => {
                    in_frame = true;
                    continue;
                }
                ProgressiveBlock::FrameEnd(_) => {
                    in_frame = false;
                    frame_ended = true;
                    continue;
                }
                ProgressiveBlock::Region(r) if in_frame => r,
                _ => continue,
            };

            let mut region_tiles = BTreeMap::new();
            for tile_block in &region.tiles {
                let tiles = decode_tile_block(
                    surface_id,
                    &mut context.surface,
                    references,
                    tile_block,
                    &region.quant_vals,
                    &region.quant_prog_vals,
                    use_reduce_extrapolate,
                )?;
                for tile in tiles {
                    let key = (tile.x_idx, tile.y_idx);
                    frame_tiles.insert(key);
                    region_tiles.insert(key, tile);
                }
            }

            let mut clipping_region = Region::new();
            for rectangle in &region.rects {
                let left = rectangle.x.min(surface_width);
                let top = rectangle.y.min(surface_height);
                let right = rectangle.x.saturating_add(rectangle.width).min(surface_width);
                let bottom = rectangle.y.saturating_add(rectangle.height).min(surface_height);
                if left < right && top < bottom {
                    charge_region_clipping_work(
                        &mut region_clipping_work,
                        clipping_region.rectangles.len().saturating_add(1),
                    )?;
                    clipping_region.union_rectangle(InclusiveRectangle {
                        left,
                        top,
                        right: right - 1,
                        bottom: bottom - 1,
                    });
                }
            }

            // REGION rectangles may be covered by tiles sent in an earlier REGION
            // within the same frame, so clip them against every tile currently
            // available for this frame rather than only the newly decoded tiles.
            for &(x_idx, y_idx) in frame_tiles.iter() {
                charge_region_clipping_work(&mut region_clipping_work, clipping_region.rectangles.len().max(1))?;
                let left = x_idx.saturating_mul(TILE_DIM);
                let top = y_idx.saturating_mul(TILE_DIM);
                let right = left.saturating_add(TILE_DIM).min(surface_width);
                let bottom = top.saturating_add(TILE_DIM).min(surface_height);
                if left >= right || top >= bottom {
                    continue;
                }

                let update_rectangles = clipping_region
                    .intersect_rectangle(&InclusiveRectangle {
                        left,
                        top,
                        right: right - 1,
                        bottom: bottom - 1,
                    })
                    .rectangles
                    .into_iter()
                    .map(|rectangle| ExclusiveRectangle {
                        left: rectangle.left,
                        top: rectangle.top,
                        right: rectangle.right + 1,
                        bottom: rectangle.bottom + 1,
                    })
                    .collect::<Vec<_>>();
                if update_rectangles.is_empty() {
                    continue;
                }

                let mut tile = if let Some(tile) = region_tiles.remove(&(x_idx, y_idx)) {
                    tile
                } else {
                    let Some(tile_state) = context.surface.get(x_idx, y_idx) else {
                        continue;
                    };
                    let mut pixels = vec![0u8; usize::from(TILE_DIM) * usize::from(TILE_DIM) * TILE_BYTES_PER_PIXEL];
                    tile_state.reconstruct_to_rgba(&mut pixels);
                    DecodedTile {
                        x_idx,
                        y_idx,
                        pixels,
                        update_rectangles: Vec::new(),
                    }
                };
                tile.update_rectangles = update_rectangles;
                decoded_tiles.push(tile);
            }
        }

        if !self.frame_active {
            self.frame_tiles.clear();
        }

        Ok(decoded_tiles)
    }

    /// Delete a codec context, freeing its progressive tile state.
    ///
    /// Called when the server sends RDPGFX_DELETE_ENCODING_CONTEXT, which
    /// identifies both the surface and codec context.
    pub fn delete_context(&mut self, surface_id: u16, codec_context_id: u32) {
        self.contexts.remove(&(surface_id, codec_context_id));
        self.frame_tiles.remove(&(surface_id, codec_context_id));
    }

    /// Delete every codec context associated with a surface.
    ///
    /// Call this when discarding a surface so a subsequent surface with the
    /// same ID cannot inherit stale Progressive tile state.
    pub fn delete_surface(&mut self, surface_id: u16) {
        self.contexts
            .retain(|(context_surface_id, _), _| *context_surface_id != surface_id);
        self.references
            .retain(|(reference_surface_id, _, _), _| *reference_surface_id != surface_id);
        self.frame_tiles
            .retain(|(context_surface_id, _), _| *context_surface_id != surface_id);
        self.surface_context_flags.remove(&surface_id);
    }

    /// Reset codec-context state while retaining surface sub-band references.
    pub fn reset(&mut self) {
        self.contexts.clear();
        self.frame_tiles.clear();
        self.frame_active = false;
    }
}

/// Resolve the progressive quantization values a tile's `quality` byte selects.
///
/// Per [MS-RDPEGFX] 2.2.4.2.1.5.2 `quality` indexes the REGION's `quantProgVals`, except for
/// the reserved value 0xFF, which selects full quality instead of indexing. Windows servers
/// send 0xFF with an empty table, so treating it as an index rejects every tile they encode.
fn progressive_quant_for(
    quality: u8,
    prog_quant_vals: &[ProgressiveCodecQuant],
) -> Result<ProgressiveCodecQuant, ProgressiveDecodeError> {
    const FULL_QUALITY: u8 = 0xFF;

    if quality == FULL_QUALITY {
        return Ok(ProgressiveCodecQuant {
            quality,
            y_quant: ComponentCodecQuant::LOSSLESS,
            cb_quant: ComponentCodecQuant::LOSSLESS,
            cr_quant: ComponentCodecQuant::LOSSLESS,
        });
    }

    prog_quant_vals
        .get(usize::from(quality))
        .copied()
        .ok_or(ProgressiveDecodeError::InvalidQuantIndex {
            index: usize::from(quality),
            table_len: prog_quant_vals.len(),
        })
}

#[expect(
    clippy::similar_names,
    reason = "q_y/q_cb/q_cr are standard component quant index names"
)]
fn decode_tile_block(
    surface_id: u16,
    surface: &mut SurfaceTiles,
    references: &mut BTreeMap<SubBandDiffingTileKey, DecDwtQ>,
    tile_block: &ironrdp_pdu::codecs::rfx::progressive::ProgressiveTile<'_>,
    quant_vals: &[ComponentCodecQuant],
    prog_quant_vals: &[ProgressiveCodecQuant],
    use_reduce_extrapolate: bool,
) -> Result<Vec<DecodedTile>, ProgressiveDecodeError> {
    use ironrdp_pdu::codecs::rfx::progressive::ProgressiveTile;

    match tile_block {
        ProgressiveTile::Simple(tile) => {
            let x_idx = tile.x_idx;
            let y_idx = tile.y_idx;
            let is_difference = tile.flags & TILE_FLAG_DIFFERENCE != 0;

            if surface.tile_index(x_idx, y_idx).is_none() {
                return Err(ProgressiveDecodeError::TileOutOfBounds { x_idx, y_idx });
            }
            let reference_key = (surface_id, x_idx, y_idx);
            let reference = if is_difference {
                Some(
                    references
                        .get(&reference_key)
                        .ok_or(ProgressiveDecodeError::MissingTileReference { x_idx, y_idx })?,
                )
            } else {
                None
            };
            let tile_state = surface
                .get_or_create(x_idx, y_idx)
                .ok_or(ProgressiveDecodeError::TileOutOfBounds { x_idx, y_idx })?;

            let q_y = usize::from(tile.quant_idx_y);
            let q_cb = usize::from(tile.quant_idx_cb);
            let q_cr = usize::from(tile.quant_idx_cr);

            if q_y >= quant_vals.len() || q_cb >= quant_vals.len() || q_cr >= quant_vals.len() {
                return Err(ProgressiveDecodeError::InvalidQuantIndex {
                    index: q_y.max(q_cb).max(q_cr),
                    table_len: quant_vals.len(),
                });
            }

            // TILE_SIMPLE uses lossless progressive quant (no progressive refinement)
            let prog = ComponentCodecQuant::LOSSLESS;

            tile_state.decode_first_with_difference(
                [tile.y_data, tile.cb_data, tile.cr_data],
                [&quant_vals[q_y], &quant_vals[q_cb], &quant_vals[q_cr]],
                [prog, prog, prog],
                reference,
                FirstPassOptions {
                    quant_idx: [tile.quant_idx_y, tile.quant_idx_cb, tile.quant_idx_cr],
                    quality: 0xFF, // full quality
                    use_reduce_extrapolate,
                },
            )?;
            references.insert(reference_key, tile_state.coefficients);

            let mut pixels = vec![0u8; usize::from(TILE_DIM) * usize::from(TILE_DIM) * TILE_BYTES_PER_PIXEL];
            tile_state.reconstruct_to_rgba(&mut pixels);

            Ok(vec![DecodedTile {
                x_idx,
                y_idx,
                pixels,
                update_rectangles: Vec::new(),
            }])
        }

        ProgressiveTile::First(tile) => {
            let x_idx = tile.x_idx;
            let y_idx = tile.y_idx;
            let is_difference = tile.flags & TILE_FLAG_DIFFERENCE != 0;

            if surface.tile_index(x_idx, y_idx).is_none() {
                return Err(ProgressiveDecodeError::TileOutOfBounds { x_idx, y_idx });
            }
            let reference_key = (surface_id, x_idx, y_idx);
            let reference = if is_difference {
                Some(
                    references
                        .get(&reference_key)
                        .ok_or(ProgressiveDecodeError::MissingTileReference { x_idx, y_idx })?,
                )
            } else {
                None
            };
            let tile_state = surface
                .get_or_create(x_idx, y_idx)
                .ok_or(ProgressiveDecodeError::TileOutOfBounds { x_idx, y_idx })?;

            let q_y = usize::from(tile.quant_idx_y);
            let q_cb = usize::from(tile.quant_idx_cb);
            let q_cr = usize::from(tile.quant_idx_cr);

            if q_y >= quant_vals.len() || q_cb >= quant_vals.len() || q_cr >= quant_vals.len() {
                return Err(ProgressiveDecodeError::InvalidQuantIndex {
                    index: q_y.max(q_cb).max(q_cr),
                    table_len: quant_vals.len(),
                });
            }

            let pq = progressive_quant_for(tile.quality, prog_quant_vals)?;

            tile_state.decode_first_with_difference(
                [tile.y_data, tile.cb_data, tile.cr_data],
                [&quant_vals[q_y], &quant_vals[q_cb], &quant_vals[q_cr]],
                [pq.y_quant, pq.cb_quant, pq.cr_quant],
                reference,
                FirstPassOptions {
                    quant_idx: [tile.quant_idx_y, tile.quant_idx_cb, tile.quant_idx_cr],
                    quality: tile.quality,
                    use_reduce_extrapolate,
                },
            )?;
            references.insert(reference_key, tile_state.coefficients);

            let mut pixels = vec![0u8; usize::from(TILE_DIM) * usize::from(TILE_DIM) * TILE_BYTES_PER_PIXEL];
            tile_state.reconstruct_to_rgba(&mut pixels);

            Ok(vec![DecodedTile {
                x_idx,
                y_idx,
                pixels,
                update_rectangles: Vec::new(),
            }])
        }

        ProgressiveTile::Upgrade(tile) => {
            let x_idx = tile.x_idx;
            let y_idx = tile.y_idx;

            let tile_state = surface
                .get_or_create(x_idx, y_idx)
                .ok_or(ProgressiveDecodeError::TileOutOfBounds { x_idx, y_idx })?;

            // If this tile hasn't had a first pass, skip the upgrade
            if tile_state.pass == 0 {
                return Ok(Vec::new());
            }

            let pq = progressive_quant_for(tile.quality, prog_quant_vals)?;

            tile_state.decode_upgrade(
                [tile.y_srl_data, tile.cb_srl_data, tile.cr_srl_data],
                [tile.y_raw_data, tile.cb_raw_data, tile.cr_raw_data],
                [pq.y_quant, pq.cb_quant, pq.cr_quant],
                tile.quality,
            )?;
            references.insert((surface_id, x_idx, y_idx), tile_state.coefficients);

            let mut pixels = vec![0u8; usize::from(TILE_DIM) * usize::from(TILE_DIM) * TILE_BYTES_PER_PIXEL];
            tile_state.reconstruct_to_rgba(&mut pixels);

            Ok(vec![DecodedTile {
                x_idx,
                y_idx,
                pixels,
                update_rectangles: Vec::new(),
            }])
        }
    }
}

impl Default for ProgressiveDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::as_conversions, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
mod tests {
    use super::*;

    fn minimal_progressive_stream(include_context: bool) -> Vec<u8> {
        use ironrdp_pdu::codecs::rfx::RfxRectangle;
        use ironrdp_pdu::codecs::rfx::progressive::{
            ProgressiveBlock, ProgressiveContextPdu, ProgressiveFrameBeginPdu, ProgressiveFrameEndPdu,
            ProgressiveRegion, ProgressiveSyncPdu, encode_progressive_stream,
        };

        let region = ProgressiveRegion {
            tile_size: 0x40,
            rects: vec![RfxRectangle {
                x: 0,
                y: 0,
                width: 64,
                height: 64,
            }],
            quant_vals: vec![],
            quant_prog_vals: vec![],
            flags: 0,
            tiles: vec![],
        };
        let mut blocks = vec![ProgressiveBlock::Sync(ProgressiveSyncPdu)];
        if include_context {
            blocks.push(ProgressiveBlock::Context(ProgressiveContextPdu {
                context_id: 0,
                tile_size: 0x0040,
                flags: 0,
            }));
        }
        blocks.extend([
            ProgressiveBlock::FrameBegin(ProgressiveFrameBeginPdu {
                frame_index: 0,
                region_count: 1,
            }),
            ProgressiveBlock::Region(region),
            ProgressiveBlock::FrameEnd(ProgressiveFrameEndPdu),
        ]);

        encode_progressive_stream(&blocks).unwrap()
    }

    #[test]
    fn surface_tiles_rejects_over_cap_dimensions() {
        // At-cap accepted on both axes
        assert!(SurfaceTiles::new(MAX_SURFACE_DIM, MAX_SURFACE_DIM, false).is_ok());

        // One axis over the cap is rejected with SurfaceTooLarge carrying both inputs
        let over_w = MAX_SURFACE_DIM.checked_add(1).unwrap();
        match SurfaceTiles::new(over_w, 1024, false) {
            Err(ProgressiveDecodeError::SurfaceTooLarge { width, height }) => {
                assert_eq!(width, over_w);
                assert_eq!(height, 1024);
            }
            Err(other) => panic!("expected SurfaceTooLarge, got Err({other})"),
            Ok(_) => panic!("expected SurfaceTooLarge, got Ok"),
        }

        match SurfaceTiles::new(1024, over_w, false) {
            Err(ProgressiveDecodeError::SurfaceTooLarge { width, height }) => {
                assert_eq!(width, 1024);
                assert_eq!(height, over_w);
            }
            Err(other) => panic!("expected SurfaceTooLarge, got Err({other})"),
            Ok(_) => panic!("expected SurfaceTooLarge, got Ok"),
        }
    }

    #[test]
    fn standard_band_layout_totals_4096() {
        let bands = standard_band_layout();
        let total: usize = bands.iter().map(|b| b.count()).sum();
        assert_eq!(total, 4096);
    }

    #[test]
    fn standard_band_offsets() {
        let bands = standard_band_layout();
        assert_eq!(bands[0].offset, 0);
        assert_eq!(bands[1].offset, 1024);
        assert_eq!(bands[2].offset, 2048);
        assert_eq!(bands[3].offset, 3072);
        assert_eq!(bands[4].offset, 3328);
        assert_eq!(bands[5].offset, 3584);
        assert_eq!(bands[6].offset, 3840);
        assert_eq!(bands[7].offset, 3904);
        assert_eq!(bands[8].offset, 3968);
        assert_eq!(bands[9].offset, 4032);
    }

    #[test]
    fn sign_capture_tri_state() {
        let coefficients = [10i16, -5, 0, 100, -1, 0];
        let mut sign = [0i8; 6];
        capture_sign(&coefficients, &mut sign);
        assert_eq!(sign, [1, -1, 0, 1, -1, 0]);
    }

    #[test]
    fn progressive_dequantize_ll3_shift() {
        // LL3 is band index 9, at offset 4032 for standard layout
        let mut coefficients = vec![0i16; 4096];
        coefficients[4032] = 5;
        coefficients[4033] = -3;

        let prog_quant = ComponentCodecQuant {
            ll3: 2,
            hl3: 0,
            lh3: 0,
            hh3: 0,
            hl2: 0,
            lh2: 0,
            hh2: 0,
            hl1: 0,
            lh1: 0,
            hh1: 0,
        };

        progressive_dequantize(&mut coefficients, &prog_quant, false);

        // LL3 uses floor shift: 5 << 2 = 20, -3 << 2 = -12
        assert_eq!(coefficients[4032], 20);
        assert_eq!(coefficients[4033], -12);
    }

    #[test]
    fn progressive_dequantize_non_ll3_preserves_sign() {
        // HL1 is band index 0, at offset 0 for standard layout
        let mut coefficients = vec![0i16; 4096];
        coefficients[0] = 5;
        coefficients[1] = -5;

        let prog_quant = ComponentCodecQuant {
            ll3: 0,
            hl3: 0,
            lh3: 0,
            hh3: 0,
            hl2: 0,
            lh2: 0,
            hh2: 0,
            hl1: 2,
            lh1: 0,
            hh1: 0,
        };

        progressive_dequantize(&mut coefficients, &prog_quant, false);

        // Non-LL3: shift absolute value, preserve sign
        assert_eq!(coefficients[0], 20); // 5 << 2
        assert_eq!(coefficients[1], -20); // -(5 << 2)
    }

    #[test]
    fn progressive_quantize_round_trip() {
        let mut coefficients = vec![0i16; 4096];
        for (i, c) in coefficients.iter_mut().enumerate() {
            *c = (i as i16).wrapping_mul(7);
        }
        let original = coefficients.clone();

        let prog_quant = ComponentCodecQuant {
            ll3: 2,
            hl3: 3,
            lh3: 3,
            hh3: 4,
            hl2: 3,
            lh2: 3,
            hh2: 4,
            hl1: 2,
            lh1: 2,
            hh1: 3,
        };

        progressive_quantize(&mut coefficients, &prog_quant, false);
        progressive_dequantize(&mut coefficients, &prog_quant, false);

        // After quantize->dequantize, values lose precision from truncation
        // but should be in the right ballpark
        for (i, (&a, &b)) in coefficients.iter().zip(original.iter()).enumerate() {
            let err = (i32::from(a) - i32::from(b)).unsigned_abs();
            // Max error bounded by 2^(bit_pos)
            assert!(err < 32, "index {i}: error {err} too large");
        }
    }

    #[test]
    fn raw_bit_reader_basic() {
        let data = [0b10110000, 0b01010000];
        let mut reader = RawBitReader::new(&data);
        assert_eq!(reader.read_bits(4), 0b1011);
        assert_eq!(reader.read_bits(4), 0b0000);
        assert_eq!(reader.read_bits(4), 0b0101);
    }

    #[test]
    fn clamp_i16_limits() {
        assert_eq!(clamp_i16(40000), i16::MAX);
        assert_eq!(clamp_i16(-40000), i16::MIN);
        assert_eq!(clamp_i16(100), 100);
        assert_eq!(clamp_i16(-100), -100);
    }

    #[test]
    fn band_zero_count_counts_correctly() {
        let mut sign = [0i8; 4096];
        // Band 0 (HL1): offset 0, count 1024
        sign[0] = SIGN_POSITIVE;
        sign[1] = SIGN_NEGATIVE;
        sign[2] = SIGN_ZERO;
        // Rest are SIGN_ZERO by default

        let bands = standard_band_layout();
        assert_eq!(band_zero_count(&sign, &bands[0]), 1022); // 1024 - 2 non-zero
    }

    #[test]
    fn ll3_offsets_correct() {
        assert_eq!(ll3_offset(false), 4032);
        assert_eq!(ll3_offset(true), 4015);
    }

    #[test]
    fn upgrade_pass_zero_das_becomes_nonzero() {
        let mut coefficients = vec![0i16; 4096];
        let mut sign = vec![SIGN_POSITIVE; 4096];
        sign[0] = SIGN_ZERO;

        // Set up SRL data that produces a non-zero value for the first position
        // For band 0 (HL1), with num_bits=2, SRL should produce some values
        let prev_prog_quant = ComponentCodecQuant {
            ll3: 0,
            hl3: 0,
            lh3: 0,
            hh3: 0,
            hl2: 0,
            lh2: 0,
            hh2: 0,
            hl1: 4,
            lh1: 0,
            hh1: 0,
        };
        let curr_prog_quant = ComponentCodecQuant {
            ll3: 0,
            hl3: 0,
            lh3: 0,
            hh3: 0,
            hl2: 0,
            lh2: 0,
            hh2: 0,
            hl1: 2,
            lh1: 0,
            hh1: 0,
        };

        // Zero run 0 (10), positive sign (0), magnitude 1 (1), then the
        // required trailing zero byte.
        let srl_data = vec![0b1001_0000, 0x00];
        let raw_data = vec![];

        decode_upgrade_pass(
            &srl_data,
            &raw_data,
            &prev_prog_quant,
            &curr_prog_quant,
            false,
            &mut coefficients,
            &mut sign,
        )
        .unwrap();

        assert_eq!(coefficients[0], 4);
        assert_eq!(sign[0], SIGN_POSITIVE);
    }

    #[test]
    fn upgrade_pass_preserves_component_streams_across_bands() {
        // MS-RDPEGFX 4.1.2.1.2 treats SRL entries in different bands as
        // consecutive. A component also has one raw bit stream for the upgrade.
        let mut coefficients = [0i16; COEFFICIENTS_PER_COMPONENT];
        let mut sign = [SIGN_POSITIVE; COEFFICIENTS_PER_COMPONENT];
        sign[0] = SIGN_ZERO;
        sign[1024] = SIGN_ZERO;

        let mut prev_prog_quant = ComponentCodecQuant::LOSSLESS;
        prev_prog_quant.hl1 = 1;
        prev_prog_quant.lh1 = 1;

        // The bits encode +1 in HL1 followed by -1 in LH1. The raw stream
        // provides one bit for HL1 and then runs out before LH1.
        decode_upgrade_pass(
            &[0b1001_1000, 0x00],
            &[0b1000_0000],
            &prev_prog_quant,
            &ComponentCodecQuant::LOSSLESS,
            false,
            &mut coefficients,
            &mut sign,
        )
        .unwrap();

        assert_eq!(coefficients[0], 1);
        assert_eq!(coefficients[1024], -1);
        assert_eq!(coefficients[1], 1);
        assert_eq!(coefficients[1025], 0);
    }

    #[test]
    fn upgrade_pass_rejects_truncated_srl() {
        let mut coefficients = [0i16; COEFFICIENTS_PER_COMPONENT];
        let mut sign = [SIGN_POSITIVE; COEFFICIENTS_PER_COMPONENT];
        sign[0] = SIGN_ZERO;

        let mut prev_prog_quant = ComponentCodecQuant::LOSSLESS;
        prev_prog_quant.hl1 = 4;

        assert_eq!(
            decode_upgrade_pass(
                &[0x80, 0x00],
                &[],
                &prev_prog_quant,
                &ComponentCodecQuant::LOSSLESS,
                false,
                &mut coefficients,
                &mut sign,
            ),
            Err(SrlError::Truncated)
        );
    }

    #[test]
    fn tile_upgrade_keeps_all_components_on_srl_error() {
        let mut tile = TileState::new();
        let mut prev_prog_quant = ComponentCodecQuant::LOSSLESS;
        prev_prog_quant.hl1 = 4;
        tile.prog_quant = [prev_prog_quant; 3];
        tile.pass = 1;
        tile.quality = 50;
        tile.sign[0][0] = SIGN_ZERO;
        tile.sign[1][0] = SIGN_ZERO;

        let coefficients = tile.coefficients;
        let sign = tile.sign;

        assert_eq!(
            tile.decode_upgrade(
                [&[0x90, 0x00], &[0x80, 0x00], &[]],
                [&[], &[], &[]],
                [ComponentCodecQuant::LOSSLESS; 3],
                75,
            ),
            Err(SrlError::Truncated)
        );

        assert_eq!(tile.coefficients, coefficients);
        assert_eq!(tile.sign, sign);
        assert_eq!(tile.prog_quant, [prev_prog_quant; 3]);
        assert_eq!(tile.pass, 1);
        assert_eq!(tile.quality, 50);
    }

    #[test]
    fn tile_state_default_is_zeroed() {
        let tile = TileState::new();
        assert_eq!(tile.pass, 0);
        assert_eq!(tile.quality, 0);
        assert!(!tile.use_reduce_extrapolate);
        assert!(tile.coefficients[0].iter().all(|&v| v == 0));
        assert!(tile.sign[0].iter().all(|&v| v == 0));
    }

    #[test]
    fn surface_tiles_dimensions() {
        let surface = SurfaceTiles::new(1920, 1080, true).unwrap();
        assert_eq!(surface.tiles_wide, 30);
        assert_eq!(surface.tiles_high, 17);
        assert!(surface.use_reduce_extrapolate);
    }

    #[test]
    fn surface_tiles_exact_multiple() {
        // 1280 / 64 = 20, 768 / 64 = 12 (exact, no rounding)
        let surface = SurfaceTiles::new(1280, 768, false).unwrap();
        assert_eq!(surface.tiles_wide, 20);
        assert_eq!(surface.tiles_high, 12);
    }

    #[test]
    fn surface_tiles_lazy_allocation() {
        let mut surface = SurfaceTiles::new(128, 128, false).unwrap();
        // No tiles allocated yet
        assert!(surface.get(0, 0).is_none());

        // Access creates tile
        let tile = surface.get_or_create(0, 0).unwrap();
        assert_eq!(tile.pass, 0);
        assert!(!tile.use_reduce_extrapolate);

        // Now it exists
        assert!(surface.get(0, 0).is_some());

        // Out of bounds returns None
        assert!(surface.get_or_create(2, 2).is_none());
    }

    #[test]
    fn surface_tiles_reset() {
        let mut surface = SurfaceTiles::new(128, 128, false).unwrap();
        surface.get_or_create(0, 0);
        assert!(surface.get(0, 0).is_some());

        surface.reset();
        assert!(surface.get(0, 0).is_none());
    }

    #[test]
    fn decoder_new_is_empty() {
        let decoder = ProgressiveDecoder::new();
        assert!(decoder.contexts.is_empty());
    }

    #[test]
    fn decoder_delete_nonexistent_context() {
        let mut decoder = ProgressiveDecoder::new();
        // Should not panic on non-existent context
        decoder.delete_context(1, 42);
    }

    #[test]
    fn decoder_reset_clears_contexts_but_preserves_sub_band_references() {
        let mut decoder = ProgressiveDecoder::new();

        let result = decoder.decode_bitmap(1, 1, 64, 64, &simple_tile_stream(0, [64, -16, 24], true));
        assert!(result.is_ok());
        assert_eq!(decoder.contexts.len(), 1);
        assert_eq!(decoder.references.len(), 1);
        let reference = *decoder
            .references
            .get(&(1, 0, 0))
            .expect("original tile reference should be retained");

        decoder.reset();
        assert!(decoder.contexts.is_empty());
        assert_eq!(decoder.references.get(&(1, 0, 0)), Some(&reference));

        assert!(
            decoder
                .decode_bitmap(
                    1,
                    2,
                    64,
                    64,
                    &simple_tile_stream(TILE_FLAG_DIFFERENCE, [7, -3, 5], true),
                )
                .is_ok(),
            "a new codec context should use the retained surface reference"
        );
    }

    #[test]
    fn decoder_contexts_are_scoped_by_surface() {
        let mut decoder = ProgressiveDecoder::new();

        let stream = minimal_progressive_stream(true);
        assert!(decoder.decode_bitmap(1, 0, 640, 480, &stream).is_ok());
        assert!(decoder.decode_bitmap(2, 0, 800, 600, &stream).is_ok());
        assert_eq!(decoder.contexts.len(), 2);

        decoder.delete_context(1, 0);
        assert_eq!(decoder.contexts.len(), 1);
        assert!(decoder.contexts.contains_key(&(2, 0)));

        assert!(decoder.decode_bitmap(1, 0, 640, 480, &stream).is_ok());
        assert!(decoder.decode_bitmap(1, 1, 640, 480, &stream).is_ok());
        assert_eq!(decoder.contexts.len(), 3);

        decoder.delete_surface(1);
        assert_eq!(decoder.contexts.len(), 1);
        assert!(decoder.contexts.contains_key(&(2, 0)));
    }

    #[test]
    fn decoder_context_fallback_is_scoped_by_surface() {
        let mut decoder = ProgressiveDecoder::new();
        let stream_with_context = minimal_progressive_stream(true);
        let stream_without_context = minimal_progressive_stream(false);

        assert!(decoder.decode_bitmap(1, 0, 640, 480, &stream_with_context).is_ok());
        assert!(matches!(
            decoder.decode_bitmap(2, 0, 640, 480, &stream_without_context),
            Err(ProgressiveDecodeError::MissingBlock("CONTEXT"))
        ));

        assert!(decoder.decode_bitmap(2, 0, 640, 480, &stream_with_context).is_ok());
        assert!(decoder.decode_bitmap(2, 0, 640, 480, &stream_without_context).is_ok());
    }

    fn rect(x: u16, y: u16, width: u16, height: u16) -> ironrdp_pdu::codecs::rfx::RfxRectangle {
        ironrdp_pdu::codecs::rfx::RfxRectangle { x, y, width, height }
    }

    #[test]
    fn decoder_bounds_region_clipping_work() {
        use ironrdp_pdu::codecs::rfx::RfxRectangle;
        use ironrdp_pdu::codecs::rfx::progressive::{
            ProgressiveBlock, ProgressiveContextPdu, ProgressiveFrameBeginPdu, ProgressiveFrameEndPdu,
            ProgressiveRegion, ProgressiveSyncPdu, encode_progressive_stream,
        };

        fn stream_with_rects(rects: Vec<RfxRectangle>) -> Vec<u8> {
            encode_progressive_stream(&[
                ProgressiveBlock::Sync(ProgressiveSyncPdu),
                ProgressiveBlock::Context(ProgressiveContextPdu {
                    context_id: 0,
                    tile_size: 0x0040,
                    flags: 0,
                }),
                ProgressiveBlock::FrameBegin(ProgressiveFrameBeginPdu {
                    frame_index: 0,
                    region_count: 1,
                }),
                ProgressiveBlock::Region(ProgressiveRegion {
                    tile_size: 0x40,
                    rects,
                    quant_vals: vec![],
                    quant_prog_vals: vec![],
                    flags: 0,
                    tiles: vec![],
                }),
                ProgressiveBlock::FrameEnd(ProgressiveFrameEndPdu),
            ])
            .unwrap()
        }

        // Each disjoint rectangle grows the normalized Region by one entry.
        // 1,500 such inserts exceed the aggregate scan budget long before the
        // wire-format u16 rectangle count could drive quadratic work unchecked.
        const RECT_COUNT: u16 = 1_500;
        let fragmented = (0..RECT_COUNT).map(|x| rect(x.saturating_mul(3), 0, 2, 2)).collect();
        let mut decoder = ProgressiveDecoder::new();
        let error = match decoder.decode_bitmap(1, 1, 8192, 64, &stream_with_rects(fragmented)) {
            Err(error) => error,
            Ok(_) => panic!("fragmented clipping region must exhaust the work budget"),
        };
        assert!(error.to_string().contains("clipping work limit exceeded"));

        // The limit tracks actual normalized-region work rather than rejecting
        // the same numRects when all rectangles collapse to one simple region.
        let collapsed = vec![rect(0, 0, 2, 2); usize::from(RECT_COUNT)];
        assert!(
            ProgressiveDecoder::new()
                .decode_bitmap(1, 1, 4096, 64, &stream_with_rects(collapsed))
                .is_ok()
        );

        // Intersecting a moderately fragmented region with an attacker-sized
        // accumulated tile set is charged to the same per-payload budget.
        let rects = (0..100u16).map(|x| rect(x.saturating_mul(3), 0, 2, 2)).collect();
        let frame_tiles = (0..11_000u16).map(|index| (index % 128, index / 128)).collect();
        let mut decoder = ProgressiveDecoder::new();
        decoder.begin_frame();
        decoder.frame_tiles.insert((1, 1), frame_tiles);
        let error = match decoder.decode_bitmap(1, 1, 8192, 8192, &stream_with_rects(rects)) {
            Err(error) => error,
            Ok(_) => panic!("tile intersections must share the clipping work budget"),
        };
        assert!(error.to_string().contains("clipping work limit exceeded"));
    }

    #[test]
    fn decoder_ignores_regions_outside_frame() {
        use ironrdp_pdu::codecs::rfx::progressive::{
            ComponentCodecQuant, ProgressiveBlock, ProgressiveContextPdu, ProgressiveFrameBeginPdu,
            ProgressiveFrameEndPdu, ProgressiveRegion, ProgressiveSyncPdu, ProgressiveTile, TileSimple,
            encode_progressive_stream,
        };

        fn invalid_region() -> ProgressiveRegion<'static> {
            ProgressiveRegion {
                tile_size: 0x40,
                rects: vec![rect(0, 0, 64, 64)],
                quant_vals: vec![ComponentCodecQuant::LOSSLESS],
                quant_prog_vals: vec![],
                flags: 0,
                tiles: vec![ProgressiveTile::Simple(TileSimple {
                    quant_idx_y: 0,
                    quant_idx_cb: 0,
                    quant_idx_cr: 0,
                    x_idx: 1,
                    y_idx: 0,
                    flags: 0,
                    y_data: &[],
                    cb_data: &[],
                    cr_data: &[],
                    tail_data: &[],
                })],
            }
        }

        let context = ProgressiveBlock::Context(ProgressiveContextPdu {
            context_id: 0,
            tile_size: 0x0040,
            flags: 0,
        });
        let empty_frame_begin = ProgressiveBlock::FrameBegin(ProgressiveFrameBeginPdu {
            frame_index: 0,
            region_count: 0,
        });

        let outside = encode_progressive_stream(&[
            ProgressiveBlock::Sync(ProgressiveSyncPdu),
            context.clone(),
            ProgressiveBlock::Region(invalid_region()),
            empty_frame_begin,
            ProgressiveBlock::FrameEnd(ProgressiveFrameEndPdu),
            ProgressiveBlock::Region(invalid_region()),
        ])
        .unwrap();

        let mut decoder = ProgressiveDecoder::new();
        let tiles = decoder.decode_bitmap(1, 10, 64, 64, &outside).unwrap();
        assert!(tiles.is_empty(), "out-of-frame regions must not produce tiles");

        // The same deliberately out-of-bounds REGION must still be decoded,
        // and fail, when it appears inside the frame.
        let inside = encode_progressive_stream(&[
            ProgressiveBlock::Sync(ProgressiveSyncPdu),
            context,
            ProgressiveBlock::FrameBegin(ProgressiveFrameBeginPdu {
                frame_index: 0,
                region_count: 1,
            }),
            ProgressiveBlock::Region(invalid_region()),
            ProgressiveBlock::FrameEnd(ProgressiveFrameEndPdu),
        ])
        .unwrap();
        assert!(matches!(
            decoder.decode_bitmap(1, 11, 64, 64, &inside),
            Err(ProgressiveDecodeError::TileOutOfBounds { .. })
        ));
    }

    #[test]
    fn full_quality_tiles_bypass_the_progressive_quant_table() {
        let lossless = progressive_quant_for(0xFF, &[]).expect("0xFF selects full quality");
        assert_eq!(lossless.y_quant, ComponentCodecQuant::LOSSLESS);
        assert_eq!(lossless.cb_quant, ComponentCodecQuant::LOSSLESS);
        assert_eq!(lossless.cr_quant, ComponentCodecQuant::LOSSLESS);

        // Every other value still indexes the table the REGION carried.
        assert!(matches!(
            progressive_quant_for(0, &[]),
            Err(ProgressiveDecodeError::InvalidQuantIndex { index: 0, table_len: 0 })
        ));
    }

    #[test]
    fn decoder_error_display() {
        let e = ProgressiveDecodeError::MissingBlock("SYNC");
        assert!(e.to_string().contains("SYNC"));

        let e = ProgressiveDecodeError::TileOutOfBounds { x_idx: 5, y_idx: 10 };
        assert!(e.to_string().contains("5"));
        assert!(e.to_string().contains("10"));

        let e = ProgressiveDecodeError::InvalidQuantIndex { index: 3, table_len: 2 };
        assert!(e.to_string().contains("3"));
    }

    #[test]
    fn dequantize_component_ccq_shifts_correctly() {
        let mut coefficients = vec![0i16; 4096];
        coefficients[0] = 10; // HL1 band (index 0)
        coefficients[4032] = 5; // LL3 band (index 9, standard layout)

        let quant = ComponentCodecQuant {
            ll3: 7,
            hl3: 0,
            lh3: 0,
            hh3: 0,
            hl2: 0,
            lh2: 0,
            hh2: 0,
            hl1: 8,
            lh1: 0,
            hh1: 0,
        };

        dequantize_component_ccq(&mut coefficients, &quant, false);

        // HL1: scale 2^(8 - 6) = 4 -> 10 * 4 = 40
        assert_eq!(coefficients[0], 40);
        // LL3: scale 2^(7 - 6) = 2 -> 5 * 2 = 10
        assert_eq!(coefficients[4032], 10);
    }

    // --- B10: Server encode pipeline tests ---

    #[test]
    fn rgba_to_ycbcr_pure_white() {
        let pixels = vec![255u8; 64 * 64 * 4];
        let mut y = vec![0i16; 4096];
        let mut cb = vec![0i16; 4096];
        let mut cr = vec![0i16; 4096];

        rgba_to_ycbcr(&pixels, &mut y, &mut cb, &mut cr);

        // Pure white: R=G=B=255
        // Y = (19595*255 + 38470*255 + 7471*255 + 32768) >> 16 - 128
        //   = (65536*255 + 32768) >> 16 - 128 = 255 - 128 = 127
        // Cb and Cr should be ~0 (achromatic)
        assert!((y[0] - 127).abs() <= 1, "Y for white: got {}", y[0]);
        assert!(cb[0].abs() <= 1, "Cb for white: got {}", cb[0]);
        assert!(cr[0].abs() <= 1, "Cr for white: got {}", cr[0]);
    }

    #[test]
    fn rgba_to_ycbcr_pure_black() {
        let pixels = vec![0u8; 64 * 64 * 4];
        let mut y = vec![0i16; 4096];
        let mut cb = vec![0i16; 4096];
        let mut cr = vec![0i16; 4096];

        rgba_to_ycbcr(&pixels, &mut y, &mut cb, &mut cr);

        // Pure black: Y = -128, Cb = 0, Cr = 0
        assert_eq!(y[0], -128);
        assert_eq!(cb[0], 0);
        assert_eq!(cr[0], 0);
    }

    #[test]
    fn base_quantization_handles_all_wire_factors() {
        for factor in 0..=15 {
            let input = if factor < 6 { 1 } else { 1i16 << u32::from(factor - 6) };
            let quant = ComponentCodecQuant {
                ll3: factor,
                hl3: factor,
                lh3: factor,
                hh3: factor,
                hl2: factor,
                lh2: factor,
                hh2: factor,
                hl1: factor,
                lh1: factor,
                hh1: factor,
            };
            let mut coefficients = [0i16; COEFFICIENTS_PER_COMPONENT];
            coefficients[0] = input;

            quantize_component_ccq(&mut coefficients, &quant, false);
            dequantize_component_ccq(&mut coefficients, &quant, false);

            assert_eq!(coefficients[0], input, "factor {factor}");
        }
    }

    #[test]
    fn base_dequantization_rounds_fractional_scales() {
        let quant = ComponentCodecQuant {
            ll3: 5,
            hl3: 5,
            lh3: 5,
            hh3: 5,
            hl2: 5,
            lh2: 5,
            hh2: 5,
            hl1: 5,
            lh1: 5,
            hh1: 5,
        };
        let mut coefficients = [0i16; COEFFICIENTS_PER_COMPONENT];
        coefficients[0] = 7;
        coefficients[1] = -7;

        dequantize_component_ccq(&mut coefficients, &quant, false);

        assert_eq!(coefficients[0], 4);
        assert_eq!(coefficients[1], -3);
    }

    #[test]
    fn progressive_state_retains_base_quantized_coefficients() {
        let base_quant = ComponentCodecQuant {
            ll3: 5,
            hl3: 5,
            lh3: 5,
            hh3: 5,
            hl2: 5,
            lh2: 5,
            hh2: 5,
            hl1: 5,
            lh1: 5,
            hh1: 5,
        };
        let prog_quant = ComponentCodecQuant {
            ll3: 1,
            hl3: 1,
            lh3: 1,
            hh3: 1,
            hl2: 1,
            lh2: 1,
            hh2: 1,
            hl1: 1,
            lh1: 1,
            hh1: 1,
        };
        let mut progressive_coefficients = [0i16; COEFFICIENTS_PER_COMPONENT];
        progressive_coefficients[0] = 7;
        progressive_coefficients[1] = -7;
        let mut encoded = [0u8; 8192];
        let encoded_len = crate::rlgr::encode(EntropyAlgorithm::Rlgr1, &progressive_coefficients, &mut encoded)
            .expect("RLGR encoding should succeed");
        let mut tile = TileState::new();

        tile.decode_first(
            [&encoded[..encoded_len]; 3],
            [&base_quant; 3],
            [prog_quant; 3],
            [0; 3],
            0,
            false,
        )
        .expect("first-pass decoding should succeed");

        // MS-RDPEGFX 3.3.8.2.1.1 requires DecDwtQ to be reconstructed with
        // only the progressive factor while upgrade data is accumulated.
        assert_eq!(tile.coefficients[0][0], 14);
        assert_eq!(tile.coefficients[0][1], -14);

        let mut coefficients = [0i16; COEFFICIENTS_PER_COMPONENT];
        let mut sign = [SIGN_ZERO; COEFFICIENTS_PER_COMPONENT];
        decode_first_pass(
            &encoded[..encoded_len],
            &base_quant,
            &prog_quant,
            false,
            &mut coefficients,
            &mut sign,
        )
        .expect("standalone first-pass decoding should succeed");

        // The standalone path applies the base scale after progressive
        // dequantization, so the factor-5 and BitPos-1 scales cancel exactly.
        assert_eq!(coefficients[0], 7);
        assert_eq!(coefficients[1], -7);
    }

    #[test]
    #[expect(clippy::similar_names, reason = "Cb and Cr are standard YCbCr component names")]
    fn progressive_fractional_base_quantization_reconstructs_rgb() {
        let base_quant = ComponentCodecQuant {
            ll3: 5,
            hl3: 5,
            lh3: 5,
            hh3: 5,
            hl2: 5,
            lh2: 5,
            hh2: 5,
            hl1: 5,
            lh1: 5,
            hh1: 5,
        };
        let prog_quant = ComponentCodecQuant {
            ll3: 1,
            hl3: 1,
            lh3: 1,
            hh3: 1,
            hl2: 1,
            lh2: 1,
            hh2: 1,
            hl1: 1,
            lh1: 1,
            hh1: 1,
        };
        let expected = [64, 128, 192];
        let mut pixels = vec![0u8; 64 * 64 * 4];
        for pixel in pixels.chunks_exact_mut(4) {
            pixel[..3].copy_from_slice(&expected);
            pixel[3] = 0xFF;
        }

        let mut y = [0i16; COEFFICIENTS_PER_COMPONENT];
        let mut cb = [0i16; COEFFICIENTS_PER_COMPONENT];
        let mut cr = [0i16; COEFFICIENTS_PER_COMPONENT];
        rgba_to_ycbcr(&pixels, &mut y, &mut cb, &mut cr);

        let mut y_data = [0u8; 8192];
        let mut cb_data = [0u8; 8192];
        let mut cr_data = [0u8; 8192];
        let y_len = encode_first_pass(&mut y, &mut y_data, &base_quant, &prog_quant, false)
            .expect("Y first-pass encoding should succeed");
        let cb_len = encode_first_pass(&mut cb, &mut cb_data, &base_quant, &prog_quant, false)
            .expect("Cb first-pass encoding should succeed");
        let cr_len = encode_first_pass(&mut cr, &mut cr_data, &base_quant, &prog_quant, false)
            .expect("Cr first-pass encoding should succeed");

        let mut tile = TileState::new();
        tile.decode_first(
            [&y_data[..y_len], &cb_data[..cb_len], &cr_data[..cr_len]],
            [&base_quant; 3],
            [prog_quant; 3],
            [0; 3],
            0,
            false,
        )
        .expect("first-pass decoding should succeed");

        let mut actual = vec![0u8; 64 * 64 * 4];
        tile.reconstruct_to_rgba(&mut actual);

        for actual in actual.chunks_exact(4) {
            for channel in 0..3 {
                let difference = i16::from(expected[channel]) - i16::from(actual[channel]);
                assert!(difference.abs() <= 2, "expected {expected:?}, got {:?}", &actual[..3]);
            }
            assert_eq!(actual[3], 0xFF);
        }
    }

    #[test]
    fn ycbcr_to_rgb_handles_full_i16_range() {
        // These products overflow i32: `cr * 91881` for |cr| > 23372,
        // `cb * 116130` for |cb| > 18492, and the `cb`/`cr` sum.
        let cases: [(i16, i16, i16, [u8; 3]); 10] = [
            (0, 0, 0, [128, 128, 128]),
            (0, 0, i16::MAX, [255, 0, 128]),
            (0, i16::MAX, 0, [128, 0, 255]),
            (0, i16::MAX, i16::MAX, [255, 0, 255]),
            (0, 0, i16::MIN, [0, 255, 128]),
            (0, i16::MIN, 0, [128, 255, 0]),
            (i16::MIN, i16::MIN, i16::MIN, [0, 255, 0]),
            (i16::MAX, i16::MAX, i16::MAX, [255, 0, 255]),
            (-20000, -20000, -20000, [0, 255, 0]),
            (20000, 20000, 20000, [255, 0, 255]),
        ];
        for (y, cb, cr, expected) in cases {
            assert_eq!(ycbcr_to_rgb(y, cb, cr), expected, "y={y} cb={cb} cr={cr}");
        }
    }

    #[test]
    fn progressive_q6_reconstructs_rgb_color_vectors() {
        let base_quant = ComponentCodecQuant {
            ll3: 6,
            hl3: 6,
            lh3: 6,
            hh3: 6,
            hl2: 6,
            lh2: 6,
            hh2: 6,
            hl1: 6,
            lh1: 6,
            hh1: 6,
        };

        for expected in [
            [0, 0, 0],
            [255, 255, 255],
            [255, 0, 0],
            [0, 255, 0],
            [0, 0, 255],
            [64, 128, 192],
        ] {
            let mut pixels = vec![0u8; 64 * 64 * 4];
            for pixel in pixels.chunks_exact_mut(4) {
                pixel[..3].copy_from_slice(&expected);
                pixel[3] = 0xFF;
            }

            let mut y = [0i16; COEFFICIENTS_PER_COMPONENT];
            let mut cb = [0i16; COEFFICIENTS_PER_COMPONENT];
            let mut cr = [0i16; COEFFICIENTS_PER_COMPONENT];
            rgba_to_ycbcr(&pixels, &mut y, &mut cb, &mut cr);

            let mut temp = [0i16; COEFFICIENTS_PER_COMPONENT];
            crate::dwt::encode(&mut y, &mut temp);
            crate::dwt::encode(&mut cb, &mut temp);
            crate::dwt::encode(&mut cr, &mut temp);

            quantize_component_ccq(&mut y, &base_quant, false);
            quantize_component_ccq(&mut cb, &base_quant, false);
            quantize_component_ccq(&mut cr, &base_quant, false);
            dequantize_component_ccq(&mut y, &base_quant, false);
            dequantize_component_ccq(&mut cb, &base_quant, false);
            dequantize_component_ccq(&mut cr, &base_quant, false);

            let mut tile = TileState::new();
            tile.coefficients = [y, cb, cr];

            let mut actual = vec![0u8; 64 * 64 * 4];
            tile.reconstruct_to_rgba(&mut actual);

            for actual in actual.chunks_exact(4) {
                for channel in 0..3 {
                    let difference = i16::from(expected[channel]) - i16::from(actual[channel]);
                    assert!(difference.abs() <= 2, "expected {:?}, got {:?}", expected, &actual[..3]);
                }
                assert_eq!(actual[3], 0xFF);
            }
        }
    }

    #[test]
    fn quantize_ccq_scales_coefficients() {
        let mut coefficients = [0i16; 4096];
        coefficients[0] = 40; // HL1 band
        coefficients[4032] = 10; // LL3 band

        let quant = ComponentCodecQuant {
            ll3: 7,
            hl3: 0,
            lh3: 0,
            hh3: 0,
            hl2: 0,
            lh2: 0,
            hh2: 0,
            hl1: 8,
            lh1: 0,
            hh1: 0,
        };

        quantize_component_ccq(&mut coefficients, &quant, false);

        // HL1: 40 / 2^(8 - 6) = 40 / 4 = 10
        assert_eq!(coefficients[0], 10);
        // LL3: 10 / 2^(7 - 6) = 10 / 2 = 5
        assert_eq!(coefficients[4032], 5);
    }

    #[test]
    fn quantize_ccq_preserves_negative_sign() {
        let mut coefficients = [0i16; 4096];
        coefficients[0] = -40; // HL1 band, negative

        let quant = ComponentCodecQuant {
            ll3: 0,
            hl3: 0,
            lh3: 0,
            hh3: 0,
            hl2: 0,
            lh2: 0,
            hh2: 0,
            hl1: 8,
            lh1: 0,
            hh1: 0,
        };

        quantize_component_ccq(&mut coefficients, &quant, false);

        // -40 / 2^(8 - 6) = -40 / 4 = -10
        assert_eq!(coefficients[0], -10);
    }

    #[test]
    fn raw_bit_writer_single_byte() {
        let mut w = RawBitWriter::new();
        w.write_bits(0xA5, 8);
        assert_eq!(w.finish(), vec![0xA5]);
    }

    #[test]
    fn raw_bit_writer_partial_byte_padded() {
        let mut w = RawBitWriter::new();
        w.write_bits(0b101, 3);
        // 3 bits: 101, padded to 10100000 = 0xA0
        assert_eq!(w.finish(), vec![0xA0]);
    }

    #[test]
    fn raw_bit_writer_multi_byte() {
        let mut w = RawBitWriter::new();
        w.write_bits(0xFF, 8);
        w.write_bits(0b1010, 4);
        // First byte: 0xFF, second partial: 1010_0000 = 0xA0
        assert_eq!(w.finish(), vec![0xFF, 0xA0]);
    }

    #[test]
    fn encode_first_pass_produces_output() {
        // Flat tile: all same value, should compress well
        let mut coefficients = [100i16; 4096];
        let mut output = vec![0u8; 8192];

        let base_quant = ComponentCodecQuant::LOSSLESS;
        let prog_quant = ComponentCodecQuant::LOSSLESS;

        let result = encode_first_pass(&mut coefficients, &mut output, &base_quant, &prog_quant, false);

        assert!(result.is_ok(), "RLGR encode failed: {:?}", result.err());
        let bytes_written = result.unwrap();
        assert!(bytes_written > 0, "expected non-zero encoded output");
        assert!(bytes_written < 8192, "flat tile should compress");
    }

    #[test]
    fn encode_first_pass_reduce_extrapolate() {
        let mut coefficients = [50i16; 4096];
        let mut output = vec![0u8; 8192];

        let base_quant = ComponentCodecQuant::LOSSLESS;
        let prog_quant = ComponentCodecQuant::LOSSLESS;

        let result = encode_first_pass(
            &mut coefficients,
            &mut output,
            &base_quant,
            &prog_quant,
            true, // reduce-extrapolate mode
        );

        assert!(result.is_ok(), "RLGR encode failed: {:?}", result.err());
        assert!(result.unwrap() > 0);
    }

    #[test]
    fn encode_upgrade_pass_empty_when_no_refinement() {
        let coefficients = [0i16; 4096];
        let prev_coefficients = [0i16; 4096];
        let sign = [SIGN_ZERO; 4096];

        // Same prog_quant for prev and curr -> num_bits = 0, no refinement
        let prog_quant = ComponentCodecQuant::LOSSLESS;

        let (srl_data, raw_data) = encode_upgrade_pass(
            &coefficients,
            &prev_coefficients,
            &prog_quant,
            &prog_quant,
            &sign,
            false,
        )
        .unwrap();

        assert!(srl_data.is_empty(), "no refinement bits, SRL should be empty");
        assert!(raw_data.is_empty(), "no refinement bits, raw should be empty");
    }

    // --- B12: Integration / round-trip tests ---

    #[test]
    fn first_pass_encode_decode_round_trip_lossless() {
        // With LOSSLESS quants (all 1s), quantization is a no-op (shift by 0).
        // The only error source is DWT integer truncation (LeGall 5/3).
        //
        // decode_first_pass returns frequency-domain coefficients (post-dequant),
        // so we apply inverse DWT to get back to spatial domain for comparison.
        let original = [42i16; COEFFICIENTS_PER_COMPONENT];
        let mut encode_buf = original;
        let mut output = vec![0u8; 16384];

        let base_quant = ComponentCodecQuant::LOSSLESS;
        let prog_quant = ComponentCodecQuant::LOSSLESS;

        let bytes = encode_first_pass(&mut encode_buf, &mut output, &base_quant, &prog_quant, false).unwrap();

        let mut decoded = [0i16; COEFFICIENTS_PER_COMPONENT];
        let mut sign = [0i8; COEFFICIENTS_PER_COMPONENT];
        decode_first_pass(
            &output[..bytes],
            &base_quant,
            &prog_quant,
            false,
            &mut decoded,
            &mut sign,
        )
        .unwrap();

        // Inverse DWT to get back to spatial domain
        let mut temp = [0i16; COEFFICIENTS_PER_COMPONENT];
        crate::dwt::decode(&mut decoded, &mut temp);

        let max_err = original
            .iter()
            .zip(decoded.iter())
            .map(|(a, b)| (i32::from(*a) - i32::from(*b)).unsigned_abs())
            .max()
            .unwrap();

        assert!(max_err <= 4, "flat data round-trip max error {max_err} exceeds 4");
    }

    #[test]
    fn first_pass_encode_decode_round_trip_reduce_extrapolate() {
        let original = [42i16; COEFFICIENTS_PER_COMPONENT];
        let mut encode_buf = original;
        let mut output = vec![0u8; 16384];

        let base_quant = ComponentCodecQuant::LOSSLESS;
        let prog_quant = ComponentCodecQuant::LOSSLESS;

        let bytes = encode_first_pass(&mut encode_buf, &mut output, &base_quant, &prog_quant, true).unwrap();

        let mut decoded = [0i16; COEFFICIENTS_PER_COMPONENT];
        let mut sign = [0i8; COEFFICIENTS_PER_COMPONENT];
        decode_first_pass(
            &output[..bytes],
            &base_quant,
            &prog_quant,
            true,
            &mut decoded,
            &mut sign,
        )
        .unwrap();

        // Inverse DWT (reduce-extrapolate variant)
        let mut temp = [0i16; COEFFICIENTS_PER_COMPONENT];
        crate::dwt_extrapolate::decode(&mut decoded, &mut temp);

        let max_err = original
            .iter()
            .zip(decoded.iter())
            .map(|(a, b)| (i32::from(*a) - i32::from(*b)).unsigned_abs())
            .max()
            .unwrap();

        assert!(
            max_err <= 6,
            "reduce-extrapolate round-trip max error {max_err} exceeds 6"
        );
    }

    #[test]
    fn first_pass_encode_decode_with_quantization() {
        // Test encode/decode with realistic quantization (non-lossless).
        // Quantization introduces controlled error, so we just verify
        // the pipeline completes and the decoded output is in a sensible range.
        let mut coefficients = [42i16; COEFFICIENTS_PER_COMPONENT];
        let mut output = vec![0u8; 16384];

        let base_quant = ComponentCodecQuant {
            ll3: 6,
            hl3: 6,
            lh3: 6,
            hh3: 6,
            hl2: 7,
            lh2: 7,
            hh2: 7,
            hl1: 8,
            lh1: 8,
            hh1: 8,
        };
        let prog_quant = ComponentCodecQuant::LOSSLESS;

        let bytes = encode_first_pass(&mut coefficients, &mut output, &base_quant, &prog_quant, false).unwrap();
        assert!(bytes > 0, "should produce encoded output");

        // Quantized data should compress better than lossless
        let mut decoded = [0i16; COEFFICIENTS_PER_COMPONENT];
        let mut sign = [0i8; COEFFICIENTS_PER_COMPONENT];
        decode_first_pass(
            &output[..bytes],
            &base_quant,
            &prog_quant,
            false,
            &mut decoded,
            &mut sign,
        )
        .unwrap();

        // Inverse DWT
        let mut temp = [0i16; COEFFICIENTS_PER_COMPONENT];
        crate::dwt::decode(&mut decoded, &mut temp);

        // With quantization, values should be approximately the original (42)
        // but with significant quantization noise. Just check within +-200.
        let mean_err: f64 = decoded
            .iter()
            .map(|v| f64::from((i32::from(*v) - 42).unsigned_abs()))
            .sum::<f64>()
            / 4096.0;

        assert!(
            mean_err < 200.0,
            "mean error {mean_err} too large for quantized flat tile"
        );
    }

    #[test]
    #[expect(clippy::similar_names, reason = "y/cb/cr are standard YCbCr component names")]
    fn rgba_ycbcr_reconstruct_round_trip() {
        // RGB -> YCbCr -> RGB. ITU-R BT.601 fixed-point round-trip carries a
        // few units of integer-rounding error per channel. We assert a bounded
        // per-channel max and verify Y/Cb/Cr stay in [-128, 127] in between.
        let mut pixels = vec![0u8; 64 * 64 * 4];
        for i in 0..64 * 64 {
            // Smooth gradient
            let row = i / 64;
            let col = i % 64;
            pixels[i * 4] = (row * 4) as u8; // R
            pixels[i * 4 + 1] = (col * 4) as u8; // G
            pixels[i * 4 + 2] = 128; // B
            pixels[i * 4 + 3] = 255; // A
        }

        let mut y = vec![0i16; 4096];
        let mut cb = vec![0i16; 4096];
        let mut cr = vec![0i16; 4096];

        rgba_to_ycbcr(&pixels, &mut y, &mut cb, &mut cr);

        // Verify Y is in expected range [-128..127] and Cb/Cr in [-128..127]
        for i in 0..4096 {
            assert!(y[i] >= -128 && y[i] <= 127, "Y[{i}] = {} out of range", y[i]);
            assert!(cb[i] >= -128 && cb[i] <= 127, "Cb[{i}] = {} out of range", cb[i]);
            assert!(cr[i] >= -128 && cr[i] <= 127, "Cr[{i}] = {} out of range", cr[i]);
        }

        // Inverse YCbCr -> RGB using the same BT.601 matrix as
        // TileState::reconstruct_to_rgba (the decode-side counterpart).
        let mut max_err = 0i32;
        for i in 0..64 * 64 {
            let y_val = i32::from(y[i]) + 128;
            let cb_val = i32::from(cb[i]);
            let cr_val = i32::from(cr[i]);

            let r_rec = (y_val + ((cr_val * 91881 + 32768) >> 16)).clamp(0, 255);
            let g_rec = (y_val - ((cb_val * 22554 + cr_val * 46802 + 32768) >> 16)).clamp(0, 255);
            let b_rec = (y_val + ((cb_val * 116130 + 32768) >> 16)).clamp(0, 255);

            let off = i * 4;
            let r_orig = i32::from(pixels[off]);
            let g_orig = i32::from(pixels[off + 1]);
            let b_orig = i32::from(pixels[off + 2]);

            max_err = max_err.max((r_rec - r_orig).abs());
            max_err = max_err.max((g_rec - g_orig).abs());
            max_err = max_err.max((b_rec - b_orig).abs());
        }
        assert!(
            max_err <= 2,
            "RGB -> YCbCr -> RGB max per-channel error {max_err} exceeds 2"
        );
    }

    #[test]
    fn upgrade_pass_encode_decode_round_trip() {
        // Two-pass refinement round-trip on the upgrade-pass wire format. Uses
        // synthetic post-DWT post-quant coefficients to isolate the upgrade-pass
        // mechanism from forward/inverse DWT and RLGR1 framing.
        //
        // The contract under test: encode_upgrade_pass(refined, prev, ...)
        // followed by decode_upgrade_pass applied to prev must not increase the
        // L1 distance to refined. The wire format is monotonic (encoder writes
        // additive magnitude deltas with DAS-determined sign per MS-RDPRFX
        // 3.1.8.1.7.2), so the post-decode distance cannot exceed pre-decode.
        let prev_prog_quant = ComponentCodecQuant {
            ll3: 0,
            hl3: 0,
            lh3: 0,
            hh3: 0,
            hl2: 0,
            lh2: 0,
            hh2: 0,
            hl1: 4,
            lh1: 0,
            hh1: 0,
        };
        let curr_prog_quant = ComponentCodecQuant {
            ll3: 0,
            hl3: 0,
            lh3: 0,
            hh3: 0,
            hl2: 0,
            lh2: 0,
            hh2: 0,
            hl1: 2,
            lh1: 0,
            hh1: 0,
        };

        // Populate HL1 band (band index 0, offset 0, count 1024) with paired
        // values: prev is coarser (low 4 bits zeroed), refined adds those bits.
        let mut prev_coeffs = vec![0i16; COEFFICIENTS_PER_COMPONENT];
        let mut refined_coeffs = vec![0i16; COEFFICIENTS_PER_COMPONENT];
        let mut sign = vec![SIGN_ZERO; COEFFICIENTS_PER_COMPONENT];

        for i in 0..1024 {
            let base = ((i as i32) * 5) % 256 - 128;
            let coarse = base & !0x0F;
            let refined = base;
            prev_coeffs[i] = coarse as i16;
            refined_coeffs[i] = refined as i16;
            sign[i] = match prev_coeffs[i].cmp(&0) {
                core::cmp::Ordering::Greater => SIGN_POSITIVE,
                core::cmp::Ordering::Less => SIGN_NEGATIVE,
                core::cmp::Ordering::Equal => SIGN_ZERO,
            };
        }

        let prev_dist: u32 = prev_coeffs
            .iter()
            .zip(refined_coeffs.iter())
            .map(|(p, r)| (i32::from(*p) - i32::from(*r)).unsigned_abs())
            .sum();

        let (srl_data, raw_data) = encode_upgrade_pass(
            &refined_coeffs,
            &prev_coeffs,
            &prev_prog_quant,
            &curr_prog_quant,
            &sign,
            false,
        )
        .unwrap();

        let mut decoded = prev_coeffs.clone();
        let mut decoded_sign = sign.clone();
        decode_upgrade_pass(
            &srl_data,
            &raw_data,
            &prev_prog_quant,
            &curr_prog_quant,
            false,
            &mut decoded,
            &mut decoded_sign,
        )
        .unwrap();

        let post_dist: u32 = decoded
            .iter()
            .zip(refined_coeffs.iter())
            .map(|(d, r)| (i32::from(*d) - i32::from(*r)).unsigned_abs())
            .sum();

        // Upgrade pass must not move further from the refined target.
        assert!(
            post_dist <= prev_dist,
            "upgrade pass must not increase distance to refined: prev_dist={prev_dist} post_dist={post_dist}"
        );
    }

    #[test]
    fn quantize_dequantize_ccq_round_trip() {
        let quant = ComponentCodecQuant {
            ll3: 4,
            hl3: 4,
            lh3: 4,
            hh3: 5,
            hl2: 5,
            lh2: 5,
            hh2: 6,
            hl1: 6,
            lh1: 6,
            hh1: 7,
        };

        // Start with some known coefficient values
        let original = {
            let mut c = [0i16; COEFFICIENTS_PER_COMPONENT];
            for (i, v) in c.iter_mut().enumerate() {
                *v = ((i * 7 % 256) as i16) - 128;
            }
            c
        };

        let mut coefficients = original;

        // Quantize then dequantize
        quantize_component_ccq(&mut coefficients, &quant, false);
        dequantize_component_ccq(&mut coefficients, &quant, false);

        // Quantization is lossy, but the round-trip should be in the right ballpark.
        // Error bound per coefficient: at most 2^(quant_val-1) per quantization step
        // With quant values 4-7, max error per step is 2^6 = 64
        let max_err = original
            .iter()
            .zip(coefficients.iter())
            .map(|(a, b)| (i32::from(*a) - i32::from(*b)).unsigned_abs())
            .max()
            .unwrap();

        assert!(
            max_err <= 64,
            "quantize/dequantize round-trip max error {max_err} exceeds 64"
        );
    }

    fn encode_full_quality_component(value: i16) -> Vec<u8> {
        let mut coefficients = [value; COEFFICIENTS_PER_COMPONENT];
        let mut encoded = vec![0; 8192];
        let encoded_len = encode_first_pass(
            &mut coefficients,
            &mut encoded,
            &ComponentCodecQuant::LOSSLESS,
            &ComponentCodecQuant::LOSSLESS,
            false,
        )
        .expect("full-quality component encoding should succeed");
        encoded.truncate(encoded_len);
        encoded
    }

    fn progressive_tile_stream(
        include_context: bool,
        quant_vals: Vec<ComponentCodecQuant>,
        quant_prog_vals: Vec<ProgressiveCodecQuant>,
        tile: ironrdp_pdu::codecs::rfx::progressive::ProgressiveTile<'_>,
    ) -> Vec<u8> {
        use ironrdp_pdu::codecs::rfx::RfxRectangle;
        use ironrdp_pdu::codecs::rfx::progressive::{
            ProgressiveBlock, ProgressiveContextPdu, ProgressiveFrameBeginPdu, ProgressiveFrameEndPdu,
            ProgressiveRegion, ProgressiveSyncPdu, encode_progressive_stream,
        };

        let mut blocks = vec![ProgressiveBlock::Sync(ProgressiveSyncPdu)];
        if include_context {
            blocks.push(ProgressiveBlock::Context(ProgressiveContextPdu {
                context_id: 0,
                tile_size: 0x0040,
                flags: 0,
            }));
        }

        blocks.extend([
            ProgressiveBlock::FrameBegin(ProgressiveFrameBeginPdu {
                frame_index: 0,
                region_count: 1,
            }),
            ProgressiveBlock::Region(ProgressiveRegion {
                tile_size: 0x40,
                rects: vec![RfxRectangle {
                    x: 0,
                    y: 0,
                    width: 64,
                    height: 64,
                }],
                quant_vals,
                quant_prog_vals,
                flags: 0,
                tiles: vec![tile],
            }),
            ProgressiveBlock::FrameEnd(ProgressiveFrameEndPdu),
        ]);

        encode_progressive_stream(&blocks).expect("synthetic progressive stream should encode")
    }

    fn simple_tile_stream(flags: u8, components: [i16; 3], include_context: bool) -> Vec<u8> {
        use ironrdp_pdu::codecs::rfx::progressive::{ProgressiveTile, TileSimple};

        let component_data = components.map(encode_full_quality_component);
        progressive_tile_stream(
            include_context,
            vec![ComponentCodecQuant::LOSSLESS],
            vec![],
            ProgressiveTile::Simple(TileSimple {
                quant_idx_y: 0,
                quant_idx_cb: 0,
                quant_idx_cr: 0,
                x_idx: 0,
                y_idx: 0,
                flags,
                y_data: &component_data[0],
                cb_data: &component_data[1],
                cr_data: &component_data[2],
                tail_data: &[],
            }),
        )
    }

    fn first_tile_stream(
        flags: u8,
        component_data: &[u8],
        base_quant: ComponentCodecQuant,
        progressive_quant: ComponentCodecQuant,
        include_context: bool,
    ) -> Vec<u8> {
        use ironrdp_pdu::codecs::rfx::progressive::{ProgressiveTile, TileFirst};

        progressive_tile_stream(
            include_context,
            vec![base_quant],
            vec![ProgressiveCodecQuant {
                quality: 0,
                y_quant: progressive_quant,
                cb_quant: progressive_quant,
                cr_quant: progressive_quant,
            }],
            ProgressiveTile::First(TileFirst {
                quant_idx_y: 0,
                quant_idx_cb: 0,
                quant_idx_cr: 0,
                x_idx: 0,
                y_idx: 0,
                flags,
                quality: 0,
                y_data: component_data,
                cb_data: component_data,
                cr_data: component_data,
                tail_data: &[],
            }),
        )
    }

    fn upgrade_tile_stream(
        raw_data: &[u8],
        base_quant: ComponentCodecQuant,
        first_progressive_quant: ComponentCodecQuant,
        upgrade_progressive_quant: ComponentCodecQuant,
        include_context: bool,
    ) -> Vec<u8> {
        use ironrdp_pdu::codecs::rfx::progressive::{ProgressiveTile, TileUpgrade};

        progressive_tile_stream(
            include_context,
            vec![base_quant],
            vec![
                ProgressiveCodecQuant {
                    quality: 0,
                    y_quant: first_progressive_quant,
                    cb_quant: first_progressive_quant,
                    cr_quant: first_progressive_quant,
                },
                ProgressiveCodecQuant {
                    quality: 1,
                    y_quant: upgrade_progressive_quant,
                    cb_quant: upgrade_progressive_quant,
                    cr_quant: upgrade_progressive_quant,
                },
            ],
            ProgressiveTile::Upgrade(TileUpgrade {
                quant_idx_y: 0,
                quant_idx_cb: 0,
                quant_idx_cr: 0,
                x_idx: 0,
                y_idx: 0,
                quality: 1,
                y_srl_data: &[],
                y_raw_data: raw_data,
                cb_srl_data: &[],
                cb_raw_data: raw_data,
                cr_srl_data: &[],
                cr_raw_data: raw_data,
            }),
        )
    }

    fn decode_full_quality_components(components: [i16; 3]) -> DecDwtQ {
        let component_data = components.map(encode_full_quality_component);
        let mut state = TileState::new();
        state
            .decode_first(
                [&component_data[0], &component_data[1], &component_data[2]],
                [&ComponentCodecQuant::LOSSLESS; 3],
                [ComponentCodecQuant::LOSSLESS; 3],
                [0; 3],
                0xFF,
                false,
            )
            .expect("full-quality components should decode");
        state.coefficients
    }

    #[test]
    fn difference_tile_adds_to_its_retained_surface_reference() {
        let original_components = [64, -16, 24];
        let other_surface_components = [-48, 8, 40];
        let difference_components = [7, -3, 5];
        let mut decoder = ProgressiveDecoder::new();

        let first_pixels = decoder
            .decode_bitmap(1, 7, 64, 64, &simple_tile_stream(0, original_components, true))
            .expect("original tile should decode")
            .pop()
            .expect("original tile should produce an update")
            .pixels;
        let reference = decoder
            .contexts
            .get(&(1, 7))
            .and_then(|context| context.surface.get(0, 0))
            .expect("original tile state should be retained")
            .coefficients;

        decoder
            .decode_bitmap(2, 8, 64, 64, &simple_tile_stream(0, other_surface_components, true))
            .expect("other surface tile should decode");
        let other_reference = decoder
            .contexts
            .get(&(2, 8))
            .and_then(|context| context.surface.get(0, 0))
            .expect("other surface tile state should be retained")
            .coefficients;

        let expected_delta = decode_full_quality_components(difference_components);

        let difference_pixels = decoder
            .decode_bitmap(
                1,
                7,
                64,
                64,
                &simple_tile_stream(TILE_FLAG_DIFFERENCE, difference_components, false),
            )
            .expect("difference tile should decode")
            .pop()
            .expect("difference tile should produce an update")
            .pixels;
        assert_ne!(first_pixels, difference_pixels);

        let updated_tile = decoder
            .contexts
            .get(&(1, 7))
            .and_then(|context| context.surface.get(0, 0))
            .expect("difference tile state should be retained");
        assert!(updated_tile.is_difference);
        for ((updated_component, reference_component), delta_component) in updated_tile
            .coefficients
            .iter()
            .zip(reference.iter())
            .zip(expected_delta.iter())
        {
            for ((updated, retained), delta) in updated_component
                .iter()
                .zip(reference_component.iter())
                .zip(delta_component.iter())
            {
                assert_eq!(*updated, retained.saturating_add(*delta));
            }
        }

        assert_eq!(
            decoder
                .contexts
                .get(&(2, 8))
                .and_then(|context| context.surface.get(0, 0))
                .expect("other surface tile state should remain retained")
                .coefficients,
            other_reference
        );
    }

    #[test]
    fn first_difference_tile_adds_to_its_retained_surface_reference() {
        let progressive_quant = ComponentCodecQuant::LOSSLESS;
        let original_data = encode_full_quality_component(64);
        let difference_data = encode_full_quality_component(7);
        let summed_data = encode_full_quality_component(71);
        let mut decoder = ProgressiveDecoder::new();

        decoder
            .decode_bitmap(
                1,
                7,
                64,
                64,
                &first_tile_stream(
                    0,
                    &original_data,
                    ComponentCodecQuant::LOSSLESS,
                    progressive_quant,
                    true,
                ),
            )
            .expect("original first-pass tile should decode");
        let accumulated = decoder
            .decode_bitmap(
                1,
                7,
                64,
                64,
                &first_tile_stream(
                    TILE_FLAG_DIFFERENCE,
                    &difference_data,
                    ComponentCodecQuant::LOSSLESS,
                    progressive_quant,
                    false,
                ),
            )
            .expect("difference first-pass tile should decode");

        let mut summed_decoder = ProgressiveDecoder::new();
        let summed = summed_decoder
            .decode_bitmap(
                1,
                7,
                64,
                64,
                &first_tile_stream(0, &summed_data, ComponentCodecQuant::LOSSLESS, progressive_quant, true),
            )
            .expect("summed first-pass tile should decode");

        assert_eq!(accumulated[0].pixels, summed[0].pixels);
        assert_eq!(
            decoder.references.get(&(1, 0, 0)),
            summed_decoder.references.get(&(1, 0, 0))
        );
        assert!(
            decoder
                .contexts
                .get(&(1, 7))
                .and_then(|context| context.surface.get(0, 0))
                .expect("difference tile state should be retained")
                .is_difference
        );
    }

    #[test]
    fn original_tile_replaces_a_retained_surface_reference() {
        let original_components = [64, -16, 24];
        let difference_components = [7, -3, 5];
        let replacement_components = [-48, 8, 40];
        let mut decoder = ProgressiveDecoder::new();

        decoder
            .decode_bitmap(1, 7, 64, 64, &simple_tile_stream(0, original_components, true))
            .expect("original tile should decode");
        decoder
            .decode_bitmap(
                1,
                7,
                64,
                64,
                &simple_tile_stream(TILE_FLAG_DIFFERENCE, difference_components, false),
            )
            .expect("difference tile should decode");
        let replacement = decoder
            .decode_bitmap(1, 7, 64, 64, &simple_tile_stream(0, replacement_components, false))
            .expect("replacement tile should decode");

        let mut standalone_decoder = ProgressiveDecoder::new();
        let standalone = standalone_decoder
            .decode_bitmap(1, 7, 64, 64, &simple_tile_stream(0, replacement_components, true))
            .expect("standalone replacement tile should decode");

        assert_eq!(replacement[0].pixels, standalone[0].pixels);
        assert_eq!(
            decoder.references.get(&(1, 0, 0)),
            standalone_decoder.references.get(&(1, 0, 0))
        );
        assert!(
            !decoder
                .contexts
                .get(&(1, 7))
                .and_then(|context| context.surface.get(0, 0))
                .expect("replacement tile state should be retained")
                .is_difference
        );
    }

    #[test]
    fn difference_tile_uses_the_reference_updated_by_an_upgrade() {
        let base_quant = ComponentCodecQuant {
            ll3: 6,
            hl3: 6,
            lh3: 6,
            hh3: 6,
            hl2: 6,
            lh2: 6,
            hh2: 6,
            hl1: 6,
            lh1: 6,
            hh1: 6,
        };
        let mut progressive_quant = ComponentCodecQuant::LOSSLESS;
        progressive_quant.ll3 = 1;

        let mut original_coefficients = [0; COEFFICIENTS_PER_COMPONENT];
        original_coefficients[4032] = 25;
        let mut difference_coefficients = [0; COEFFICIENTS_PER_COMPONENT];
        difference_coefficients[4032] = 5;
        let original_data = {
            let mut encoded = vec![0; 16 * 1024];
            let len = crate::rlgr::encode(EntropyAlgorithm::Rlgr1, &original_coefficients, &mut encoded)
                .expect("original RLGR encoding should succeed");
            encoded.truncate(len);
            encoded
        };
        let difference_data = {
            let mut encoded = vec![0; 16 * 1024];
            let len = crate::rlgr::encode(EntropyAlgorithm::Rlgr1, &difference_coefficients, &mut encoded)
                .expect("difference RLGR encoding should succeed");
            encoded.truncate(len);
            encoded
        };
        let mut decoder = ProgressiveDecoder::new();

        decoder
            .decode_bitmap(
                1,
                7,
                64,
                64,
                &first_tile_stream(0, &original_data, base_quant, progressive_quant, true),
            )
            .expect("original first-pass tile should decode");
        let initial_reference = *decoder
            .references
            .get(&(1, 0, 0))
            .expect("original tile should retain a reference");
        let raw_data = [0xFF; 8];
        decoder
            .decode_bitmap(
                1,
                7,
                64,
                64,
                &upgrade_tile_stream(
                    &raw_data,
                    base_quant,
                    progressive_quant,
                    ComponentCodecQuant::LOSSLESS,
                    false,
                ),
            )
            .expect("upgrade tile should decode");
        let upgraded_reference = *decoder
            .references
            .get(&(1, 0, 0))
            .expect("upgrade should update the retained reference");
        assert_ne!(upgraded_reference[0][4032], initial_reference[0][4032]);

        decoder
            .decode_bitmap(
                1,
                7,
                64,
                64,
                &first_tile_stream(
                    TILE_FLAG_DIFFERENCE,
                    &difference_data,
                    base_quant,
                    progressive_quant,
                    false,
                ),
            )
            .expect("difference first-pass tile should decode");
        let updated_reference = decoder
            .references
            .get(&(1, 0, 0))
            .expect("difference tile should update the retained reference");

        let mut delta = TileState::new();
        delta
            .decode_first(
                [&difference_data; 3],
                [&base_quant; 3],
                [progressive_quant; 3],
                [0; 3],
                0,
                false,
            )
            .expect("difference tile payload should decode independently");

        for ((updated_component, upgraded_component), delta_component) in updated_reference
            .iter()
            .zip(upgraded_reference.iter())
            .zip(delta.coefficients.iter())
        {
            for ((updated, upgraded), delta) in updated_component
                .iter()
                .zip(upgraded_component.iter())
                .zip(delta_component.iter())
            {
                assert_eq!(*updated, upgraded.saturating_add(*delta));
            }
        }
    }

    #[test]
    fn difference_tile_reference_survives_codec_context_deletion() {
        let original_components = [64, -16, 24];
        let difference_components = [7, -3, 5];
        let mut decoder = ProgressiveDecoder::new();

        decoder
            .decode_bitmap(1, 7, 64, 64, &simple_tile_stream(0, original_components, true))
            .expect("original tile should decode");
        let reference = *decoder
            .references
            .get(&(1, 0, 0))
            .expect("original tile reference should be retained");

        decoder.delete_context(1, 7);
        assert!(decoder.references.contains_key(&(1, 0, 0)));

        decoder
            .decode_bitmap(
                1,
                8,
                64,
                64,
                &simple_tile_stream(TILE_FLAG_DIFFERENCE, difference_components, true),
            )
            .expect("difference tile should decode with the surface reference");
        let expected_delta = decode_full_quality_components(difference_components);
        let updated = decoder
            .contexts
            .get(&(1, 8))
            .and_then(|context| context.surface.get(0, 0))
            .expect("difference tile state should be retained")
            .coefficients;

        for ((updated_component, reference_component), delta_component) in
            updated.iter().zip(reference.iter()).zip(expected_delta.iter())
        {
            for ((updated, retained), delta) in updated_component
                .iter()
                .zip(reference_component.iter())
                .zip(delta_component.iter())
            {
                assert_eq!(*updated, retained.saturating_add(*delta));
            }
        }

        assert_eq!(decoder.references.get(&(1, 0, 0)), Some(&updated));

        decoder.delete_surface(1);
        assert!(!decoder.references.contains_key(&(1, 0, 0)));
        assert!(matches!(
            decoder.decode_bitmap(
                1,
                9,
                64,
                64,
                &simple_tile_stream(TILE_FLAG_DIFFERENCE, difference_components, true),
            ),
            Err(ProgressiveDecodeError::MissingTileReference { x_idx: 0, y_idx: 0 })
        ));
    }

    #[test]
    fn resizing_a_surface_preserves_sub_band_references() {
        let mut decoder = ProgressiveDecoder::new();
        let original_components = [64, -16, 24];
        let difference_components = [7, -3, 5];

        decoder
            .decode_bitmap(1, 7, 64, 64, &simple_tile_stream(0, original_components, true))
            .expect("original tile should decode");
        let reference = *decoder
            .references
            .get(&(1, 0, 0))
            .expect("original tile reference should be retained");

        decoder
            .decode_bitmap(1, 7, 128, 64, &minimal_progressive_stream(true))
            .expect("resized surface should decode");
        assert_eq!(decoder.references.get(&(1, 0, 0)), Some(&reference));

        decoder
            .decode_bitmap(
                1,
                7,
                128,
                64,
                &simple_tile_stream(TILE_FLAG_DIFFERENCE, difference_components, false),
            )
            .expect("difference tile should decode after resizing");

        let expected_delta = decode_full_quality_components(difference_components);
        let updated = decoder
            .references
            .get(&(1, 0, 0))
            .expect("difference tile should update the retained reference");
        for ((updated_component, reference_component), delta_component) in
            updated.iter().zip(reference.iter()).zip(expected_delta.iter())
        {
            for ((updated_coefficient, reference_coefficient), delta_coefficient) in updated_component
                .iter()
                .zip(reference_component.iter())
                .zip(delta_component.iter())
            {
                assert_eq!(
                    *updated_coefficient,
                    reference_coefficient.saturating_add(*delta_coefficient)
                );
            }
        }
    }

    #[test]
    fn difference_tile_requires_a_retained_reference() {
        let mut decoder = ProgressiveDecoder::new();

        assert!(matches!(
            decoder.decode_bitmap(
                1,
                7,
                64,
                64,
                &simple_tile_stream(TILE_FLAG_DIFFERENCE, [7, -3, 5], true),
            ),
            Err(ProgressiveDecodeError::MissingTileReference { x_idx: 0, y_idx: 0 })
        ));
    }

    #[test]
    fn failed_difference_tile_keeps_retained_state() {
        let original_data = [64, -16, 24].map(encode_full_quality_component);
        let difference_data = [7, -3, 5].map(encode_full_quality_component);
        let mut state = TileState::new();
        let base_quants = [&ComponentCodecQuant::LOSSLESS; 3];
        let prog_quants = [ComponentCodecQuant::LOSSLESS; 3];

        state
            .decode_first(
                [&original_data[0], &original_data[1], &original_data[2]],
                base_quants,
                prog_quants,
                [0; 3],
                0xFF,
                false,
            )
            .expect("original tile should decode");

        let coefficients = state.coefficients;
        let sign = state.sign;
        let prog_quant = state.prog_quant;
        let quant_idx = state.quant_idx;
        let base_quant = state.base_quant;
        let pass = state.pass;
        let is_difference = state.is_difference;
        let quality = state.quality;
        let use_reduce_extrapolate = state.use_reduce_extrapolate;

        assert!(
            state
                .decode_first_with_difference(
                    [&difference_data[0], &difference_data[1], &[]],
                    base_quants,
                    prog_quants,
                    Some(&coefficients),
                    FirstPassOptions {
                        quant_idx: [0; 3],
                        quality: 0xFF,
                        use_reduce_extrapolate: false,
                    },
                )
                .is_err(),
            "invalid difference payload should fail"
        );

        assert_eq!(state.coefficients, coefficients);
        assert_eq!(state.sign, sign);
        assert_eq!(state.prog_quant, prog_quant);
        assert_eq!(state.quant_idx, quant_idx);
        assert_eq!(state.base_quant, base_quant);
        assert_eq!(state.pass, pass);
        assert_eq!(state.is_difference, is_difference);
        assert_eq!(state.quality, quality);
        assert_eq!(state.use_reduce_extrapolate, use_reduce_extrapolate);

        let mut delta = TileState::new();
        delta
            .decode_first(
                [&difference_data[0], &difference_data[1], &difference_data[2]],
                base_quants,
                prog_quants,
                [0; 3],
                0xFF,
                false,
            )
            .expect("valid difference payload should decode");
        state
            .decode_first_with_difference(
                [&difference_data[0], &difference_data[1], &difference_data[2]],
                base_quants,
                prog_quants,
                Some(&coefficients),
                FirstPassOptions {
                    quant_idx: [0; 3],
                    quality: 0xFF,
                    use_reduce_extrapolate: false,
                },
            )
            .expect("difference tile after failed decode should use retained state");

        for ((updated_component, retained_component), delta_component) in state
            .coefficients
            .iter()
            .zip(coefficients.iter())
            .zip(delta.coefficients.iter())
        {
            for ((updated, retained), delta) in updated_component
                .iter()
                .zip(retained_component.iter())
                .zip(delta_component.iter())
            {
                assert_eq!(*updated, retained.saturating_add(*delta));
            }
        }
    }
}
