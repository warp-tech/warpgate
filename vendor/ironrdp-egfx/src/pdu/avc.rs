use core::fmt;

use bit_field::BitField as _;
use bitflags::bitflags;
use ironrdp_pdu::geometry::InclusiveRectangle;
use ironrdp_pdu::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, cast_length, ensure_fixed_part_size,
    ensure_size, invalid_field_err,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuantQuality {
    pub quantization_parameter: u8,
    pub progressive: bool,
    pub quality: u8,
}

// Manual `Arbitrary` impl: the encoder packs `quantization_parameter` into bits 0..6
// via `set_bits`, which panics when the value exceeds 6 bits. Mask the field to its
// wire-allowed range so fuzz inputs always round-trip through `Encode`. The other
// fields use their full type range.
#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for QuantQuality {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            quantization_parameter: u.arbitrary::<u8>()? & 0x3F, // 6 bits
            progressive: u.arbitrary()?,
            quality: u.arbitrary()?,
        })
    }
}

impl QuantQuality {
    const NAME: &'static str = "GfxQuantQuality";

    const FIXED_PART_SIZE: usize = 1 /* data */ + 1 /* quality */;
}

impl Encode for QuantQuality {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        let mut data = 0u8;
        data.set_bits(0..6, self.quantization_parameter);
        data.set_bit(7, self.progressive);
        dst.write_u8(data);
        dst.write_u8(self.quality);
        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for QuantQuality {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let data = src.read_u8();
        let qp = data.get_bits(0..6);
        let progressive = data.get_bit(7);
        let quality = src.read_u8();
        Ok(QuantQuality {
            quantization_parameter: qp,
            progressive,
            quality,
        })
    }
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, PartialEq, Eq)]
pub struct Avc420BitmapStream<'a> {
    pub rectangles: Vec<InclusiveRectangle>,
    pub quant_qual_vals: Vec<QuantQuality>,
    pub data: &'a [u8],
}

impl fmt::Debug for Avc420BitmapStream<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Avc420BitmapStream")
            .field("rectangles", &self.rectangles)
            .field("quant_qual_vals", &self.quant_qual_vals)
            .field("data_len", &self.data.len())
            .finish()
    }
}

impl Avc420BitmapStream<'_> {
    const NAME: &'static str = "Avc420BitmapStream";

    const FIXED_PART_SIZE: usize = 4 /* nRect */;
}

impl Encode for Avc420BitmapStream<'_> {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        // INVARIANT: rectangles.len() == quant_qual_vals.len()
        debug_assert_eq!(self.rectangles.len(), self.quant_qual_vals.len());

        dst.write_u32(cast_length!("len", self.rectangles.len())?);
        for rectangle in &self.rectangles {
            rectangle.encode(dst)?;
        }
        for quant_qual_val in &self.quant_qual_vals {
            quant_qual_val.encode(dst)?;
        }
        dst.write_slice(self.data);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        // Each rectangle is 8 bytes and 2 bytes for each quant val
        Self::FIXED_PART_SIZE + self.rectangles.len() * 10 + self.data.len()
    }
}

impl<'de> Decode<'de> for Avc420BitmapStream<'de> {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let num_regions = src.read_u32();
        #[expect(clippy::as_conversions, reason = "num_regions bounded by practical limits")]
        let num_regions_usize = num_regions as usize;
        // Cap pre-allocation against the remaining buffer to avoid OOM from a
        // malicious num_regions: each region needs at least one rectangle
        // (8 bytes) plus one QuantQuality entry (2 bytes). The actual read
        // loop will fail with NotEnoughBytes if num_regions is bogus.
        let per_region = InclusiveRectangle::FIXED_PART_SIZE + QuantQuality::FIXED_PART_SIZE;
        let max_possible = src.len() / per_region;
        let bounded_capacity = num_regions_usize.min(max_possible);
        let mut rectangles = Vec::with_capacity(bounded_capacity);
        let mut quant_qual_vals = Vec::with_capacity(bounded_capacity);
        for _ in 0..num_regions {
            rectangles.push(InclusiveRectangle::decode(src)?);
        }
        for _ in 0..num_regions {
            quant_qual_vals.push(QuantQuality::decode(src)?);
        }
        let data = src.remaining();
        Ok(Avc420BitmapStream {
            rectangles,
            quant_qual_vals,
            data,
        })
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Encoding: u8 {
        const LUMA_AND_CHROMA = 0x00;
        const LUMA = 0x01;
        const CHROMA = 0x02;

        const _ = !0;
    }
}

// Manual `Arbitrary` impl: the encoder packs `encoding.bits()` into 2 bits via
// `set_bits(30..32, ...)` on the Avc444BitmapStream stream-info field. The bitflag
// otherwise accepts any u8 value (via `const _ = !0`), so the bitflags-crate-provided
// derive would generate values that exceed the 2-bit wire range and panic the encoder.
// Mask to 2 bits.
#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Encoding {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from_bits_retain(u.arbitrary::<u8>()? & 0x03))
    }
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Avc444BitmapStream<'a> {
    pub encoding: Encoding,
    pub stream1: Avc420BitmapStream<'a>,
    pub stream2: Option<Avc420BitmapStream<'a>>,
}

impl Avc444BitmapStream<'_> {
    const NAME: &'static str = "Avc444BitmapStream";

    const FIXED_PART_SIZE: usize = 4 /* streamInfo */;
}

impl Encode for Avc444BitmapStream<'_> {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        let mut stream_info = 0u32;
        stream_info.set_bits(0..30, cast_length!("stream1size", self.stream1.size())?);
        stream_info.set_bits(30..32, self.encoding.bits().into());
        dst.write_u32(stream_info);
        self.stream1.encode(dst)?;
        if let Some(stream) = self.stream2.as_ref() {
            stream.encode(dst)?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        let stream2_size = if let Some(stream) = self.stream2.as_ref() {
            stream.size()
        } else {
            0
        };

        Self::FIXED_PART_SIZE + self.stream1.size() + stream2_size
    }
}

impl<'de> Decode<'de> for Avc444BitmapStream<'de> {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let stream_info = src.read_u32();
        let stream_len = stream_info.get_bits(0..30);
        #[expect(clippy::unwrap_used, reason = "2-bit extraction always fits in u8")]
        let encoding_raw: u8 = stream_info.get_bits(30..32).try_into().unwrap();
        // Only 0x00 (LUMA_AND_CHROMA), 0x01 (LUMA), 0x02 (CHROMA) are defined.
        if encoding_raw > 2 {
            return Err(invalid_field_err!("encoding", "reserved encoding value"));
        }
        let encoding = Encoding::from_bits_retain(encoding_raw);

        if stream_len == 0 {
            if encoding == Encoding::LUMA_AND_CHROMA {
                return Err(invalid_field_err!("encoding", "invalid encoding"));
            }

            let stream1 = Avc420BitmapStream::decode(src)?;
            Ok(Avc444BitmapStream {
                encoding,
                stream1,
                stream2: None,
            })
        } else {
            #[expect(clippy::as_conversions, reason = "30-bit value fits in usize")]
            let stream_len = stream_len as usize;
            // Validate that the declared stream length fits in the remaining
            // buffer; src.split_at panics on overflow, so a malformed
            // streamLen field would otherwise crash the decoder. Surfaced
            // by the pdu_decode fuzz target.
            ensure_size!(ctx: Self::NAME, in: src, size: stream_len);
            let (mut stream1, mut stream2) = src.split_at(stream_len);
            let stream1 = Avc420BitmapStream::decode(&mut stream1)?;
            let stream2 = if encoding == Encoding::LUMA_AND_CHROMA {
                Some(Avc420BitmapStream::decode(&mut stream2)?)
            } else {
                None
            };
            Ok(Avc444BitmapStream {
                encoding,
                stream1,
                stream2,
            })
        }
    }
}

// ============================================================================
// Server-side utilities for H.264/AVC encoding
// ============================================================================

/// Region metadata for AVC420 bitmap streams (server-side)
///
/// Describes a rectangular region within the frame along with its
/// H.264 encoding parameters.
///
/// # Example
///
/// ```
/// use ironrdp_egfx::pdu::Avc420Region;
///
/// // Create a region covering a 1920x1080 frame
/// let region = Avc420Region::full_frame(1920, 1080, 22);
/// assert_eq!(region.left, 0);
/// assert_eq!(region.right, 1919);
/// ```
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Avc420Region {
    /// Left edge of the region (inclusive)
    pub left: u16,
    /// Top edge of the region (inclusive)
    pub top: u16,
    /// Right edge of the region (inclusive)
    pub right: u16,
    /// Bottom edge of the region (inclusive)
    pub bottom: u16,
    /// H.264 quantization parameter (0-51, lower = higher quality)
    pub quantization_parameter: u8,
    /// Quality value (0-100)
    pub quality: u8,
}

impl Avc420Region {
    /// Create a region covering the entire frame
    ///
    /// # Arguments
    ///
    /// * `width` - Frame width in pixels
    /// * `height` - Frame height in pixels
    /// * `qp` - H.264 quantization parameter (0-51)
    #[must_use]
    pub fn full_frame(width: u16, height: u16, qp: u8) -> Self {
        Self {
            left: 0,
            top: 0,
            right: width.saturating_sub(1),
            bottom: height.saturating_sub(1),
            quantization_parameter: qp,
            quality: 100,
        }
    }

    /// Create a region with custom bounds
    #[must_use]
    pub fn new(left: u16, top: u16, right: u16, bottom: u16, qp: u8, quality: u8) -> Self {
        Self {
            left,
            top,
            right,
            bottom,
            quantization_parameter: qp,
            quality,
        }
    }

    /// Convert to `InclusiveRectangle` for PDU encoding
    #[must_use]
    pub fn to_rectangle(&self) -> InclusiveRectangle {
        InclusiveRectangle {
            left: self.left,
            top: self.top,
            right: self.right,
            bottom: self.bottom,
        }
    }

    /// Convert to `QuantQuality` for PDU encoding
    #[must_use]
    pub fn to_quant_quality(&self) -> QuantQuality {
        QuantQuality {
            quantization_parameter: self.quantization_parameter,
            progressive: false,
            quality: self.quality,
        }
    }
}

/// Convert H.264 Annex B format to AVC format
///
/// MS-RDPEGFX requires AVC format (length-prefixed NAL units),
/// but most encoders output Annex B format (start code prefixed).
///
/// ```text
/// Annex B: 00 00 00 01 <NAL> 00 00 00 01 <NAL> ...
/// AVC:     <4-byte BE length> <NAL> <4-byte BE length> <NAL> ...
/// ```
///
/// # Arguments
///
/// * `data` - H.264 bitstream in Annex B format
///
/// # Returns
///
/// H.264 bitstream in AVC format with 4-byte big-endian length prefixes
///
/// # Example
///
/// ```
/// use ironrdp_egfx::pdu::annex_b_to_avc;
///
/// // NAL unit with 3-byte start code
/// let annex_b = [0x00, 0x00, 0x01, 0x67, 0x42, 0x00];
/// let avc = annex_b_to_avc(&annex_b);
/// // Result: [0x00, 0x00, 0x00, 0x03, 0x67, 0x42, 0x00]
/// assert_eq!(avc[0..4], [0, 0, 0, 3]); // 4-byte length = 3
/// ```
#[must_use]
pub fn annex_b_to_avc(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut i = 0;

    while i < data.len() {
        // Find start code (00 00 01 or 00 00 00 01)
        let start;

        if i + 4 <= data.len() && data[i..i + 4] == [0, 0, 0, 1] {
            start = i + 4;
        } else if i + 3 <= data.len() && data[i..i + 3] == [0, 0, 1] {
            start = i + 3;
        } else {
            i += 1;
            continue;
        }

        // Find next start code or end of data
        let mut end = data.len();
        for j in start..data.len().saturating_sub(2) {
            if data[j..j + 3] == [0, 0, 1] {
                // Could be 3-byte or 4-byte start code
                // Check if there's a leading zero (4-byte)
                if j > 0 && data[j - 1] == 0 {
                    end = j - 1;
                } else {
                    end = j;
                }
                break;
            }
        }

        // Write length-prefixed NAL unit
        let nal_data = &data[start..end];
        if !nal_data.is_empty() {
            // NAL units in H.264 are limited to ~4GB (32-bit length), so truncation is not a concern
            #[expect(
                clippy::cast_possible_truncation,
                clippy::as_conversions,
                reason = "NAL unit length fits in u32"
            )]
            let len = nal_data.len() as u32;
            result.extend_from_slice(&len.to_be_bytes());
            result.extend_from_slice(nal_data);
        }

        // Move to end of current NAL unit; next iteration will find the next start code
        i = end;
    }

    result
}

/// Align a dimension to 16-pixel boundary
///
/// H.264 operates on 16x16 macroblocks. This function rounds up
/// a dimension to the nearest multiple of 16.
///
/// # Example
///
/// ```
/// use ironrdp_egfx::pdu::align_to_16;
///
/// assert_eq!(align_to_16(1920), 1920); // Already aligned
/// assert_eq!(align_to_16(1080), 1088); // Rounded up
/// assert_eq!(align_to_16(1), 16);
/// ```
#[must_use]
pub const fn align_to_16(dimension: u32) -> u32 {
    (dimension + 15) & !15
}

/// Create an owned AVC420 bitmap stream from regions and H.264 data
///
/// This is a helper for server-side frame encoding. It creates
/// the bitmap stream structure that can be embedded in a
/// `WireToSurface1Pdu`.
///
/// # Arguments
///
/// * `regions` - List of regions with their encoding parameters
/// * `h264_data` - H.264 encoded data (should be in AVC format, not Annex B)
///
/// # Returns
///
/// Encoded `Avc420BitmapStream` as a byte vector
///
/// # Panics
///
/// Panics if internal encoding fails (should not happen with valid inputs).
#[must_use]
pub fn encode_avc420_bitmap_stream(regions: &[Avc420Region], h264_data: &[u8]) -> Vec<u8> {
    let rectangles: Vec<InclusiveRectangle> = regions.iter().map(Avc420Region::to_rectangle).collect();

    let quant_qual_vals: Vec<QuantQuality> = regions.iter().map(Avc420Region::to_quant_quality).collect();

    let stream = Avc420BitmapStream {
        rectangles,
        quant_qual_vals,
        data: h264_data,
    };

    // Calculate size and encode
    let size = stream.size();
    let mut buf = vec![0u8; size];
    let mut cursor = WriteCursor::new(&mut buf);

    // This should not fail as we pre-allocated the exact size
    stream
        .encode(&mut cursor)
        .expect("encode_avc420_bitmap_stream: encoding failed");

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_avc420_region_full_frame() {
        let region = Avc420Region::full_frame(1920, 1080, 22);
        assert_eq!(region.left, 0);
        assert_eq!(region.top, 0);
        assert_eq!(region.right, 1919);
        assert_eq!(region.bottom, 1079);
        assert_eq!(region.quantization_parameter, 22);
        assert_eq!(region.quality, 100);
    }

    #[test]
    fn test_align_to_16() {
        assert_eq!(align_to_16(0), 0);
        assert_eq!(align_to_16(1), 16);
        assert_eq!(align_to_16(15), 16);
        assert_eq!(align_to_16(16), 16);
        assert_eq!(align_to_16(17), 32);
        assert_eq!(align_to_16(1920), 1920);
        assert_eq!(align_to_16(1080), 1088);
    }

    #[test]
    fn test_annex_b_to_avc_3byte_start() {
        // NAL with 3-byte start code: 00 00 01 <NAL>
        let annex_b = [0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1E];
        let avc = annex_b_to_avc(&annex_b);

        // Should be: 4-byte length (4) + NAL data
        assert_eq!(avc.len(), 8);
        assert_eq!(&avc[0..4], &[0, 0, 0, 4]); // Length = 4
        assert_eq!(&avc[4..8], &[0x67, 0x42, 0x00, 0x1E]);
    }

    #[test]
    fn test_annex_b_to_avc_4byte_start() {
        // NAL with 4-byte start code: 00 00 00 01 <NAL>
        let annex_b = [0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00];
        let avc = annex_b_to_avc(&annex_b);

        assert_eq!(avc.len(), 7);
        assert_eq!(&avc[0..4], &[0, 0, 0, 3]); // Length = 3
        assert_eq!(&avc[4..7], &[0x67, 0x42, 0x00]);
    }

    #[test]
    fn test_annex_b_to_avc_multiple_nals() {
        // Two NAL units
        let annex_b = [
            0x00, 0x00, 0x00, 0x01, 0x67, 0x42, // SPS
            0x00, 0x00, 0x01, 0x68, 0xCE, // PPS with 3-byte start
        ];
        let avc = annex_b_to_avc(&annex_b);

        // First NAL: 4 bytes length + 2 bytes data
        // Second NAL: 4 bytes length + 2 bytes data
        assert!(avc.len() >= 12);
    }

    #[test]
    fn test_annex_b_to_avc_empty() {
        let avc = annex_b_to_avc(&[]);
        assert!(avc.is_empty());
    }

    #[test]
    fn test_encode_avc420_bitmap_stream() {
        let regions = vec![Avc420Region::full_frame(1920, 1080, 22)];
        let h264_data = [0x00, 0x00, 0x00, 0x01, 0x67]; // Minimal H.264

        let encoded = encode_avc420_bitmap_stream(&regions, &h264_data);

        // Should have: 4 bytes (nRect=1) + 8 bytes (rectangle) + 2 bytes (quant) + 5 bytes (data)
        assert_eq!(encoded.len(), 4 + 8 + 2 + 5);

        // Verify we can decode it back
        let mut cursor = ReadCursor::new(&encoded);
        let decoded = Avc420BitmapStream::decode(&mut cursor).expect("decode failed");

        assert_eq!(decoded.rectangles.len(), 1);
        assert_eq!(decoded.quant_qual_vals.len(), 1);
        assert_eq!(decoded.data, &h264_data);
    }
}
