//! ClearCodec bitmap compression codec (MS-RDPEGFX 2.2.4.1).
//!
//! ClearCodec is a mandatory lossless codec for all EGFX versions (V8-V10.7).
//! It uses a three-layer composite architecture: residual (BGR RLE), bands
//! (V-bar cached columns), and subcodec (raw / NSCodec / RLEX).
//!
//! The codec is transported inside `WireToSurface1Pdu` with `codecId = 0x0008`.

mod bands;
mod residual;
mod rlex;
mod subcodec;

use ironrdp_core::{DecodeResult, ReadCursor, cast_length, ensure_size, invalid_field_err};

pub use self::bands::{
    Band, MAX_BAND_HEIGHT, SHORT_VBAR_CACHE_SIZE, ShortVBarCacheMiss, VBAR_CACHE_SIZE, VBar, decode_bands_layer,
};
pub use self::residual::{RgbRunSegment, decode_residual_layer, encode_residual_layer};
pub use self::rlex::{MAX_PALETTE_COUNT, RlexData, RlexSegment, decode_rlex};
pub use self::subcodec::{Subcodec, SubcodecId, decode_subcodec_layer};

// --- Flag constants ---

/// `glyphIndex` field is present (bitmap area <= 1024 pixels).
pub const FLAG_GLYPH_INDEX: u8 = 0x01;
/// Use cached glyph at `glyphIndex`; no composite payload follows.
pub const FLAG_GLYPH_HIT: u8 = 0x02;
/// Reset V-Bar and Short V-Bar storage cursors to 0.
pub const FLAG_CACHE_RESET: u8 = 0x04;

// --- Top-level bitmap stream ---

/// Decoded ClearCodec bitmap stream ([MS-RDPEGFX] 2.2.4.1).
#[derive(Debug, Clone)]
pub struct ClearCodecBitmapStream<'a> {
    /// Combination of `FLAG_GLYPH_INDEX`, `FLAG_GLYPH_HIT`, `FLAG_CACHE_RESET`.
    pub flags: u8,
    /// Sequence number (wraps 0xFF -> 0x00).
    pub seq_number: u8,
    /// Glyph cache index, present when `FLAG_GLYPH_INDEX` is set.
    pub glyph_index: Option<u16>,
    /// Composite payload (three layers), absent when `FLAG_GLYPH_HIT` is set.
    pub composite: Option<CompositePayload<'a>>,
}

impl<'a> ClearCodecBitmapStream<'a> {
    const NAME: &'static str = "ClearCodecBitmapStream";

    /// Decode the complete bitmap stream from raw bytes.
    pub fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_size!(ctx: Self::NAME, in: src, size: 2);
        let flags = src.read_u8();
        let seq_number = src.read_u8();

        let glyph_index = if flags & FLAG_GLYPH_INDEX != 0 {
            ensure_size!(ctx: Self::NAME, in: src, size: 2);
            Some(src.read_u16())
        } else {
            None
        };

        // GLYPH_HIT means use cached glyph; no payload follows.
        let composite = if flags & FLAG_GLYPH_HIT != 0 {
            None
        } else if src.is_empty() {
            // No composite payload (valid for cache reset only messages)
            None
        } else {
            Some(CompositePayload::decode(src)?)
        };

        Ok(Self {
            flags,
            seq_number,
            glyph_index,
            composite,
        })
    }

    pub fn has_glyph_index(&self) -> bool {
        self.flags & FLAG_GLYPH_INDEX != 0
    }

    pub fn is_glyph_hit(&self) -> bool {
        self.flags & FLAG_GLYPH_HIT != 0
    }

    pub fn is_cache_reset(&self) -> bool {
        self.flags & FLAG_CACHE_RESET != 0
    }
}

// --- Composite payload (3 layers) ---

/// The three-layer composite payload ([MS-RDPEGFX] 2.2.4.1.1).
///
/// Layers are applied in order: residual -> bands -> subcodec.
/// Each layer composites on top of the previous result.
#[derive(Debug, Clone)]
pub struct CompositePayload<'a> {
    /// Raw bytes for the residual (BGR RLE) layer.
    pub residual_data: &'a [u8],
    /// Raw bytes for the bands (V-bar cached columns) layer.
    pub bands_data: &'a [u8],
    /// Raw bytes for the subcodec layer.
    pub subcodec_data: &'a [u8],
}

impl<'a> CompositePayload<'a> {
    const NAME: &'static str = "CompositePayload";

    /// Header: 3 x u32 byte counts.
    const HEADER_SIZE: usize = 12;

    pub fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_size!(ctx: Self::NAME, in: src, size: Self::HEADER_SIZE);

        let residual_byte_count: usize = cast_length!("residualByteCount", src.read_u32())?;
        let bands_byte_count: usize = cast_length!("bandsByteCount", src.read_u32())?;
        let subcodec_byte_count: usize = cast_length!("subcodecByteCount", src.read_u32())?;

        let total = residual_byte_count
            .checked_add(bands_byte_count)
            .and_then(|s| s.checked_add(subcodec_byte_count))
            .ok_or_else(|| invalid_field_err!("byteCount", "layer byte counts overflow"))?;

        ensure_size!(ctx: Self::NAME, in: src, size: total);

        let residual_data = src.read_slice(residual_byte_count);
        let bands_data = src.read_slice(bands_byte_count);
        let subcodec_data = src.read_slice(subcodec_byte_count);

        Ok(Self {
            residual_data,
            bands_data,
            subcodec_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_glyph_hit() {
        // flags=0x03 (GLYPH_INDEX | GLYPH_HIT), seq=0x05, glyphIndex=0x0042
        let data = [0x03, 0x05, 0x42, 0x00];
        let mut cursor = ReadCursor::new(&data);
        let stream = ClearCodecBitmapStream::decode(&mut cursor).unwrap();
        assert!(stream.has_glyph_index());
        assert!(stream.is_glyph_hit());
        assert!(!stream.is_cache_reset());
        assert_eq!(stream.seq_number, 5);
        assert_eq!(stream.glyph_index, Some(0x0042));
        assert!(stream.composite.is_none());
    }

    #[test]
    fn decode_cache_reset_only() {
        // flags=0x04 (CACHE_RESET), seq=0x00, no glyph, no composite
        let data = [0x04, 0x00];
        let mut cursor = ReadCursor::new(&data);
        let stream = ClearCodecBitmapStream::decode(&mut cursor).unwrap();
        assert!(stream.is_cache_reset());
        assert!(!stream.has_glyph_index());
        assert!(stream.composite.is_none());
    }

    #[test]
    fn decode_composite_payload_empty_layers() {
        // flags=0x00, seq=0x01, composite with all-zero byte counts
        let data = [
            0x00, 0x01, // flags, seq
            0x00, 0x00, 0x00, 0x00, // residualByteCount = 0
            0x00, 0x00, 0x00, 0x00, // bandsByteCount = 0
            0x00, 0x00, 0x00, 0x00, // subcodecByteCount = 0
        ];
        let mut cursor = ReadCursor::new(&data);
        let stream = ClearCodecBitmapStream::decode(&mut cursor).unwrap();
        let composite = stream.composite.unwrap();
        assert!(composite.residual_data.is_empty());
        assert!(composite.bands_data.is_empty());
        assert!(composite.subcodec_data.is_empty());
    }

    #[test]
    fn decode_composite_with_residual_data() {
        // flags=0x00, seq=0x02, residual=4 bytes, bands=0, subcodec=0
        let data = [
            0x00, 0x02, // flags, seq
            0x04, 0x00, 0x00, 0x00, // residualByteCount = 4
            0x00, 0x00, 0x00, 0x00, // bandsByteCount = 0
            0x00, 0x00, 0x00, 0x00, // subcodecByteCount = 0
            0xFF, 0x00, 0x00, 0x01, // 4 bytes of residual data
        ];
        let mut cursor = ReadCursor::new(&data);
        let stream = ClearCodecBitmapStream::decode(&mut cursor).unwrap();
        let composite = stream.composite.unwrap();
        assert_eq!(composite.residual_data, &[0xFF, 0x00, 0x00, 0x01]);
    }
}
