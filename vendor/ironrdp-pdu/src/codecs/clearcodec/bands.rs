//! ClearCodec Layer 2: Bands (V-Bar Cached Columns) ([MS-RDPEGFX] 2.2.4.1.1.2).
//!
//! Bands encode rectangular strips of a bitmap using cached vertical column
//! data ("V-bars"). Each band covers a horizontal extent and contains one
//! V-bar per x-coordinate column. V-bars reference a two-level cache
//! (full V-bar storage + short V-bar storage) to exploit recurring vertical
//! column patterns typical of text glyphs.

use ironrdp_core::{DecodeResult, ReadCursor, ensure_size, invalid_field_err};

/// Maximum band height per the spec.
pub const MAX_BAND_HEIGHT: u16 = 52;

/// Number of entries in the full V-bar storage.
pub const VBAR_CACHE_SIZE: usize = 32_768;

/// Number of entries in the short V-bar storage.
pub const SHORT_VBAR_CACHE_SIZE: usize = 16_384;

/// A decoded band structure.
#[derive(Debug, Clone)]
pub struct Band<'a> {
    pub x_start: u16,
    pub x_end: u16,
    pub y_start: u16,
    pub y_end: u16,
    /// Background color (BGR).
    pub blue_bkg: u8,
    pub green_bkg: u8,
    pub red_bkg: u8,
    /// One V-bar per column from x_start to x_end (inclusive).
    pub vbars: Vec<VBar<'a>>,
}

impl Band<'_> {
    const NAME: &'static str = "ClearCodecBand";
    /// Band header: 4 x u16 + 3 x u8 = 11 bytes.
    const HEADER_SIZE: usize = 11;
}

/// A V-bar reference within a band.
///
/// Discriminated by the top 2 bits of the first u16 word:
/// - `1x` (bit 15 set): full V-bar cache hit (15-bit index)
/// - `01` (bits 15:14 = 01): short V-bar cache hit (14-bit index + yOn offset)
/// - `00` (bits 15:14 = 00): short V-bar cache miss (inline pixel data)
#[derive(Debug, Clone)]
pub enum VBar<'a> {
    /// Full V-bar cache hit. Index into V-Bar Storage (0..32767).
    CacheHit { index: u16 },
    /// Short V-bar cache hit. Index into Short V-Bar Storage (0..16383)
    /// plus a `yOn` offset byte for vertical positioning.
    ShortCacheHit { index: u16, y_on: u8 },
    /// Short V-bar cache miss. Contains inline pixel data.
    ShortCacheMiss(ShortVBarCacheMiss<'a>),
}

/// Inline short V-bar data from a cache miss.
#[derive(Debug, Clone)]
pub struct ShortVBarCacheMiss<'a> {
    /// First pixel row within the band where color data starts (shortVBarYOn).
    pub y_on: u8,
    /// Number of pixel rows with color data (`shortVBarYOff - shortVBarYOn`).
    pub y_off_delta: u8,
    /// Raw BGR pixel data: `y_off_delta * 3` bytes.
    pub pixel_data: &'a [u8],
}

/// Decode all bands from the bands layer data.
pub fn decode_bands_layer<'a>(data: &'a [u8]) -> DecodeResult<Vec<Band<'a>>> {
    let mut bands = Vec::new();
    let mut src = ReadCursor::new(data);

    while src.len() >= Band::HEADER_SIZE {
        let band = decode_single_band(&mut src)?;
        bands.push(band);
    }

    Ok(bands)
}

fn decode_single_band<'a>(src: &mut ReadCursor<'a>) -> DecodeResult<Band<'a>> {
    ensure_size!(ctx: Band::NAME, in: src, size: Band::HEADER_SIZE);

    let x_start = src.read_u16();
    let x_end = src.read_u16();
    let y_start = src.read_u16();
    let y_end = src.read_u16();
    let blue_bkg = src.read_u8();
    let green_bkg = src.read_u8();
    let red_bkg = src.read_u8();

    // Validate band height
    let height = y_end
        .checked_sub(y_start)
        .and_then(|h| h.checked_add(1))
        .ok_or_else(|| invalid_field_err!("yEnd", "yEnd < yStart"))?;

    if height > MAX_BAND_HEIGHT {
        return Err(invalid_field_err!("bandHeight", "band height exceeds 52"));
    }

    if x_end < x_start {
        return Err(invalid_field_err!("xEnd", "xEnd < xStart"));
    }

    // `x_end - x_start` is at most u16::MAX (when x_end = u16::MAX and
    // x_start = 0), so the `+ 1` would overflow u16. Cast to usize first.
    let column_count = usize::from(x_end - x_start) + 1;
    let mut vbars = Vec::with_capacity(column_count);

    for _ in 0..column_count {
        let vbar = decode_vbar(src, height)?;
        vbars.push(vbar);
    }

    Ok(Band {
        x_start,
        x_end,
        y_start,
        y_end,
        blue_bkg,
        green_bkg,
        red_bkg,
        vbars,
    })
}

fn decode_vbar<'a>(src: &mut ReadCursor<'a>, band_height: u16) -> DecodeResult<VBar<'a>> {
    ensure_size!(ctx: "VBar", in: src, size: 2);
    let first_word = src.read_u16();

    // Top bit set: full V-bar cache hit
    if first_word & 0x8000 != 0 {
        let index = first_word & 0x7FFF;
        return Ok(VBar::CacheHit { index });
    }

    // Bit 14 set (bit 15 clear): short V-bar cache hit
    if first_word & 0x4000 != 0 {
        let index = first_word & 0x3FFF;
        ensure_size!(ctx: "ShortVBarCacheHit", in: src, size: 1);
        let y_on = src.read_u8();
        return Ok(VBar::ShortCacheHit { index, y_on });
    }

    // Both top bits clear: short V-bar cache miss
    // Per MS-RDPEGFX 2.2.4.1.1.2.1.1.3 (SHORT_VBAR_CACHE_MISS):
    //   bits 13:6 = shortVBarYOn (8 bits): row where Short V-Bar begins
    //   bits 5:0  = shortVBarYOff (6 bits): row where Short V-Bar ends
    // Pixel count = shortVBarYOff - shortVBarYOn
    let y_on = u8::try_from(first_word >> 6).expect("top 2 bits are clear, so shifted value fits in u8");
    let y_off = u8::try_from(first_word & 0x3F).expect("masked to 6 bits, always fits in u8");

    if y_off < y_on {
        return Err(invalid_field_err!("shortVBarCacheMiss", "shortVBarYOff < shortVBarYOn"));
    }

    if u16::from(y_off) > band_height {
        return Err(invalid_field_err!(
            "shortVBarCacheMiss",
            "shortVBarYOff exceeds band height"
        ));
    }

    let pixel_count = y_off - y_on;
    let pixel_byte_count = usize::from(pixel_count) * 3;
    ensure_size!(ctx: "ShortVBarCacheMiss", in: src, size: pixel_byte_count);
    let pixel_data = src.read_slice(pixel_byte_count);

    Ok(VBar::ShortCacheMiss(ShortVBarCacheMiss {
        y_on,
        y_off_delta: pixel_count,
        pixel_data,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_vbar_cache_hit() {
        // Bit 15 set, index = 42
        let data = (0x8000u16 | 42).to_le_bytes();
        let mut cursor = ReadCursor::new(&data);
        let vbar = decode_vbar(&mut cursor, 10).unwrap();
        match vbar {
            VBar::CacheHit { index } => assert_eq!(index, 42),
            _ => panic!("expected CacheHit"),
        }
    }

    #[test]
    fn decode_vbar_short_cache_hit() {
        // Bit 14 set, bit 15 clear, index = 100, yOn = 5
        let mut data = Vec::new();
        data.extend_from_slice(&(0x4000u16 | 100).to_le_bytes());
        data.push(5); // yOn
        let mut cursor = ReadCursor::new(&data);
        let vbar = decode_vbar(&mut cursor, 10).unwrap();
        match vbar {
            VBar::ShortCacheHit { index, y_on } => {
                assert_eq!(index, 100);
                assert_eq!(y_on, 5);
            }
            _ => panic!("expected ShortCacheHit"),
        }
    }

    #[test]
    fn decode_vbar_short_cache_miss() {
        // Both top bits clear: y_on=2, y_off=5, pixel_count = y_off - y_on = 3
        let y_on: u16 = 2;
        let y_off: u16 = 5;
        let first_word = (y_on << 6) | y_off;
        let mut data = Vec::new();
        data.extend_from_slice(&first_word.to_le_bytes());
        // 3 pixels * 3 bytes = 9 bytes BGR data
        data.extend_from_slice(&[0xFF, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0xFF]);
        let mut cursor = ReadCursor::new(&data);
        let vbar = decode_vbar(&mut cursor, 10).unwrap();
        match vbar {
            VBar::ShortCacheMiss(miss) => {
                assert_eq!(miss.y_on, 2);
                assert_eq!(miss.y_off_delta, 3); // pixel_count = y_off - y_on = 5 - 2 = 3
                assert_eq!(miss.pixel_data.len(), 9);
            }
            _ => panic!("expected ShortCacheMiss"),
        }
    }

    #[test]
    fn decode_band_validates_height() {
        // Band with height > 52 should fail
        let mut data = Vec::new();
        data.extend_from_slice(&0u16.to_le_bytes()); // x_start
        data.extend_from_slice(&0u16.to_le_bytes()); // x_end = 0 (1 column)
        data.extend_from_slice(&0u16.to_le_bytes()); // y_start
        data.extend_from_slice(&52u16.to_le_bytes()); // y_end = 52, height = 53 > MAX
        data.extend_from_slice(&[0, 0, 0]); // bkg BGR
        let result = decode_bands_layer(&data);
        assert!(result.is_err());
    }

    #[test]
    fn decode_empty_bands_layer() {
        let bands = decode_bands_layer(&[]).unwrap();
        assert!(bands.is_empty());
    }
}
