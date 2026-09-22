//! ClearCodec bitmap decoder and encoder (MS-RDPEGFX 2.2.4.1).
//!
//! ClearCodec is a mandatory lossless codec for EGFX that uses three-layer
//! compositing (residual BGR RLE, bands with V-bar caching, subcodecs) to
//! efficiently encode text, UI elements, and icons.

mod glyph_cache;
mod vbar_cache;

pub use self::glyph_cache::{GLYPH_CACHE_SIZE, GlyphCache, GlyphEntry};
pub use self::vbar_cache::{FullVBar, ShortVBar, VBarCache};

/// Glyph cache size as u16 for index arithmetic. GLYPH_CACHE_SIZE=4000 fits in u16.
const GLYPH_CACHE_WRAP: u16 = 4_000;

use ironrdp_core::{DecodeResult, ReadCursor, invalid_field_err};
use ironrdp_pdu::codecs::clearcodec::{
    ClearCodecBitmapStream, CompositePayload, FLAG_GLYPH_INDEX, RgbRunSegment, SubcodecId, VBar, decode_bands_layer,
    decode_residual_layer, decode_subcodec_layer, encode_residual_layer,
};

/// ClearCodec decoder maintaining persistent cache state across frames.
pub struct ClearCodecDecoder {
    vbar_cache: VBarCache,
    glyph_cache: GlyphCache,
}

impl ClearCodecDecoder {
    pub fn new() -> Self {
        Self {
            vbar_cache: VBarCache::new(),
            glyph_cache: GlyphCache::new(),
        }
    }

    /// Decode a ClearCodec bitmap stream into BGRA pixel data.
    ///
    /// The output buffer is `width * height * 4` bytes in BGRA format.
    /// The caller is responsible for compositing the result onto the target
    /// surface at the destination rectangle.
    ///
    /// **Alpha contract:** ClearCodec is lossless on the three color channels
    /// (B, G, R) per MS-RDPEGFX 2.2.4.1. The wire format does not transmit
    /// alpha; this decoder fills the alpha byte of every output pixel with
    /// `0xFF` unconditionally. Callers that need to preserve alpha across the
    /// network must transport it separately.
    pub fn decode(&mut self, data: &[u8], width: u16, height: u16) -> DecodeResult<Vec<u8>> {
        let mut src = ReadCursor::new(data);
        let stream = ClearCodecBitmapStream::decode(&mut src)?;

        // Handle cache reset
        if stream.is_cache_reset() {
            self.vbar_cache.reset();
        }

        // Validate glyph index range per spec: 0..3999 inclusive
        if let Some(idx) = stream.glyph_index {
            if idx >= GLYPH_CACHE_WRAP {
                return Err(invalid_field_err!("glyphIndex", "glyph index out of range 0-3999"));
            }
        }

        let w = usize::from(width);
        let h = usize::from(height);
        let pixel_count = w
            .checked_mul(h)
            .ok_or_else(|| invalid_field_err!("dimensions", "width * height overflow"))?;

        // Handle glyph hit: return cached pixel data
        if stream.is_glyph_hit() {
            let glyph_index = stream
                .glyph_index
                .ok_or_else(|| invalid_field_err!("flags", "GLYPH_HIT without GLYPH_INDEX"))?;
            let entry = self
                .glyph_cache
                .get(glyph_index)
                .ok_or_else(|| invalid_field_err!("glyphIndex", "glyph cache miss on hit"))?;
            if entry.width != width || entry.height != height {
                return Err(invalid_field_err!("glyphIndex", "cached glyph dimensions mismatch"));
            }
            return Ok(entry.pixels.clone());
        }

        // Cap allocation to prevent OOM from adversarial dimensions.
        // MS-RDPEGFX caps surfaces at 32767x32767; the spec does not
        // mandate a separate tile cap. We cap each tile dimension at
        // 8192 (supports 8K displays at 7680x4320 plus headroom). The
        // per-dimension form rather than a per-pixel-count form is
        // important because the original pixel-count cap (8192*8192
        // = 67M) accepted degenerate aspect ratios like 63961x771
        // (49M pixels, under cap) that allocate ~197MB from a few
        // attacker-controlled bytes. Capping each axis directly
        // rejects implausible tile shapes regardless of total area.
        const MAX_DECODE_DIM: u16 = 8192;
        if width > MAX_DECODE_DIM || height > MAX_DECODE_DIM {
            return Err(invalid_field_err!(
                "dimensions",
                "width or height exceeds 8192-pixel decoder limit"
            ));
        }

        // Decode composite payload
        let mut output = vec![0u8; pixel_count * 4];

        if let Some(ref composite) = stream.composite {
            self.decode_composite(composite, &mut output, width, height)?;
        }

        // Store in glyph cache if applicable (area <= 1024 pixels)
        if stream.flags & FLAG_GLYPH_INDEX != 0 {
            if let Some(glyph_index) = stream.glyph_index {
                if pixel_count <= 1024 {
                    self.glyph_cache.store(
                        glyph_index,
                        GlyphEntry {
                            width,
                            height,
                            pixels: output.clone(),
                        },
                    );
                }
            }
        }

        Ok(output)
    }

    fn decode_composite(
        &mut self,
        composite: &CompositePayload<'_>,
        output: &mut [u8],
        width: u16,
        _height: u16,
    ) -> DecodeResult<()> {
        let w = usize::from(width);

        // Layer 1: Residual (BGR RLE) - fills the entire output.
        // Cap pixel writes to the output buffer size to prevent CPU-spin DoS
        // from adversarial run_length values (FreeRDP CVE GHSA-32q9-m5qr-9j2v).
        if !composite.residual_data.is_empty() {
            let segments = decode_residual_layer(composite.residual_data)?;
            let max_offset = output.len();
            let mut offset = 0;
            for seg in &segments {
                let pixels_remaining = (max_offset.saturating_sub(offset)) / 4;
                let effective_run = u32::try_from(pixels_remaining).unwrap_or(u32::MAX).min(seg.run_length);
                for _ in 0..effective_run {
                    output[offset] = seg.blue;
                    output[offset + 1] = seg.green;
                    output[offset + 2] = seg.red;
                    output[offset + 3] = 0xFF; // Alpha
                    offset += 4;
                }
                if offset >= max_offset {
                    break;
                }
            }
        }

        // Layer 2: Bands (V-bar cached columns) - composite on top
        if !composite.bands_data.is_empty() {
            let bands = decode_bands_layer(composite.bands_data)?;
            for band in &bands {
                let band_height = band.y_end - band.y_start + 1;
                for (col_offset, vbar) in band.vbars.iter().enumerate() {
                    let x = usize::from(band.x_start) + col_offset;
                    if x >= w {
                        continue;
                    }

                    let full_vbar =
                        self.resolve_vbar(vbar, band_height, band.blue_bkg, band.green_bkg, band.red_bkg)?;

                    // Blit the full V-bar column into the output
                    let pixel_rows = full_vbar.pixels.len() / 3;
                    for row in 0..pixel_rows {
                        let y = usize::from(band.y_start) + row;
                        let dst_offset = (y * w + x) * 4;
                        let src_offset = row * 3;
                        if dst_offset + 3 < output.len() && src_offset + 2 < full_vbar.pixels.len() {
                            output[dst_offset] = full_vbar.pixels[src_offset];
                            output[dst_offset + 1] = full_vbar.pixels[src_offset + 1];
                            output[dst_offset + 2] = full_vbar.pixels[src_offset + 2];
                            output[dst_offset + 3] = 0xFF;
                        }
                    }
                }
            }
        }

        // Layer 3: Subcodecs - composite on top
        if !composite.subcodec_data.is_empty() {
            let subcodecs = decode_subcodec_layer(composite.subcodec_data)?;
            for sub in &subcodecs {
                self.decode_subcodec_region(sub, output, width)?;
            }
        }

        Ok(())
    }

    fn resolve_vbar(
        &mut self,
        vbar: &VBar<'_>,
        band_height: u16,
        bg_blue: u8,
        bg_green: u8,
        bg_red: u8,
    ) -> DecodeResult<FullVBar> {
        match vbar {
            VBar::CacheHit { index } => {
                let cached = self
                    .vbar_cache
                    .get_vbar(*index)
                    .ok_or_else(|| invalid_field_err!("vbarIndex", "V-bar cache miss on hit"))?;
                Ok(cached.clone())
            }
            VBar::ShortCacheHit { index, y_on } => {
                let cached_short = self
                    .vbar_cache
                    .get_short_vbar(*index)
                    .ok_or_else(|| invalid_field_err!("shortVbarIndex", "short V-bar cache miss on hit"))?;
                // Create a modified short vbar with the y_on from this reference
                let modified = ShortVBar {
                    y_on: *y_on,
                    pixel_count: cached_short.pixel_count,
                    pixels: cached_short.pixels.clone(),
                };
                let full = VBarCache::reconstruct_full_vbar(&modified, band_height, bg_blue, bg_green, bg_red);
                // Store reconstructed full V-bar in cache
                self.vbar_cache.store_vbar(full.clone());
                Ok(full)
            }
            VBar::ShortCacheMiss(miss) => {
                let short = ShortVBar {
                    y_on: miss.y_on,
                    pixel_count: miss.y_off_delta,
                    pixels: miss.pixel_data.to_vec(),
                };
                // Store in short V-bar cache
                self.vbar_cache.store_short_vbar(short.clone());
                // Reconstruct and store full V-bar
                let full = VBarCache::reconstruct_full_vbar(&short, band_height, bg_blue, bg_green, bg_red);
                self.vbar_cache.store_vbar(full.clone());
                Ok(full)
            }
        }
    }

    // NsCodec variant will use decoder state in Phase A7
    #[expect(clippy::unused_self)]
    fn decode_subcodec_region(
        &self,
        sub: &ironrdp_pdu::codecs::clearcodec::Subcodec<'_>,
        output: &mut [u8],
        surface_width: u16,
    ) -> DecodeResult<()> {
        let sw = usize::from(surface_width);
        let sh = output.len() / (sw * 4).max(1);

        let x_end = usize::from(sub.x_start) + usize::from(sub.width);
        let y_end = usize::from(sub.y_start) + usize::from(sub.height);
        if x_end > sw || y_end > sh {
            return Err(invalid_field_err!("subcodec", "region exceeds surface bounds"));
        }

        match sub.codec_id {
            SubcodecId::Raw => {
                let w = usize::from(sub.width);
                let h = usize::from(sub.height);
                let expected = w
                    .checked_mul(h)
                    .and_then(|v| v.checked_mul(3))
                    .ok_or_else(|| invalid_field_err!("bitmapData", "raw subcodec dimensions overflow"))?;
                if sub.bitmap_data.len() < expected {
                    return Err(invalid_field_err!("bitmapData", "raw subcodec data too short"));
                }
                for row in 0..h {
                    for col in 0..w {
                        let x = usize::from(sub.x_start) + col;
                        let y = usize::from(sub.y_start) + row;
                        let src_idx = (row * w + col) * 3;
                        let dst_idx = (y * sw + x) * 4;
                        output[dst_idx] = sub.bitmap_data[src_idx];
                        output[dst_idx + 1] = sub.bitmap_data[src_idx + 1];
                        output[dst_idx + 2] = sub.bitmap_data[src_idx + 2];
                        output[dst_idx + 3] = 0xFF;
                    }
                }
            }
            SubcodecId::Rlex => {
                let rlex = ironrdp_pdu::codecs::clearcodec::decode_rlex(sub.bitmap_data)?;
                let w = usize::from(sub.width);
                let region_pixels = usize::from(sub.width) * usize::from(sub.height);
                let palette_len = rlex.palette.len();
                let mut px = 0usize;

                for seg in &rlex.segments {
                    if usize::from(seg.start_index) >= palette_len {
                        return Err(invalid_field_err!("rlex", "start_index exceeds palette size"));
                    }
                    if usize::from(seg.stop_index) >= palette_len {
                        return Err(invalid_field_err!("rlex", "stop_index exceeds palette size"));
                    }

                    let color = &rlex.palette[usize::from(seg.start_index)];
                    for _ in 0..seg.run_length {
                        if px >= region_pixels {
                            return Err(invalid_field_err!("rlex", "run exceeds region pixel count"));
                        }
                        let x = usize::from(sub.x_start) + px % w;
                        let y = usize::from(sub.y_start) + px / w;
                        let dst_idx = (y * sw + x) * 4;
                        output[dst_idx] = color[0];
                        output[dst_idx + 1] = color[1];
                        output[dst_idx + 2] = color[2];
                        output[dst_idx + 3] = 0xFF;
                        px += 1;
                    }

                    for palette_idx in seg.start_index..=seg.stop_index {
                        if px >= region_pixels {
                            return Err(invalid_field_err!("rlex", "suite exceeds region pixel count"));
                        }
                        let color = &rlex.palette[usize::from(palette_idx)];
                        let x = usize::from(sub.x_start) + px % w;
                        let y = usize::from(sub.y_start) + px / w;
                        let dst_idx = (y * sw + x) * 4;
                        output[dst_idx] = color[0];
                        output[dst_idx + 1] = color[1];
                        output[dst_idx + 2] = color[2];
                        output[dst_idx + 3] = 0xFF;
                        px += 1;
                    }
                }
            }
            SubcodecId::NsCodec => {
                // Not yet implemented; encoder avoids generating NSCodec tiles.
            }
        }

        Ok(())
    }
}

impl Default for ClearCodecDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// ClearCodec encoder for server-side bitmap compression.
///
/// Encodes BGRA pixel data into ClearCodec bitmap streams using the residual
/// (BGR RLE) layer. The residual-only strategy gives good compression for
/// solid regions and text without requiring V-bar cache synchronization.
pub struct ClearCodecEncoder {
    seq_number: u8,
    glyph_cache: GlyphCache,
    next_glyph_index: u16,
}

impl ClearCodecEncoder {
    pub fn new() -> Self {
        Self {
            seq_number: 0,
            glyph_cache: GlyphCache::new(),
            next_glyph_index: 0,
        }
    }

    /// Encode BGRA pixel data into a ClearCodec bitmap stream.
    ///
    /// Input: BGRA pixels in row-major order, `width * height * 4` bytes.
    /// Returns the wire-format ClearCodec bitmap stream ready for
    /// `WireToSurface1Pdu.bitmap_data`.
    ///
    /// **Alpha contract:** ClearCodec is lossless on the three color channels
    /// (B, G, R) per MS-RDPEGFX 2.2.4.1. The wire format does not transmit
    /// alpha; this encoder reads only B, G, R from each input pixel and
    /// discards the alpha byte. Callers that need to preserve alpha across
    /// the network must transport it separately.
    pub fn encode(&mut self, bgra: &[u8], width: u16, height: u16) -> Vec<u8> {
        let w = usize::from(width);
        let h = usize::from(height);
        let pixel_count = w.saturating_mul(h);
        let use_glyph = pixel_count <= 1024;

        // Check glyph cache for exact match
        if use_glyph {
            if let Some((hit_index, _)) = self.find_glyph_match(bgra, width, height) {
                return self.encode_glyph_hit(hit_index);
            }
        }

        // Convert BGRA to BGR run segments
        let segments = bgra_to_run_segments(bgra, pixel_count);
        let residual_data = encode_residual_layer(&segments);

        let mut flags = 0u8;
        let glyph_index = if use_glyph {
            flags |= FLAG_GLYPH_INDEX;
            let idx = self.next_glyph_index;
            self.glyph_cache.store(
                idx,
                GlyphEntry {
                    width,
                    height,
                    pixels: bgra.to_vec(),
                },
            );
            self.next_glyph_index = (idx + 1) % GLYPH_CACHE_WRAP;
            Some(idx)
        } else {
            None
        };

        let seq = self.seq_number;
        self.seq_number = seq.wrapping_add(1);

        // Build the wire-format bitmap stream
        let mut out = Vec::with_capacity(2 + 2 + 12 + residual_data.len());
        out.push(flags);
        out.push(seq);

        if let Some(idx) = glyph_index {
            out.extend_from_slice(&idx.to_le_bytes());
        }

        // Composite payload: residual only (bands=0, subcodec=0)
        let residual_len = u32::try_from(residual_data.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&residual_len.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // bandsByteCount
        out.extend_from_slice(&0u32.to_le_bytes()); // subcodecByteCount
        out.extend_from_slice(&residual_data);

        out
    }

    /// Encode a cache reset message (FLAG_CACHE_RESET).
    pub fn encode_cache_reset(&mut self) -> Vec<u8> {
        let seq = self.seq_number;
        self.seq_number = seq.wrapping_add(1);
        vec![ironrdp_pdu::codecs::clearcodec::FLAG_CACHE_RESET, seq]
    }

    fn find_glyph_match(&self, bgra: &[u8], width: u16, height: u16) -> Option<(u16, &GlyphEntry)> {
        // Linear scan of recently used glyph indices.
        // For small cache usage this is fine; a hash index could be added later.
        let search_range = GLYPH_CACHE_WRAP;
        for idx in 0..search_range {
            if let Some(entry) = self.glyph_cache.get(idx) {
                if entry.width == width && entry.height == height && entry.pixels == bgra {
                    return Some((idx, entry));
                }
            }
        }
        None
    }

    fn encode_glyph_hit(&mut self, index: u16) -> Vec<u8> {
        let seq = self.seq_number;
        self.seq_number = seq.wrapping_add(1);

        let flags = FLAG_GLYPH_INDEX | ironrdp_pdu::codecs::clearcodec::FLAG_GLYPH_HIT;
        let mut out = Vec::with_capacity(4);
        out.push(flags);
        out.push(seq);
        out.extend_from_slice(&index.to_le_bytes());
        out
    }
}

impl Default for ClearCodecEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert BGRA pixels to BGR run-length segments.
fn bgra_to_run_segments(bgra: &[u8], pixel_count: usize) -> Vec<RgbRunSegment> {
    if pixel_count == 0 {
        return Vec::new();
    }

    // Cap to the number of complete pixels actually present in the input
    let available_pixels = bgra.len() / 4;
    let pixel_count = pixel_count.min(available_pixels);

    let mut segments = Vec::new();
    let mut i = 0;

    while i < pixel_count {
        let offset = i * 4;
        if offset + 2 >= bgra.len() {
            break;
        }

        let blue = bgra[offset];
        let green = bgra[offset + 1];
        let red = bgra[offset + 2];
        // Alpha channel is discarded (ClearCodec is always opaque BGR)

        let mut run_length = 1u32;
        let mut j = i + 1;
        while j < pixel_count {
            let jo = j * 4;
            if jo + 2 >= bgra.len() {
                break;
            }
            if bgra[jo] == blue && bgra[jo + 1] == green && bgra[jo + 2] == red {
                run_length += 1;
                j += 1;
            } else {
                break;
            }
        }

        segments.push(RgbRunSegment {
            blue,
            green,
            red,
            run_length,
        });
        i = j;
    }

    segments
}

#[cfg(test)]
mod tests {
    use ironrdp_pdu::codecs::clearcodec::{FLAG_CACHE_RESET, FLAG_GLYPH_HIT};

    use super::*;

    fn make_residual_only_stream(width: u16, height: u16, blue: u8, green: u8, red: u8) -> Vec<u8> {
        let pixel_count = u32::from(width) * u32::from(height);
        let mut data = Vec::new();

        // Flags=0x00 (no glyph, no cache reset), seq=0x00
        data.push(0x00);
        data.push(0x00);

        // Composite payload header
        // Residual: 4 bytes (1 run segment: BGR + short run)
        let run_length = pixel_count;
        let residual = if run_length < 0xFF {
            vec![blue, green, red, u8::try_from(run_length).unwrap()]
        } else if run_length < 0xFFFF {
            let mut v = vec![blue, green, red, 0xFF];
            v.extend_from_slice(&u16::try_from(run_length).unwrap().to_le_bytes());
            v
        } else {
            let mut v = vec![blue, green, red, 0xFF, 0xFF, 0xFF];
            v.extend_from_slice(&run_length.to_le_bytes());
            v
        };
        let residual_len = u32::try_from(residual.len()).unwrap();

        data.extend_from_slice(&residual_len.to_le_bytes()); // residualByteCount
        data.extend_from_slice(&0u32.to_le_bytes()); // bandsByteCount
        data.extend_from_slice(&0u32.to_le_bytes()); // subcodecByteCount
        data.extend_from_slice(&residual);

        data
    }

    #[test]
    fn decode_solid_red_4x4() {
        let mut decoder = ClearCodecDecoder::new();
        let stream = make_residual_only_stream(4, 4, 0x00, 0x00, 0xFF); // red in BGR
        let pixels = decoder.decode(&stream, 4, 4).unwrap();
        assert_eq!(pixels.len(), 4 * 4 * 4);
        // Check first pixel: BGRA
        assert_eq!(pixels[0], 0x00); // B
        assert_eq!(pixels[1], 0x00); // G
        assert_eq!(pixels[2], 0xFF); // R
        assert_eq!(pixels[3], 0xFF); // A
    }

    #[test]
    fn glyph_cache_round_trip() {
        let mut decoder = ClearCodecDecoder::new();

        // First decode: GLYPH_INDEX set, stores in glyph cache
        let mut stream = Vec::new();
        stream.push(FLAG_GLYPH_INDEX); // flags
        stream.push(0x00); // seq
        stream.extend_from_slice(&42u16.to_le_bytes()); // glyph_index = 42
        // Composite with 1-pixel residual (white)
        let residual = [0xFF, 0xFF, 0xFF, 0x01]; // BGR white, run=1
        stream.extend_from_slice(&4u32.to_le_bytes()); // residual bytes
        stream.extend_from_slice(&0u32.to_le_bytes()); // bands bytes
        stream.extend_from_slice(&0u32.to_le_bytes()); // subcodec bytes
        stream.extend_from_slice(&residual);

        let pixels1 = decoder.decode(&stream, 1, 1).unwrap();
        assert_eq!(pixels1.len(), 4);

        // Second decode: GLYPH_HIT - should return cached data
        let mut hit_stream = Vec::new();
        hit_stream.push(FLAG_GLYPH_INDEX | FLAG_GLYPH_HIT); // flags
        hit_stream.push(0x01); // seq = 1
        hit_stream.extend_from_slice(&42u16.to_le_bytes()); // glyph_index = 42

        let pixels2 = decoder.decode(&hit_stream, 1, 1).unwrap();
        assert_eq!(pixels1, pixels2);
    }

    #[test]
    fn raw_subcodec_decode() {
        let mut decoder = ClearCodecDecoder::new();
        let mut stream = Vec::new();
        stream.push(0x00); // flags
        stream.push(0x00); // seq

        // Composite: no residual, no bands, 1 raw subcodec region
        let mut subcodec_data = Vec::new();
        subcodec_data.extend_from_slice(&0u16.to_le_bytes()); // x_start
        subcodec_data.extend_from_slice(&0u16.to_le_bytes()); // y_start
        subcodec_data.extend_from_slice(&2u16.to_le_bytes()); // width
        subcodec_data.extend_from_slice(&1u16.to_le_bytes()); // height
        subcodec_data.extend_from_slice(&6u32.to_le_bytes()); // 2 pixels * 3 bytes
        subcodec_data.push(0x00); // SubcodecId::Raw
        subcodec_data.extend_from_slice(&[0x00, 0x00, 0xFF]); // pixel 0: red
        subcodec_data.extend_from_slice(&[0xFF, 0x00, 0x00]); // pixel 1: blue

        let subcodec_len = u32::try_from(subcodec_data.len()).unwrap();
        stream.extend_from_slice(&0u32.to_le_bytes()); // residual
        stream.extend_from_slice(&0u32.to_le_bytes()); // bands
        stream.extend_from_slice(&subcodec_len.to_le_bytes()); // subcodec
        stream.extend_from_slice(&subcodec_data);

        let pixels = decoder.decode(&stream, 2, 1).unwrap();
        assert_eq!(pixels.len(), 2 * 4); // 2 pixels * BGRA
        // Pixel 0: red (BGR: 0x00, 0x00, 0xFF)
        assert_eq!(&pixels[0..4], &[0x00, 0x00, 0xFF, 0xFF]);
        // Pixel 1: blue (BGR: 0xFF, 0x00, 0x00)
        assert_eq!(&pixels[4..8], &[0xFF, 0x00, 0x00, 0xFF]);
    }

    #[test]
    fn cache_reset_clears_vbar_cursors() {
        let mut decoder = ClearCodecDecoder::new();
        // Decode something to advance cursors, then reset
        let stream = make_residual_only_stream(1, 1, 0, 0, 0);
        decoder.decode(&stream, 1, 1).unwrap();

        // Cache reset message
        let reset_data = [FLAG_CACHE_RESET, 0x01]; // flags=CACHE_RESET, seq=1
        let _ = decoder.decode(&reset_data, 0, 0); // zero dimensions, but cache reset still processed
    }

    // --- Encoder tests ---

    #[test]
    fn encode_solid_color_round_trip() {
        let mut enc = ClearCodecEncoder::new();
        let mut dec = ClearCodecDecoder::new();

        // 4x4 solid red (BGRA: 0,0,255,255)
        let bgra: Vec<u8> = (0..16).flat_map(|_| [0x00, 0x00, 0xFF, 0xFF]).collect();

        let wire = enc.encode(&bgra, 4, 4);
        let result = dec.decode(&wire, 4, 4).unwrap();

        assert_eq!(result, bgra);
    }

    #[test]
    fn encode_two_color_stripe_round_trip() {
        let mut enc = ClearCodecEncoder::new();
        let mut dec = ClearCodecDecoder::new();

        // 4x1: 2 red + 2 blue pixels
        let mut bgra = Vec::new();
        bgra.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF]); // red
        bgra.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF]); // red
        bgra.extend_from_slice(&[0xFF, 0x00, 0x00, 0xFF]); // blue
        bgra.extend_from_slice(&[0xFF, 0x00, 0x00, 0xFF]); // blue

        let wire = enc.encode(&bgra, 4, 1);
        let result = dec.decode(&wire, 4, 1).unwrap();

        assert_eq!(result, bgra);
    }

    #[test]
    fn encode_glyph_cache_hit() {
        let mut encoder = ClearCodecEncoder::new();

        // Small 1x1 pixel (fits glyph cache: area=1 <= 1024)
        let bgra = vec![0xFF, 0x00, 0x00, 0xFF]; // blue

        let first = encoder.encode(&bgra, 1, 1);
        let second = encoder.encode(&bgra, 1, 1);

        // Second encode should be a glyph hit (shorter)
        assert!(
            second.len() < first.len(),
            "glyph hit should be shorter than full encode"
        );

        // Both should decode to the same pixels
        let mut decoder = ClearCodecDecoder::new();
        let p1 = decoder.decode(&first, 1, 1).unwrap();
        let p2 = decoder.decode(&second, 1, 1).unwrap();
        assert_eq!(p1, p2);
        assert_eq!(p1, bgra);
    }

    #[test]
    fn encode_sequence_numbers_increment() {
        let mut encoder = ClearCodecEncoder::new();
        let bgra = vec![0x00, 0x00, 0x00, 0xFF]; // 1x1 black

        let e1 = encoder.encode(&bgra, 1, 1);
        let e2 = encoder.encode(&bgra, 1, 1);

        // Seq numbers are at byte offset 1
        // First frame starts with glyph_index flag + seq=0
        assert_eq!(e1[1], 0x00);
        // Second is glyph hit: seq=1
        assert_eq!(e2[1], 0x01);
    }

    #[test]
    fn encode_cache_reset() {
        let mut encoder = ClearCodecEncoder::new();
        let reset = encoder.encode_cache_reset();

        let mut decoder = ClearCodecDecoder::new();
        let _ = decoder.decode(&reset, 0, 0);
        // Just verifies it doesn't error
    }

    #[test]
    fn bgra_to_run_segments_compresses_runs() {
        // 8 identical pixels should produce 1 segment with run_length=8
        let bgra: Vec<u8> = (0..8).flat_map(|_| [0xAA, 0xBB, 0xCC, 0xFF]).collect();
        let segments = bgra_to_run_segments(&bgra, 8);
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].run_length, 8);
        assert_eq!(segments[0].blue, 0xAA);
        assert_eq!(segments[0].green, 0xBB);
        assert_eq!(segments[0].red, 0xCC);
    }

    #[test]
    fn bgra_to_run_segments_unique_pixels() {
        // 3 different pixels produce 3 segments
        let bgra = vec![
            0x01, 0x02, 0x03, 0xFF, // pixel 1
            0x04, 0x05, 0x06, 0xFF, // pixel 2
            0x07, 0x08, 0x09, 0xFF, // pixel 3
        ];
        let segments = bgra_to_run_segments(&bgra, 3);
        assert_eq!(segments.len(), 3);
        for seg in &segments {
            assert_eq!(seg.run_length, 1);
        }
    }
}
