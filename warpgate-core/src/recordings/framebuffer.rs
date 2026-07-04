//! Server-side framebuffer reconstruction for desktop recordings.
//!
//! Mirrors the browser's `applyDesktopFrame` (warpgate-web `common/desktopCanvas.ts`) so
//! the recorder can composite the incremental delta stream into a full RGBA buffer and
//! periodically snapshot it as a PNG keyframe. All rectangle ops are bounds-checked and
//! clip silently rather than panicking (Cranky denies indexing/unwrap/panic here).

use super::{Error, Result};

/// RGBA (row-major, 4 bytes/pixel) framebuffer reconstructed from desktop deltas.
#[derive(Default)]
pub(crate) struct Framebuffer {
    width: u32,
    height: u32,
    rgba: Vec<u8>,
}

impl Framebuffer {
    pub(crate) fn size(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0
    }

    pub(crate) fn rgba(&self) -> &[u8] {
        &self.rgba
    }

    pub(crate) fn resize(&mut self, width: u32, height: u32) {
        self.width = width;
        self.height = height;
        let needed = (width as usize)
            .saturating_mul(height as usize)
            .saturating_mul(4);
        self.rgba.clear();
        self.rgba.resize(needed, 0);
    }

    /// Blit a BGRA rectangle (RDP/VNC raw frames) at (x, y).
    pub(crate) fn blit_bgra(&mut self, x: u32, y: u32, w: u32, h: u32, data: &[u8]) {
        self.blit::<4>(x, y, w, h, data, |px| {
            // BGRA -> RGBA; opaque.
            match (px.first(), px.get(1), px.get(2)) {
                (Some(&b), Some(&g), Some(&r)) => [r, g, b, 255],
                _ => [0, 0, 0, 255],
            }
        });
    }

    /// Blit an RGB rectangle (decoded JPEG) at (x, y).
    pub(crate) fn blit_rgb(&mut self, x: u32, y: u32, w: u32, h: u32, data: &[u8]) {
        self.blit::<3>(x, y, w, h, data, |px| match (px.first(), px.get(1), px.get(2)) {
            (Some(&r), Some(&g), Some(&b)) => [r, g, b, 255],
            _ => [0, 0, 0, 255],
        });
    }

    fn blit<const SRC: usize>(
        &mut self,
        x: u32,
        y: u32,
        w: u32,
        h: u32,
        data: &[u8],
        convert: impl Fn(&[u8]) -> [u8; 4],
    ) {
        if self.is_empty() {
            return;
        }
        let fb_w = self.width as usize;
        let fb_h = self.height as usize;
        let (x, y, w, h) = (x as usize, y as usize, w as usize, h as usize);
        if x >= fb_w || y >= fb_h {
            return;
        }
        // Clip once, then process whole rows so bounds checks stay out of the inner loop.
        let cols = w.min(fb_w - x);
        let rows = h.min(fb_h - y);
        let src_stride = w.saturating_mul(SRC);
        for row in 0..rows {
            let src_off = row * src_stride;
            let Some(src_row) = data.get(src_off..src_off + cols * SRC) else {
                break; // truncated source: leave the rest stale, as before
            };
            let dst_off = ((y + row) * fb_w + x) * 4;
            let Some(dst_row) = self.rgba.get_mut(dst_off..dst_off + cols * 4) else {
                break;
            };
            for (dst, src) in dst_row.chunks_exact_mut(4).zip(src_row.chunks_exact(SRC)) {
                dst.copy_from_slice(&convert(src));
            }
        }
    }

    /// Copy a `w`x`h` region from `(src_x, src_y)` to `(dst_x, dst_y)` (overlap-safe via a
    /// scratch copy). Used for RDP/VNC CopyRect (scrolling).
    pub(crate) fn copy_rect(
        &mut self,
        dst_x: u32,
        dst_y: u32,
        w: u32,
        h: u32,
        src_x: u32,
        src_y: u32,
    ) {
        if self.is_empty() {
            return;
        }
        let fb_w = self.width as usize;
        let fb_h = self.height as usize;
        let (sx, sy, dx, dy, w, h) = (
            src_x as usize,
            src_y as usize,
            dst_x as usize,
            dst_y as usize,
            w as usize,
            h as usize,
        );
        if sx >= fb_w || sy >= fb_h || dx >= fb_w || dy >= fb_h {
            return;
        }
        // Clip so both src and dst rows stay in bounds, then memmove one contiguous run per
        // row. Iterate rows away from the destination so overlapping bands aren't clobbered
        // before they're read (same reasoning as memmove direction).
        let cols = w.min(fb_w - sx).min(fb_w - dx);
        let rows = h.min(fb_h - sy).min(fb_h - dy);
        let run = cols * 4;
        for row in 0..rows {
            let row = if dy > sy { rows - 1 - row } else { row };
            let src_off = ((sy + row) * fb_w + sx) * 4;
            let dst_off = ((dy + row) * fb_w + dx) * 4;
            self.rgba.copy_within(src_off..src_off + run, dst_off);
        }
    }
}

/// Convert a `w`x`h` BGRA rectangle to RGBA (opaque) into `out` (cleared + refilled). Used
/// to feed the PNG encoder for a delta rect without allocating a fresh buffer each frame.
pub(crate) fn bgra_to_rgba(bgra: &[u8], w: u16, h: u16, out: &mut Vec<u8>) {
    let count = usize::from(w).saturating_mul(usize::from(h));
    out.clear();
    out.reserve(count.saturating_mul(4));
    for src in bgra.chunks_exact(4).take(count) {
        if let &[b, g, r, _] = src {
            out.extend_from_slice(&[r, g, b, 255]);
        }
    }
}

/// Encode an RGBA buffer as PNG into `out` (reused; cleared first), fast compression for
/// the recording hot path.
pub(crate) fn encode_png_rgba(
    width: u32,
    height: u32,
    rgba: &[u8],
    out: &mut Vec<u8>,
) -> Result<()> {
    out.clear();
    let mut encoder = png::Encoder::new(&mut *out, width, height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    encoder.set_compression(png::Compression::Fast);
    let mut writer = encoder
        .write_header()
        .map_err(|e| Error::Codec(e.to_string()))?;
    writer
        .write_image_data(rgba)
        .map_err(|e| Error::Codec(e.to_string()))?;
    writer.finish().map_err(|e| Error::Codec(e.to_string()))?;
    Ok(())
}

/// Decode a JPEG (VNC tight encoding) to RGB. Best-effort: returns `None` on any error so
/// the recording continues (that framebuffer region is simply left stale until repaint).
pub(crate) fn decode_jpeg_rgb(data: &[u8]) -> Option<(u32, u32, Vec<u8>)> {
    use zune_jpeg::JpegDecoder;
    use zune_jpeg::zune_core::colorspace::ColorSpace;
    use zune_jpeg::zune_core::options::DecoderOptions;

    let options = DecoderOptions::default().jpeg_set_out_colorspace(ColorSpace::RGB);
    let mut decoder = JpegDecoder::new_with_options(data, options);
    let pixels = decoder.decode().ok()?;
    let (w, h) = decoder.dimensions()?;
    Some((w as u32, h as u32, pixels))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_png(bytes: &[u8]) -> (u32, u32, Vec<u8>) {
        let decoder = png::Decoder::new(std::io::Cursor::new(bytes));
        let mut reader = decoder.read_info().unwrap();
        let mut buf = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut buf).unwrap();
        buf.truncate(info.buffer_size());
        (info.width, info.height, buf)
    }

    #[test]
    fn blit_bgra_then_encode_roundtrips_to_rgba() {
        let mut fb = Framebuffer::default();
        fb.resize(2, 2);
        // BGRA rows: red, green / blue, white.
        let bgra = vec![
            0, 0, 255, 255, 0, 255, 0, 255, // red, green
            255, 0, 0, 255, 255, 255, 255, 255, // blue, white
        ];
        fb.blit_bgra(0, 0, 2, 2, &bgra);
        let mut out = Vec::new();
        encode_png_rgba(2, 2, fb.rgba(), &mut out).unwrap();
        let (w, h, rgba) = decode_png(&out);
        assert_eq!((w, h), (2, 2));
        assert_eq!(&rgba[0..4], &[255, 0, 0, 255]); // red
        assert_eq!(&rgba[4..8], &[0, 255, 0, 255]); // green
        assert_eq!(&rgba[8..12], &[0, 0, 255, 255]); // blue
        assert_eq!(&rgba[12..16], &[255, 255, 255, 255]); // white
    }

    #[test]
    fn copy_rect_moves_pixels() {
        let mut fb = Framebuffer::default();
        fb.resize(2, 1);
        // (0,0)=red, (1,0)=green (BGRA).
        fb.blit_bgra(0, 0, 2, 1, &[0, 0, 255, 255, 0, 255, 0, 255]);
        fb.copy_rect(1, 0, 1, 1, 0, 0); // copy red over green
        assert_eq!(&fb.rgba()[4..8], &[255, 0, 0, 255]);
    }

    #[test]
    fn out_of_bounds_blit_is_clipped_not_panicking() {
        let mut fb = Framebuffer::default();
        fb.resize(1, 1);
        // A 2x2 blit into a 1x1 buffer must clip to the single pixel.
        fb.blit_bgra(
            0,
            0,
            2,
            2,
            &[10, 20, 30, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255],
        );
        assert_eq!(fb.size(), (1, 1));
        assert_eq!(&fb.rgba()[0..4], &[30, 20, 10, 255]); // BGRA(10,20,30) -> RGBA
    }

    #[test]
    fn bgra_to_rgba_swaps_channels() {
        let mut out = Vec::new();
        bgra_to_rgba(&[1, 2, 3, 255, 4, 5, 6, 255], 2, 1, &mut out);
        assert_eq!(out, vec![3, 2, 1, 255, 6, 5, 4, 255]);
    }
}
