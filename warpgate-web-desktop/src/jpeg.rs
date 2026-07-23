//! JPEG re-encoding for backends that only emit raw framebuffer tiles.
//!
//! A raw tile costs 4 bytes per pixel, so a full-screen update is several megabytes on
//! the wire and in the recording. Re-encoding to JPEG shrinks that by well over an order
//! of magnitude, and both the browser canvas and the recording player already decode
//! [`DesktopEvent::JpegImage`].

use bytes::Bytes;
use jpeg_encoder::{ColorType, Encoder};
use warpgate_core::{DesktopEvent, DesktopRect};

/// High enough that desktop text stays crisp; the point of JPEG here is the ~40x size
/// win over raw, not squeezing the last few percent out of it.
const QUALITY: u8 = 90;

/// Below this, a tile is cheaper to ship raw: JPEG's headers and quantisation tables cost
/// several hundred bytes, so re-encoding a small update (a cursor trail, a caret blink)
/// makes it bigger. 4 KiB is a 32x32 tile.
const MIN_RAW_BYTES: usize = 4096;

/// Re-encode a raw BGRA tile as JPEG, leaving every other event untouched.
///
/// Falls back to the original event if encoding fails — a degraded-but-correct frame
/// beats dropping it.
pub async fn encode_raw_images(event: DesktopEvent) -> DesktopEvent {
    let DesktopEvent::RawImage { rect, data } = event else {
        return event;
    };

    // `Bytes` clones are refcount bumps, so the fallback copy is free. Encoding is
    // CPU-bound: run it off the async worker, but await it here so frames stay ordered.
    let encoded = tokio::task::spawn_blocking({
        let data = data.clone();
        move || encode(rect, &data)
    })
    .await;

    match encoded {
        Ok(Some(data)) => DesktopEvent::JpegImage { rect, data },
        _ => DesktopEvent::RawImage { rect, data },
    }
}

fn encode(rect: DesktopRect, data: &[u8]) -> Option<Bytes> {
    // A tile whose payload doesn't match its geometry is not something we can encode;
    // pass it through rather than handing the encoder a short buffer.
    let expected = usize::from(rect.width)
        .checked_mul(usize::from(rect.height))?
        .checked_mul(4)?;
    if expected == 0 || data.len() != expected || expected < MIN_RAW_BYTES {
        return None;
    }

    let mut out = Vec::new();
    // Raw desktop tiles are BGRA on the wire — the browser's `drawRaw` and the recorder's
    // `blit_bgra` both read them that way. Encoding as RGBA would swap red and blue.
    Encoder::new(&mut out, QUALITY)
        .encode(data, rect.width, rect.height, ColorType::Bgra)
        .ok()?;
    Some(out.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(width: u16, height: u16) -> DesktopRect {
        DesktopRect {
            x: 0,
            y: 0,
            width,
            height,
        }
    }

    #[test]
    fn encodes_bgra_to_jpeg() {
        let out = encode(rect(64, 64), &[0xffu8; 64 * 64 * 4]).unwrap();
        // SOI marker — proves we produced an actual JPEG, not an empty buffer.
        assert_eq!(&out[..2], &[0xff, 0xd8]);
        assert!(out.len() < 64 * 64 * 4);
    }

    /// A grey tile would pass whatever the channel order is; a saturated colour is what
    /// catches an RGBA/BGRA mix-up.
    #[test]
    fn preserves_channel_order() {
        // BGRA red: blue=0, green=0, red=255.
        let tile: Vec<u8> = [0u8, 0, 255, 255].repeat(64 * 64);
        let jpeg = encode(rect(64, 64), &tile).unwrap();

        let mut decoder = zune_jpeg::JpegDecoder::new_with_options(
            ZCursor::from(&jpeg[..]),
            zune_jpeg::zune_core::options::DecoderOptions::default()
                .jpeg_set_out_colorspace(zune_jpeg::zune_core::colorspace::ColorSpace::RGB),
        );
        let pixels = decoder.decode().unwrap();
        // Decoded as RGB, so red must dominate. Swapped channels would put it in blue.
        let (r, g, b) = (pixels[0], pixels[1], pixels[2]);
        assert!(r > 200, "expected red channel to dominate, got {r},{g},{b}");
        assert!(b < 60, "blue channel leaked, got {r},{g},{b}");
    }

    #[test]
    fn rejects_mismatched_payload() {
        assert!(encode(rect(64, 64), &[0u8; 64 * 64 * 4 - 1]).is_none());
        assert!(encode(rect(0, 0), &[]).is_none());
    }

    #[test]
    fn leaves_small_tiles_raw() {
        // A tile this size would grow under JPEG's header overhead.
        assert!(encode(rect(16, 16), &[0xffu8; 16 * 16 * 4]).is_none());
    }

    #[tokio::test]
    async fn passes_through_non_raw_events() {
        let event = DesktopEvent::Bell;
        assert!(matches!(encode_raw_images(event).await, DesktopEvent::Bell));
    }

    #[tokio::test]
    async fn falls_back_to_raw_when_encoding_fails() {
        let event = DesktopEvent::RawImage {
            rect: rect(16, 16),
            data: Bytes::from_static(&[0u8; 4]),
        };
        assert!(matches!(
            encode_raw_images(event).await,
            DesktopEvent::RawImage { .. }
        ));
    }
}
