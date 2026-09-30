//! V-Bar caching for ClearCodec bands layer.
//!
//! The V-bar cache uses two ring buffers:
//! - **V-Bar Storage**: 32,768 full V-bars (complete column pixel data for a band height)
//! - **Short V-Bar Storage**: 16,384 short V-bars (only the non-background portion)
//!
//! Cache cursors advance linearly and wrap around, implementing LRU eviction
//! as specified in MS-RDPEGFX 3.3.8.1.

use ironrdp_pdu::codecs::clearcodec::{SHORT_VBAR_CACHE_SIZE, VBAR_CACHE_SIZE};

// VBAR_CACHE_SIZE (32,768) and SHORT_VBAR_CACHE_SIZE (16,384) as u16 for cursor wrapping.
const VBAR_WRAP: u16 = 32_768;
const SHORT_VBAR_WRAP: u16 = 16_384;

/// A full V-bar: column of BGR pixels for the full band height.
#[derive(Debug, Clone)]
pub struct FullVBar {
    /// BGR pixel data, length = band_height * 3.
    pub pixels: Vec<u8>,
}

/// A short V-bar: only the non-background pixels within a column.
#[derive(Debug, Clone)]
pub struct ShortVBar {
    /// First row index where pixel data starts.
    pub y_on: u8,
    /// Number of pixel rows with color data.
    pub pixel_count: u8,
    /// BGR pixel data, length = pixel_count * 3.
    pub pixels: Vec<u8>,
}

/// Combined V-bar cache state.
pub struct VBarCache {
    /// Full V-bar storage (32,768 entries, ring buffer).
    vbar_storage: Vec<Option<FullVBar>>,
    /// Short V-bar storage (16,384 entries, ring buffer).
    short_vbar_storage: Vec<Option<ShortVBar>>,
    /// Current write cursor for V-bar storage (wraps at 32767).
    vbar_cursor: u16,
    /// Current write cursor for short V-bar storage (wraps at 16383).
    short_vbar_cursor: u16,
}

impl VBarCache {
    pub fn new() -> Self {
        let mut vbar_storage = Vec::with_capacity(VBAR_CACHE_SIZE);
        vbar_storage.resize_with(VBAR_CACHE_SIZE, || None);

        let mut short_vbar_storage = Vec::with_capacity(SHORT_VBAR_CACHE_SIZE);
        short_vbar_storage.resize_with(SHORT_VBAR_CACHE_SIZE, || None);

        Self {
            vbar_storage,
            short_vbar_storage,
            vbar_cursor: 0,
            short_vbar_cursor: 0,
        }
    }

    /// Reset both caches (when FLAG_CACHE_RESET is received).
    pub fn reset(&mut self) {
        self.vbar_cursor = 0;
        self.short_vbar_cursor = 0;
        // Per spec, only cursors reset. Existing entries become stale
        // but the cursor reset means new entries overwrite from index 0.
    }

    /// Get a full V-bar from cache by index.
    pub fn get_vbar(&self, index: u16) -> Option<&FullVBar> {
        self.vbar_storage.get(usize::from(index)).and_then(|slot| slot.as_ref())
    }

    /// Get a short V-bar from cache by index.
    pub fn get_short_vbar(&self, index: u16) -> Option<&ShortVBar> {
        self.short_vbar_storage
            .get(usize::from(index))
            .and_then(|slot| slot.as_ref())
    }

    /// Store a short V-bar and return its cache index.
    pub fn store_short_vbar(&mut self, short_vbar: ShortVBar) -> u16 {
        let index = self.short_vbar_cursor;
        self.short_vbar_storage[usize::from(index)] = Some(short_vbar);
        self.short_vbar_cursor = (index + 1) % SHORT_VBAR_WRAP;
        index
    }

    /// Store a full V-bar and return its cache index.
    pub fn store_vbar(&mut self, vbar: FullVBar) -> u16 {
        let index = self.vbar_cursor;
        self.vbar_storage[usize::from(index)] = Some(vbar);
        self.vbar_cursor = (index + 1) % VBAR_WRAP;
        index
    }

    /// Reconstruct a full V-bar from a short V-bar and background color.
    ///
    /// The full V-bar has:
    /// - Background color above y_on
    /// - Short V-bar pixel data from y_on to y_on + pixel_count
    /// - Background color below y_on + pixel_count
    pub fn reconstruct_full_vbar(
        short_vbar: &ShortVBar,
        band_height: u16,
        bg_blue: u8,
        bg_green: u8,
        bg_red: u8,
    ) -> FullVBar {
        let height = usize::from(band_height);
        let mut pixels = Vec::with_capacity(height * 3);

        // Background above y_on
        for _ in 0..usize::from(short_vbar.y_on) {
            pixels.push(bg_blue);
            pixels.push(bg_green);
            pixels.push(bg_red);
        }

        // Pixel data from short V-bar
        pixels.extend_from_slice(&short_vbar.pixels);

        // Background below y_on + pixel_count
        let bottom_start = usize::from(short_vbar.y_on) + usize::from(short_vbar.pixel_count);
        for _ in bottom_start..height {
            pixels.push(bg_blue);
            pixels.push(bg_green);
            pixels.push(bg_red);
        }

        FullVBar { pixels }
    }
}

impl Default for VBarCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_and_retrieve_vbar() {
        let mut cache = VBarCache::new();
        let vbar = FullVBar {
            pixels: vec![0xFF, 0x00, 0x00],
        };
        let idx = cache.store_vbar(vbar);
        assert_eq!(idx, 0);
        let retrieved = cache.get_vbar(0).unwrap();
        assert_eq!(retrieved.pixels, vec![0xFF, 0x00, 0x00]);
    }

    #[test]
    fn cursor_wraps() {
        let mut cache = VBarCache::new();
        // Store VBAR_CACHE_SIZE entries, cursor should wrap to 0
        for i in 0..VBAR_CACHE_SIZE {
            let idx = cache.store_vbar(FullVBar {
                pixels: vec![u8::try_from(i & 0xFF).unwrap()],
            });
            assert_eq!(idx, u16::try_from(i).unwrap());
        }
        // Next store should be at index 0 (wrapped)
        let idx = cache.store_vbar(FullVBar { pixels: vec![0xAA] });
        assert_eq!(idx, 0);
    }

    #[test]
    fn reconstruct_full_vbar() {
        let short = ShortVBar {
            y_on: 1,
            pixel_count: 2,
            pixels: vec![0xFF, 0x00, 0x00, 0x00, 0xFF, 0x00], // 2 pixels BGR
        };
        let full = VBarCache::reconstruct_full_vbar(&short, 4, 0xAA, 0xBB, 0xCC);
        // Height=4: 1 bg row, 2 data rows, 1 bg row
        assert_eq!(full.pixels.len(), 12); // 4 * 3
        // Row 0: background
        assert_eq!(&full.pixels[0..3], &[0xAA, 0xBB, 0xCC]);
        // Row 1-2: pixel data
        assert_eq!(&full.pixels[3..9], &[0xFF, 0x00, 0x00, 0x00, 0xFF, 0x00]);
        // Row 3: background
        assert_eq!(&full.pixels[9..12], &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn reset_resets_cursors() {
        let mut cache = VBarCache::new();
        cache.store_vbar(FullVBar { pixels: vec![0x01] });
        cache.store_short_vbar(ShortVBar {
            y_on: 0,
            pixel_count: 0,
            pixels: vec![],
        });
        assert_eq!(cache.vbar_cursor, 1);
        assert_eq!(cache.short_vbar_cursor, 1);
        cache.reset();
        assert_eq!(cache.vbar_cursor, 0);
        assert_eq!(cache.short_vbar_cursor, 0);
    }
}
