//! Glyph cache for ClearCodec (MS-RDPEGFX 2.2.4.1).
//!
//! When a bitmap area is <= 1024 pixels, ClearCodec can index it in a
//! 4,000-entry glyph cache. On a cache hit (FLAG_GLYPH_HIT), the previously
//! cached pixel data is reused without retransmission.

/// Maximum number of glyph cache entries.
pub const GLYPH_CACHE_SIZE: usize = 4_000;

/// A cached glyph entry: BGRA pixel data with dimensions.
#[derive(Debug, Clone)]
pub struct GlyphEntry {
    pub width: u16,
    pub height: u16,
    /// BGRA pixel data (4 bytes per pixel).
    pub pixels: Vec<u8>,
}

/// Glyph cache for ClearCodec bitmap deduplication.
pub struct GlyphCache {
    entries: Vec<Option<GlyphEntry>>,
}

impl GlyphCache {
    pub fn new() -> Self {
        let mut entries = Vec::with_capacity(GLYPH_CACHE_SIZE);
        entries.resize_with(GLYPH_CACHE_SIZE, || None);
        Self { entries }
    }

    /// Look up a glyph by its cache index.
    pub fn get(&self, index: u16) -> Option<&GlyphEntry> {
        self.entries.get(usize::from(index)).and_then(|slot| slot.as_ref())
    }

    /// Store a glyph at the given index.
    ///
    /// Returns `true` if the index was valid and the entry was stored.
    pub fn store(&mut self, index: u16, entry: GlyphEntry) -> bool {
        let idx = usize::from(index);
        if idx < GLYPH_CACHE_SIZE {
            self.entries[idx] = Some(entry);
            true
        } else {
            false
        }
    }

    /// Reset the entire glyph cache, removing all entries.
    pub fn reset(&mut self) {
        for slot in &mut self.entries {
            *slot = None;
        }
    }
}

impl Default for GlyphCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_and_retrieve() {
        let mut cache = GlyphCache::new();
        let entry = GlyphEntry {
            width: 8,
            height: 16,
            pixels: vec![0xFF; 8 * 16 * 4],
        };
        assert!(cache.store(42, entry));
        let retrieved = cache.get(42).unwrap();
        assert_eq!(retrieved.width, 8);
        assert_eq!(retrieved.height, 16);
    }

    #[test]
    fn get_empty_returns_none() {
        let cache = GlyphCache::new();
        assert!(cache.get(0).is_none());
        assert!(cache.get(3999).is_none());
    }

    #[test]
    fn reject_out_of_range() {
        let mut cache = GlyphCache::new();
        let entry = GlyphEntry {
            width: 1,
            height: 1,
            pixels: vec![0; 4],
        };
        assert!(!cache.store(4000, entry));
    }
}
