use std::sync::LazyLock;

use ironrdp_core::{decode, encode_vec};

use super::*;

const GLYPH_CACHE_BUFFER: [u8; 48] = [
    0xfe, 0x00, 0x04, 0x00, 0xfe, 0x00, 0x04, 0x00, 0xfe, 0x00, 0x08, 0x00, 0xfe, 0x00, 0x08, 0x00, 0xfe, 0x00, 0x10,
    0x00, 0xfe, 0x00, 0x20, 0x00, 0xfe, 0x00, 0x40, 0x00, 0xfe, 0x00, 0x80, 0x00, 0xfe, 0x00, 0x00, 0x01, 0x40, 0x00,
    0x00, 0x08, // GlyphCache
    0x00, 0x01, 0x00, 0x01, // FragCache
    0x03, 0x00, // GlyphSupportLevel
    0x00, 0x00, // pad2octets
];

const CACHE_DEFINITION_BUFFER: [u8; 4] = [0xfe, 0x00, 0x04, 0x00];

static GLYPH_CACHE: LazyLock<GlyphCache> = LazyLock::new(|| GlyphCache {
    glyph_cache: [
        CacheDefinition {
            entries: 254,
            max_cell_size: 4,
        },
        CacheDefinition {
            entries: 254,
            max_cell_size: 4,
        },
        CacheDefinition {
            entries: 254,
            max_cell_size: 8,
        },
        CacheDefinition {
            entries: 254,
            max_cell_size: 8,
        },
        CacheDefinition {
            entries: 254,
            max_cell_size: 16,
        },
        CacheDefinition {
            entries: 254,
            max_cell_size: 32,
        },
        CacheDefinition {
            entries: 254,
            max_cell_size: 64,
        },
        CacheDefinition {
            entries: 254,
            max_cell_size: 128,
        },
        CacheDefinition {
            entries: 254,
            max_cell_size: 256,
        },
        CacheDefinition {
            entries: 64,
            max_cell_size: 2048,
        },
    ],
    frag_cache: CacheDefinition {
        entries: 256,
        max_cell_size: 256,
    },
    glyph_support_level: GlyphSupportLevel::Encode,
});
static CACHE_DEFINITION: LazyLock<CacheDefinition> = LazyLock::new(|| CacheDefinition {
    entries: 254,
    max_cell_size: 4,
});

#[test]
fn from_buffer_correctly_parses_glyph_cache_capset() {
    assert_eq!(*GLYPH_CACHE, decode(GLYPH_CACHE_BUFFER.as_ref()).unwrap(),);
}

#[test]
fn to_buffer_correctly_serializes_glyph_cache_capset() {
    let glyph_cache = GLYPH_CACHE.clone();

    let buffer = encode_vec(&glyph_cache).unwrap();

    assert_eq!(buffer, GLYPH_CACHE_BUFFER.as_ref());
}

#[test]
fn buffer_length_is_correct_for_glyph_cache_capset() {
    assert_eq!(GLYPH_CACHE_BUFFER.len(), GLYPH_CACHE.size());
}

#[test]
fn from_buffer_correctly_parses_cache_definition() {
    assert_eq!(*CACHE_DEFINITION, decode(CACHE_DEFINITION_BUFFER.as_ref()).unwrap());
}

#[test]
fn to_buffer_correctly_serializes_cache_definition() {
    let cache_def = *CACHE_DEFINITION;

    let buffer = encode_vec(&cache_def).unwrap();

    assert_eq!(buffer, CACHE_DEFINITION_BUFFER.as_ref());
}

#[test]
fn buffer_length_is_correct_for_cache_definition() {
    assert_eq!(CACHE_DEFINITION_BUFFER.len(), CACHE_DEFINITION.size());
}
