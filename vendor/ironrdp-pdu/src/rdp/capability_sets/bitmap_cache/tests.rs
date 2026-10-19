use std::sync::LazyLock;

use ironrdp_core::{decode, encode_vec};

use super::*;

const CACHE_ENTRY_BUFFER: [u8; 4] = [0x64, 0x00, 0x32, 0x00];

const BITMAP_CACHE_BUFFER: [u8; 36] = [
    0x00, 0x00, 0x00, 0x00, // pad
    0x00, 0x00, 0x00, 0x00, // pad
    0x00, 0x00, 0x00, 0x00, // pad
    0x00, 0x00, 0x00, 0x00, // pad
    0x00, 0x00, 0x00, 0x00, // pad
    0x00, 0x00, 0x00, 0x00, // pad
    0xc8, 0x00, // Cache0Entries
    0x00, 0x02, // Cache0MaximumCellSize
    0x58, 0x02, // Cache1Entries
    0x00, 0x08, // Cache1MaximumCellSize
    0xe8, 0x03, // Cache2Entries
    0x00, 0x20, // Cache2MaximumCellSize
];

const BITMAP_CACHE_REV2_BUFFER: [u8; 36] = [
    0x03, 0x00, // CacheFlags
    0x00, // pad2
    0x03, // NumCellCaches
    0x78, 0x00, 0x00, 0x00, // BitmapCache0CellInfo
    0x78, 0x00, 0x00, 0x00, // BitmapCache1CellInfo
    0xfb, 0x09, 0x00, 0x80, // BitmapCache2CellInfo
    0x00, 0x00, 0x00, 0x00, // BitmapCache3CellInfo
    0x00, 0x00, 0x00, 0x00, // BitmapCache4CellInfo
    0x00, 0x00, 0x00, 0x00, // pad
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

const CELL_INFO_BUFFER: [u8; 4] = [0xfb, 0x09, 0x00, 0x80];

static BITMAP_CACHE: LazyLock<BitmapCache> = LazyLock::new(|| BitmapCache {
    caches: [
        CacheEntry {
            entries: 200,
            max_cell_size: 512,
        },
        CacheEntry {
            entries: 600,
            max_cell_size: 2048,
        },
        CacheEntry {
            entries: 1000,
            max_cell_size: 8192,
        },
    ],
});
static BITMAP_CACHE_REV2: LazyLock<BitmapCacheRev2> = LazyLock::new(|| BitmapCacheRev2 {
    cache_flags: CacheFlags::PERSISTENT_KEYS_EXPECTED_FLAG | CacheFlags::ALLOW_CACHE_WAITING_LIST_FLAG,
    num_cell_caches: 3,
    cache_cell_info: [
        CellInfo {
            num_entries: 120,
            is_cache_persistent: false,
        },
        CellInfo {
            num_entries: 120,
            is_cache_persistent: false,
        },
        CellInfo {
            num_entries: 2555,
            is_cache_persistent: true,
        },
        CellInfo {
            num_entries: 0,
            is_cache_persistent: false,
        },
        CellInfo {
            num_entries: 0,
            is_cache_persistent: false,
        },
    ],
});
static CELL_INFO: LazyLock<CellInfo> = LazyLock::new(|| CellInfo {
    num_entries: 2555,
    is_cache_persistent: true,
});
static CACHE_ENTRY: LazyLock<CacheEntry> = LazyLock::new(|| CacheEntry {
    entries: 0x64,
    max_cell_size: 0x32,
});

#[test]
fn from_buffer_correctly_parses_bitmap_cache_capset() {
    let buffer = BITMAP_CACHE_BUFFER.as_ref();

    assert_eq!(*BITMAP_CACHE, decode(buffer).unwrap());
}

#[test]
fn to_buffer_correctly_serializes_bitmap_cache_capset() {
    let buffer = encode_vec(&*BITMAP_CACHE).unwrap();

    assert_eq!(buffer, BITMAP_CACHE_BUFFER.as_ref());
}

#[test]
fn buffer_length_is_correct_for_bitmap_cache_capset() {
    assert_eq!(BITMAP_CACHE_BUFFER.len(), BITMAP_CACHE.size());
}

#[test]
fn from_buffer_correctly_parses_bitmap_cache_rev2_capset() {
    let buffer = BITMAP_CACHE_REV2_BUFFER.as_ref();

    assert_eq!(*BITMAP_CACHE_REV2, decode(buffer).unwrap());
}

#[test]
fn to_buffer_correctly_serializes_bitmap_cache_rev2_capset() {
    let buffer = encode_vec(&*BITMAP_CACHE_REV2).unwrap();

    assert_eq!(buffer, BITMAP_CACHE_REV2_BUFFER.as_ref());
}

#[test]
fn buffer_length_is_correct_for_bitmap_cache_rev2_capset() {
    assert_eq!(BITMAP_CACHE_REV2_BUFFER.len(), BITMAP_CACHE_REV2.size());
}

#[test]
fn from_buffer_correctly_parses_cell_info() {
    assert_eq!(*CELL_INFO, decode(CELL_INFO_BUFFER.as_ref()).unwrap());
}

#[test]
fn to_buffer_correctly_serializes_cell_info() {
    let cell_info = *CELL_INFO;

    let buffer = encode_vec(&cell_info).unwrap();

    assert_eq!(buffer, CELL_INFO_BUFFER.as_ref());
}

#[test]
fn buffer_length_is_correct_for_cell_info() {
    assert_eq!(CELL_INFO_BUFFER.len(), CELL_INFO.size());
}

#[test]
fn from_buffer_correctly_parses_cache_entry() {
    assert_eq!(*CACHE_ENTRY, decode(CACHE_ENTRY_BUFFER.as_ref()).unwrap());
}

#[test]
fn to_buffer_correctly_serializes_cache_entry() {
    let cache_entry = *CACHE_ENTRY;

    let buffer = encode_vec(&cache_entry).unwrap();

    assert_eq!(buffer, CACHE_ENTRY_BUFFER.as_ref());
}

#[test]
fn buffer_length_is_correct_for_cache_entry() {
    assert_eq!(CACHE_ENTRY_BUFFER.len(), CACHE_ENTRY.size());
}
