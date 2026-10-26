use std::sync::LazyLock;

use ironrdp_core::{decode, encode_vec};

use super::*;

const POINTER_BUFFER: [u8; 6] = [
    0x01, 0x00, // colorPointerFlag
    0x14, 0x00, // colorPointerCacheSize
    0x15, 0x00, // pointerCacheSize
];

static POINTER: LazyLock<Pointer> = LazyLock::new(|| Pointer {
    color_pointer_cache_size: 20,
    pointer_cache_size: 21,
});

#[test]
fn from_buffer_correctly_parses_pointer_capset() {
    let buffer = POINTER_BUFFER.as_ref();

    assert_eq!(*POINTER, decode(buffer).unwrap());
}

#[test]
fn to_buffer_correctly_serializes_pointer_capset() {
    let capset = POINTER.clone();

    let buffer = encode_vec(&capset).unwrap();

    assert_eq!(buffer, POINTER_BUFFER.as_ref());
}

#[test]
fn buffer_length_is_correct_for_pointer_capset() {
    let correct_length = POINTER_BUFFER.len();

    assert_eq!(correct_length, POINTER.size());
}
