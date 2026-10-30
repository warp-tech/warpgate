use std::sync::LazyLock;

use ironrdp_core::{decode, encode_vec};

use super::*;

const BRUSH_BUFFER: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

static BRUSH: LazyLock<Brush> = LazyLock::new(|| Brush {
    support_level: SupportLevel::Color8x8,
});

#[test]
fn from_buffer_successfully_parses_brush_capset() {
    assert_eq!(*BRUSH, decode(BRUSH_BUFFER.as_ref()).unwrap());
}

#[test]
fn to_buffer_successfully_serializes_brush_capset() {
    let brush = BRUSH.clone();

    let buffer = encode_vec(&brush).unwrap();

    assert_eq!(buffer, BRUSH_BUFFER.as_ref());
}

#[test]
fn buffer_length_is_correct_for_input_capset() {
    assert_eq!(BRUSH_BUFFER.len(), BRUSH.size());
}
