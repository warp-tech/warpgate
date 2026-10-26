use std::sync::LazyLock;

use ironrdp_core::{decode, encode_vec};

use super::*;

const GENERAL_CAPSET_BUFFER: [u8; 20] = [
    0x01, 0x00, // osMajorType
    0x03, 0x00, // osMinorType
    0x00, 0x02, // protocolVersion
    0x00, 0x00, // pad2octetsA
    0x00, 0x00, // generalCompressionTypes
    0x1d, 0x04, // extraFlags
    0x00, 0x00, // updateCapabilityFlag
    0x00, 0x00, // remoteUnshareFlag
    0x00, 0x00, // generalCompressionLevel
    0x00, // refreshRectSupport
    0x00, // suppressOutputSupport
];

static CAPSET_GENERAL: LazyLock<General> = LazyLock::new(|| General {
    major_platform_type: MajorPlatformType::WINDOWS,
    minor_platform_type: MinorPlatformType::WINDOWS_NT,
    protocol_version: PROTOCOL_VER,
    extra_flags: GeneralExtraFlags::FASTPATH_OUTPUT_SUPPORTED
        | GeneralExtraFlags::LONG_CREDENTIALS_SUPPORTED
        | GeneralExtraFlags::AUTORECONNECT_SUPPORTED
        | GeneralExtraFlags::ENC_SALTED_CHECKSUM
        | GeneralExtraFlags::NO_BITMAP_COMPRESSION_HDR,
    refresh_rect_support: false,
    suppress_output_support: false,
});

#[test]
fn from_buffer_correctly_parses_general_capset() {
    let buffer = GENERAL_CAPSET_BUFFER.as_ref();

    assert_eq!(*CAPSET_GENERAL, decode(buffer).unwrap());
}

#[test]
fn to_buffer_correctly_serializes_general_capset() {
    let capset = CAPSET_GENERAL.clone();

    let buffer = encode_vec(&capset).unwrap();

    assert_eq!(buffer, GENERAL_CAPSET_BUFFER.as_ref());
}

#[test]
fn buffer_length_is_correct_for_general_capset() {
    let correct_buffer_length = GENERAL_CAPSET_BUFFER.len();

    assert_eq!(correct_buffer_length, CAPSET_GENERAL.size());
}
