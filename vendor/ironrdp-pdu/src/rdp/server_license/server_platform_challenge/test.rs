use std::sync::LazyLock;

use ironrdp_core::{decode, encode_vec};

use super::*;
use crate::rdp::server_license::{
    BASIC_SECURITY_HEADER_SIZE, BasicSecurityHeader, BasicSecurityHeaderFlags, LicensePdu, PreambleFlags,
    PreambleVersion,
};

const PLATFORM_CHALLENGE_BUFFER: [u8; 42] = [
    0x80, 0x00, // flags
    0x00, 0x00, // flagsHi
    0x02, 0x03, 0x26, 0x00, // preamble
    0x00, 0x00, 0x00, 0x00, // connect_flags (ignored)
    0x00, 0x00, // blob_type, ignored;
    0x0a, 0x00, // blob len
    0x46, 0x37, 0x85, 0x54, 0x8e, 0xc5, 0x91, 0x34, 0x97, 0x5d, // challenge
    0x38, 0x23, 0x62, 0x5d, 0x10, 0x8b, 0x93, 0xc3, 0xf1, 0xe4, 0x67, 0x1f, 0x4a, 0xb6, 0x00, 0x0a, // mac data
];

const CHALLENGE_BUFFER: [u8; 10] = [
    0x46, 0x37, 0x85, 0x54, 0x8e, 0xc5, 0x91, 0x34, 0x97, 0x5d, // challenge
];

const MAC_DATA_BUFFER: [u8; MAC_SIZE] = [
    0x38, 0x23, 0x62, 0x5d, 0x10, 0x8b, 0x93, 0xc3, 0xf1, 0xe4, 0x67, 0x1f, 0x4a, 0xb6, 0x00, 0x0a, // mac data
];

static PLATFORM_CHALLENGE: LazyLock<LicensePdu> = LazyLock::new(|| {
    ServerPlatformChallenge {
        license_header: LicenseHeader {
            security_header: BasicSecurityHeader {
                flags: BasicSecurityHeaderFlags::LICENSE_PKT,
            },
            preamble_message_type: PreambleType::PlatformChallenge,
            preamble_flags: PreambleFlags::empty(),
            preamble_version: PreambleVersion::V3,
            preamble_message_size: u16::try_from(PLATFORM_CHALLENGE_BUFFER.len() - BASIC_SECURITY_HEADER_SIZE)
                .expect("can't panic"),
        },
        encrypted_platform_challenge: Vec::from(CHALLENGE_BUFFER.as_ref()),
        mac_data: Vec::from(MAC_DATA_BUFFER.as_ref()),
    }
    .into()
});

#[test]
fn from_buffer_correctly_parses_server_platform_challenge() {
    assert_eq!(*PLATFORM_CHALLENGE, decode(PLATFORM_CHALLENGE_BUFFER.as_ref()).unwrap());
}

#[test]
fn from_buffer_correctly_parses_server_platform_challenge_resiliently() {
    let mut buffer = PLATFORM_CHALLENGE_BUFFER;
    // Change blob type to junk value 0xbeef
    buffer[12] = 0xbe;
    buffer[13] = 0xef;
    assert_eq!(*PLATFORM_CHALLENGE, decode(buffer.as_ref()).unwrap());
}

#[test]
fn to_buffer_correctly_serializes_server_platform_challenge() {
    let serialized_platform_challenge = encode_vec(&*PLATFORM_CHALLENGE).unwrap();

    assert_eq!(
        PLATFORM_CHALLENGE_BUFFER.as_ref(),
        serialized_platform_challenge.as_slice()
    );
}

#[test]
fn buffer_length_is_correct_for_server_platform_challenge() {
    assert_eq!(PLATFORM_CHALLENGE_BUFFER.len(), PLATFORM_CHALLENGE.size());
}
