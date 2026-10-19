use std::sync::LazyLock;

use ironrdp_core::{decode, encode_vec};

use super::*;

const LICENSE_HEADER_BUFFER: [u8; 8] = [
    0x80, 0x00, // flags
    0x00, 0x00, // flagsHi
    0xff, 0x03, 0x10, 0x00,
];

const BLOB_BUFFER: [u8; 76] = [
    0x08, 0x00, // sig blob type
    0x48, 0x00, // sig blob len
    0xe9, 0xe1, 0xd6, 0x28, 0x46, 0x8b, 0x4e, 0xf5, 0x0a, 0xdf, 0xfd, 0xee, 0x21, 0x99, 0xac, 0xb4, 0xe1, 0x8f, 0x5f,
    0x81, 0x57, 0x82, 0xef, 0x9d, 0x96, 0x52, 0x63, 0x27, 0x18, 0x29, 0xdb, 0xb3, 0x4a, 0xfd, 0x9a, 0xda, 0x42, 0xad,
    0xb5, 0x69, 0x21, 0x89, 0x0e, 0x1d, 0xc0, 0x4c, 0x1a, 0xa8, 0xaa, 0x71, 0x3e, 0x0f, 0x54, 0xb9, 0x9a, 0xe4, 0x99,
    0x68, 0x3f, 0x6c, 0xd6, 0x76, 0x84, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // blob data
];

const PLATFORM_CHALLENGE_BUFFER: [u8; 42] = [
    0x80, 0x00, // flags
    0x00, 0x00, // flagsHi
    0x02, 0x03, 0x26, 0x00, // preamble
    0x00, 0x00, 0x00, 0x00, // connect flags
    0x00, 0x00, // ignored
    0x0a, 0x00, // blob len
    0x46, 0x37, 0x85, 0x54, 0x8e, 0xc5, 0x91, 0x34, 0x97, 0x5d, // challenge
    0x38, 0x23, 0x62, 0x5d, 0x10, 0x8b, 0x93, 0xc3, 0xf1, 0xe4, 0x67, 0x1f, 0x4a, 0xb6, 0x00, 0x0a, // mac data
];

const STATUS_VALID_CLIENT_BUFFER: [u8; 20] = [
    0x80, 0x00, // flags
    0x00, 0x00, // flagsHi
    0xff, 0x03, 0x10, 0x00, 0x07, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
];

static LICENSE_HEADER: LazyLock<LicenseHeader> = LazyLock::new(|| LicenseHeader {
    security_header: BasicSecurityHeader {
        flags: BasicSecurityHeaderFlags::LICENSE_PKT,
    },
    preamble_message_type: PreambleType::ErrorAlert,
    preamble_flags: PreambleFlags::empty(),
    preamble_version: PreambleVersion::V3,
    preamble_message_size: 0x10,
});

#[test]
fn read_blob_header_handles_wrong_type_correctly() {
    let h = decode::<BlobHeader>(&BLOB_BUFFER).unwrap();
    assert_ne!(h.blob_type, BlobType::CERTIFICATE);
}

#[test]
fn read_blob_header_handles_invalid_type_correctly() {
    let invalid_blob_buffer: [u8; 76] = [
        0x99, 0x00, // sig blob type
        0x48, 0x00, // sig blob len
        0xe9, 0xe1, 0xd6, 0x28, 0x46, 0x8b, 0x4e, 0xf5, 0x0a, 0xdf, 0xfd, 0xee, 0x21, 0x99, 0xac, 0xb4, 0xe1, 0x8f,
        0x5f, 0x81, 0x57, 0x82, 0xef, 0x9d, 0x96, 0x52, 0x63, 0x27, 0x18, 0x29, 0xdb, 0xb3, 0x4a, 0xfd, 0x9a, 0xda,
        0x42, 0xad, 0xb5, 0x69, 0x21, 0x89, 0x0e, 0x1d, 0xc0, 0x4c, 0x1a, 0xa8, 0xaa, 0x71, 0x3e, 0x0f, 0x54, 0xb9,
        0x9a, 0xe4, 0x99, 0x68, 0x3f, 0x6c, 0xd6, 0x76, 0x84, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // blob data
    ];

    let header = decode::<BlobHeader>(&invalid_blob_buffer).unwrap();
    assert_eq!(
        header,
        BlobHeader {
            blob_type: BlobType(0x99),
            length: 0x48
        }
    )
}

#[test]
fn read_blob_header_reads_blob_correctly() {
    let blob = decode::<BlobHeader>(&BLOB_BUFFER).unwrap();
    assert_eq!(blob.blob_type, BlobType::RSA_SIGNATURE);
    assert_eq!(blob.length, BLOB_BUFFER.len() - 4);
}

#[test]
fn write_blob_header_writes_blob_header_correctly() {
    let correct_blob_header = &BLOB_BUFFER[..4];
    let blob_data = &BLOB_BUFFER[4..];

    let blob = BlobHeader::new(BlobType::RSA_SIGNATURE, blob_data.len());
    let buffer = encode_vec(&blob).unwrap();

    assert_eq!(correct_blob_header, buffer.as_slice());
}

#[test]
fn mac_data_computes_correctly() {
    let mac_salt_key: [u8; 16] = [
        0x68, 0x1f, 0x7b, 0x26, 0x7e, 0x76, 0xa, 0x24, 0x2d, 0x98, 0x7, 0xd6, 0x6b, 0x56, 0xc5, 0x1,
    ];

    let server_mac_data: [u8; 16] = [
        0x58, 0xaf, 0x1f, 0x30, 0xd6, 0x4e, 0xe8, 0x6, 0xfc, 0xf9, 0xe6, 0x68, 0x21, 0x64, 0x25, 0x3d,
    ];

    let decrypted_server_challenge: [u8; 10] = [0x54, 0x0, 0x45, 0x0, 0x53, 0x0, 0x54, 0x0, 0x0, 0x0];

    assert_eq!(
        compute_mac_data(mac_salt_key.as_ref(), decrypted_server_challenge.as_ref()).unwrap(),
        server_mac_data.as_ref()
    );
}

#[test]
fn from_buffer_correctly_parses_license_header() {
    assert_eq!(
        decode::<LicenseHeader>(&LICENSE_HEADER_BUFFER).unwrap(),
        *LICENSE_HEADER
    );
}

#[test]
fn to_buffer_correctly_serializes_license_header() {
    let buffer = encode_vec(&*LICENSE_HEADER).unwrap();

    assert_eq!(buffer, LICENSE_HEADER_BUFFER.as_ref());
}

#[test]
fn buffer_length_is_correct_for_license_header() {
    assert_eq!(LICENSE_HEADER.size(), PREAMBLE_SIZE + BASIC_SECURITY_HEADER_SIZE);
}

#[test]
fn read_license_header_reads_correctly() {
    decode::<LicensePdu>(&PLATFORM_CHALLENGE_BUFFER).unwrap();
}

#[test]
fn read_license_header_handles_valid_client_correctly() {
    let pdu = decode::<LicensePdu>(&STATUS_VALID_CLIENT_BUFFER).unwrap();
    assert_eq!(
        pdu,
        LicensingErrorMessage {
            license_header: LicenseHeader {
                security_header: BasicSecurityHeader {
                    flags: BasicSecurityHeaderFlags::LICENSE_PKT,
                },
                preamble_message_type: PreambleType::ErrorAlert,
                preamble_flags: PreambleFlags::empty(),
                preamble_version: PreambleVersion::V3,
                preamble_message_size: 0x10,
            },
            error_code: LicenseErrorCode::StatusValidClient,
            state_transition: LicensingStateTransition::NoTransition,
            error_info: Vec::new()
        }
        .into()
    );
}
