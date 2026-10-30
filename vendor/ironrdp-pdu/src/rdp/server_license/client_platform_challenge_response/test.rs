use std::sync::LazyLock;

use ironrdp_core::{decode, encode_vec};

use super::*;
use crate::rdp::server_license::{BASIC_SECURITY_HEADER_SIZE, LicensePdu};

const PLATFORM_CHALLENGE_RESPONSE_DATA_BUFFER: [u8; 18] = [
    0x00, 0x01, // version
    0x00, 0x01, // client type
    0x03, 0x00, // license detail level
    0x0a, 0x00, // challenge len
    0x54, 0x00, 0x45, 0x00, 0x53, 0x00, 0x54, 0x00, 0x00, 0x00, // challenge
];

const CLIENT_HARDWARE_IDENTIFICATION_BUFFER: [u8; 20] = [
    0x02, 0x00, 0x00, 0x00, // hardware_id
    0xf1, 0x59, 0x87, 0x3e, // data 1
    0xc9, 0xd8, 0x98, 0xaf, // data 2
    0x24, 0x02, 0xf8, 0xf3, // data 3
    0x29, 0x3a, 0xf0, 0x26, // data 4
];

const CLIENT_PLATFORM_CHALLENGE_RESPONSE_BUFFER: [u8; 70] = [
    0x80, 0x00, // flags
    0x00, 0x00, // flagsHi
    0x15, 0x03, 0x42, 0x00, // preamble
    0x09, 0x00, // blob type, ignored
    0x12, 0x00, // blob len
    0xfa, 0xb4, 0xe8, 0x24, 0xcf, 0x56, 0xb2, 0x4e, 0x80, 0x02, 0xbd, 0xb6, 0x61, 0xfc, 0xdf, 0xe9, 0x6c,
    0x44, // encrypted platform challenge response
    0x09, 0x00, // blob type, ignored
    0x14, 0x00, // blob len
    0xf8, 0xb5, 0xe8, 0x25, 0x3d, 0x0f, 0x3f, 0x70, 0x1d, 0xda, 0x60, 0x19, 0x16, 0xfe, 0x73, 0x1a, 0x45, 0x7e, 0x02,
    0x71, // encrypted hwid
    0x38, 0x23, 0x62, 0x5d, 0x10, 0x8b, 0x93, 0xc3, 0xf1, 0xe4, 0x67, 0x1f, 0x4a, 0xb6, 0x00, 0x0a, // mac data
];

const CHALLENGE_BUFFER: [u8; 10] = [
    0x54, 0x00, 0x45, 0x00, 0x53, 0x00, 0x54, 0x00, 0x00, 0x00, // challenge
];

const HARDWARE_ID: u32 = 2;
const DATA_BUFFER: [u8; 16] = [
    0xf1, 0x59, 0x87, 0x3e, 0xc9, 0xd8, 0x98, 0xaf, 0x24, 0x02, 0xf8, 0xf3, 0x29, 0x3a, 0xf0, 0x26,
];

pub(crate) static RESPONSE: LazyLock<PlatformChallengeResponseData> = LazyLock::new(|| PlatformChallengeResponseData {
    client_type: ClientType::Win32,
    license_detail_level: LicenseDetailLevel::Detail,
    challenge: Vec::from(CHALLENGE_BUFFER.as_ref()),
});
pub(crate) static CLIENT_HARDWARE_IDENTIFICATION: LazyLock<ClientHardwareIdentification> =
    LazyLock::new(|| ClientHardwareIdentification {
        platform_id: HARDWARE_ID,
        data: Vec::from(DATA_BUFFER.as_ref()),
    });
pub(crate) static CLIENT_PLATFORM_CHALLENGE_RESPONSE: LazyLock<LicensePdu> = LazyLock::new(|| {
    LicensePdu::ClientPlatformChallengeResponse(ClientPlatformChallengeResponse {
        license_header: LicenseHeader {
            security_header: BasicSecurityHeader {
                flags: BasicSecurityHeaderFlags::LICENSE_PKT,
            },
            preamble_message_type: PreambleType::PlatformChallengeResponse,
            preamble_flags: PreambleFlags::empty(),
            preamble_version: PreambleVersion::V3,
            preamble_message_size: u16::try_from(
                CLIENT_PLATFORM_CHALLENGE_RESPONSE_BUFFER.len() - BASIC_SECURITY_HEADER_SIZE,
            )
            .expect("can't panic"),
        },
        encrypted_challenge_response_data: Vec::from(&CLIENT_PLATFORM_CHALLENGE_RESPONSE_BUFFER[12..30]),
        encrypted_hwid: Vec::from(&CLIENT_PLATFORM_CHALLENGE_RESPONSE_BUFFER[34..54]),
        mac_data: Vec::from(
            &CLIENT_PLATFORM_CHALLENGE_RESPONSE_BUFFER[CLIENT_PLATFORM_CHALLENGE_RESPONSE_BUFFER.len() - 16..],
        ),
    })
});

#[test]
fn from_buffer_correctly_parses_platform_challenge_response_data() {
    assert_eq!(
        *RESPONSE,
        decode(PLATFORM_CHALLENGE_RESPONSE_DATA_BUFFER.as_ref()).unwrap()
    );
}

#[test]
fn to_buffer_correctly_serializes_platform_challenge_response_data() {
    let serialized_response = encode_vec(&*RESPONSE).unwrap();

    assert_eq!(
        PLATFORM_CHALLENGE_RESPONSE_DATA_BUFFER.as_ref(),
        serialized_response.as_slice()
    );
}

#[test]
fn buffer_length_is_correct_for_platform_challenge_response_data() {
    assert_eq!(PLATFORM_CHALLENGE_RESPONSE_DATA_BUFFER.len(), RESPONSE.size());
}

#[test]
fn from_buffer_correctly_parses_client_hardware_identification() {
    assert_eq!(
        *CLIENT_HARDWARE_IDENTIFICATION,
        decode(CLIENT_HARDWARE_IDENTIFICATION_BUFFER.as_ref()).unwrap()
    );
}

#[test]
fn to_buffer_correctly_serializes_client_hardware_identification() {
    let serialized_hardware_identification = encode_vec(&*CLIENT_HARDWARE_IDENTIFICATION).unwrap();

    assert_eq!(
        CLIENT_HARDWARE_IDENTIFICATION_BUFFER.as_ref(),
        serialized_hardware_identification.as_slice()
    );
}

#[test]
fn buffer_length_is_correct_for_client_hardware_identification() {
    assert_eq!(
        CLIENT_HARDWARE_IDENTIFICATION_BUFFER.len(),
        CLIENT_HARDWARE_IDENTIFICATION.size()
    );
}

#[test]
fn from_buffer_correctly_parses_client_platform_challenge_response() {
    assert_eq!(
        *CLIENT_PLATFORM_CHALLENGE_RESPONSE,
        decode(CLIENT_PLATFORM_CHALLENGE_RESPONSE_BUFFER.as_ref()).unwrap()
    );
}

#[test]
fn to_buffer_correctly_serializes_client_platform_challenge_response() {
    let serialized_response = encode_vec(&*CLIENT_PLATFORM_CHALLENGE_RESPONSE).unwrap();

    assert_eq!(
        CLIENT_PLATFORM_CHALLENGE_RESPONSE_BUFFER.as_ref(),
        serialized_response.as_slice()
    );
}

#[test]
fn buffer_length_is_correct_for_client_platform_challenge_response() {
    assert_eq!(
        CLIENT_PLATFORM_CHALLENGE_RESPONSE_BUFFER.len(),
        CLIENT_PLATFORM_CHALLENGE_RESPONSE.size()
    );
}

#[test]
fn challenge_response_creates_from_server_challenge_and_encryption_data_correctly() {
    let encrypted_platform_challenge = vec![0x26, 0x38, 0x88, 0x77, 0xcb, 0xe8, 0xbf, 0xce, 0x2c, 0x51];

    let mac_data = vec![
        0x51, 0x4a, 0x27, 0x2c, 0x74, 0x18, 0xec, 0x88, 0x95, 0xdd, 0xac, 0x10, 0x3e, 0x3f, 0xa, 0x72,
    ];

    let server_challenge = ServerPlatformChallenge {
        license_header: LicenseHeader {
            security_header: BasicSecurityHeader {
                flags: BasicSecurityHeaderFlags::LICENSE_PKT,
            },
            preamble_message_type: PreambleType::PlatformChallenge,
            preamble_flags: PreambleFlags::empty(),
            preamble_version: PreambleVersion::V3,
            preamble_message_size: u16::try_from(encrypted_platform_challenge.len() + mac_data.len() + PREAMBLE_SIZE)
                .expect("can't panic"),
        },
        encrypted_platform_challenge,
        mac_data,
    };

    let encryption_data = LicenseEncryptionData {
        premaster_secret: Vec::new(), // premaster secret is not involved in this unit test
        mac_salt_key: vec![
            0x1, 0x5b, 0x9e, 0x5f, 0x6, 0x97, 0x71, 0x58, 0xc3, 0xb8, 0x8b, 0x8c, 0x6e, 0x77, 0x21, 0x37,
        ],
        license_key: vec![
            0xe1, 0x78, 0xe4, 0xa0, 0x2a, 0xc5, 0xca, 0xb8, 0xa2, 0xd1, 0x53, 0xb8, 0x7, 0x23, 0xf3, 0xd2,
        ],
    };

    let hardware_data = vec![0u8; 16];
    let mut hardware_id = Vec::with_capacity(CLIENT_HARDWARE_IDENTIFICATION_SIZE);
    hardware_id.write_u32::<LittleEndian>(PLATFORM_ID).unwrap();
    hardware_id.write_all(&hardware_data).unwrap();

    let mut rc4 = Rc4::new(&encryption_data.license_key);
    let encrypted_hwid = rc4.process(&hardware_id);

    let response_data: [u8; 26] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0xff, 0x03, 0x00, 0x0a, 0x00, 0x54, 0x00,
        0x45, 0x00, 0x53, 0x00, 0x54, 0x00, 0x00, 0x00,
    ];

    let mut rc4 = Rc4::new(&encryption_data.license_key);
    let encrypted_challenge_response_data = rc4.process(&response_data);

    let mac_data = crate::rdp::server_license::compute_mac_data(
        encryption_data.mac_salt_key.as_slice(),
        [response_data.as_ref(), hardware_id.as_slice()].concat().as_slice(),
    )
    .expect("can't panic");

    let correct_challenge_response = ClientPlatformChallengeResponse {
        license_header: LicenseHeader {
            security_header: BasicSecurityHeader {
                flags: BasicSecurityHeaderFlags::LICENSE_PKT,
            },
            preamble_message_type: PreambleType::PlatformChallengeResponse,
            preamble_flags: PreambleFlags::empty(),
            preamble_version: PreambleVersion::V3,
            preamble_message_size: u16::try_from(
                PREAMBLE_SIZE
                + (BLOB_TYPE_SIZE + BLOB_LENGTH_SIZE) * 2 // 2 blobs in this structure
                + MAC_SIZE + encrypted_challenge_response_data.len() + encrypted_hwid.len(),
            )
            .expect("can't panic"),
        },
        encrypted_challenge_response_data,
        encrypted_hwid,
        mac_data,
    };

    let challenge_response =
        ClientPlatformChallengeResponse::from_server_platform_challenge(&server_challenge, [0u32; 4], &encryption_data)
            .unwrap();

    assert_eq!(challenge_response, correct_challenge_response);
}
