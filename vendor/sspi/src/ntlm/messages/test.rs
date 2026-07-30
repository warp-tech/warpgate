use std::sync::LazyLock;

use crate::ntlm::{AuthIdentityBuffers, NTLM_VERSION_SIZE};
use crate::*;

pub(crate) const SIGNATURE_SIZE: usize = 8;
pub(crate) const MESSAGE_TYPE_SIZE: usize = 4;
pub(crate) const NEGOTIATE_FLAGS_SIZE: usize = 4;
pub(crate) const MIC_SIZE: usize = 16;
pub(crate) const FIELD_SIZE: usize = 8;

pub(crate) const SIGNATURE_START: usize = 0;
pub(crate) const MESSAGE_TYPE_START: usize = SIGNATURE_START + SIGNATURE_SIZE;

pub(crate) const NEGOTIATE_FLAGS_START: usize = MESSAGE_TYPE_START + MESSAGE_TYPE_SIZE;
pub(crate) const NEGOTIATE_DOMAIN_NAME_START: usize = NEGOTIATE_FLAGS_START + NEGOTIATE_FLAGS_SIZE;
pub(crate) const NEGOTIATE_WORKSTATION_START: usize = NEGOTIATE_DOMAIN_NAME_START + FIELD_SIZE;
pub(crate) const NEGOTIATE_VERSION_START: usize = NEGOTIATE_WORKSTATION_START + FIELD_SIZE;

pub(crate) const CHALLENGE_TARGET_NAME_START: usize = MESSAGE_TYPE_START + MESSAGE_TYPE_SIZE;
pub(crate) const CHALLENGE_FLAGS_START: usize = CHALLENGE_TARGET_NAME_START + FIELD_SIZE;
pub(crate) const CHALLENGE_SERVER_CHALLENGE_START: usize = CHALLENGE_FLAGS_START + NEGOTIATE_FLAGS_SIZE;
pub(crate) const CHALLENGE_RESERVED_START: usize = CHALLENGE_SERVER_CHALLENGE_START + FIELD_SIZE;
pub(crate) const CHALLENGE_TARGET_INFO_START: usize = CHALLENGE_RESERVED_START + FIELD_SIZE;
pub(crate) const CHALLENGE_VERSION_START: usize = CHALLENGE_TARGET_INFO_START + FIELD_SIZE;
pub(crate) const CHALLENGE_HEADER_SIZE: usize = CHALLENGE_VERSION_START + NTLM_VERSION_SIZE;

pub(crate) const AUTHENTICATE_TARGET_INFO_PADDING_SIZE: usize = 8;
pub(crate) const AUTHENTICATE_LM_CHALLENGE_RESPONSE_START: usize = MESSAGE_TYPE_START + MESSAGE_TYPE_SIZE;
pub(crate) const AUTHENTICATE_NT_CHALLENGE_RESPONSE_START: usize =
    AUTHENTICATE_LM_CHALLENGE_RESPONSE_START + FIELD_SIZE;
pub(crate) const AUTHENTICATE_DOMAIN_NAME_START: usize = AUTHENTICATE_NT_CHALLENGE_RESPONSE_START + FIELD_SIZE;
pub(crate) const AUTHENTICATE_USER_NAME_START: usize = AUTHENTICATE_DOMAIN_NAME_START + FIELD_SIZE;
pub(crate) const AUTHENTICATE_WORKSTATION_START: usize = AUTHENTICATE_USER_NAME_START + FIELD_SIZE;
pub(crate) const AUTHENTICATE_ENCRYPTED_KEY_START: usize = AUTHENTICATE_WORKSTATION_START + FIELD_SIZE;
pub(crate) const AUTHENTICATE_FLAGS_START: usize = AUTHENTICATE_ENCRYPTED_KEY_START + FIELD_SIZE;
pub(crate) const AUTHENTICATE_OFFSET: usize = 64 + NTLM_VERSION_SIZE;
pub(crate) const AUTHENTICATE_OFFSET_WITH_MIC: usize = AUTHENTICATE_OFFSET + MIC_SIZE;

pub(crate) const TIMESTAMP: u64 = 130_475_779_380_041_523;
pub(crate) const SERVER_CHALLENGE: [u8; 8] = [0xa4, 0xf1, 0xba, 0xa6, 0x7c, 0xdc, 0x1a, 0x12];
pub(crate) const CLIENT_CHALLENGE: [u8; 8] = [0x20, 0xc0, 0x2b, 0x3d, 0xc0, 0x61, 0xa7, 0x73];
pub(crate) const NTLM_VERSION: [u8; NTLM_VERSION_SIZE] = [0x00; NTLM_VERSION_SIZE];

pub(crate) const NTLM_SIGNATURE: [u8; 8] = [0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00];
pub(crate) const NEGOTIATE_MESSAGE_TYPE: [u8; 4] = [0x01, 0x00, 0x00, 0x00];
pub(crate) const CHALLENGE_MESSAGE_TYPE: [u8; 4] = [0x02, 0x00, 0x00, 0x00];

pub(crate) const LOCAL_NEGOTIATE_FLAGS: u32 = 0xe208_82b7;
pub(crate) const LOCAL_NEGOTIATE_DOMAIN: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00];
pub(crate) const LOCAL_NEGOTIATE_WORKSTATION: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00];
pub(crate) const LOCAL_NEGOTIATE_VERSION: [u8; 8] = [0x05, 0x01, 0x28, 0x0a, 0x00, 0x00, 0x00, 0x0f];
const LOCAL_NEGOTIATE_MESSAGE_SIZE: usize = 40;

pub(crate) const LOCAL_CHALLENGE_TARGET_NAME_EMPTY: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00];
pub(crate) const LOCAL_CHALLENGE_TARGET_NAME: [u8; 8] = [0x08, 0x00, 0x08, 0x00, 0x38, 0x00, 0x00, 0x00];
pub(crate) const LOCAL_CHALLENGE_FLAGS: u32 = 0xE288_82B7;
pub(crate) const LOCAL_CHALLENGE_SERVER_CHALLENGE: [u8; 8] = [0x26, 0x6e, 0xcd, 0x75, 0xaa, 0x41, 0xe7, 0x6f];
pub(crate) const LOCAL_CHALLENGE_RESERVED: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
pub(crate) const LOCAL_CHALLENGE_TARGET_INFO: [u8; 8] = [0x40, 0x00, 0x40, 0x00, 0x40, 0x00, 0x00, 0x00];
pub(crate) const LOCAL_CHALLENGE_VERSION: [u8; 8] = [0x06, 0x01, 0xb0, 0x1d, 0x00, 0x00, 0x00, 0x0f];
pub(crate) const LOCAL_CHALLENGE_TARGET_NAME_BUFFER: [u8; 8] = [0x57, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x37, 0x00];
pub(crate) const LOCAL_CHALLENGE_TARGET_INFO_BUFFER: [u8; 64] = [
    0x02, 0x00, // AvId (MsvAvNbDomainName)
    0x08, 0x00, // AvLen (8)
    0x57, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x37, 0x00, // "WIN7"
    //
    0x01, 0x00, // AvId (MsvAvNbComputerName)
    0x08, 0x00, // AvLen (8)
    0x57, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x37, 0x00, // "WIN7"
    //
    0x04, 0x00, // AvId (MsvAvDnsDomainName)
    0x08, 0x00, // AvLen (8)
    0x77, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x37, 0x00, // "win7"
    //
    0x03, 0x00, // AvId (MsvAvDnsComputerName)
    0x08, 0x00, // AvLen (8)
    0x77, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x37, 0x00, // "win7"
    //
    0x07, 0x00, // AvId (MsvAvTimestamp)
    0x08, 0x00, // AvLen (8)
    0xa9, 0x8d, 0x9b, 0x1a, 0x6c, 0xb0, 0xcb, 0x01, //
    0x00, 0x00, // AvId (MsvAvEOL)
    0x00, 0x00, // AvLen (0)
];
pub(crate) const LOCAL_CHALLENGE_TIMESTAMP: u64 = 0x01cb_b06c_1a9b_8da9;
const LOCAL_CHALLENGE_MESSAGE_SIZE: usize = 128;

pub(crate) static LOCAL_NEGOTIATE_MESSAGE: LazyLock<[u8; LOCAL_NEGOTIATE_MESSAGE_SIZE]> = LazyLock::new(|| {
    let mut message = Vec::with_capacity(LOCAL_NEGOTIATE_MESSAGE_SIZE);
    message.extend_from_slice(NTLM_SIGNATURE.as_ref());
    message.extend_from_slice(NEGOTIATE_MESSAGE_TYPE.as_ref());
    message.extend_from_slice(LOCAL_NEGOTIATE_FLAGS.to_le_bytes().as_ref());
    message.extend_from_slice(LOCAL_NEGOTIATE_DOMAIN.as_ref());
    message.extend_from_slice(LOCAL_NEGOTIATE_WORKSTATION.as_ref());
    message.extend_from_slice(LOCAL_NEGOTIATE_VERSION.as_ref());

    let mut result = [0x00; LOCAL_NEGOTIATE_MESSAGE_SIZE];
    result.clone_from_slice(message.as_ref());

    result
});

pub(crate) static LOCAL_CHALLENGE_MESSAGE: LazyLock<[u8; LOCAL_CHALLENGE_MESSAGE_SIZE]> = LazyLock::new(|| {
    let mut message = Vec::with_capacity(LOCAL_CHALLENGE_MESSAGE_SIZE);
    message.extend_from_slice(NTLM_SIGNATURE.as_ref());
    message.extend_from_slice(CHALLENGE_MESSAGE_TYPE.as_ref());
    message.extend_from_slice(LOCAL_CHALLENGE_TARGET_NAME.as_ref());
    message.extend_from_slice(LOCAL_CHALLENGE_FLAGS.to_le_bytes().as_ref());
    message.extend_from_slice(LOCAL_CHALLENGE_SERVER_CHALLENGE.as_ref());
    message.extend_from_slice(LOCAL_CHALLENGE_RESERVED.as_ref());
    message.extend_from_slice(LOCAL_CHALLENGE_TARGET_INFO.as_ref());
    message.extend_from_slice(LOCAL_CHALLENGE_VERSION.as_ref());
    message.extend_from_slice(LOCAL_CHALLENGE_TARGET_NAME_BUFFER.as_ref());
    message.extend_from_slice(LOCAL_CHALLENGE_TARGET_INFO_BUFFER.as_ref());

    let mut result = [0x00; LOCAL_CHALLENGE_MESSAGE_SIZE];
    result.clone_from_slice(message.as_ref());

    result
});

pub(crate) static TEST_CREDENTIALS: LazyLock<AuthIdentityBuffers> = LazyLock::new(|| {
    AuthIdentity {
        username: Username::new("User", Some("Domain")).unwrap(),
        password: String::from("Password").into(),
    }
    .into()
});
