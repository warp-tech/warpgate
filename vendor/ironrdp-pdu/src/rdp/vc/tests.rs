use std::sync::LazyLock;

use ironrdp_core::{decode, encode_vec};

use super::*;

const CHANNEL_CHUNK_LENGTH_DEFAULT: u32 = 1600;
const CHANNEL_PDU_HEADER_BUFFER: [u8; CHANNEL_PDU_HEADER_SIZE] = [0x40, 0x06, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];

static CHANNEL_PDU_HEADER: LazyLock<ChannelPduHeader> = LazyLock::new(|| ChannelPduHeader {
    length: CHANNEL_CHUNK_LENGTH_DEFAULT,
    flags: ChannelControlFlags::FLAG_FIRST,
});

#[test]
fn from_buffer_correct_parses_channel_header() {
    assert_eq!(
        CHANNEL_PDU_HEADER.clone(),
        decode(CHANNEL_PDU_HEADER_BUFFER.as_ref()).unwrap(),
    );
}

#[test]
fn to_buffer_correct_serializes_channel_header() {
    let channel_header = CHANNEL_PDU_HEADER.clone();

    let buffer = encode_vec(&channel_header).unwrap();

    assert_eq!(CHANNEL_PDU_HEADER_BUFFER.as_ref(), buffer.as_slice());
}

#[test]
fn buffer_length_is_correct_for_channel_header() {
    let channel_header = CHANNEL_PDU_HEADER.clone();
    let expected_buf_len = CHANNEL_PDU_HEADER_BUFFER.len();

    let len = channel_header.size();

    assert_eq!(expected_buf_len, len);
}
