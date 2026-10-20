use std::sync::LazyLock;

use ironrdp_core::{decode, encode};

use super::*;

const FAST_PATH_HEADER_WITH_SHORT_LEN_BUFFER: [u8; 2] = [0x80, 0x08];
const FAST_PATH_HEADER_WITH_LONG_LEN_BUFFER: [u8; 3] = [0x80, 0x81, 0xE7];
const FAST_PATH_UPDATE_PDU_BUFFER: [u8; 19] = [
    0x4, 0x10, 0x0, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0,
];
const FAST_PATH_UPDATE_PDU_WITH_LONG_LEN_BUFFER: [u8; 19] = [
    0x4, 0xff, 0x0, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0,
];
const FAST_PATH_HEADER_WITH_FORCED_LONG_LEN_BUFFER: [u8; 3] = [0x80, 0x80, 0x08];

const FAST_PATH_HEADER_WITH_SHORT_LEN_PDU: FastPathHeader = FastPathHeader {
    flags: EncryptionFlags::ENCRYPTED,
    data_length: 6,
    forced_long_length: false,
};
const FAST_PATH_HEADER_WITH_LONG_LEN_PDU: FastPathHeader = FastPathHeader {
    flags: EncryptionFlags::ENCRYPTED,
    data_length: 484,
    forced_long_length: false,
};
const FAST_PATH_HEADER_WITH_FORCED_LONG_LEN_PDU: FastPathHeader = FastPathHeader {
    flags: EncryptionFlags::ENCRYPTED,
    data_length: 5,
    forced_long_length: true,
};

static FAST_PATH_UPDATE_PDU: LazyLock<FastPathUpdatePdu<'static>> = LazyLock::new(|| FastPathUpdatePdu {
    fragmentation: Fragmentation::Single,
    update_code: UpdateCode::SurfaceCommands,
    compression_flags: None,
    compression_type: None,
    data: &FAST_PATH_UPDATE_PDU_BUFFER[3..],
});

#[test]
fn from_buffer_correctly_parses_fast_path_header_with_short_length() {
    assert_eq!(
        FAST_PATH_HEADER_WITH_SHORT_LEN_PDU,
        decode::<FastPathHeader>(FAST_PATH_HEADER_WITH_SHORT_LEN_BUFFER.as_ref()).unwrap()
    );
}

#[test]
fn to_buffer_correctly_serializes_fast_path_header_with_short_length() {
    let expected = FAST_PATH_HEADER_WITH_SHORT_LEN_BUFFER.as_ref();
    let mut buffer = vec![0; expected.len()];

    encode(&FAST_PATH_HEADER_WITH_SHORT_LEN_PDU, buffer.as_mut_slice()).unwrap();
    assert_eq!(expected, buffer.as_slice());
}

#[test]
fn buffer_length_is_correct_for_fast_path_header_with_short_length() {
    assert_eq!(
        FAST_PATH_HEADER_WITH_SHORT_LEN_BUFFER.len(),
        FAST_PATH_HEADER_WITH_SHORT_LEN_PDU.size()
    );
}

#[test]
fn from_buffer_correctly_parses_fast_path_header_with_long_length() {
    assert_eq!(
        FAST_PATH_HEADER_WITH_LONG_LEN_PDU,
        decode::<FastPathHeader>(FAST_PATH_HEADER_WITH_LONG_LEN_BUFFER.as_ref()).unwrap()
    );
}

#[test]
fn to_buffer_correctly_serializes_fast_path_header_with_long_length() {
    let expected = FAST_PATH_HEADER_WITH_LONG_LEN_BUFFER.as_ref();
    let mut buffer = vec![0; expected.len()];

    encode(&FAST_PATH_HEADER_WITH_LONG_LEN_PDU, buffer.as_mut_slice()).unwrap();
    assert_eq!(expected, buffer.as_slice());
}

#[test]
fn buffer_length_is_correct_for_fast_path_header_with_long_length() {
    assert_eq!(
        FAST_PATH_HEADER_WITH_LONG_LEN_BUFFER.len(),
        FAST_PATH_HEADER_WITH_LONG_LEN_PDU.size()
    );
}

#[test]
fn from_buffer_correctly_parses_fast_path_header_with_forced_long_length() {
    assert_eq!(
        FAST_PATH_HEADER_WITH_FORCED_LONG_LEN_PDU,
        decode::<FastPathHeader>(FAST_PATH_HEADER_WITH_FORCED_LONG_LEN_BUFFER.as_ref()).unwrap()
    );
}

#[test]
fn to_buffer_correctly_serializes_fast_path_header_with_forced_long_length() {
    let expected = FAST_PATH_HEADER_WITH_FORCED_LONG_LEN_BUFFER.as_ref();
    let mut buffer = vec![0; expected.len()];

    encode(&FAST_PATH_HEADER_WITH_FORCED_LONG_LEN_PDU, buffer.as_mut_slice()).unwrap();
    assert_eq!(expected, buffer.as_slice());
}

#[test]
fn buffer_length_is_correct_for_fast_path_header_with_forced_long_length() {
    assert_eq!(
        FAST_PATH_HEADER_WITH_FORCED_LONG_LEN_BUFFER.len(),
        FAST_PATH_HEADER_WITH_FORCED_LONG_LEN_PDU.size()
    );
}

#[test]
fn from_buffer_correctly_parses_fast_path_update() {
    assert_eq!(
        *FAST_PATH_UPDATE_PDU,
        decode::<FastPathUpdatePdu<'_>>(FAST_PATH_UPDATE_PDU_BUFFER.as_ref()).unwrap()
    );
}

#[test]
fn from_buffer_returns_error_on_long_length_for_fast_path_update() {
    assert!(decode::<FastPathUpdatePdu<'_>>(FAST_PATH_UPDATE_PDU_WITH_LONG_LEN_BUFFER.as_ref()).is_err());
}

#[test]
fn to_buffer_correctly_serializes_fast_path_update() {
    let expected = FAST_PATH_UPDATE_PDU_BUFFER.as_ref();
    let mut buffer = vec![0; expected.len()];

    encode(&*FAST_PATH_UPDATE_PDU, buffer.as_mut_slice()).unwrap();
    assert_eq!(expected, buffer.as_slice());
}

#[test]
fn buffer_length_is_correct_for_fast_path_update() {
    assert_eq!(FAST_PATH_UPDATE_PDU_BUFFER.len(), FAST_PATH_UPDATE_PDU.size());
}

#[test]
fn buffer_size_boundary_fast_path_update() {
    let fph = FastPathHeader {
        flags: EncryptionFlags::ENCRYPTED,
        data_length: 125,
        forced_long_length: false,
    };
    assert_eq!(fph.size(), 2);
    let fph = FastPathHeader {
        flags: EncryptionFlags::ENCRYPTED,
        data_length: 126,
        forced_long_length: false,
    };
    assert_eq!(fph.size(), 3);
}

// Minimal palette: pad(2) + numberColors(1) + 1 x TS_COLOR_QUAD [B, G, R, pad]
const PALETTE_PAYLOAD: [u8; 10] = [
    0x00, 0x00, // pad
    0x01, 0x00, 0x00, 0x00, // numberColors = 1
    0xFF, 0x00, 0x80, 0x00, // B=0xFF, G=0x00, R=0x80, pad=0x00
];

// header(1) + length(2) + payload(10)
const FAST_PATH_PALETTE_BUFFER: [u8; 13] = [
    0x02, // updateCode=Palette(0x2), fragmentation=Single(0x0)
    0x0A, 0x00, // data length = 10 (LE)
    0x00, 0x00, // pad
    0x01, 0x00, 0x00, 0x00, // numberColors = 1
    0xFF, 0x00, 0x80, 0x00, // B=0xFF, G=0x00, R=0x80, pad=0x00
];

#[test]
fn from_buffer_correctly_parses_palette_update() {
    let pdu = decode::<FastPathUpdatePdu<'_>>(FAST_PATH_PALETTE_BUFFER.as_ref()).unwrap();
    assert_eq!(pdu.update_code, UpdateCode::Palette);
    assert_eq!(pdu.fragmentation, Fragmentation::Single);
    assert_eq!(pdu.data, PALETTE_PAYLOAD.as_ref());
}

#[test]
fn palette_update_round_trips() {
    let pdu = decode::<FastPathUpdatePdu<'_>>(FAST_PATH_PALETTE_BUFFER.as_ref()).unwrap();
    let mut buffer = vec![0u8; pdu.size()];
    encode(&pdu, buffer.as_mut_slice()).unwrap();
    assert_eq!(FAST_PATH_PALETTE_BUFFER.as_ref(), buffer.as_slice());
}

#[test]
fn palette_decode_with_code_returns_palette_variant() {
    let update = FastPathUpdate::decode_with_code(&PALETTE_PAYLOAD, UpdateCode::Palette).unwrap();
    match update {
        FastPathUpdate::Palette(data) => assert_eq!(data, PALETTE_PAYLOAD.as_ref()),
        other => panic!("Expected Palette variant, got: {other:?}"),
    }
}

#[test]
fn compressed_update_round_trips() {
    // The encoder must set the COMPRESSION_USED bit on the update header when
    // compression flags are present, otherwise the decoder does not consume the
    // trailing compression flags byte and misreads the data length.
    let data = [0xAAu8; 8];
    let pdu = FastPathUpdatePdu {
        fragmentation: Fragmentation::Single,
        update_code: UpdateCode::SurfaceCommands,
        compression_flags: Some(CompressionFlags::COMPRESSED),
        compression_type: Some(CompressionType::K64),
        data: &data,
    };

    let mut buffer = vec![0u8; pdu.size()];
    encode(&pdu, buffer.as_mut_slice()).unwrap();

    assert_eq!(pdu, decode::<FastPathUpdatePdu<'_>>(&buffer).unwrap());
}
