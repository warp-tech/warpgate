use std::sync::LazyLock;

use ironrdp_core::{DecodeErrorKind, decode_cursor, encode_vec};

use super::*;

const GUID_BUFFER: [u8; 16] = [
    0xb9, 0x1b, 0x8d, 0xca, 0x0f, 0x00, 0x4f, 0x15, 0x58, 0x9f, 0xae, 0x2d, 0x1a, 0x87, 0xe2, 0xd6,
];

const RFX_ICAP_BUFFER: [u8; 8] = [
    0x00, 0x01, // version
    0x40, 0x00, // tile size
    0x02, // flags
    0x01, // col conv bits
    0x01, // transform bits
    0x04, // entropy_bits
];

const RFX_CAPSET_BUFFER: [u8; 29] = [
    0xc1, 0xcb, // block type
    0x1d, 0x00, 0x00, 0x00, // block len
    0x01, // codec id
    0xc0, 0xcf, // capset type
    0x02, 0x00, // num icaps
    0x08, 0x00, // icap len
    0x00, 0x01, // version
    0x40, 0x00, // tile size
    0x00, // flags
    0x01, // col conv bits
    0x01, // transform bits
    0x01, // entropy_bits
    0x00, 0x01, // version
    0x40, 0x00, // tile size
    0x02, // flags
    0x01, // col conv bits
    0x01, // transform bits
    0x04, // entropy_bits
];

const RFX_CAPS_BUFFER: [u8; 37] = [
    0xc0, 0xcb, // block type
    0x08, 0x00, 0x00, 0x00, // block len
    0x01, 0x00, // num capsets
    0xc1, 0xcb, // block type
    0x1d, 0x00, 0x00, 0x00, // block len
    0x01, // codec id
    0xc0, 0xcf, // capset type
    0x02, 0x00, // num icaps
    0x08, 0x00, // icap len
    0x00, 0x01, // version
    0x40, 0x00, // tile size
    0x00, // flags
    0x01, // col conv bits
    0x01, // transform bits
    0x01, // entropy_bits
    0x00, 0x01, // version
    0x40, 0x00, // tile size
    0x02, // flags
    0x01, // col conv bits
    0x01, // transform bits
    0x04, // entropy_bits
];

const RFX_CLIENT_CAPS_CONTAINER_BUFFER: [u8; 49] = [
    0x31, 0x00, 0x00, 0x00, // length
    0x01, 0x00, 0x00, 0x00, // capture flags
    0x25, 0x00, 0x00, 0x00, // caps length
    0xc0, 0xcb, // block type
    0x08, 0x00, 0x00, 0x00, // block len
    0x01, 0x00, // num capsets
    0xc1, 0xcb, // block type
    0x1d, 0x00, 0x00, 0x00, // block len
    0x01, // codec id
    0xc0, 0xcf, // capset type
    0x02, 0x00, // num icaps
    0x08, 0x00, // icap len
    0x00, 0x01, // version
    0x40, 0x00, // tile size
    0x00, // flags
    0x01, // col conv bits
    0x01, // transform bits
    0x01, // entropy_bits
    0x00, 0x01, // version
    0x40, 0x00, // tile size
    0x02, // flags
    0x01, // col conv bits
    0x01, // transform bits
    0x04, // entropy_bits
];

const NSCODEC_BUFFER: [u8; 3] = [
    0x01, // allow dynamic fidelity
    0x01, // allow subsampling
    0x03, // color loss level
];

const CODEC_BUFFER: [u8; 68] = [
    0x12, 0x2f, 0x77, 0x76, 0x72, 0xbd, 0x63, 0x44, 0xAF, 0xB3, 0xB7, 0x3C, 0x9C, 0x6F, 0x78, 0x86, // guid
    0x03, // codec id
    0x31, 0x00, // codec properties len
    0x31, 0x00, 0x00, 0x00, // length
    0x01, 0x00, 0x00, 0x00, // capture flags
    0x25, 0x00, 0x00, 0x00, // caps length
    0xc0, 0xcb, // block type
    0x08, 0x00, 0x00, 0x00, // block len
    0x01, 0x00, // num capsets
    0xc1, 0xcb, // block type
    0x1d, 0x00, 0x00, 0x00, // block len
    0x01, // codec id
    0xc0, 0xcf, // capset type
    0x02, 0x00, // num icaps
    0x08, 0x00, // icap len
    0x00, 0x01, // version
    0x40, 0x00, // tile size
    0x00, // flags
    0x01, // col conv bits
    0x01, // transform bits
    0x01, // entropy_bits
    0x00, 0x01, // version
    0x40, 0x00, // tile size
    0x02, // flags
    0x01, // col conv bits
    0x01, // transform bits
    0x04, // entropy_bits
];

const CODEC_SERVER_MODE_BUFFER: [u8; 23] = [
    0xd4, 0xcc, 0x44, 0x27, 0x8a, 0x9d, 0x74, 0x4e, 0x80, 0x3C, 0x0E, 0xCB, 0xEE, 0xA1, 0x9C, 0x54,
    0x00, // codec id
    0x04, 0x00, // codec properties len
    0x00, 0x00, 0x00, 0x00, // server_cap container
];

const BITMAP_CODECS_BUFFER: [u8; 91] = [
    0x02, // codec count
    0x12, 0x2f, 0x77, 0x76, 0x72, 0xbd, 0x63, 0x44, 0xAF, 0xB3, 0xB7, 0x3C, 0x9C, 0x6F, 0x78, 0x86,
    0x03, // codec id
    0x31, 0x00, // codec properties len
    0x31, 0x00, 0x00, 0x00, // length
    0x01, 0x00, 0x00, 0x00, // capture flags
    0x25, 0x00, 0x00, 0x00, // caps length
    0xc0, 0xcb, // block type
    0x08, 0x00, 0x00, 0x00, // block len
    0x01, 0x00, // num capsets
    0xc1, 0xcb, // block type
    0x1d, 0x00, 0x00, 0x00, // block len
    0x01, // codec id
    0xc0, 0xcf, // capset type
    0x02, 0x00, // num icaps
    0x08, 0x00, // icap len
    0x00, 0x01, // version
    0x40, 0x00, // tile size
    0x00, // flags
    0x01, // col conv bits
    0x01, // transform bits
    0x01, // entropy_bits
    0x00, 0x01, // version
    0x40, 0x00, // tile size
    0x02, // flags
    0x01, // col conv bits
    0x01, // transform bits
    0x04, // entropy_bits
    0xb9, 0x1b, 0x8d, 0xca, 0x0f, 0x00, 0x4f, 0x15, 0x58, 0x9F, 0xAE, 0x2D, 0x1A, 0x87, 0xE2, 0xD6,
    0x01, // codec id
    0x03, 0x00, // codec properties len
    0x01, // allow dynamic fidelity
    0x01, // allow subsampling
    0x03, // color loss level
];

static GUID: LazyLock<Guid> = LazyLock::new(|| {
    Guid(
        0xca8d_1bb9,
        0x000f,
        0x154f,
        0x58,
        0x9f,
        0xae,
        0x2d,
        0x1a,
        0x87,
        0xe2,
        0xd6,
    )
});
static RFX_ICAP: LazyLock<RfxICap> = LazyLock::new(|| RfxICap {
    flags: RfxICapFlags::CODEC_MODE,
    entropy_bits: EntropyBits::Rlgr3,
});
static RFX_CAPSET: LazyLock<RfxCapset> = LazyLock::new(|| {
    RfxCapset(vec![
        RfxICap {
            flags: RfxICapFlags::empty(),
            entropy_bits: EntropyBits::Rlgr1,
        },
        RfxICap {
            flags: RfxICapFlags::CODEC_MODE,
            entropy_bits: EntropyBits::Rlgr3,
        },
    ])
});
static RFX_CAPS: LazyLock<RfxCaps> = LazyLock::new(|| {
    RfxCaps(RfxCapset(vec![
        RfxICap {
            flags: RfxICapFlags::empty(),
            entropy_bits: EntropyBits::Rlgr1,
        },
        RfxICap {
            flags: RfxICapFlags::CODEC_MODE,
            entropy_bits: EntropyBits::Rlgr3,
        },
    ]))
});
static RFX_CLIENT_CAPS_CONTAINER: LazyLock<RfxClientCapsContainer> = LazyLock::new(|| RfxClientCapsContainer {
    capture_flags: CaptureFlags::CARDP_CAPS_CAPTURE_NON_CAC,
    caps_data: RfxCaps(RfxCapset(vec![
        RfxICap {
            flags: RfxICapFlags::empty(),
            entropy_bits: EntropyBits::Rlgr1,
        },
        RfxICap {
            flags: RfxICapFlags::CODEC_MODE,
            entropy_bits: EntropyBits::Rlgr3,
        },
    ])),
});
static NSCODEC: LazyLock<NsCodec> = LazyLock::new(|| NsCodec {
    is_dynamic_fidelity_allowed: true,
    is_subsampling_allowed: true,
    color_loss_level: 3,
});
static CODEC: LazyLock<Codec> = LazyLock::new(|| Codec {
    id: 3,
    property: CodecProperty::RemoteFx(RemoteFxContainer::ClientContainer(RfxClientCapsContainer {
        capture_flags: CaptureFlags::CARDP_CAPS_CAPTURE_NON_CAC,
        caps_data: RfxCaps(RfxCapset(vec![
            RfxICap {
                flags: RfxICapFlags::empty(),
                entropy_bits: EntropyBits::Rlgr1,
            },
            RfxICap {
                flags: RfxICapFlags::CODEC_MODE,
                entropy_bits: EntropyBits::Rlgr3,
            },
        ])),
    })),
});
static CODEC_SERVER_MODE: LazyLock<Codec> = LazyLock::new(|| Codec {
    id: 0,
    property: CodecProperty::ImageRemoteFx(RemoteFxContainer::ServerContainer(4)),
});
static BITMAP_CODECS: LazyLock<BitmapCodecs> = LazyLock::new(|| {
    BitmapCodecs(vec![
        Codec {
            id: 3,
            property: CodecProperty::RemoteFx(RemoteFxContainer::ClientContainer(RfxClientCapsContainer {
                capture_flags: CaptureFlags::CARDP_CAPS_CAPTURE_NON_CAC,
                caps_data: RfxCaps(RfxCapset(vec![
                    RfxICap {
                        flags: RfxICapFlags::empty(),
                        entropy_bits: EntropyBits::Rlgr1,
                    },
                    RfxICap {
                        flags: RfxICapFlags::CODEC_MODE,
                        entropy_bits: EntropyBits::Rlgr3,
                    },
                ])),
            })),
        },
        Codec {
            id: 1,
            property: CodecProperty::NsCodec(NsCodec {
                is_dynamic_fidelity_allowed: true,
                is_subsampling_allowed: true,
                color_loss_level: 3,
            }),
        },
    ])
});

#[test]
fn from_buffer_correctly_parses_guid() {
    assert_eq!(*GUID, decode(GUID_BUFFER.as_ref()).unwrap());
}

#[test]
fn to_buffer_correctly_serializes_guid() {
    let buffer = encode_vec(&*GUID).unwrap();
    assert_eq!(buffer, GUID_BUFFER.as_ref());
}

#[test]
fn buffer_length_is_correct_for_guid() {
    assert_eq!(GUID_BUFFER.len(), GUID.size());
}

#[test]
fn from_buffer_correctly_parses_rfx_icap() {
    assert_eq!(*RFX_ICAP, decode(RFX_ICAP_BUFFER.as_ref()).unwrap());
}

#[test]
fn to_buffer_correctly_serializes_rfx_icap() {
    let buffer = encode_vec(&*RFX_ICAP).unwrap();
    assert_eq!(buffer, RFX_ICAP_BUFFER.as_ref());
}

#[test]
fn buffer_length_is_correct_for_rfx_icap() {
    assert_eq!(RFX_ICAP_BUFFER.len(), RFX_ICAP.size());
}

#[test]
fn from_buffer_correctly_parses_rfx_capset() {
    assert_eq!(*RFX_CAPSET, decode(RFX_CAPSET_BUFFER.as_ref()).unwrap());
}

#[test]
fn to_buffer_correctly_serializes_rfx_capset() {
    let buffer = encode_vec(&*RFX_CAPSET).unwrap();

    assert_eq!(buffer, RFX_CAPSET_BUFFER.as_ref());
}

#[test]
fn buffer_length_is_correct_for_rfx_capset() {
    assert_eq!(RFX_CAPSET_BUFFER.len(), RFX_CAPSET.size());
}

#[test]
fn from_buffer_correctly_parses_rfx_caps() {
    assert_eq!(*RFX_CAPS, decode(RFX_CAPS_BUFFER.as_ref()).unwrap());
}

#[test]
fn to_buffer_correctly_serializes_rfx_caps() {
    let buffer = encode_vec(&*RFX_CAPS).unwrap();
    assert_eq!(buffer, RFX_CAPS_BUFFER.as_ref());
}

#[test]
fn buffer_length_is_correct_for_rfx_caps() {
    assert_eq!(RFX_CAPS_BUFFER.len(), RFX_CAPS.size());
}

#[test]
fn from_buffer_correctly_parses_rfx_client_caps_container() {
    assert_eq!(
        *RFX_CLIENT_CAPS_CONTAINER,
        decode(RFX_CLIENT_CAPS_CONTAINER_BUFFER.as_ref()).unwrap()
    );
}

#[test]
fn to_buffer_correctly_serializes_rfx_client_caps_container() {
    let buffer = encode_vec(&*RFX_CLIENT_CAPS_CONTAINER).unwrap();
    assert_eq!(buffer, RFX_CLIENT_CAPS_CONTAINER_BUFFER.as_ref());
}

#[test]
fn buffer_length_is_correct_for_rfx_client_caps_container() {
    assert_eq!(RFX_CLIENT_CAPS_CONTAINER_BUFFER.len(), RFX_CLIENT_CAPS_CONTAINER.size());
}

#[test]
fn from_buffer_correctly_parses_nscodec() {
    assert_eq!(*NSCODEC, decode(NSCODEC_BUFFER.as_ref()).unwrap());
}

#[test]
fn to_buffer_correctly_serializes_nscodec() {
    let buffer = encode_vec(&*NSCODEC).unwrap();
    assert_eq!(buffer, NSCODEC_BUFFER.as_ref());
}

#[test]
fn buffer_length_is_correct_for_nscodec() {
    assert_eq!(NSCODEC_BUFFER.len(), NSCODEC.size());
}

#[test]
fn from_buffer_correctly_parses_codec() {
    assert_eq!(*CODEC, decode(CODEC_BUFFER.as_ref()).unwrap());
}

#[test]
fn to_buffer_correctly_serializes_codec() {
    let buffer = encode_vec(&*CODEC).unwrap();
    assert_eq!(buffer, CODEC_BUFFER.as_ref());
}

#[test]
fn buffer_length_is_correct_for_codec() {
    assert_eq!(CODEC_BUFFER.len(), CODEC.size());
}

#[test]
fn from_buffer_correctly_parses_codec_server_mode() {
    assert_eq!(*CODEC_SERVER_MODE, decode(CODEC_SERVER_MODE_BUFFER.as_ref()).unwrap());
}

#[test]
fn to_buffer_correctly_serializes_codec_server_mode() {
    let buffer = encode_vec(&*CODEC_SERVER_MODE).unwrap();
    assert_eq!(buffer, CODEC_SERVER_MODE_BUFFER.as_ref());
}

#[test]
fn buffer_length_is_correct_for_codec_server_mode() {
    assert_eq!(CODEC_BUFFER.len(), CODEC.size());
}

#[test]
fn from_buffer_correctly_parses_bitmap_codecs() {
    assert_eq!(*BITMAP_CODECS, decode(BITMAP_CODECS_BUFFER.as_ref()).unwrap());
}

#[test]
fn to_buffer_correctly_serializes_bitmap_codes() {
    let buffer = encode_vec(&*BITMAP_CODECS).unwrap();
    assert_eq!(buffer, BITMAP_CODECS_BUFFER.as_ref());
}

#[test]
fn buffer_length_is_correct_for_bitmap_codec() {
    assert_eq!(BITMAP_CODECS_BUFFER.len(), BITMAP_CODECS.size());
}

#[test]
fn codec_with_invalid_property_length_handles_correctly() {
    let codec_buffer: [u8; 68] = [
        0x12, 0x2f, 0x77, 0x76, 0x72, 0xbd, 0x63, 0x44, 0xAF, 0xB3, 0xB7, 0x3C, 0x9C, 0x6F, 0x78, 0x86, // guid
        0x03, // codec id
        0x00, 0x00, // codec properties len
        0x31, 0x00, 0x00, 0x00, // length
        0x01, 0x00, 0x00, 0x00, // capture flags
        0x25, 0x00, 0x00, 0x00, // caps length
        0xc0, 0xcb, // block type
        0x08, 0x00, 0x00, 0x00, // block len
        0x01, 0x00, // num capsets
        0xc1, 0xcb, // block type
        0x1d, 0x00, 0x00, 0x00, // block len
        0x01, // codec id
        0xc0, 0xcf, // capset type
        0x02, 0x00, // num icaps
        0x08, 0x00, // icap len
        0x00, 0x01, // version
        0x40, 0x00, // tile size
        0x00, // flags
        0x01, // col conv bits
        0x01, // transform bits
        0x01, // entropy_bits
        0x00, 0x01, // version
        0x40, 0x00, // tile size
        0x02, // flags
        0x01, // col conv bits
        0x01, // transform bits
        0x04, // entropy_bits
    ];

    match decode::<Codec>(codec_buffer.as_ref()) {
        Err(e) if matches!(e.kind(), DecodeErrorKind::InvalidField { .. }) => (),
        Err(e) => panic!("wrong error type: {e}"),
        _ => panic!("error expected"),
    }
}

#[test]
fn codec_with_empty_property_length_and_ignore_guid_handles_correctly() {
    let codec_buffer: [u8; 19] = [
        0xa6, 0x51, 0x43, 0x9c, 0x35, 0x35, 0xae, 0x42, 0x91, 0x0c, 0xcd, 0xfc, 0xe5, 0x76, 0x0b, 0x58,
        0x00, // codec id
        0x00, 0x00, // codec properties len
    ];

    let codec = Codec {
        id: 0,
        property: CodecProperty::Ignore,
    };

    assert_eq!(codec, decode(codec_buffer.as_ref()).unwrap());
}

#[test]
fn codec_with_property_length_and_ignore_guid_handled_correctly() {
    let codec_buffer = vec![
        0xa6u8, 0x51, 0x43, 0x9c, 0x35, 0x35, 0xae, 0x42, 0x91, 0x0c, 0xcd, 0xfc, 0xe5, 0x76, 0x0b, 0x58,
        0x00, // codec id
        0x0f, 0x00, // codec properties len
        0xa6, 0x51, 0x43, 0x9c, 0x35, 0x35, 0xae, 0x42, 0x91, 0x0c, 0xcd, 0xfc, 0xe5, 0x76, 0x0b,
    ];

    let codec = Codec {
        id: 0,
        property: CodecProperty::Ignore,
    };

    let slice = codec_buffer.as_slice();
    let mut cur = ReadCursor::new(slice);
    assert_eq!(codec, decode_cursor(&mut cur).unwrap());
    assert!(cur.is_empty());
}

#[test]
fn ns_codec_with_too_high_color_loss_level_handled_correctly() {
    let codec_buffer = vec![
        0xb9, 0x1b, 0x8d, 0xca, 0x0f, 0x00, 0x4f, 0x15, 0x58, 0x9F, 0xAE, 0x2D, 0x1A, 0x87, 0xE2, 0xd6, // guid
        0x00, // codec id
        0x03, 0x00, // codec properties len
        0x01, // allow dynamic fidelity
        0x01, // allow subsampling
        0xff, // color loss level
    ];

    let codec = Codec {
        id: 0,
        property: CodecProperty::NsCodec(NsCodec {
            is_dynamic_fidelity_allowed: true,
            is_subsampling_allowed: true,
            color_loss_level: 7,
        }),
    };

    assert_eq!(codec, decode(codec_buffer.as_slice()).unwrap());
}

#[test]
fn ns_codec_with_too_low_color_loss_level_handled_correctly() {
    let codec_buffer = vec![
        0xb9, 0x1b, 0x8d, 0xca, 0x0f, 0x00, 0x4f, 0x15, 0x58, 0x9F, 0xAE, 0x2D, 0x1A, 0x87, 0xE2, 0xd6, // guid
        0x00, // codec id
        0x03, 0x00, // codec properties len
        0x01, // allow dynamic fidelity
        0x01, // allow subsampling
        0x00, // color loss level
    ];

    let codec = Codec {
        id: 0,
        property: CodecProperty::NsCodec(NsCodec {
            is_dynamic_fidelity_allowed: true,
            is_subsampling_allowed: true,
            color_loss_level: 1,
        }),
    };

    assert_eq!(codec, decode(codec_buffer.as_slice()).unwrap());
}
