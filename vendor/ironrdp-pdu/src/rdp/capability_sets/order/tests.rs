use std::sync::LazyLock;

use ironrdp_core::{decode, encode_vec};

use super::*;

const ORDER_BUFFER: [u8; 84] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, // pad4octetsA
    0x01, 0x00, // desktopSaveXGranularity
    0x14, 0x00, // desktopSaveYGranularity
    0x00, 0x00, // pad2octetsA
    0x01, 0x00, // maximumOrderLevel
    0x00, 0x00, // numberFonts
    0x22, 0x00, // orderFlags
    0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, // orderSupport
    0x00, 0x00, // textFlags
    0x02, 0x00, // orderSupportExFlags
    0x00, 0x00, 0x00, 0x00, // pad4octetsB
    0x00, 0x84, 0x03, 0x00, // desktopSaveSize
    0x00, 0x00, // pad2octetsC
    0x00, 0x00, // pad2octetsD
    0x00, 0x00, // testANSICodePage
    0x00, 0x00, // pad2octetsE
];

static ORDER: LazyLock<Order> = LazyLock::new(|| Order {
    order_flags: OrderFlags::COLOR_INDEX_SUPPORT | OrderFlags::NEGOTIATE_ORDER_SUPPORT,
    order_support: {
        let mut array = [0u8; 32];

        array[usize::from(OrderSupportIndex::DstBlt.as_u8())] = 1;
        array[usize::from(OrderSupportIndex::PatBlt.as_u8())] = 1;
        array[usize::from(OrderSupportIndex::ScrBlt.as_u8())] = 1;
        array[usize::from(OrderSupportIndex::MemBlt.as_u8())] = 1;
        array[usize::from(OrderSupportIndex::Mem3Blt.as_u8())] = 1;
        array[usize::from(OrderSupportIndex::DrawnInEGrid.as_u8())] = 1;
        array[usize::from(OrderSupportIndex::LineTo.as_u8())] = 1;
        array[usize::from(OrderSupportIndex::MultiDrawnInEGrid.as_u8())] = 1;
        array[usize::from(OrderSupportIndex::SaveBitmap.as_u8())] = 1;
        array[usize::from(OrderSupportIndex::MultiDstBlt.as_u8())] = 1;
        array[usize::from(OrderSupportIndex::MultiPatBlt.as_u8())] = 1;
        array[usize::from(OrderSupportIndex::MultiScrBlt.as_u8())] = 1;
        array[usize::from(OrderSupportIndex::MultiOpaqueRect.as_u8())] = 1;
        array[usize::from(OrderSupportIndex::Fast.as_u8())] = 1;
        array[usize::from(OrderSupportIndex::PolygonSC.as_u8())] = 1;
        array[usize::from(OrderSupportIndex::PolygonCB.as_u8())] = 1;
        array[usize::from(OrderSupportIndex::Polyline.as_u8())] = 1;
        array[usize::from(OrderSupportIndex::FastGlyph.as_u8())] = 1;
        array[usize::from(OrderSupportIndex::EllipseSC.as_u8())] = 1;
        array[usize::from(OrderSupportIndex::EllipseCB.as_u8())] = 1;
        array[usize::from(OrderSupportIndex::Index.as_u8())] = 1;

        array
    },

    order_support_ex_flags: OrderSupportExFlags::CACHE_BITMAP_REV3_SUPPORT,
    desktop_save_size: 230_400,
    text_ansi_code_page: 0,
});

#[test]
fn from_buffer_correctly_parses_order_capset() {
    let buffer = ORDER_BUFFER.as_ref();

    assert_eq!(*ORDER, decode(buffer).unwrap());
}

#[test]
fn to_buffer_correctly_serializes_order_capset() {
    let capset = ORDER.clone();

    let buffer = encode_vec(&capset).unwrap();

    assert_eq!(buffer, ORDER_BUFFER.as_ref());
}

#[test]
fn buffer_length_is_correct_for_order_capset() {
    let correct_buffer_length = ORDER_BUFFER.len();

    assert_eq!(correct_buffer_length, ORDER.size());
}
