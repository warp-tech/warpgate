#[cfg(test)]
mod tests;

use bitflags::bitflags;
use ironrdp_core::{Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, ensure_fixed_part_size};

const ORDER_LENGTH: usize = 84;
const ORD_LEVEL_1_ORDERS: u16 = 1;
const SUPPORT_ARRAY_LEN: usize = 32;
const DESKTOP_SAVE_Y_GRAN_VAL: u16 = 20;

#[repr(u8)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum OrderSupportIndex {
    DstBlt = 0x00,
    PatBlt = 0x01,
    ScrBlt = 0x02,
    MemBlt = 0x03,
    Mem3Blt = 0x04,
    DrawnInEGrid = 0x07,
    LineTo = 0x08,
    MultiDrawnInEGrid = 0x09,
    SaveBitmap = 0x0B,
    MultiDstBlt = 0x0F,
    MultiPatBlt = 0x10,
    MultiScrBlt = 0x11,
    MultiOpaqueRect = 0x12,
    Fast = 0x13,
    PolygonSC = 0x14,
    PolygonCB = 0x15,
    Polyline = 0x16,
    FastGlyph = 0x18,
    EllipseSC = 0x19,
    EllipseCB = 0x1A,
    Index = 0x1B,
}

impl OrderSupportIndex {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u8(self) -> u8 {
        self as u8
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct OrderFlags: u16 {
        const NEGOTIATE_ORDER_SUPPORT = 0x0002;
        const ZERO_BOUNDS_DELTAS_SUPPORT = 0x0008;
        const COLOR_INDEX_SUPPORT = 0x0020;
        const SOLID_PATTERN_BRUSH_ONLY = 0x0040;
        const ORDER_FLAGS_EXTRA_FLAGS = 0x0080;

        const _ = !0;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct OrderSupportExFlags: u16 {
        const CACHE_BITMAP_REV3_SUPPORT = 2;
        const ALTSEC_FRAME_MARKER_SUPPORT = 4;

        const _ = !0;
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Order {
    order_flags: OrderFlags,
    order_support: [u8; SUPPORT_ARRAY_LEN],
    order_support_ex_flags: OrderSupportExFlags,
    desktop_save_size: u32,
    text_ansi_code_page: u16,
}

impl Order {
    const NAME: &'static str = "Order";

    const FIXED_PART_SIZE: usize = ORDER_LENGTH;

    pub fn new(
        order_flags: OrderFlags,
        order_support_ex_flags: OrderSupportExFlags,
        desktop_save_size: u32,
        text_ansi_code_page: u16,
    ) -> Self {
        Self {
            order_flags,
            order_support: [0; SUPPORT_ARRAY_LEN],
            order_support_ex_flags,
            desktop_save_size,
            text_ansi_code_page,
        }
    }

    pub fn set_support_flag(&mut self, flag: OrderSupportIndex, value: bool) {
        self.order_support[usize::from(flag.as_u8())] = u8::from(value)
    }

    pub fn get_support_flag(&mut self, flag: OrderSupportIndex) -> bool {
        self.order_support[usize::from(flag.as_u8())] == 1
    }
}

impl Encode for Order {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u128(0);

        dst.write_u32(0); // padding
        dst.write_u16(1); // desktopSaveXGranularity
        dst.write_u16(DESKTOP_SAVE_Y_GRAN_VAL);
        dst.write_u16(0); // padding
        dst.write_u16(ORD_LEVEL_1_ORDERS); // maximumOrderLevel
        dst.write_u16(0); // numberFonts
        dst.write_u16(self.order_flags.bits());
        dst.write_slice(&self.order_support);
        dst.write_u16(0); // textFlags
        dst.write_u16(self.order_support_ex_flags.bits());
        dst.write_u32(0); // padding
        dst.write_u32(self.desktop_save_size);
        dst.write_u16(0); // padding
        dst.write_u16(0); // padding
        dst.write_u16(self.text_ansi_code_page);
        dst.write_u16(0); // padding

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for Order {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let _terminal_descriptor = src.read_u128();
        let _padding = src.read_u32();
        let _desktop_save_x_granularity = src.read_u16();
        let _desktop_save_y_granularity = src.read_u16();
        let _padding = src.read_u16();
        let _max_order_level = src.read_u16();
        let _num_fonts = src.read_u16();

        let order_flags = OrderFlags::from_bits_retain(src.read_u16());
        let order_support = src.read_array();

        let _text_flags = src.read_u16();

        let order_support_ex_flags = OrderSupportExFlags::from_bits_retain(src.read_u16());

        let _padding = src.read_u32();
        let desktop_save_size = src.read_u32();
        let _padding = src.read_u16();
        let _padding = src.read_u16();
        let text_ansi_code_page = src.read_u16();
        let _padding = src.read_u16();

        Ok(Order {
            order_flags,
            order_support,
            order_support_ex_flags,
            desktop_save_size,
            text_ansi_code_page,
        })
    }
}
