// Slow-path graphics and pointer update parsing.
//
// Slow-path updates arrive inside ShareDataPdu::Update (graphics) and
// ShareDataPdu::Pointer, wrapped with a small framing header that differs
// from the fast-path encoding. The inner payload structures are identical
// to their fast-path counterparts.
//
// References:
//   [MS-RDPBCGR] 2.2.9.1.1.3   — Slow-Path Graphics Update
//   [MS-RDPBCGR] 2.2.9.1.1.4   — Slow-Path Pointer Update

use ironrdp_core::{Decode as _, DecodeResult, ReadCursor, ensure_size, invalid_field_err};

use super::bitmap::{BitmapData, BitmapUpdateData};
use super::pointer::{
    CachedPointerAttribute, ColorPointerAttribute, LargePointerAttribute, PointerAttribute, PointerPositionAttribute,
    PointerUpdateData,
};

// --- Graphics updates ([MS-RDPBCGR] 2.2.9.1.1.3.1) ---

/// `updateType` field in TS_UPDATE_HDR for slow-path graphics updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u16)]
pub enum GraphicsUpdateType {
    Orders = 0x0000,
    Bitmap = 0x0001,
    Palette = 0x0002,
    Synchronize = 0x0003,
}

/// Read the `updateType` u16 from the front of a slow-path graphics update.
pub fn read_graphics_update_type(src: &mut ReadCursor<'_>) -> DecodeResult<GraphicsUpdateType> {
    ensure_size!(in: src, size: 2);
    let raw = src.read_u16();
    match raw {
        0x0000 => Ok(GraphicsUpdateType::Orders),
        0x0001 => Ok(GraphicsUpdateType::Bitmap),
        0x0002 => Ok(GraphicsUpdateType::Palette),
        0x0003 => Ok(GraphicsUpdateType::Synchronize),
        _ => Err(invalid_field_err!(
            "updateType",
            "unknown slow-path graphics update type"
        )),
    }
}

/// Decode a slow-path bitmap update.
///
/// The cursor must be positioned right after the `updateType` field
/// (i.e. already consumed by [`read_graphics_update_type`]).
pub fn decode_slow_path_bitmap<'a>(src: &mut ReadCursor<'a>) -> DecodeResult<BitmapUpdateData<'a>> {
    // Read numberRectangles directly; updateType was already consumed by the dispatcher.
    ensure_size!(in: src, size: 2);
    let rectangle_count = usize::from(src.read_u16());
    let mut rectangles = Vec::with_capacity(rectangle_count);
    for _ in 0..rectangle_count {
        rectangles.push(BitmapData::decode(src)?);
    }
    Ok(BitmapUpdateData { rectangles })
}

// --- Pointer updates ([MS-RDPBCGR] 2.2.9.1.1.4) ---

/// `messageType` values for slow-path pointer updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u16)]
pub enum PointerMessageType {
    System = 0x0001,
    Position = 0x0003,
    Color = 0x0006,
    Cached = 0x0007,
    /// TS_POINTERATTRIBUTE (new pointer with xor_bpp)
    Pointer = 0x0008,
    Large = 0x0009,
}

/// `systemPointerType` values used when `messageType == System`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u32)]
pub enum SystemPointerType {
    /// SYSPTR_NULL — hide the pointer
    Null = 0x0000_0000,
    /// SYSPTR_DEFAULT — show the OS default pointer
    Default = 0x0000_7F00,
}

/// Decode a complete slow-path pointer update from its raw payload.
///
/// The payload starts with `messageType(u16)` + `pad2Octets(u16)`,
/// followed by the type-specific data.
pub fn decode_slow_path_pointer<'a>(src: &mut ReadCursor<'a>) -> DecodeResult<PointerUpdateData<'a>> {
    ensure_size!(in: src, size: 4);
    let message_type = src.read_u16();
    let _pad = src.read_u16();

    match message_type {
        0x0001 => {
            // System pointer: the body is a single u32 indicating which system pointer.
            ensure_size!(in: src, size: 4);
            let system_type = src.read_u32();
            match system_type {
                0x0000_0000 => Ok(PointerUpdateData::SetHidden),
                0x0000_7F00 => Ok(PointerUpdateData::SetDefault),
                _ => Err(invalid_field_err!("systemPointerType", "unknown system pointer type")),
            }
        }
        0x0003 => {
            let pos = PointerPositionAttribute::decode(src)?;
            Ok(PointerUpdateData::SetPosition(pos))
        }
        0x0006 => {
            let color = ColorPointerAttribute::decode(src)?;
            Ok(PointerUpdateData::Color(color))
        }
        0x0007 => {
            let cached = CachedPointerAttribute::decode(src)?;
            Ok(PointerUpdateData::Cached(cached))
        }
        0x0008 => {
            let attr = PointerAttribute::decode(src)?;
            Ok(PointerUpdateData::New(attr))
        }
        0x0009 => {
            let large = LargePointerAttribute::decode(src)?;
            Ok(PointerUpdateData::Large(large))
        }
        _ => Err(invalid_field_err!(
            "messageType",
            "unknown slow-path pointer message type"
        )),
    }
}
