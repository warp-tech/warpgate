use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, cast_length, ensure_fixed_part_size,
    ensure_size, invalid_field_err, read_padding, write_padding,
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive as _;

pub mod fast_path;
pub mod mouse;
pub mod mouse_rel;
pub mod mouse_x;
pub mod scan_code;
pub mod sync;
pub mod unicode;
pub mod unused;

pub use self::mouse::MousePdu;
pub use self::mouse_rel::MouseRelPdu;
pub use self::mouse_x::MouseXPdu;
pub use self::scan_code::ScanCodePdu;
pub use self::sync::SyncPdu;
pub use self::unicode::UnicodePdu;
pub use self::unused::UnusedPdu;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct InputEventPdu(pub Vec<InputEvent>);

impl InputEventPdu {
    const NAME: &'static str = "InputEventPdu";

    const FIXED_PART_SIZE: usize = 4 /* nEvents */;
}

impl Encode for InputEventPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u16(cast_length!("input events count", self.0.len())?);
        write_padding!(dst, 2);

        for event in self.0.iter() {
            event.encode(dst)?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        4 + self.0.iter().map(Encode::size).sum::<usize>()
    }
}

impl<'de> Decode<'de> for InputEventPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let number_of_events = usize::from(src.read_u16());
        read_padding!(src, 2);

        let events = core::iter::repeat_with(|| InputEvent::decode(src))
            .take(number_of_events)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self(events))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum InputEvent {
    Sync(SyncPdu),
    Unused(UnusedPdu),
    ScanCode(ScanCodePdu),
    Unicode(UnicodePdu),
    Mouse(MousePdu),
    MouseX(MouseXPdu),
    MouseRel(MouseRelPdu),
}

impl InputEvent {
    const NAME: &'static str = "InputEvent";

    const FIXED_PART_SIZE: usize = 4 /* eventTime */ + 2 /* eventType */;
}

impl Encode for InputEvent {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u32(0); // event time is ignored by a server
        dst.write_u16(InputEventType::from(self).as_u16());

        match self {
            Self::Sync(pdu) => pdu.encode(dst),
            Self::Unused(pdu) => pdu.encode(dst),
            Self::ScanCode(pdu) => pdu.encode(dst),
            Self::Unicode(pdu) => pdu.encode(dst),
            Self::Mouse(pdu) => pdu.encode(dst),
            Self::MouseX(pdu) => pdu.encode(dst),
            Self::MouseRel(pdu) => pdu.encode(dst),
        }
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
            + match self {
                Self::Sync(pdu) => pdu.size(),
                Self::Unused(pdu) => pdu.size(),
                Self::ScanCode(pdu) => pdu.size(),
                Self::Unicode(pdu) => pdu.size(),
                Self::Mouse(pdu) => pdu.size(),
                Self::MouseX(pdu) => pdu.size(),
                Self::MouseRel(pdu) => pdu.size(),
            }
    }
}

impl<'de> Decode<'de> for InputEvent {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let _event_time = src.read_u32(); // ignored by a server
        let event_type = src.read_u16();
        let event_type = InputEventType::from_u16(event_type)
            .ok_or_else(|| invalid_field_err!("eventType", "invalid input event type"))?;

        match event_type {
            InputEventType::Sync => Ok(Self::Sync(SyncPdu::decode(src)?)),
            InputEventType::Unused => Ok(Self::Unused(UnusedPdu::decode(src)?)),
            InputEventType::ScanCode => Ok(Self::ScanCode(ScanCodePdu::decode(src)?)),
            InputEventType::Unicode => Ok(Self::Unicode(UnicodePdu::decode(src)?)),
            InputEventType::Mouse => Ok(Self::Mouse(MousePdu::decode(src)?)),
            InputEventType::MouseX => Ok(Self::MouseX(MouseXPdu::decode(src)?)),
            InputEventType::MouseRel => Ok(Self::MouseRel(MouseRelPdu::decode(src)?)),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, FromPrimitive)]
#[repr(u16)]
enum InputEventType {
    Sync = 0x0000,
    Unused = 0x0002,
    ScanCode = 0x0004,
    Unicode = 0x0005,
    Mouse = 0x8001,
    MouseX = 0x8002,
    MouseRel = 0x8004,
}

impl InputEventType {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u16(self) -> u16 {
        self as u16
    }
}

impl From<&InputEvent> for InputEventType {
    fn from(event: &InputEvent) -> Self {
        match event {
            InputEvent::Sync(_) => Self::Sync,
            InputEvent::Unused(_) => Self::Unused,
            InputEvent::ScanCode(_) => Self::ScanCode,
            InputEvent::Unicode(_) => Self::Unicode,
            InputEvent::Mouse(_) => Self::Mouse,
            InputEvent::MouseX(_) => Self::MouseX,
            InputEvent::MouseRel(_) => Self::MouseRel,
        }
    }
}
