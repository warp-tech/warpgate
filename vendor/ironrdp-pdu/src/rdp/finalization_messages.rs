use bitflags::bitflags;
use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, cast_length, ensure_fixed_part_size,
    invalid_field_err,
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive as _;

use crate::gcc;

const SYNCHRONIZE_PDU_SIZE: usize = 2 + 2;
const CONTROL_PDU_SIZE: usize = 2 + 2 + 4;
const FONT_PDU_SIZE: usize = 2 * 4;
const SYNCHRONIZE_MESSAGE_TYPE: u16 = 1;
const MAX_MONITOR_COUNT: u32 = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct SynchronizePdu {
    pub target_user_id: u16,
}

impl SynchronizePdu {
    const NAME: &'static str = "SynchronizePdu";

    const FIXED_PART_SIZE: usize = SYNCHRONIZE_PDU_SIZE;
}

impl Encode for SynchronizePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(SYNCHRONIZE_MESSAGE_TYPE);
        dst.write_u16(self.target_user_id);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        SYNCHRONIZE_PDU_SIZE
    }
}

impl<'de> Decode<'de> for SynchronizePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let message_type = src.read_u16();
        if message_type != SYNCHRONIZE_MESSAGE_TYPE {
            return Err(invalid_field_err!("messageType", "invalid message type"));
        }

        let target_user_id = src.read_u16();

        Ok(Self { target_user_id })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ControlPdu {
    pub action: ControlAction,
    pub grant_id: u16,
    pub control_id: u32,
}

impl ControlPdu {
    const NAME: &'static str = "ControlPdu";

    const FIXED_PART_SIZE: usize = CONTROL_PDU_SIZE;
}

impl Encode for ControlPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(self.action.as_u16());
        dst.write_u16(self.grant_id);
        dst.write_u32(self.control_id);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for ControlPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let action = ControlAction::from_u16(src.read_u16())
            .ok_or_else(|| invalid_field_err!("action", "invalid control action"))?;
        let grant_id = src.read_u16();
        let control_id = src.read_u32();

        Ok(Self {
            action,
            grant_id,
            control_id,
        })
    }
}

/// [2.2.1.22.1] Font Map PDU Data (TS_FONT_MAP_PDU)
///
/// [2.2.1.22.1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b4e557f3-7540-46fc-815d-0c12299cf1ee
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct FontPdu {
    pub number: u16,
    pub total_number: u16,
    pub flags: SequenceFlags,
    pub entry_size: u16,
}

impl Default for FontPdu {
    fn default() -> Self {
        // Those values are recommended in [2.2.1.22.1].
        Self {
            number: 0,
            total_number: 0,
            flags: SequenceFlags::FIRST | SequenceFlags::LAST,
            entry_size: 4,
        }
    }
}

impl FontPdu {
    const NAME: &'static str = "FontPdu";

    const FIXED_PART_SIZE: usize = FONT_PDU_SIZE;
}

impl Encode for FontPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(self.number);
        dst.write_u16(self.total_number);
        dst.write_u16(self.flags.bits());
        dst.write_u16(self.entry_size);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for FontPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let number = src.read_u16();
        let total_number = src.read_u16();
        let flags = SequenceFlags::from_bits(src.read_u16())
            .ok_or_else(|| invalid_field_err!("flags", "invalid sequence flags"))?;
        let entry_size = src.read_u16();

        Ok(Self {
            number,
            total_number,
            flags,
            entry_size,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct MonitorLayoutPdu {
    pub monitors: Vec<gcc::Monitor>,
}

impl MonitorLayoutPdu {
    const NAME: &'static str = "MonitorLayoutPdu";

    const FIXED_PART_SIZE: usize = 4 /* nMonitors */;
}

impl Encode for MonitorLayoutPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u32(cast_length!("nMonitors", self.monitors.len())?);

        for monitor in self.monitors.iter() {
            monitor.encode(dst)?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.monitors.len() * gcc::MONITOR_SIZE
    }
}

impl<'de> Decode<'de> for MonitorLayoutPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let monitor_count = src.read_u32();
        if monitor_count > MAX_MONITOR_COUNT {
            return Err(invalid_field_err!("nMonitors", "invalid monitor count"));
        }

        let mut monitors = Vec::with_capacity(
            usize::try_from(monitor_count)
                .expect("monitor_count is guaranteed to fit into usize due to the prior check"),
        );
        for _ in 0..monitor_count {
            monitors.push(gcc::Monitor::decode(src)?);
        }

        Ok(Self { monitors })
    }
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum ControlAction {
    RequestControl = 1,
    GrantedControl = 2,
    Detach = 3,
    Cooperate = 4,
}

impl ControlAction {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u16(self) -> u16 {
        self as u16
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct SequenceFlags: u16 {
        const FIRST = 1;
        const LAST = 2;
    }
}
