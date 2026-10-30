use bitflags::bitflags;
use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, cast_length, ensure_fixed_part_size,
    invalid_field_err,
};

pub const MONITOR_COUNT_SIZE: usize = 4;
pub const MONITOR_SIZE: usize = 20;
pub const MONITOR_FLAGS_SIZE: usize = 4;

const MONITOR_COUNT_MAX: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ClientMonitorData {
    pub monitors: Vec<Monitor>,
}

impl ClientMonitorData {
    const NAME: &'static str = "ClientMonitorData";

    const FIXED_PART_SIZE: usize = 4 /* flags */ + 4 /* count */;
}

impl Encode for ClientMonitorData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u32(0); // flags
        dst.write_u32(cast_length!("nMonitors", self.monitors.len())?);

        for monitor in self.monitors.iter().take(MONITOR_COUNT_MAX) {
            monitor.encode(dst)?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.monitors.len() * Monitor::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for ClientMonitorData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let _flags = src.read_u32(); // is unused
        let monitor_count = cast_length!("number of monitors", src.read_u32())?;

        if monitor_count > MONITOR_COUNT_MAX {
            return Err(invalid_field_err!("nMonitors", "too many monitors"));
        }

        let mut monitors = Vec::with_capacity(monitor_count);
        for _ in 0..monitor_count {
            monitors.push(Monitor::decode(src)?);
        }

        Ok(Self { monitors })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Monitor {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
    pub flags: MonitorFlags,
}

impl Monitor {
    const NAME: &'static str = "Monitor";

    const FIXED_PART_SIZE: usize = 4 /* left */ + 4 /* top */ + 4 /* right */ + 4 /* bottom */ + 4 /* flags */;
}

impl Encode for Monitor {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_i32(self.left);
        dst.write_i32(self.top);
        dst.write_i32(self.right);
        dst.write_i32(self.bottom);
        dst.write_u32(self.flags.bits());

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for Monitor {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let left = src.read_i32();
        let top = src.read_i32();
        let right = src.read_i32();
        let bottom = src.read_i32();
        let flags = MonitorFlags::from_bits(src.read_u32())
            .ok_or_else(|| invalid_field_err!("flags", "invalid monitor flags"))?;

        Ok(Self {
            left,
            top,
            right,
            bottom,
            flags,
        })
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct MonitorFlags: u32 {
        const PRIMARY = 1;
    }
}
