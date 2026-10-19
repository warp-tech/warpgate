use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, cast_length, ensure_fixed_part_size,
    ensure_size, invalid_field_err,
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive as _;

const MONITOR_COUNT_MAX: usize = 16;
const MONITOR_ATTRIBUTE_SIZE: u32 = 20;

const FLAGS_SIZE: usize = 4;
const MONITOR_ATTRIBUTE_SIZE_FIELD_SIZE: usize = 4;
const MONITOR_COUNT: usize = 4;
const MONITOR_SIZE: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ClientMonitorExtendedData {
    pub extended_monitors_info: Vec<ExtendedMonitorInfo>,
}

impl ClientMonitorExtendedData {
    const NAME: &'static str = "ClientMonitorExtendedData";

    const FIXED_PART_SIZE: usize = FLAGS_SIZE + MONITOR_ATTRIBUTE_SIZE_FIELD_SIZE + MONITOR_COUNT;
}

impl Encode for ClientMonitorExtendedData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u32(0); // flags
        dst.write_u32(MONITOR_ATTRIBUTE_SIZE); // flags
        dst.write_u32(cast_length!("nMonitors", self.extended_monitors_info.len())?);

        for extended_monitor_info in self.extended_monitors_info.iter().take(MONITOR_COUNT_MAX) {
            extended_monitor_info.encode(dst)?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.extended_monitors_info.len() * MONITOR_SIZE
    }
}

impl<'de> Decode<'de> for ClientMonitorExtendedData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let _flags = src.read_u32(); // is unused

        let monitor_attribute_size = src.read_u32();
        if monitor_attribute_size != MONITOR_ATTRIBUTE_SIZE {
            return Err(invalid_field_err!("monitorAttributeSize", "invalid size"));
        }

        let monitor_count = cast_length!("monitorCount", src.read_u32())?;

        if monitor_count > MONITOR_COUNT_MAX {
            return Err(invalid_field_err!("monitorCount", "invalid monitor count"));
        }

        let mut extended_monitors_info = Vec::with_capacity(monitor_count);
        for _ in 0..monitor_count {
            extended_monitors_info.push(ExtendedMonitorInfo::decode(src)?);
        }

        Ok(Self { extended_monitors_info })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ExtendedMonitorInfo {
    pub physical_width: u32,
    pub physical_height: u32,
    pub orientation: MonitorOrientation,
    pub desktop_scale_factor: u32,
    pub device_scale_factor: u32,
}

impl ExtendedMonitorInfo {
    const NAME: &'static str = "ExtendedMonitorInfo";

    const FIXED_PART_SIZE: usize = MONITOR_SIZE;
}

impl Encode for ExtendedMonitorInfo {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u32(self.physical_width);
        dst.write_u32(self.physical_height);
        dst.write_u32(u32::from(self.orientation.as_u16()));
        dst.write_u32(self.desktop_scale_factor);
        dst.write_u32(self.device_scale_factor);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for ExtendedMonitorInfo {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let physical_width = src.read_u32();
        let physical_height = src.read_u32();
        let orientation = MonitorOrientation::from_u32(src.read_u32())
            .ok_or_else(|| invalid_field_err!("orientation", "invalid monitor orientation"))?;
        let desktop_scale_factor = src.read_u32();
        let device_scale_factor = src.read_u32();

        Ok(Self {
            physical_width,
            physical_height,
            orientation,
            desktop_scale_factor,
            device_scale_factor,
        })
    }
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum MonitorOrientation {
    Landscape = 0,
    Portrait = 90,
    LandscapeFlipped = 180,
    PortraitFlipped = 270,
}

impl MonitorOrientation {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    pub fn as_u16(self) -> u16 {
        self as u16
    }
}
