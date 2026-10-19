#[cfg(test)]
mod tests;

use std::fmt;

use bitflags::bitflags;
use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, ensure_fixed_part_size, invalid_field_err,
};

const GENERAL_LENGTH: usize = 20;
pub const PROTOCOL_VER: u16 = 0x0200;

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct MajorPlatformType(u16);

impl fmt::Debug for MajorPlatformType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::UNSPECIFIED => "UNSPECIFIED",
            Self::WINDOWS => "WINDOWS",
            Self::OS2 => "OS2",
            Self::MACINTOSH => "MACINTOSH",
            Self::UNIX => "UNIX",
            Self::IOS => "IOS",
            Self::OSX => "OSX",
            Self::ANDROID => "ANDROID",
            Self::CHROMEOS => "CHROMEOS",
            _ => "UNKNOWN",
        };

        write!(f, "MajorPlatformType(0x{:02X}-{name})", self.0)
    }
}

impl MajorPlatformType {
    pub const UNSPECIFIED: Self = Self(0);
    pub const WINDOWS: Self = Self(1);
    pub const OS2: Self = Self(2);
    pub const MACINTOSH: Self = Self(3);
    pub const UNIX: Self = Self(4);
    pub const IOS: Self = Self(5);
    pub const OSX: Self = Self(6);
    pub const ANDROID: Self = Self(7);
    pub const CHROMEOS: Self = Self(8);
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct MinorPlatformType(u16);

impl fmt::Debug for MinorPlatformType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::UNSPECIFIED => "UNSPECIFIED",
            Self::WINDOWS_31X => "WINDOWS_31X",
            Self::WINDOWS_95 => "WINDOWS_95",
            Self::WINDOWS_NT => "WINDOWS_NT",
            Self::OS2V21 => "OS2_V21",
            Self::POWER_PC => "POWER_PC",
            Self::MACINTOSH => "MACINTOSH",
            Self::NATIVE_XSERVER => "NATIVE_XSERVER",
            Self::PSEUDO_XSERVER => "PSEUDO_XSERVER",
            Self::WINDOWS_RT => "WINDOWS_RT",
            _ => "UNKNOWN",
        };

        write!(f, "MinorPlatformType(0x{:02X}-{name})", self.0)
    }
}

impl MinorPlatformType {
    pub const UNSPECIFIED: Self = Self(0);
    pub const WINDOWS_31X: Self = Self(1);
    pub const WINDOWS_95: Self = Self(2);
    pub const WINDOWS_NT: Self = Self(3);
    pub const OS2V21: Self = Self(4);
    pub const POWER_PC: Self = Self(5);
    pub const MACINTOSH: Self = Self(6);
    pub const NATIVE_XSERVER: Self = Self(7);
    pub const PSEUDO_XSERVER: Self = Self(8);
    pub const WINDOWS_RT: Self = Self(9);
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct GeneralExtraFlags: u16 {
        const FASTPATH_OUTPUT_SUPPORTED = 0x0001;
        const NO_BITMAP_COMPRESSION_HDR = 0x0400;
        const LONG_CREDENTIALS_SUPPORTED = 0x0004;
        const AUTORECONNECT_SUPPORTED = 0x0008;
        const ENC_SALTED_CHECKSUM = 0x0010;

        const _ = !0;
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct General {
    pub major_platform_type: MajorPlatformType,
    pub minor_platform_type: MinorPlatformType,
    pub protocol_version: u16,
    pub extra_flags: GeneralExtraFlags,
    pub refresh_rect_support: bool,
    pub suppress_output_support: bool,
}

impl General {
    const NAME: &'static str = "General";

    const FIXED_PART_SIZE: usize = GENERAL_LENGTH;
}

impl Default for General {
    fn default() -> Self {
        Self {
            major_platform_type: MajorPlatformType::UNSPECIFIED,
            minor_platform_type: MinorPlatformType::UNSPECIFIED,
            protocol_version: PROTOCOL_VER,
            extra_flags: GeneralExtraFlags::empty(),
            refresh_rect_support: Default::default(),
            suppress_output_support: Default::default(),
        }
    }
}

impl Encode for General {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(self.major_platform_type.0);
        dst.write_u16(self.minor_platform_type.0);
        dst.write_u16(PROTOCOL_VER);
        dst.write_u16(0); // padding
        dst.write_u16(0); // generalCompressionTypes
        dst.write_u16(self.extra_flags.bits());
        dst.write_u16(0); // updateCapabilityFlag
        dst.write_u16(0); // remoteUnshareFlag
        dst.write_u16(0); // generalCompressionLevel
        dst.write_u8(u8::from(self.refresh_rect_support));
        dst.write_u8(u8::from(self.suppress_output_support));

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for General {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let major_platform_type = MajorPlatformType(src.read_u16());
        let minor_platform_type = MinorPlatformType(src.read_u16());

        let protocol_version = src.read_u16();

        let _padding = src.read_u16();

        let compression_types = src.read_u16();
        if compression_types != 0 {
            return Err(invalid_field_err!("compressionTypes", "invalid compression types"));
        }

        let extra_flags = GeneralExtraFlags::from_bits_retain(src.read_u16());

        let update_cap_flags = src.read_u16();
        if update_cap_flags != 0 {
            return Err(invalid_field_err!("updateCapFlags", "invalid update cap flags"));
        }

        let remote_unshare_flag = src.read_u16();
        if remote_unshare_flag != 0 {
            return Err(invalid_field_err!("remoteUnshareFlags", "invalid remote unshare flag"));
        }

        let compression_level = src.read_u16();
        if compression_level != 0 {
            return Err(invalid_field_err!("compressionLevel", "invalid compression level"));
        }

        let refresh_rect_support = src.read_u8() != 0;
        let suppress_output_support = src.read_u8() != 0;

        Ok(General {
            major_platform_type,
            minor_platform_type,
            protocol_version,
            extra_flags,
            refresh_rect_support,
            suppress_output_support,
        })
    }
}
