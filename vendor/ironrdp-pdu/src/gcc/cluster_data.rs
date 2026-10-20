use bitflags::bitflags;
use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, ensure_fixed_part_size, invalid_field_err,
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive as _;

const REDIRECTION_VERSION_MASK: u32 = 0x0000_003C;

const FLAGS_SIZE: usize = 4;
const REDIRECTED_SESSION_ID_SIZE: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ClientClusterData {
    pub flags: RedirectionFlags,
    pub redirection_version: RedirectionVersion,
    pub redirected_session_id: u32,
}

impl ClientClusterData {
    const NAME: &'static str = "ClientClusterData";

    const FIXED_PART_SIZE: usize = FLAGS_SIZE + REDIRECTED_SESSION_ID_SIZE;
}

impl Encode for ClientClusterData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        let flags_with_version = self.flags.bits() | (self.redirection_version.as_u32() << 2);

        dst.write_u32(flags_with_version);
        dst.write_u32(self.redirected_session_id);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for ClientClusterData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let flags_with_version = src.read_u32();
        let redirected_session_id = src.read_u32();

        let flags = RedirectionFlags::from_bits(flags_with_version & !REDIRECTION_VERSION_MASK)
            .ok_or_else(|| invalid_field_err!("flags", "invalid redirection flags"))?;
        let redirection_version = RedirectionVersion::from_u32((flags_with_version & REDIRECTION_VERSION_MASK) >> 2)
            .ok_or_else(|| invalid_field_err!("redirVersion", "invalid redirection version"))?;

        Ok(Self {
            flags,
            redirection_version,
            redirected_session_id,
        })
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct RedirectionFlags: u32 {
        const REDIRECTION_SUPPORTED = 0x0000_0001;
        const REDIRECTED_SESSION_FIELD_VALID = 0x0000_0002;
        const REDIRECTED_SMARTCARD = 0x0000_0040;
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum RedirectionVersion {
    V1 = 0,
    V2 = 1,
    V3 = 2,
    V4 = 3,
    V5 = 4,
    V6 = 5,
}

impl RedirectionVersion {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u32(self) -> u32 {
        self as u32
    }
}
