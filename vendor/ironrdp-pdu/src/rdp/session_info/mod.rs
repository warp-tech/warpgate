use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, ensure_fixed_part_size, ensure_size,
    invalid_field_err, read_padding, write_padding,
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive as _;

#[cfg(test)]
mod tests;

mod logon_extended;
mod logon_info;

pub use self::logon_extended::{
    LogonErrorNotificationData, LogonErrorNotificationDataErrorCode, LogonErrorNotificationType, LogonErrorsInfo,
    LogonExFlags, LogonInfoExtended, ServerAutoReconnect,
};
pub use self::logon_info::{LogonInfo, LogonInfoVersion1, LogonInfoVersion2};

const INFO_TYPE_FIELD_SIZE: usize = 4;
const PLAIN_NOTIFY_PADDING_SIZE: usize = 576;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct SaveSessionInfoPdu {
    pub info_type: InfoType,
    pub info_data: InfoData,
}

impl SaveSessionInfoPdu {
    const NAME: &'static str = "SaveSessionInfoPdu";

    const FIXED_PART_SIZE: usize = INFO_TYPE_FIELD_SIZE;
}

impl Encode for SaveSessionInfoPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u32(self.info_type.as_u32());
        match self.info_data {
            InfoData::LogonInfoV1(ref info_v1) => {
                info_v1.encode(dst)?;
            }
            InfoData::LogonInfoV2(ref info_v2) => {
                info_v2.encode(dst)?;
            }
            InfoData::PlainNotify => {
                ensure_size!(in: dst, size: PLAIN_NOTIFY_PADDING_SIZE);
                write_padding!(dst, PLAIN_NOTIFY_PADDING_SIZE);
            }
            InfoData::LogonExtended(ref extended) => {
                extended.encode(dst)?;
            }
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        let info_data_size = match self.info_data {
            InfoData::LogonInfoV1(ref info_v1) => info_v1.size(),
            InfoData::LogonInfoV2(ref info_v2) => info_v2.size(),
            InfoData::PlainNotify => PLAIN_NOTIFY_PADDING_SIZE,
            InfoData::LogonExtended(ref extended) => extended.size(),
        };

        Self::FIXED_PART_SIZE + info_data_size
    }
}

impl<'de> Decode<'de> for SaveSessionInfoPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let info_type = InfoType::from_u32(src.read_u32())
            .ok_or_else(|| invalid_field_err!("infoType", "invalid save session info type"))?;

        let info_data = match info_type {
            InfoType::Logon => InfoData::LogonInfoV1(LogonInfoVersion1::decode(src)?),
            InfoType::LogonLong => InfoData::LogonInfoV2(LogonInfoVersion2::decode(src)?),
            InfoType::PlainNotify => {
                ensure_size!(in: src, size: PLAIN_NOTIFY_PADDING_SIZE);
                read_padding!(src, PLAIN_NOTIFY_PADDING_SIZE);

                InfoData::PlainNotify
            }
            InfoType::LogonExtended => InfoData::LogonExtended(LogonInfoExtended::decode(src)?),
        };

        Ok(Self { info_type, info_data })
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum InfoType {
    Logon = 0x0000_0000,
    LogonLong = 0x0000_0001,
    PlainNotify = 0x0000_0002,
    LogonExtended = 0x0000_0003,
}

impl InfoType {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u32(self) -> u32 {
        self as u32
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum InfoData {
    LogonInfoV1(LogonInfoVersion1),
    LogonInfoV2(LogonInfoVersion2),
    PlainNotify,
    LogonExtended(LogonInfoExtended),
}
