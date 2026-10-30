use bitflags::bitflags;
use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, cast_length, ensure_fixed_part_size,
    ensure_size, invalid_field_err, read_padding,
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive as _;

const LOGON_EX_LENGTH_FIELD_SIZE: usize = 2;
const LOGON_EX_FLAGS_FIELD_SIZE: usize = 4;
const LOGON_EX_PADDING_SIZE: usize = 570;
const LOGON_EX_PADDING_BUFFER: [u8; LOGON_EX_PADDING_SIZE] = [0; LOGON_EX_PADDING_SIZE];

const LOGON_INFO_FIELD_DATA_SIZE: usize = 4;
const AUTO_RECONNECT_VERSION_1: u32 = 0x0000_0001;
const AUTO_RECONNECT_PACKET_SIZE: usize = 28;
const AUTO_RECONNECT_RANDOM_BITS_SIZE: usize = 16;
const LOGON_ERRORS_INFO_SIZE: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct LogonInfoExtended {
    pub present_fields_flags: LogonExFlags,
    pub auto_reconnect: Option<ServerAutoReconnect>,
    pub errors_info: Option<LogonErrorsInfo>,
}

impl LogonInfoExtended {
    const NAME: &'static str = "LogonInfoExtended";

    const FIXED_PART_SIZE: usize = LOGON_EX_LENGTH_FIELD_SIZE + LOGON_EX_FLAGS_FIELD_SIZE;

    fn get_internal_size(&self) -> usize {
        let reconnect_size = self.auto_reconnect.as_ref().map(|r| r.size()).unwrap_or(0);

        let errors_size = self.errors_info.as_ref().map(|r| r.size()).unwrap_or(0);

        Self::FIXED_PART_SIZE + reconnect_size + errors_size
    }
}

impl Encode for LogonInfoExtended {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u16(cast_length!("internalSize", self.get_internal_size())?);
        dst.write_u32(self.present_fields_flags.bits());

        if let Some(ref reconnect) = self.auto_reconnect {
            reconnect.encode(dst)?;
        }
        if let Some(ref errors) = self.errors_info {
            errors.encode(dst)?;
        }

        dst.write_slice(LOGON_EX_PADDING_BUFFER.as_ref());

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        self.get_internal_size() + LOGON_EX_PADDING_SIZE
    }
}

impl<'de> Decode<'de> for LogonInfoExtended {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let _self_length = src.read_u16();
        let present_fields_flags = LogonExFlags::from_bits_retain(src.read_u32());

        let auto_reconnect = if present_fields_flags.contains(LogonExFlags::AUTO_RECONNECT_COOKIE) {
            Some(ServerAutoReconnect::decode(src)?)
        } else {
            None
        };

        let errors_info = if present_fields_flags.contains(LogonExFlags::LOGON_ERRORS) {
            Some(LogonErrorsInfo::decode(src)?)
        } else {
            None
        };

        ensure_size!(in: src, size: LOGON_EX_PADDING_SIZE);
        read_padding!(src, LOGON_EX_PADDING_SIZE);

        Ok(Self {
            present_fields_flags,
            auto_reconnect,
            errors_info,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ServerAutoReconnect {
    pub logon_id: u32,
    pub random_bits: [u8; AUTO_RECONNECT_RANDOM_BITS_SIZE],
}

impl ServerAutoReconnect {
    const NAME: &'static str = "ServerAutoReconnect";

    const FIXED_PART_SIZE: usize = AUTO_RECONNECT_PACKET_SIZE + LOGON_INFO_FIELD_DATA_SIZE;
}

impl Encode for ServerAutoReconnect {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u32(u32::try_from(AUTO_RECONNECT_PACKET_SIZE).expect("AUTO_RECONNECT_PACKET_SIZE fits into u32"));
        dst.write_u32(u32::try_from(AUTO_RECONNECT_PACKET_SIZE).expect("AUTO_RECONNECT_PACKET_SIZE fits into u32"));
        dst.write_u32(AUTO_RECONNECT_VERSION_1);
        dst.write_u32(self.logon_id);
        dst.write_slice(self.random_bits.as_ref());

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for ServerAutoReconnect {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let _data_length = src.read_u32();
        let packet_length = src.read_u32();
        if packet_length != u32::try_from(AUTO_RECONNECT_PACKET_SIZE).expect("AUTO_RECONNECT_PACKET_SIZE fits into u32")
        {
            return Err(invalid_field_err!("packetLen", "invalid auto-reconnect packet size"));
        }

        let version = src.read_u32();
        if version != AUTO_RECONNECT_VERSION_1 {
            return Err(invalid_field_err!("version", "invalid auto-reconnect version"));
        }

        let logon_id = src.read_u32();
        let random_bits = src.read_array();

        Ok(Self { logon_id, random_bits })
    }
}

/// TS_LOGON_ERRORS_INFO
///
/// [Doc](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/845eb789-6edf-453a-8b0e-c976823d1f72)
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct LogonErrorsInfo {
    pub error_type: LogonErrorNotificationType,
    pub error_data: LogonErrorNotificationData,
}

impl LogonErrorsInfo {
    const NAME: &'static str = "LogonErrorsInfo";

    const FIXED_PART_SIZE: usize = LOGON_ERRORS_INFO_SIZE + LOGON_INFO_FIELD_DATA_SIZE;
}

impl Encode for LogonErrorsInfo {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u32(u32::try_from(LOGON_ERRORS_INFO_SIZE).expect("LOGON_ERRORS_INFO_SIZE fits into u32"));
        dst.write_u32(self.error_type.as_u32());
        dst.write_u32(self.error_data.to_u32());

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for LogonErrorsInfo {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let _data_length = src.read_u32();
        let error_type = LogonErrorNotificationType::from_u32(src.read_u32())
            .ok_or_else(|| invalid_field_err!("errorType", "invalid logon error type"))?;

        let error_notification_data = src.read_u32();
        let error_data = LogonErrorNotificationDataErrorCode::from_u32(error_notification_data)
            .map(LogonErrorNotificationData::ErrorCode)
            .unwrap_or(LogonErrorNotificationData::SessionId(error_notification_data));

        Ok(Self { error_type, error_data })
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct LogonExFlags: u32 {
        const AUTO_RECONNECT_COOKIE = 0x0000_0001;
        const LOGON_ERRORS = 0x0000_0002;

        const _ = !0;
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum LogonErrorNotificationType {
    SessionBusyOptions = 0xFFFF_FFF8,
    DisconnectRefused = 0xFFFF_FFF9,
    NoPermission = 0xFFFF_FFFA,
    BumpOptions = 0xFFFF_FFFB,
    ReconnectOptions = 0xFFFF_FFFC,
    SessionTerminate = 0xFFFF_FFFD,
    SessionContinue = 0xFFFF_FFFE,
    AccessDenied = 0xFFFF_FFFF,
}

impl LogonErrorNotificationType {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u32(self) -> u32 {
        self as u32
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum LogonErrorNotificationDataErrorCode {
    FailedBadPassword = 0x0000_0000,
    FailedUpdatePassword = 0x0000_0001,
    FailedOther = 0x0000_0002,
    Warning = 0x0000_0003,
}

impl LogonErrorNotificationDataErrorCode {
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
pub enum LogonErrorNotificationData {
    ErrorCode(LogonErrorNotificationDataErrorCode),
    SessionId(u32),
}

impl LogonErrorNotificationData {
    pub fn to_u32(&self) -> u32 {
        match self {
            LogonErrorNotificationData::ErrorCode(code) => code.as_u32(),
            LogonErrorNotificationData::SessionId(id) => *id,
        }
    }
}
