use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, cast_length, ensure_fixed_part_size,
    ensure_size, invalid_field_err, read_padding, write_padding,
};

use crate::utils;

const DOMAIN_NAME_SIZE_FIELD_SIZE: usize = 4;
const DOMAIN_NAME_SIZE_V1: usize = 52;
const USER_NAME_SIZE_FIELD_SIZE: usize = 4;
const USER_NAME_SIZE_V1: usize = 512;
const ID_SESSION_SIZE: usize = 4;

const SAVE_SESSION_PDU_VERSION_ONE: u16 = 0x0001;
const LOGON_INFO_V2_SIZE: usize = 18;
const LOGON_INFO_V2_PADDING_SIZE: usize = 558;
const DOMAIN_NAME_SIZE_V2: usize = 52;
const USER_NAME_SIZE_V2: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct LogonInfoVersion1 {
    pub logon_info: LogonInfo,
}

impl LogonInfoVersion1 {
    const NAME: &'static str = "LogonInfoVersion1";

    const FIXED_PART_SIZE: usize = DOMAIN_NAME_SIZE_FIELD_SIZE
        + DOMAIN_NAME_SIZE_V1
        + USER_NAME_SIZE_FIELD_SIZE
        + USER_NAME_SIZE_V1
        + ID_SESSION_SIZE;
}

impl Encode for LogonInfoVersion1 {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        let mut domain_name_buffer = utils::to_utf16_bytes(self.logon_info.domain_name.as_ref());
        domain_name_buffer.resize(DOMAIN_NAME_SIZE_V1 - 2, 0);
        let mut user_name_buffer = utils::to_utf16_bytes(self.logon_info.user_name.as_ref());
        user_name_buffer.resize(USER_NAME_SIZE_V1 - 2, 0);

        dst.write_u32(cast_length!(
            "domainNameSize",
            (self.logon_info.domain_name.len() + 1) * 2
        )?);
        dst.write_slice(domain_name_buffer.as_ref());
        dst.write_u16(0); // UTF-16 null terminator
        dst.write_u32(cast_length!("userNameSize", (self.logon_info.user_name.len() + 1) * 2)?);
        dst.write_slice(user_name_buffer.as_ref());
        dst.write_u16(0); // UTF-16 null terminator
        dst.write_u32(self.logon_info.session_id);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for LogonInfoVersion1 {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let domain_name_size: usize = cast_length!("domainNameSize", src.read_u32())?;
        if domain_name_size > DOMAIN_NAME_SIZE_V1 {
            return Err(invalid_field_err!("domainNameSize", "invalid domain name size"));
        }

        let domain_name =
            utils::decode_string(src.read_slice(DOMAIN_NAME_SIZE_V1), utils::CharacterSet::Unicode, false)?;

        let user_name_size: usize = cast_length!("userNameSize", src.read_u32())?;
        if user_name_size > USER_NAME_SIZE_V1 {
            return Err(invalid_field_err!("userNameSize", "invalid user name size"));
        }

        let user_name = utils::decode_string(src.read_slice(USER_NAME_SIZE_V1), utils::CharacterSet::Unicode, false)?;

        let session_id = src.read_u32();

        Ok(Self {
            logon_info: LogonInfo {
                session_id,
                domain_name,
                user_name,
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct LogonInfoVersion2 {
    pub logon_info: LogonInfo,
}

impl LogonInfoVersion2 {
    const NAME: &'static str = "LogonInfoVersion2";

    const FIXED_PART_SIZE: usize = LOGON_INFO_V2_SIZE + LOGON_INFO_V2_PADDING_SIZE;
}

impl Encode for LogonInfoVersion2 {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u16(SAVE_SESSION_PDU_VERSION_ONE);
        dst.write_u32(u32::try_from(LOGON_INFO_V2_SIZE).expect("LOGON_INFO_V2_SIZE fits into u32"));
        dst.write_u32(self.logon_info.session_id);
        dst.write_u32(cast_length!(
            "domainNameSize",
            (self.logon_info.domain_name.len() + 1) * 2
        )?);
        dst.write_u32(cast_length!("userNameSize", (self.logon_info.user_name.len() + 1) * 2)?);
        write_padding!(dst, LOGON_INFO_V2_PADDING_SIZE);

        utils::write_string_to_cursor(
            dst,
            self.logon_info.domain_name.as_ref(),
            utils::CharacterSet::Unicode,
            true,
        )?;
        utils::write_string_to_cursor(
            dst,
            self.logon_info.user_name.as_ref(),
            utils::CharacterSet::Unicode,
            true,
        )?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + (self.logon_info.domain_name.len() + 1) * 2 + (self.logon_info.user_name.len() + 1) * 2
    }
}

impl<'de> Decode<'de> for LogonInfoVersion2 {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let version = src.read_u16();
        if version != SAVE_SESSION_PDU_VERSION_ONE {
            return Err(invalid_field_err!("version", "invalid logon version 2"));
        }

        let size: usize = cast_length!("LogonInfoSize", src.read_u32())?;
        if size != LOGON_INFO_V2_SIZE {
            return Err(invalid_field_err!("domainNameSize", "invalid logon info size"));
        }

        let session_id = src.read_u32();
        let domain_name_size: usize = cast_length!("domainNameSize", src.read_u32())?;
        if domain_name_size > DOMAIN_NAME_SIZE_V2 {
            return Err(invalid_field_err!("domainNameSize", "invalid domain name size"));
        }

        let user_name_size: usize = cast_length!("userNameSize", src.read_u32())?;
        if user_name_size > USER_NAME_SIZE_V2 {
            return Err(invalid_field_err!("userNameSize", "invalid user name size"));
        }

        read_padding!(src, LOGON_INFO_V2_PADDING_SIZE);

        ensure_size!(in: src, size: domain_name_size);
        let domain_name = utils::decode_string(src.read_slice(domain_name_size), utils::CharacterSet::Unicode, false)?;

        ensure_size!(in: src, size: user_name_size);
        let user_name = utils::decode_string(src.read_slice(user_name_size), utils::CharacterSet::Unicode, false)?;

        Ok(Self {
            logon_info: LogonInfo {
                session_id,
                domain_name,
                user_name,
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct LogonInfo {
    pub session_id: u32,
    pub user_name: String,
    pub domain_name: String,
}
