#[cfg(test)]
mod test;

use ironrdp_core::{
    Decode as _, DecodeResult, Encode as _, EncodeResult, ReadCursor, WriteCursor, cast_length, ensure_fixed_part_size,
    ensure_size, invalid_field_err,
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive as _;

use super::{BLOB_LENGTH_SIZE, BLOB_TYPE_SIZE, BlobHeader, BlobType, LicenseHeader, PreambleFlags, PreambleVersion};
use crate::rdp::headers::{BASIC_SECURITY_HEADER_SIZE, BasicSecurityHeader, BasicSecurityHeaderFlags};
use crate::rdp::server_license::PreambleType;

const ERROR_CODE_SIZE: usize = 4;
const STATE_TRANSITION_SIZE: usize = 4;

/// [2.2.1.12.1.3] Licensing Error Message (LICENSE_ERROR_MESSAGE)
///
/// [2.2.1.12.1.3]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f18b6c9f-f3d8-4a0e-8398-f9b153233dca
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct LicensingErrorMessage {
    pub license_header: LicenseHeader,
    pub error_code: LicenseErrorCode,
    pub state_transition: LicensingStateTransition,
    pub error_info: Vec<u8>,
}

impl LicensingErrorMessage {
    const NAME: &'static str = "LicensingErrorMessage";

    const FIXED_PART_SIZE: usize = ERROR_CODE_SIZE + STATE_TRANSITION_SIZE;

    pub fn new_valid_client() -> EncodeResult<Self> {
        let mut this = Self {
            license_header: LicenseHeader {
                security_header: BasicSecurityHeader {
                    flags: BasicSecurityHeaderFlags::LICENSE_PKT,
                },
                preamble_message_type: PreambleType::ErrorAlert,
                preamble_flags: PreambleFlags::empty(),
                preamble_version: PreambleVersion::V3,
                preamble_message_size: 0,
            },
            error_code: LicenseErrorCode::StatusValidClient,
            state_transition: LicensingStateTransition::NoTransition,
            error_info: Vec::new(),
        };
        this.license_header.preamble_message_size = cast_length!(
            "LicensingErrorMessage",
            "preamble_message_size",
            this.size() - BASIC_SECURITY_HEADER_SIZE
        )?;
        Ok(this)
    }

    pub fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        self.license_header.encode(dst)?;

        dst.write_u32(self.error_code.as_u32());
        dst.write_u32(self.state_transition.as_u32());

        BlobHeader::new(BlobType::ERROR, self.error_info.len()).encode(dst)?;
        dst.write_slice(&self.error_info);

        Ok(())
    }

    pub fn decode(license_header: LicenseHeader, src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        if license_header.preamble_message_type != PreambleType::ErrorAlert {
            return Err(invalid_field_err!("preambleMessageType", "unexpected preamble type"));
        }

        ensure_fixed_part_size!(in: src);
        let error_code = LicenseErrorCode::from_u32(src.read_u32())
            .ok_or_else(|| invalid_field_err!("errorCode", "invalid error code"))?;
        let state_transition = LicensingStateTransition::from_u32(src.read_u32())
            .ok_or_else(|| invalid_field_err!("stateTransition", "invalid state transition"))?;

        let error_info_blob = BlobHeader::decode(src)?;
        if error_info_blob.length != 0 && error_info_blob.blob_type != BlobType::ERROR {
            return Err(invalid_field_err!("blobType", "invalid blob type"));
        }

        let error_info = vec![0u8; error_info_blob.length];

        Ok(Self {
            license_header,
            error_code,
            state_transition,
            error_info,
        })
    }

    pub fn name(&self) -> &'static str {
        Self::NAME
    }

    pub fn size(&self) -> usize {
        self.license_header.size() + Self::FIXED_PART_SIZE + self.error_info.len() + BLOB_LENGTH_SIZE + BLOB_TYPE_SIZE
    }
}

#[repr(u32)]
#[derive(Debug, PartialEq, Eq, FromPrimitive, Copy, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum LicenseErrorCode {
    InvalidServerCertificate = 0x01,
    NoLicense = 0x02,
    InvalidMac = 0x03,
    InvalidScope = 0x4,
    NoLicenseServer = 0x06,
    StatusValidClient = 0x07,
    InvalidClient = 0x08,
    InvalidProductId = 0x0b,
    InvalidFieldLen = 0x0c,
}

impl LicenseErrorCode {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u32(self) -> u32 {
        self as u32
    }
}

#[repr(u32)]
#[derive(Debug, PartialEq, Eq, FromPrimitive, Copy, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum LicensingStateTransition {
    TotalAbort = 1,
    NoTransition = 2,
    ResetPhaseToStart = 3,
    ResendLastMessage = 4,
}

impl LicensingStateTransition {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u32(self) -> u32 {
        self as u32
    }
}
