#[cfg(test)]
mod test;

use std::io::Write as _;

use byteorder::{LittleEndian, WriteBytesExt as _};
use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, cast_length, ensure_fixed_part_size,
    ensure_size, invalid_field_err,
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive as _;

use super::{
    BLOB_LENGTH_SIZE, BLOB_TYPE_SIZE, BasicSecurityHeader, BasicSecurityHeaderFlags, BlobHeader, BlobType,
    LicenseEncryptionData, LicenseHeader, MAC_SIZE, PLATFORM_ID, PREAMBLE_SIZE, PreambleFlags, PreambleType,
    PreambleVersion, ServerLicenseError, ServerPlatformChallenge,
};
use crate::crypto::rc4::Rc4;

const RESPONSE_DATA_VERSION: u16 = 0x100;
const RESPONSE_DATA_STATIC_FIELDS_SIZE: usize = 8;

pub(crate) const CLIENT_HARDWARE_IDENTIFICATION_SIZE: usize = 20;

/// [2.2.2.5] Client Platform Challenge Response (CLIENT_PLATFORM_CHALLENGE_RESPONSE)
///
/// [2.2.2.5]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/f53ab87c-d07d-4bf9-a2ac-79542f7b456c
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ClientPlatformChallengeResponse {
    pub license_header: LicenseHeader,
    pub encrypted_challenge_response_data: Vec<u8>,
    pub encrypted_hwid: Vec<u8>,
    pub mac_data: Vec<u8>,
}

impl ClientPlatformChallengeResponse {
    const NAME: &'static str = "ClientPlatformChallengeResponse";

    pub fn from_server_platform_challenge(
        platform_challenge: &ServerPlatformChallenge,
        hardware_data: [u32; 4],
        encryption_data: &LicenseEncryptionData,
    ) -> Result<Self, ServerLicenseError> {
        let mut rc4 = Rc4::new(&encryption_data.license_key);
        let decrypted_challenge = rc4.process(platform_challenge.encrypted_platform_challenge.as_slice());

        let decrypted_challenge_mac =
            super::compute_mac_data(encryption_data.mac_salt_key.as_slice(), decrypted_challenge.as_slice())?;

        if decrypted_challenge_mac != platform_challenge.mac_data {
            return Err(ServerLicenseError::InvalidMacData);
        }

        let mut challenge_response_data = vec![0u8; RESPONSE_DATA_STATIC_FIELDS_SIZE];
        challenge_response_data.write_u16::<LittleEndian>(RESPONSE_DATA_VERSION)?;
        challenge_response_data.write_u16::<LittleEndian>(ClientType::Other.as_u16())?;
        challenge_response_data.write_u16::<LittleEndian>(LicenseDetailLevel::Detail.as_u16())?;
        challenge_response_data.write_u16::<LittleEndian>(
            u16::try_from(decrypted_challenge.len())
                .map_err(|_| ServerLicenseError::InvalidField("decrypted challenge len"))?,
        )?;
        challenge_response_data.write_all(&decrypted_challenge)?;

        let mut hardware_id = Vec::with_capacity(CLIENT_HARDWARE_IDENTIFICATION_SIZE);
        hardware_id.write_u32::<LittleEndian>(PLATFORM_ID)?;
        for data in hardware_data {
            hardware_id.write_u32::<LittleEndian>(data)?;
        }

        let mut rc4 = Rc4::new(&encryption_data.license_key);
        let encrypted_hwid = rc4.process(&hardware_id);

        let mut rc4 = Rc4::new(&encryption_data.license_key);
        let encrypted_challenge_response_data = rc4.process(&challenge_response_data);

        challenge_response_data.extend(&hardware_id);
        let mac_data = super::compute_mac_data(
            encryption_data.mac_salt_key.as_slice(),
            challenge_response_data.as_slice(),
        )?;

        let license_header = LicenseHeader {
            security_header: BasicSecurityHeader {
                flags: BasicSecurityHeaderFlags::LICENSE_PKT,
            },
            preamble_message_type: PreambleType::PlatformChallengeResponse,
            preamble_flags: PreambleFlags::empty(),
            preamble_version: PreambleVersion::V3,
            preamble_message_size: u16::try_from(
                PREAMBLE_SIZE
                + (BLOB_TYPE_SIZE + BLOB_LENGTH_SIZE) * 2 // 2 blobs in this structure
                + MAC_SIZE + encrypted_challenge_response_data.len() + encrypted_hwid.len(),
            )
            .map_err(|_| ServerLicenseError::InvalidField("preamble message size"))?,
        };

        Ok(Self {
            license_header,
            encrypted_challenge_response_data,
            encrypted_hwid,
            mac_data,
        })
    }

    pub fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        self.license_header.encode(dst)?;

        BlobHeader::new(BlobType::ENCRYPTED_DATA, self.encrypted_challenge_response_data.len()).encode(dst)?;
        dst.write_slice(&self.encrypted_challenge_response_data);

        BlobHeader::new(BlobType::ENCRYPTED_DATA, self.encrypted_hwid.len()).encode(dst)?;
        dst.write_slice(&self.encrypted_hwid);

        dst.write_slice(&self.mac_data);

        Ok(())
    }

    pub fn decode(license_header: LicenseHeader, src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        if license_header.preamble_message_type != PreambleType::PlatformChallengeResponse {
            return Err(invalid_field_err!(
                "preambleMessageType",
                "unexpected preamble message type"
            ));
        }

        let encrypted_challenge_blob = BlobHeader::decode(src)?;
        if encrypted_challenge_blob.blob_type != BlobType::ENCRYPTED_DATA {
            return Err(invalid_field_err!("blobType", "unexpected blob type"));
        }
        ensure_size!(in: src, size: encrypted_challenge_blob.length);
        let encrypted_challenge_response_data = src.read_slice(encrypted_challenge_blob.length).into();

        let encrypted_hwid_blob = BlobHeader::decode(src)?;
        if encrypted_hwid_blob.blob_type != BlobType::ENCRYPTED_DATA {
            return Err(invalid_field_err!("blobType", "unexpected blob type"));
        }
        ensure_size!(in: src, size: encrypted_hwid_blob.length);
        let encrypted_hwid = src.read_slice(encrypted_hwid_blob.length).into();

        ensure_size!(in: src, size: MAC_SIZE);
        let mac_data = src.read_slice(MAC_SIZE).into();

        Ok(Self {
            license_header,
            encrypted_challenge_response_data,
            encrypted_hwid,
            mac_data,
        })
    }

    pub fn name(&self) -> &'static str {
        Self::NAME
    }

    pub fn size(&self) -> usize {
        self.license_header.size()
        + (BLOB_TYPE_SIZE + BLOB_LENGTH_SIZE) * 2 // 2 blobs in this structure
        + MAC_SIZE + self.encrypted_challenge_response_data.len() + self.encrypted_hwid.len()
    }
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, FromPrimitive)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum ClientType {
    Win32 = 0x0100,
    Win16 = 0x0200,
    WinCe = 0x0300,
    Other = 0xff00,
}

impl ClientType {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u16(self) -> u16 {
        self as u16
    }
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, FromPrimitive)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum LicenseDetailLevel {
    Simple = 1,
    Moderate = 2,
    Detail = 3,
}

impl LicenseDetailLevel {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u16(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct PlatformChallengeResponseData {
    pub client_type: ClientType,
    pub license_detail_level: LicenseDetailLevel,
    pub challenge: Vec<u8>,
}

impl PlatformChallengeResponseData {
    const NAME: &'static str = "PlatformChallengeResponseData";

    const FIXED_PART_SIZE: usize = RESPONSE_DATA_STATIC_FIELDS_SIZE;
}

impl Encode for PlatformChallengeResponseData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u16(RESPONSE_DATA_VERSION);
        dst.write_u16(self.client_type.as_u16());
        dst.write_u16(self.license_detail_level.as_u16());
        dst.write_u16(cast_length!("len", self.challenge.len())?);
        dst.write_slice(&self.challenge);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.challenge.len()
    }
}

impl<'de> Decode<'de> for PlatformChallengeResponseData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let version = src.read_u16();
        if version != RESPONSE_DATA_VERSION {
            return Err(invalid_field_err!("version", "invalid challenge response version"));
        }

        let client_type = ClientType::from_u16(src.read_u16())
            .ok_or_else(|| invalid_field_err!("clientType", "invalid client type"))?;

        let license_detail_level = LicenseDetailLevel::from_u16(src.read_u16())
            .ok_or_else(|| invalid_field_err!("licenseDetailLevel", "invalid license detail level"))?;

        let challenge_len: usize = cast_length!("len", src.read_u16())?;
        ensure_size!(in: src, size: challenge_len);
        let challenge = src.read_slice(challenge_len).into();

        Ok(Self {
            client_type,
            license_detail_level,
            challenge,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ClientHardwareIdentification {
    pub platform_id: u32,
    pub data: Vec<u8>,
}

impl ClientHardwareIdentification {
    const NAME: &'static str = "ClientHardwareIdentification";

    const FIXED_PART_SIZE: usize = CLIENT_HARDWARE_IDENTIFICATION_SIZE;
}

impl Encode for ClientHardwareIdentification {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u32(self.platform_id);
        dst.write_slice(&self.data);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for ClientHardwareIdentification {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let platform_id = src.read_u32();
        let data = src.read_slice(MAC_SIZE).into();

        Ok(Self { platform_id, data })
    }
}
