#[cfg(test)]
mod tests;

use std::io;

use bitflags::bitflags;
use ironrdp_core::{
    Decode as _, DecodeResult, Encode as _, EncodeResult, ReadCursor, WriteCursor, ensure_size, invalid_field_err,
};
use md5::Digest as _;

use super::{
    BasicSecurityHeader, BasicSecurityHeaderFlags, BlobHeader, BlobType, KEY_EXCHANGE_ALGORITHM_RSA,
    LicenseEncryptionData, LicenseHeader, PREAMBLE_SIZE, PreambleFlags, PreambleType, PreambleVersion,
    RANDOM_NUMBER_SIZE, ServerLicenseError, ServerLicenseRequest, UTF8_NULL_TERMINATOR_SIZE,
};
use crate::crypto::rsa::encrypt_with_public_key;
use crate::utils::{self, CharacterSet};

const LICENSE_REQUEST_STATIC_FIELDS_SIZE: usize = 20;

pub const PLATFORM_ID: u32 = ClientOsType::NT_POST_52.bits() | Isv::MICROSOFT.bits();

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct ClientOsType: u32 {
        const NT_351 = 0x100_0000;
        const NT_40 = 0x200_0000;
        const NT_50 = 0x300_0000;
        const NT_POST_52 = 0x400_0000;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct Isv: u32 {
        const MICROSOFT = 0x10000;
        const CITRIX = 0x20000;
    }
}

/// [2.2.2.2] Client New License Request (CLIENT_NEW_LICENSE_REQUEST)
///
/// [2.2.2.2]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/c57e4890-9049-421e-9fe8-9a6f9519675a
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ClientNewLicenseRequest {
    pub license_header: LicenseHeader,
    pub client_random: Vec<u8>,
    pub encrypted_premaster_secret: Vec<u8>,
    pub client_username: String,
    pub client_machine_name: String,
}

impl ClientNewLicenseRequest {
    const NAME: &'static str = "ClientNewLicenseRequest";

    pub fn from_server_license_request(
        license_request: &ServerLicenseRequest,
        client_random: &[u8],
        premaster_secret: &[u8],
        client_username: &str,
        client_machine_name: &str,
    ) -> Result<(Self, LicenseEncryptionData), ServerLicenseError> {
        let public_key = license_request.get_public_key()?
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                                          "attempted to retrieve the server public key from a server license request message that does not have a certificate"))?;

        let encrypted_premaster_secret = encrypt_with_public_key(premaster_secret, &public_key)?;

        let master_secret = compute_master_secret(
            premaster_secret,
            client_random,
            license_request.server_random.as_slice(),
        );
        let session_key_blob = compute_session_key_blob(
            master_secret.as_slice(),
            client_random,
            license_request.server_random.as_slice(),
        );
        let mac_salt_key = &session_key_blob[..16];

        let mut md5 = md5::Md5::new();
        md5.update(
            [
                &session_key_blob[16..32],
                client_random,
                license_request.server_random.as_slice(),
            ]
            .concat()
            .as_slice(),
        );
        let license_key = md5.finalize().to_vec();

        let license_header = LicenseHeader {
            security_header: BasicSecurityHeader {
                flags: BasicSecurityHeaderFlags::LICENSE_PKT,
            },
            preamble_message_type: PreambleType::NewLicenseRequest,
            preamble_flags: PreambleFlags::empty(),
            preamble_version: PreambleVersion::V3,
            preamble_message_size: u16::try_from(
                RANDOM_NUMBER_SIZE
                    + PREAMBLE_SIZE
                    + LICENSE_REQUEST_STATIC_FIELDS_SIZE
                    + encrypted_premaster_secret.len()
                    + client_machine_name.len()
                    + UTF8_NULL_TERMINATOR_SIZE
                    + client_username.len()
                    + UTF8_NULL_TERMINATOR_SIZE,
            )
            .map_err(|_| ServerLicenseError::InvalidField("preamble message size"))?,
        };

        Ok((
            Self {
                license_header,
                client_random: Vec::from(client_random),
                encrypted_premaster_secret,
                client_username: client_username.to_owned(),
                client_machine_name: client_machine_name.to_owned(),
            },
            LicenseEncryptionData {
                premaster_secret: Vec::from(premaster_secret),
                mac_salt_key: Vec::from(mac_salt_key),
                license_key,
            },
        ))
    }

    pub fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        self.license_header.encode(dst)?;

        dst.write_u32(KEY_EXCHANGE_ALGORITHM_RSA);
        dst.write_u32(PLATFORM_ID);
        dst.write_slice(&self.client_random);

        BlobHeader::new(BlobType::RANDOM, self.encrypted_premaster_secret.len()).encode(dst)?;
        dst.write_slice(&self.encrypted_premaster_secret);

        BlobHeader::new(
            BlobType::CLIENT_USER_NAME,
            self.client_username.len() + UTF8_NULL_TERMINATOR_SIZE,
        )
        .encode(dst)?;
        utils::write_string_to_cursor(dst, &self.client_username, CharacterSet::Ansi, true)?;

        BlobHeader::new(
            BlobType::CLIENT_MACHINE_NAME_BLOB,
            self.client_machine_name.len() + UTF8_NULL_TERMINATOR_SIZE,
        )
        .encode(dst)?;
        utils::write_string_to_cursor(dst, &self.client_machine_name, CharacterSet::Ansi, true)?;

        Ok(())
    }

    pub fn decode(license_header: LicenseHeader, src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        if license_header.preamble_message_type != PreambleType::NewLicenseRequest {
            return Err(invalid_field_err!("preambleMessageType", "unexpected preamble type"));
        }

        ensure_size!(in: src, size: LICENSE_REQUEST_STATIC_FIELDS_SIZE + RANDOM_NUMBER_SIZE);
        let key_exchange_algorithm = src.read_u32();
        if key_exchange_algorithm != KEY_EXCHANGE_ALGORITHM_RSA {
            return Err(invalid_field_err!("keyExchangeAlgo", "invalid key exchange algorithm"));
        }

        let _platform_id = src.read_u32();
        let client_random = src.read_slice(RANDOM_NUMBER_SIZE).into();

        let premaster_secret_blob_header = BlobHeader::decode(src)?;
        if premaster_secret_blob_header.blob_type != BlobType::RANDOM {
            return Err(invalid_field_err!("blobType", "invalid blob type"));
        }
        ensure_size!(in: src, size: premaster_secret_blob_header.length);
        let encrypted_premaster_secret = src.read_slice(premaster_secret_blob_header.length).into();

        let username_blob_header = BlobHeader::decode(src)?;
        if username_blob_header.blob_type != BlobType::CLIENT_USER_NAME {
            return Err(invalid_field_err!("blobType", "invalid blob type"));
        }
        ensure_size!(in: src, size: username_blob_header.length);
        let client_username =
            utils::decode_string(src.read_slice(username_blob_header.length), CharacterSet::Ansi, false)?;

        let machine_name_blob = BlobHeader::decode(src)?;
        if machine_name_blob.blob_type != BlobType::CLIENT_MACHINE_NAME_BLOB {
            return Err(invalid_field_err!("blobType", "invalid blob type"));
        }
        ensure_size!(in: src, size: machine_name_blob.length);
        let client_machine_name =
            utils::decode_string(src.read_slice(machine_name_blob.length), CharacterSet::Ansi, false)?;

        Ok(Self {
            license_header,
            client_random,
            encrypted_premaster_secret,
            client_username,
            client_machine_name,
        })
    }

    pub fn name(&self) -> &'static str {
        Self::NAME
    }

    pub fn size(&self) -> usize {
        self.license_header.size()
            + LICENSE_REQUEST_STATIC_FIELDS_SIZE
            + RANDOM_NUMBER_SIZE
            + self.encrypted_premaster_secret.len()
            + self.client_machine_name.len()
            + UTF8_NULL_TERMINATOR_SIZE
            + self.client_username.len()
            + UTF8_NULL_TERMINATOR_SIZE
    }
}

fn salted_hash(salt: &[u8], salt_first: &[u8], salt_second: &[u8], input: &[u8]) -> Vec<u8> {
    let mut hasher = sha1::Sha1::new();
    hasher.update([input, salt, salt_first, salt_second].concat().as_slice());
    let sha_result = hasher.finalize();

    let mut md5 = md5::Md5::new();
    md5.update([salt, sha_result.as_ref()].concat().as_slice());

    md5.finalize().to_vec()
}

// According to https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/88061224-4a2f-4a28-a52e-e896b75ed2d3
pub(crate) fn compute_master_secret(premaster_secret: &[u8], client_random: &[u8], server_random: &[u8]) -> Vec<u8> {
    [
        salted_hash(premaster_secret, client_random, server_random, b"A"),
        salted_hash(premaster_secret, client_random, server_random, b"BB"),
        salted_hash(premaster_secret, client_random, server_random, b"CCC"),
    ]
    .concat()
}

// According to https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/88061224-4a2f-4a28-a52e-e896b75ed2d3
pub(crate) fn compute_session_key_blob(master_secret: &[u8], client_random: &[u8], server_random: &[u8]) -> Vec<u8> {
    [
        salted_hash(master_secret, server_random, client_random, b"A"),
        salted_hash(master_secret, server_random, client_random, b"BB"),
        salted_hash(master_secret, server_random, client_random, b"CCC"),
    ]
    .concat()
}
