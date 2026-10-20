use std::io;

use byteorder::{LittleEndian, WriteBytesExt as _};
use ironrdp_core::{
    Decode as _, DecodeResult, Encode as _, EncodeResult, ReadCursor, WriteCursor, ensure_size, invalid_field_err,
};
use md5::Digest as _;

use crate::crypto::rc4::Rc4;
use crate::crypto::rsa::encrypt_with_public_key;
use crate::rdp::headers::{BasicSecurityHeader, BasicSecurityHeaderFlags};
use crate::rdp::server_license::client_new_license_request::{compute_master_secret, compute_session_key_blob};
use crate::rdp::server_license::client_platform_challenge_response::CLIENT_HARDWARE_IDENTIFICATION_SIZE;
use crate::rdp::server_license::{
    BlobHeader, BlobType, KEY_EXCHANGE_ALGORITHM_RSA, LicenseEncryptionData, LicenseHeader, MAC_SIZE, PLATFORM_ID,
    PREAMBLE_SIZE, PreambleFlags, PreambleType, PreambleVersion, RANDOM_NUMBER_SIZE, ServerLicenseError,
    ServerLicenseRequest, compute_mac_data,
};

const LICENSE_INFO_STATIC_FIELDS_SIZE: usize = 20;

/// [2.2.2.3] Client License Info (CLIENT_LICENSE_INFO)
///
/// [2.2.2.3]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/9407b2eb-f180-4827-9488-cdbff4a5d4ea
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ClientLicenseInfo {
    pub license_header: LicenseHeader,
    pub client_random: Vec<u8>,
    pub encrypted_premaster_secret: Vec<u8>,
    pub license_info: Vec<u8>,
    pub encrypted_hwid: Vec<u8>,
    pub mac_data: Vec<u8>,
}

impl ClientLicenseInfo {
    const NAME: &'static str = "ClientLicenseInfo";

    pub fn from_server_license_request(
        license_request: &ServerLicenseRequest,
        client_random: &[u8],
        premaster_secret: &[u8],
        hardware_data: [u32; 4],
        license_info: Vec<u8>,
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

        let mut hardware_id = Vec::with_capacity(CLIENT_HARDWARE_IDENTIFICATION_SIZE);
        hardware_id.write_u32::<LittleEndian>(PLATFORM_ID)?;
        for data in hardware_data {
            hardware_id.write_u32::<LittleEndian>(data)?;
        }

        let mut rc4 = Rc4::new(&license_key);
        let encrypted_hwid = rc4.process(&hardware_id);

        let mac_data = compute_mac_data(mac_salt_key, &hardware_id)?;

        let size = RANDOM_NUMBER_SIZE
            + PREAMBLE_SIZE
            + LICENSE_INFO_STATIC_FIELDS_SIZE
            + encrypted_premaster_secret.len()
            + license_info.len()
            + encrypted_hwid.len()
            + MAC_SIZE;

        let license_header = LicenseHeader {
            security_header: BasicSecurityHeader {
                flags: BasicSecurityHeaderFlags::LICENSE_PKT,
            },
            preamble_message_type: PreambleType::LicenseInfo,
            preamble_flags: PreambleFlags::empty(),
            preamble_version: PreambleVersion::V3,
            preamble_message_size: u16::try_from(size)
                .map_err(|_| ServerLicenseError::InvalidField("preamble message size"))?,
        };

        Ok((
            Self {
                license_header,
                client_random: Vec::from(client_random),
                encrypted_premaster_secret,
                license_info,
                encrypted_hwid,
                mac_data,
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

        BlobHeader::new(BlobType::DATA, self.license_info.len()).encode(dst)?;
        dst.write_slice(&self.license_info);

        BlobHeader::new(BlobType::ENCRYPTED_DATA, self.encrypted_hwid.len()).encode(dst)?;
        dst.write_slice(&self.encrypted_hwid);

        dst.write_slice(&self.mac_data);

        Ok(())
    }

    pub fn decode(license_header: LicenseHeader, src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        if license_header.preamble_message_type != PreambleType::LicenseInfo {
            return Err(invalid_field_err!("preambleMessageType", "unexpected preamble type"));
        }

        let key_exchange_algorithm = src.read_u32();
        if key_exchange_algorithm != KEY_EXCHANGE_ALGORITHM_RSA {
            return Err(invalid_field_err!("keyExchangeAlgo", "invalid key exchange algorithm"));
        }

        // We can ignore platform ID
        let _platform_id = src.read_u32();

        ensure_size!(in: src, size:  RANDOM_NUMBER_SIZE);
        let client_random = src.read_slice(RANDOM_NUMBER_SIZE).into();

        let premaster_secret_blob_header = BlobHeader::decode(src)?;
        if premaster_secret_blob_header.blob_type != BlobType::RANDOM {
            return Err(invalid_field_err!("blobType", "invalid blob type"));
        }
        ensure_size!(in: src, size: premaster_secret_blob_header.length);
        let encrypted_premaster_secret = src.read_slice(premaster_secret_blob_header.length).into();

        let license_info_blob_header = BlobHeader::decode(src)?;
        if license_info_blob_header.blob_type != BlobType::DATA {
            return Err(invalid_field_err!("blobType", "invalid blob type"));
        }
        ensure_size!(in: src, size: license_info_blob_header.length);
        let license_info = src.read_slice(license_info_blob_header.length).into();

        let encrypted_hwid_blob_header = BlobHeader::decode(src)?;
        if encrypted_hwid_blob_header.blob_type != BlobType::DATA {
            return Err(invalid_field_err!("blobType", "invalid blob type"));
        }
        ensure_size!(in: src, size: encrypted_hwid_blob_header.length);
        let encrypted_hwid = src.read_slice(encrypted_hwid_blob_header.length).into();

        ensure_size!(in: src, size: MAC_SIZE);
        let mac_data = src.read_slice(MAC_SIZE).into();

        Ok(Self {
            license_header,
            client_random,
            encrypted_premaster_secret,
            license_info,
            encrypted_hwid,
            mac_data,
        })
    }

    pub fn name(&self) -> &'static str {
        Self::NAME
    }

    pub fn size(&self) -> usize {
        self.license_header.size()
            + LICENSE_INFO_STATIC_FIELDS_SIZE
            + RANDOM_NUMBER_SIZE
            + self.encrypted_premaster_secret.len()
            + self.license_info.len()
            + self.encrypted_hwid.len()
            + MAC_SIZE
    }
}
