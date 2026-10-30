use core::fmt;
use std::io;

use bitflags::bitflags;
use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, cast_length, ensure_fixed_part_size,
    invalid_field_err, unsupported_value_err,
};
use md5::Digest as _;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive as _;

use crate::PduError;
use crate::rdp::headers::{BASIC_SECURITY_HEADER_SIZE, BasicSecurityHeader, BasicSecurityHeaderFlags};
pub use crate::rdp::server_license::client_license_info::ClientLicenseInfo;

#[cfg(test)]
mod tests;

mod client_license_info;
mod client_new_license_request;
mod client_platform_challenge_response;
mod licensing_error_message;
mod server_license_request;
mod server_platform_challenge;
mod server_upgrade_license;

pub use self::client_new_license_request::{ClientNewLicenseRequest, PLATFORM_ID};
pub use self::client_platform_challenge_response::{
    ClientHardwareIdentification, ClientPlatformChallengeResponse, PlatformChallengeResponseData,
};
pub use self::licensing_error_message::{LicenseErrorCode, LicensingErrorMessage, LicensingStateTransition};
pub use self::server_license_request::{ProductInfo, Scope, ServerCertificate, ServerLicenseRequest, cert};
pub use self::server_platform_challenge::ServerPlatformChallenge;
pub use self::server_upgrade_license::{LicenseInformation, ServerUpgradeLicense};

pub const PREAMBLE_SIZE: usize = 4;
pub const PREMASTER_SECRET_SIZE: usize = 48;
pub const RANDOM_NUMBER_SIZE: usize = 32;

const PROTOCOL_VERSION_MASK: u8 = 0x0F;

const BLOB_TYPE_SIZE: usize = 2;
const BLOB_LENGTH_SIZE: usize = 2;

const UTF8_NULL_TERMINATOR_SIZE: usize = 1;
const UTF16_NULL_TERMINATOR_SIZE: usize = 2;

const KEY_EXCHANGE_ALGORITHM_RSA: u32 = 1;

const MAC_SIZE: usize = 16;

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct LicenseEncryptionData {
    pub premaster_secret: Vec<u8>,
    pub mac_salt_key: Vec<u8>,
    pub license_key: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct LicenseHeader {
    pub security_header: BasicSecurityHeader,
    pub preamble_message_type: PreambleType,
    pub preamble_flags: PreambleFlags,
    pub preamble_version: PreambleVersion,
    pub preamble_message_size: u16,
}

impl LicenseHeader {
    const NAME: &'static str = "LicenseHeader";

    const FIXED_PART_SIZE: usize = PREAMBLE_SIZE + BASIC_SECURITY_HEADER_SIZE;
}

impl Encode for LicenseHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        self.security_header.encode(dst)?;

        let flags_with_version = self.preamble_flags.bits() | self.preamble_version.as_u8();

        dst.write_u8(self.preamble_message_type.as_u8());
        dst.write_u8(flags_with_version);
        dst.write_u16(self.preamble_message_size); // msg size

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for LicenseHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let security_header = BasicSecurityHeader::decode(src)?;

        if !security_header.flags.contains(BasicSecurityHeaderFlags::LICENSE_PKT) {
            return Err(invalid_field_err!(
                "securityHeaderFlags",
                "invalid security header flags"
            ));
        }

        let preamble_message_type = PreambleType::from_u8(src.read_u8())
            .ok_or_else(|| invalid_field_err!("preambleType", "invalid license type"))?;

        let flags_with_version = src.read_u8();
        let preamble_message_size = src.read_u16();

        let preamble_flags = PreambleFlags::from_bits(flags_with_version & !PROTOCOL_VERSION_MASK)
            .ok_or_else(|| invalid_field_err!("preambleFlags", "Got invalid flags field"))?;

        let preamble_version = PreambleVersion::from_u8(flags_with_version & PROTOCOL_VERSION_MASK)
            .ok_or_else(|| invalid_field_err!("preambleVersion", "Got invalid version in the flags filed"))?;

        Ok(Self {
            security_header,
            preamble_message_type,
            preamble_flags,
            preamble_version,
            preamble_message_size,
        })
    }
}

/// [2.2.1.12.1.1] Licensing Preamble (LICENSE_PREAMBLE)
///
/// [2.2.1.12.1.1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/73170ca2-5f82-4a2d-9d1b-b439f3d8dadc
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, FromPrimitive, Copy, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum PreambleType {
    LicenseRequest = 0x01,
    PlatformChallenge = 0x02,
    NewLicense = 0x03,
    UpgradeLicense = 0x04,
    LicenseInfo = 0x12,
    NewLicenseRequest = 0x13,
    PlatformChallengeResponse = 0x15,
    ErrorAlert = 0xff,
}

impl PreambleType {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u8(self) -> u8 {
        self as u8
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct PreambleFlags: u8 {
        const EXTENDED_ERROR_MSG_SUPPORTED = 0x80;
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, FromPrimitive, Copy, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum PreambleVersion {
    V2 = 2, // RDP 4.0
    V3 = 3, // RDP 5.0, 5.1, 5.2, 6.0, 6.1, 7.0, 7.1, 8.0, 8.1, 10.0, 10.1, 10.2, 10.3, 10.4, and 10.5
}

impl PreambleVersion {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct BlobType(u16);

impl BlobType {
    pub const ANY: Self = Self(0x00);
    pub const DATA: Self = Self(0x01);
    pub const RANDOM: Self = Self(0x02);
    pub const CERTIFICATE: Self = Self(0x03);
    pub const ERROR: Self = Self(0x04);
    pub const RSA_KEY: Self = Self(0x06);
    pub const ENCRYPTED_DATA: Self = Self(0x09);
    pub const RSA_SIGNATURE: Self = Self(0x08);
    pub const KEY_EXCHANGE_ALGORITHM: Self = Self(0x0d);
    pub const SCOPE: Self = Self(0x0e);
    pub const CLIENT_USER_NAME: Self = Self(0x0f);
    pub const CLIENT_MACHINE_NAME_BLOB: Self = Self(0x10);
}

// FIXME: licensing logic and any code that is not purely about PDU
// encoding/decoding concerns should be moved out of ironrdp-pdu.
#[derive(Debug)]
pub enum ServerLicenseError {
    IOError(io::Error),
    Utf8Error(std::string::FromUtf8Error),
    DerError(pkcs1::der::Error),
    InvalidField(&'static str),
    InvalidPreamble(String),
    InvalidLicenseType,
    InvalidErrorCode,
    InvalidStateTransition,
    InvalidBlobType,
    RandomNumberGenerationError(String),
    UnableToGetPublicKey,
    RsaKeyEncryptionError,
    InvalidKeyExchangeValue,
    InvalidMacData,
    InvalidChallengeResponseDataVersion,
    InvalidChallengeResponseDataClientType,
    InvalidChallengeResponseDataLicenseDetail,
    InvalidX509Certificate {
        source: x509_cert::der::Error,
        cert_der: Vec<u8>,
    },
    InvalidCertificateVersion,
    InvalidX509CertificatesAmount,
    InvalidPropCertSignatureAlgorithmId,
    InvalidPropCertKeyAlgorithmId,
    InvalidRsaPublicKeyMagic,
    InvalidRsaPublicKeyLength,
    InvalidRsaPublicKeyDataLength,
    InvalidRsaPublicKeyBitLength,
    InvalidSecurityFlags,
    UnexpectedError(LicensingErrorMessage),
    UnexpectedLicenseMessage,
    UnexpectedServerError(LicensingErrorMessage),
    ValidClientStatus(LicensingErrorMessage),
    InvalidKeyExchangeAlgorithm,
    InvalidCompanyNameLength(u32),
    InvalidProductIdLength(u32),
    InvalidScopeCount(u32),
    InvalidCertificateLength(u32),
    BlobTooSmall,
    Pdu(PduError),
}

impl fmt::Display for ServerLicenseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IOError(e) => write!(f, "IO error: {e}"),
            Self::Utf8Error(e) => write!(f, "UTF-8 error: {e}"),
            Self::DerError(e) => write!(f, "DER error: {e}"),
            Self::InvalidField(name) => write!(f, "invalid `{name}`: out of range integral type conversion"),
            Self::InvalidPreamble(s) => write!(f, "invalid preamble field: {s}"),
            Self::InvalidLicenseType => f.write_str("invalid preamble message type field"),
            Self::InvalidErrorCode => f.write_str("invalid error code field"),
            Self::InvalidStateTransition => f.write_str("invalid state transition field"),
            Self::InvalidBlobType => f.write_str("invalid blob type field"),
            Self::RandomNumberGenerationError(s) => write!(f, "unable to generate random number {s}"),
            Self::UnableToGetPublicKey => f.write_str("unable to retrieve public key from the certificate"),
            Self::RsaKeyEncryptionError => f.write_str("unable to encrypt RSA public key"),
            Self::InvalidKeyExchangeValue => f.write_str("invalid License Request key exchange algorithm value"),
            Self::InvalidMacData => {
                f.write_str("MAC checksum generated over decrypted data does not match the server's checksum")
            }
            Self::InvalidChallengeResponseDataVersion => {
                f.write_str("invalid platform challenge response data version")
            }
            Self::InvalidChallengeResponseDataClientType => {
                f.write_str("invalid platform challenge response data client type")
            }
            Self::InvalidChallengeResponseDataLicenseDetail => {
                f.write_str("invalid platform challenge response data license detail level")
            }
            Self::InvalidX509Certificate { .. } => f.write_str("invalid x509 certificate"),
            Self::InvalidCertificateVersion => f.write_str("invalid certificate version"),
            Self::InvalidX509CertificatesAmount => f.write_str("invalid x509 certificates amount"),
            Self::InvalidPropCertSignatureAlgorithmId => {
                f.write_str("invalid proprietary certificate signature algorithm ID")
            }
            Self::InvalidPropCertKeyAlgorithmId => f.write_str("invalid proprietary certificate key algorithm ID"),
            Self::InvalidRsaPublicKeyMagic => f.write_str("invalid RSA public key magic"),
            Self::InvalidRsaPublicKeyLength => f.write_str("invalid RSA public key length"),
            Self::InvalidRsaPublicKeyDataLength => f.write_str("invalid RSA public key data length"),
            Self::InvalidRsaPublicKeyBitLength => f.write_str("invalid RSA public key bit length"),
            Self::InvalidSecurityFlags => f.write_str("invalid License Header security flags"),
            Self::UnexpectedError(msg) => write!(f, "the server returned unexpected error: {msg:?}"),
            Self::UnexpectedLicenseMessage => f.write_str("got unexpected license message"),
            Self::UnexpectedServerError(_) => f.write_str("the server has returned an unexpected error"),
            Self::ValidClientStatus(_) => f.write_str("the server has returned STATUS_VALID_CLIENT (not an error)"),
            Self::InvalidKeyExchangeAlgorithm => f.write_str("invalid Key Exchange List field"),
            Self::InvalidCompanyNameLength(n) => {
                write!(f, "received invalid company name length (Product Information): {n}")
            }
            Self::InvalidProductIdLength(n) => {
                write!(f, "received invalid product ID length (Product Information): {n}")
            }
            Self::InvalidScopeCount(n) => write!(f, "received invalid scope count field: {n}"),
            Self::InvalidCertificateLength(n) => write!(f, "received invalid certificate length: {n}"),
            Self::BlobTooSmall => f.write_str("blob too small"),
            Self::Pdu(e) => write!(f, "PDU error: {e}"),
        }
    }
}

impl core::error::Error for ServerLicenseError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::IOError(e) => Some(e),
            Self::Utf8Error(e) => Some(e),
            Self::DerError(e) => Some(e),
            Self::InvalidX509Certificate { source, .. } => Some(source),
            Self::InvalidField(_)
            | Self::InvalidPreamble(_)
            | Self::InvalidLicenseType
            | Self::InvalidErrorCode
            | Self::InvalidStateTransition
            | Self::InvalidBlobType
            | Self::RandomNumberGenerationError(_)
            | Self::UnableToGetPublicKey
            | Self::RsaKeyEncryptionError
            | Self::InvalidKeyExchangeValue
            | Self::InvalidMacData
            | Self::InvalidChallengeResponseDataVersion
            | Self::InvalidChallengeResponseDataClientType
            | Self::InvalidChallengeResponseDataLicenseDetail
            | Self::InvalidCertificateVersion
            | Self::InvalidX509CertificatesAmount
            | Self::InvalidPropCertSignatureAlgorithmId
            | Self::InvalidPropCertKeyAlgorithmId
            | Self::InvalidRsaPublicKeyMagic
            | Self::InvalidRsaPublicKeyLength
            | Self::InvalidRsaPublicKeyDataLength
            | Self::InvalidRsaPublicKeyBitLength
            | Self::InvalidSecurityFlags
            | Self::UnexpectedError(_)
            | Self::UnexpectedLicenseMessage
            | Self::UnexpectedServerError(_)
            | Self::ValidClientStatus(_)
            | Self::InvalidKeyExchangeAlgorithm
            | Self::InvalidCompanyNameLength(_)
            | Self::InvalidProductIdLength(_)
            | Self::InvalidScopeCount(_)
            | Self::InvalidCertificateLength(_)
            | Self::BlobTooSmall
            | Self::Pdu(_) => None,
        }
    }
}

impl From<io::Error> for ServerLicenseError {
    fn from(e: io::Error) -> Self {
        Self::IOError(e)
    }
}

impl From<std::string::FromUtf8Error> for ServerLicenseError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Self::Utf8Error(e)
    }
}

impl From<pkcs1::der::Error> for ServerLicenseError {
    fn from(e: pkcs1::der::Error) -> Self {
        Self::DerError(e)
    }
}

impl From<PduError> for ServerLicenseError {
    fn from(e: PduError) -> Self {
        Self::Pdu(e)
    }
}

impl From<LicensingErrorMessage> for ServerLicenseError {
    fn from(e: LicensingErrorMessage) -> Self {
        Self::UnexpectedError(e)
    }
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct BlobHeader {
    pub blob_type: BlobType,
    pub length: usize,
}

impl BlobHeader {
    const NAME: &'static str = "BlobHeader";

    const FIXED_PART_SIZE: usize = 2 /* blobType */ + 2 /* len */;

    pub fn new(blob_type: BlobType, length: usize) -> Self {
        Self { blob_type, length }
    }
}

impl Encode for BlobHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(self.blob_type.0);
        dst.write_u16(cast_length!("len", self.length)?);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for BlobHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let blob_type = BlobType(src.read_u16());
        let length = cast_length!("len", src.read_u16())?;

        Ok(Self { blob_type, length })
    }
}

fn compute_mac_data(mac_salt_key: &[u8], data: &[u8]) -> Result<Vec<u8>, ServerLicenseError> {
    let data_len_buffer = u32::try_from(data.len())
        .map_err(|_| ServerLicenseError::InvalidField("MAC data length"))?
        .to_le_bytes();

    let pad_one: [u8; 40] = [0x36; 40];

    let mut hasher = sha1::Sha1::new();
    hasher.update(
        [mac_salt_key, pad_one.as_ref(), data_len_buffer.as_ref(), data]
            .concat()
            .as_slice(),
    );
    let sha_result = hasher.finalize();

    let pad_two: [u8; 48] = [0x5c; 48];

    let mut md5 = md5::Md5::new();
    md5.update(
        [mac_salt_key, pad_two.as_ref(), sha_result.as_ref()]
            .concat()
            .as_slice(),
    );

    Ok(md5.finalize().to_vec())
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum LicensePdu {
    ClientNewLicenseRequest(ClientNewLicenseRequest),
    ClientLicenseInfo(ClientLicenseInfo),
    ClientPlatformChallengeResponse(ClientPlatformChallengeResponse),
    ServerLicenseRequest(ServerLicenseRequest),
    ServerPlatformChallenge(ServerPlatformChallenge),
    ServerUpgradeLicense(ServerUpgradeLicense),
    LicensingErrorMessage(LicensingErrorMessage),
}

impl<'de> Decode<'de> for LicensePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let license_header = LicenseHeader::decode(src)?;

        match license_header.preamble_message_type {
            PreambleType::LicenseRequest => Ok(ServerLicenseRequest::decode(license_header, src)?.into()),
            PreambleType::PlatformChallenge => Ok(ServerPlatformChallenge::decode(license_header, src)?.into()),
            PreambleType::NewLicense | PreambleType::UpgradeLicense => {
                Ok(ServerUpgradeLicense::decode(license_header, src)?.into())
            }
            PreambleType::LicenseInfo => Err(unsupported_value_err!(
                "LicensePdu::LicenseInfo",
                "LicenseInfo is not supported".to_owned()
            )),
            PreambleType::NewLicenseRequest => Ok(ClientNewLicenseRequest::decode(license_header, src)?.into()),
            PreambleType::PlatformChallengeResponse => {
                Ok(ClientPlatformChallengeResponse::decode(license_header, src)?.into())
            }
            PreambleType::ErrorAlert => Ok(LicensingErrorMessage::decode(license_header, src)?.into()),
        }
    }
}

impl Encode for LicensePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        match self {
            Self::ClientNewLicenseRequest(pdu) => pdu.encode(dst),
            Self::ClientLicenseInfo(pdu) => pdu.encode(dst),
            Self::ClientPlatformChallengeResponse(pdu) => pdu.encode(dst),
            Self::ServerLicenseRequest(pdu) => pdu.encode(dst),
            Self::ServerPlatformChallenge(pdu) => pdu.encode(dst),
            Self::ServerUpgradeLicense(pdu) => pdu.encode(dst),
            Self::LicensingErrorMessage(pdu) => pdu.encode(dst),
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::ClientNewLicenseRequest(pdu) => pdu.name(),
            Self::ClientLicenseInfo(pdu) => pdu.name(),
            Self::ClientPlatformChallengeResponse(pdu) => pdu.name(),
            Self::ServerLicenseRequest(pdu) => pdu.name(),
            Self::ServerPlatformChallenge(pdu) => pdu.name(),
            Self::ServerUpgradeLicense(pdu) => pdu.name(),
            Self::LicensingErrorMessage(pdu) => pdu.name(),
        }
    }

    fn size(&self) -> usize {
        match self {
            Self::ClientNewLicenseRequest(pdu) => pdu.size(),
            Self::ClientLicenseInfo(pdu) => pdu.size(),
            Self::ClientPlatformChallengeResponse(pdu) => pdu.size(),
            Self::ServerLicenseRequest(pdu) => pdu.size(),
            Self::ServerPlatformChallenge(pdu) => pdu.size(),
            Self::ServerUpgradeLicense(pdu) => pdu.size(),
            Self::LicensingErrorMessage(pdu) => pdu.size(),
        }
    }
}

impl From<ClientNewLicenseRequest> for LicensePdu {
    fn from(pdu: ClientNewLicenseRequest) -> Self {
        Self::ClientNewLicenseRequest(pdu)
    }
}

impl From<ClientLicenseInfo> for LicensePdu {
    fn from(pdu: ClientLicenseInfo) -> Self {
        Self::ClientLicenseInfo(pdu)
    }
}

impl From<ClientPlatformChallengeResponse> for LicensePdu {
    fn from(pdu: ClientPlatformChallengeResponse) -> Self {
        Self::ClientPlatformChallengeResponse(pdu)
    }
}

impl From<ServerLicenseRequest> for LicensePdu {
    fn from(pdu: ServerLicenseRequest) -> Self {
        Self::ServerLicenseRequest(pdu)
    }
}

impl From<ServerPlatformChallenge> for LicensePdu {
    fn from(pdu: ServerPlatformChallenge) -> Self {
        Self::ServerPlatformChallenge(pdu)
    }
}

impl From<ServerUpgradeLicense> for LicensePdu {
    fn from(pdu: ServerUpgradeLicense) -> Self {
        Self::ServerUpgradeLicense(pdu)
    }
}

impl From<LicensingErrorMessage> for LicensePdu {
    fn from(pdu: LicensingErrorMessage) -> Self {
        Self::LicensingErrorMessage(pdu)
    }
}
