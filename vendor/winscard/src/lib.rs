#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

#[macro_use]
extern crate tracing;

#[macro_use]
mod macros;

mod ber_tlv;
mod cache;
mod card_capability_container;
mod chuid;
mod compression;
mod dummy_rng;
/// Contains env variables names that represent smart card credentials.
#[cfg(feature = "std")]
pub mod env;
mod piv_cert;
mod scard;
mod scard_context;
/// Constants with most popular tags used in this PIV smart card implementation.
pub mod tlv_tags;
/// The [winscard] module contains traits for easier interop between WinSCard API and our emulated scard.
pub mod winscard;

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::num::TryFromIntError;

pub use ber_tlv::ber_tlv_length_encoding;
pub use cache::Cache;
use iso7816_tlv::TlvError;
use num_derive::{FromPrimitive, ToPrimitive};
use picky::key::KeyError;
use picky::x509::certificate::CertError;
pub use scard::{
    ATR, CARD_AUTH_CERT_TAG, CHUNK_SIZE, DIGITAL_SIGNATURE_CERT_TAG, KEY_MANAGEMENT_CERT_TAG, PIV_AID, PIV_CERT_TAG,
    SUPPORTED_CONNECTION_PROTOCOL, SmartCard,
};
pub use scard_context::{
    DEFAULT_CARD_NAME, MICROSOFT_DEFAULT_CSP, MICROSOFT_DEFAULT_KSP, MICROSOFT_SCARD_DRIVER_LOCATION, Reader,
    ScardContext, SmartCardInfo,
};

/// The [WinScardResult] type.
pub type WinScardResult<T> = Result<T, Error>;

/// Represents a response after the APDU command execution.
#[derive(Debug)]
pub struct Response {
    /// Resulting APDU status.
    pub status: Status,
    /// Output APDU.
    pub data: Option<Vec<u8>>,
}

impl Response {
    /// Creates a new [Response] based on the `status` and `data`.
    pub fn new(status: Status, data: Option<Vec<u8>>) -> Self {
        Response { status, data }
    }
}

impl From<Status> for Response {
    fn from(value: Status) -> Self {
        Response::new(value, None)
    }
}

impl From<Response> for Vec<u8> {
    fn from(value: Response) -> Self {
        let status_as_bytes: [u8; 2] = value.status.into();
        let vec_capacity = status_as_bytes.len() + value.data.as_ref().map(|data| data.len()).unwrap_or(0);
        let mut encoded: Vec<u8> = Vec::with_capacity(vec_capacity);
        if let Some(bytes) = value.data {
            encoded.extend(bytes);
        }
        encoded.extend(status_as_bytes);
        encoded
    }
}

/// Represents general WinSCard error.
#[derive(Debug)]
pub struct Error {
    /// Represents on the defined [Smart Card Return Values](https://learn.microsoft.com/en-us/windows/win32/secauthn/authentication-return-values).
    pub error_kind: ErrorKind,
    /// Additional error description.
    pub description: String,
}

impl Error {
    /// Creates a new [Error] based on the `error_kind` and `description`.
    pub fn new(error_kind: ErrorKind, description: impl Into<String>) -> Self {
        Error {
            error_kind,
            description: description.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error{{ {:?}: {} }}", self.error_kind, self.description)?;
        Ok(())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(feature = "std")]
impl From<picky_asn1_der::Asn1DerError> for Error {
    fn from(value: picky_asn1_der::Asn1DerError) -> Self {
        Self::new(ErrorKind::InvalidValue, value.to_string())
    }
}

#[cfg(feature = "std")]
impl From<base64::DecodeError> for Error {
    fn from(value: base64::DecodeError) -> Self {
        Self::new(ErrorKind::InvalidValue, value.to_string())
    }
}

impl From<KeyError> for Error {
    fn from(value: KeyError) -> Self {
        Error::new(
            ErrorKind::InternalError,
            format!("error: an unexpected KeyError happened: {value}"),
        )
    }
}

impl From<rsa::Error> for Error {
    fn from(value: rsa::Error) -> Self {
        Error::new(
            ErrorKind::InternalError,
            format!("Error: an unexpected RsaError happened: {value}"),
        )
    }
}

impl From<TlvError> for Error {
    fn from(value: TlvError) -> Self {
        Error::new(
            ErrorKind::InternalError,
            format!("error: an unexpected TlvError happened: {value}"),
        )
    }
}

impl From<TryFromIntError> for Error {
    fn from(value: TryFromIntError) -> Self {
        Error::new(
            ErrorKind::InsufficientBuffer,
            format!("error: can not convert integers: {value}"),
        )
    }
}

impl From<CertError> for Error {
    fn from(value: CertError) -> Self {
        Error::new(ErrorKind::InsufficientBuffer, format!("certificate error: {value}"))
    }
}

impl From<core::convert::Infallible> for Error {
    fn from(_: core::convert::Infallible) -> Self {
        Error::new(ErrorKind::InternalError, "Infallible")
    }
}

impl From<core::str::Utf8Error> for Error {
    fn from(value: core::str::Utf8Error) -> Self {
        Error::new(ErrorKind::InternalError, format!("UTF-8 error: {value}"))
    }
}

impl From<alloc::string::FromUtf16Error> for Error {
    fn from(value: alloc::string::FromUtf16Error) -> Self {
        Error::new(ErrorKind::InvalidParameter, format!("UTF-16 error: {value}"))
    }
}

impl From<widestring::error::Utf16Error> for Error {
    fn from(value: widestring::error::Utf16Error) -> Self {
        Error::new(ErrorKind::InvalidParameter, format!("UTF-16 error: {value}"))
    }
}

impl From<widestring::error::ContainsNul<u16>> for Error {
    fn from(value: widestring::error::ContainsNul<u16>) -> Self {
        Error::new(ErrorKind::InvalidParameter, format!("UTF-16 error: {value}"))
    }
}

#[cfg(feature = "std")]
impl From<std::ffi::NulError> for Error {
    fn from(value: std::ffi::NulError) -> Self {
        Error::new(ErrorKind::InvalidParameter, value.to_string())
    }
}

/// [Smart Card Return Values](https://learn.microsoft.com/en-us/windows/win32/secauthn/authentication-return-values).
#[derive(Debug, PartialEq, ToPrimitive, FromPrimitive)]
#[repr(u32)]
pub enum ErrorKind {
    /// The client attempted a smart card operation in a remote session, such as a client session running on a terminal server,
    /// and the operating system in use does not support smart card redirection.
    BrokenPipe = 0x00000109,
    /// An error occurred in setting the smart card file object pointer.
    BadSeek = 0x80100029,
    /// The action was canceled by an SCardCancel request.
    Canceled = 0x80100002,
    /// The system could not dispose of the media in the requested manner.
    CantDispose = 0x8010000E,
    /// The smart card does not meet minimal requirements for support.
    CardUnsupported = 0x8010001C,
    /// The requested certificate could not be obtained.
    CertificateUnavailable = 0x8010002D,
    /// A communications error with the smart card has been detected.
    CommDataLost = 0x8010002F,
    /// The specified directory does not exist in the smart card.
    DirNotFound = 0x80100023,
    /// The reader driver did not produce a unique reader name.
    DuplicateReader = 0x8010001B,
    /// The specified file does not exist in the smart card.
    FileNotFound = 0x80100024,
    /// The requested order of object creation is not supported.
    IccCreateOrder = 0x80100021,
    /// No primary provider can be found for the smart card.
    IccInstallation = 0x80100020,
    /// The data buffer for returned data is too small for the returned data.
    InsufficientBuffer = 0x80100008,
    /// An ATR string obtained from the registry is not a valid ATR string.
    InvalidAtr = 0x80100015,
    /// The supplied PIN is incorrect.
    InvalidChv = 0x8010002A,
    /// The supplied handle was not valid.
    InvalidHandle = 0x80100003,
    /// One or more of the supplied parameters could not be properly interpreted.
    InvalidParameter = 0x80100004,
    /// Registry startup information is missing or not valid.
    InvalidTarget = 0x80100005,
    /// One or more of the supplied parameter values could not be properly interpreted.
    InvalidValue = 0x80100011,
    /// Access is denied to the file.
    NoAccess = 0x80100027,
    /// The supplied path does not represent a smart card directory.
    NoDir = 0x80100025,
    /// The supplied path does not represent a smart card file.
    NoFile = 0x80100026,
    /// The requested key container does not exist on the smart card.
    NoKeyContainer = 0x80100030,
    /// Not enough memory available to complete this command.
    NoMemory = 0x80100006,
    /// The smart card PIN cannot be cached.
    NoPinCache = 0x80100033,
    /// No smart card reader is available.
    NoReadersAvailable = 0x8010002E,
    /// The smart card resource manager is not running.
    NoService = 0x8010001D,
    /// The operation requires a smart card, but no smart card is currently in the device.
    NoSmartCard = 0x8010000C,
    /// The requested certificate does not exist.
    NoSuchCertificate = 0x8010002C,
    /// The reader or card is not ready to accept commands.
    NotReady = 0x80100010,
    /// An attempt was made to end a nonexistent transaction.
    NotTransacted = 0x80100016,
    /// The PCI receive buffer was too small.
    PciTooSmall = 0x80100019,
    /// The smart card PIN cache has expired.
    PinCacheExpired = 0x80100032,
    /// The requested protocols are incompatible with the protocol currently in use with the card.
    ProtoMismatch = 0x8010000F,
    /// The smart card is read-only and cannot be written to.
    ReadOnlyCard = 0x80100034,
    /// The specified reader is not currently available for use.
    ReaderUnavailable = 0x80100017,
    /// The reader driver does not meet minimal requirements for support.
    ReaderUnsupported = 0x8010001A,
    /// The smart card resource manager is too busy to complete this operation.
    ServerTooBusy = 0x80100031,
    /// The smart card resource manager has shut down.
    ServiceStopped = 0x8010001E,
    /// The smart card cannot be accessed because of other outstanding connections.
    SharingViolation = 0x8010000B,
    /// The action was canceled by the system, presumably to log off or shut down.
    SystemCanceled = 0x80100012,
    /// The user-specified time-out value has expired.
    Timeout = 0x8010000A,
    /// An unexpected card error has occurred.
    Unexpected = 0x8010001F,
    /// The specified smart card name is not recognized.
    UnknownCard = 0x8010000D,
    /// The specified reader name is not recognized.
    UnknownReader = 0x80100009,
    /// An unrecognized error code was returned.
    UnknownResMng = 0x8010002B,
    /// This smart card does not support the requested feature.
    UnsupportedFeature = 0x80100022,
    /// An attempt was made to write more data than would fit in the target object.
    WriteTooMany = 0x80100028,
    /// An internal communications error has been detected.
    CommError = 0x80100013,
    /// An internal consistency check failed.
    InternalError = 0x80100001,
    /// An internal error has been detected, but the source is unknown.
    UnknownError = 0x80100014,
    /// An internal consistency timer has expired.
    WaitedTooLong = 0x80100007,
    /// The operation has been aborted to allow the server application to exit.
    Shutdown = 0x80100018,
    /// No error was encountered.
    Success = 0,
    /// The action was canceled by the user.
    CanceledByUser = 0x8010006E,
    /// The requested item could not be found in the cache.
    CacheItemNotFound = 0x80100070,
    /// The requested cache item is too old and was deleted from the cache.
    CacheItemStale = 0x80100071,
    /// The new cache item exceeds the maximum per-item size defined for the cache.
    CacheItemTooBig = 0x80100072,
    /// No PIN was presented to the smart card.
    CardNotAuthenticated = 0x8010006F,
    /// The card cannot be accessed because the maximum number of PIN entry attempts has been reached.
    ChvBlocked = 0x8010006C,
    /// The end of the smart card file has been reached.
    Eof = 0x8010006D,
    /// The smart card has been removed, so further communication is not possible.
    RemovedCard = 0x80100069,
    /// The smart card was reset.
    ResetCard = 0x80100068,
    /// Access was denied because of a security violation.
    SecurityViolation = 0x8010006A,
    /// Power has been removed from the smart card, so that further communication is not possible.
    UnpoweredCard = 0x80100067,
    /// The smart card is not responding to a reset.
    UnresponsiveCard = 0x80100066,
    /// The reader cannot communicate with the card, due to ATR string configuration conflicts.
    UnsupportedCard = 0x80100065,
    /// The card cannot be accessed because the wrong PIN was presented.
    WrongChv = 0x8010006B,
}

impl From<ErrorKind> for u32 {
    fn from(value: ErrorKind) -> Self {
        #[expect(clippy::as_conversions, reason = "enum repr cast in From impl")]
        {
            value as u32
        }
    }
}

/// Represents Status Word (SW) - a 2-byte value returned by a card command at the card edge.
/// [Table 6. Status Words](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=36)
#[derive(Debug, Clone, PartialEq)]
pub enum Status {
    /// Data object or application not found.
    NotFound,
    /// Successful execution.
    OK,
    /// Verification failed, X indicates the number of further allowed retries or resets.
    /// Number of allowed retries is always 9.
    VerificationFailedWithRetries,
    /// Successful execution where SW2 encodes the number of response data bytes still available.
    MoreAvailable(u8),
    /// Referenced data or reference data not found.
    KeyReferenceNotFound,
    /// Security status not satisfied.
    SecurityStatusNotSatisfied,
    /// Incorrect parameter in P1 or P2.
    IncorrectP1orP2,
    /// Incorrect parameter in command data field.
    IncorrectDataField,
    /// Instruction code not supported or invalid.
    InstructionNotSupported,
}

// ISO/IEC 7816-4, Section 5.1.3, Tables 5-6
impl From<Status> for [u8; 2] {
    fn from(value: Status) -> Self {
        match value {
            Status::NotFound => [0x6A, 0x82],
            Status::OK => [0x90, 0x00],
            Status::VerificationFailedWithRetries => [0x63, 0xC9],
            Status::MoreAvailable(bytes_left) => [0x61, bytes_left],
            Status::KeyReferenceNotFound => [0x6A, 0x88],
            Status::SecurityStatusNotSatisfied => [0x69, 0x82],
            Status::IncorrectP1orP2 => [0x6A, 0x86],
            Status::IncorrectDataField => [0x6A, 0x80],
            Status::InstructionNotSupported => [0x6D, 0x00],
        }
    }
}
