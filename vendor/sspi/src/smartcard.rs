#![cfg(feature = "scard")]

use std::borrow::Cow;
use std::fmt;
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

#[cfg(not(target_arch = "wasm32"))]
use cryptoki::context::{CInitializeArgs, Pkcs11};
#[cfg(not(target_arch = "wasm32"))]
use cryptoki::mechanism::Mechanism;
#[cfg(not(target_arch = "wasm32"))]
use cryptoki::object::{Attribute, KeyType, ObjectClass};
#[cfg(not(target_arch = "wasm32"))]
use cryptoki::session::UserType;
#[cfg(not(target_arch = "wasm32"))]
use cryptoki::types::AuthPin;
use picky::key::PrivateKey;
use winscard::SmartCard as PivSmartCard;

use crate::{Error, ErrorKind, Result, Secret, SmartCardIdentity, SmartCardType};

/// Smart cad API to use.
pub(crate) enum SmartCardApi {
    /// Represents emulated smart cards API.
    ///
    /// No real device or driver is needed.
    PivEmulated(Box<PivSmartCard<'static>>),
    #[cfg(not(target_arch = "wasm32"))]
    /// Represents system-provided smart card API.
    ///
    /// PKCS11 API will be used for data signing.
    Pkcs11 {
        /// PKCS11 module.
        pkcs11_module: Pkcs11,
        /// Reader name.
        ///
        /// Reader name is needed to determine which PKCS11 slot to use.
        reader_name: String,
    },
    /// Represents Windows native smart card API.
    ///
    /// The native Windows API will be used for data signing.
    #[cfg(target_os = "windows")]
    Windows {
        /// key container name.
        container_name: String,
    },
}

impl fmt::Debug for SmartCardApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PivEmulated { .. } => f.write_str("SmartCardApi::PivEmulated"),
            #[cfg(not(target_arch = "wasm32"))]
            Self::Pkcs11 { .. } => f.write_str("SmartCardApi::Pkcs11"),
            #[cfg(target_os = "windows")]
            Self::Windows { .. } => f.write_str("SmartCardApi::Windows"),
        }
    }
}

/// Generic interface for data signing using smart card.
///
/// This implementation can use any supported smart card type. It depends on the provided credentials set.
#[derive(Debug)]
pub(crate) struct SmartCard {
    smart_card_type: SmartCardApi,
    pin: Secret<Vec<u8>>,
}

impl SmartCard {
    /// Creates a new [SmartCard] instance from the provided credentials.
    pub(crate) fn from_credentials(credentials: &SmartCardIdentity) -> Result<Self> {
        let SmartCardIdentity {
            username: _,
            certificate,
            reader_name,
            card_name: _,
            container_name: _container_name,
            csp_name: _,
            pin: user_pin,
            private_key,
            scard_type,
        } = credentials;

        let user_pin = user_pin.clone();

        match scard_type {
            SmartCardType::Emulated { scard_pin } => {
                let private_key = private_key
                    .as_ref()
                    .ok_or(Error::new(
                        ErrorKind::IncompleteCredentials,
                        "emulated smart card private key is missing",
                    ))?
                    .as_ref()
                    .clone();

                Self::new_emulated(
                    Cow::Owned(reader_name.clone()),
                    scard_pin.as_ref().to_vec(),
                    user_pin,
                    private_key,
                    picky_asn1_der::to_vec(certificate)?,
                )
            }
            #[cfg(not(target_arch = "wasm32"))]
            SmartCardType::SystemProvided { pkcs11_module_path } => {
                Self::new_system_provided(pkcs11_module_path, user_pin, reader_name.clone())
            }
            #[cfg(target_os = "windows")]
            SmartCardType::WindowsNative => Self::new_windows_native(
                user_pin,
                _container_name
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorKind::NoCredentials, "container name is not provided"))?
                    .to_owned(),
            ),
        }
    }

    /// Creates a new [SmartCard] instance with the emulated smart card inside.
    fn new_emulated(
        reader_name: Cow<'static, str>,
        scard_pin: Vec<u8>,
        user_pin: Secret<Vec<u8>>,
        private_key: PrivateKey,
        auth_cert_der: Vec<u8>,
    ) -> Result<Self> {
        let scard = PivSmartCard::new(reader_name, scard_pin, auth_cert_der, private_key)?;

        Ok(Self {
            smart_card_type: SmartCardApi::PivEmulated(Box::new(scard)),
            pin: user_pin,
        })
    }

    /// Creates a new [SmartCard] instance with the system provided smart card inside (Windows API).
    #[cfg(target_os = "windows")]
    fn new_windows_native(user_pin: Secret<Vec<u8>>, container_name: String) -> Result<Self> {
        Ok(Self {
            smart_card_type: SmartCardApi::Windows { container_name },
            pin: user_pin,
        })
    }

    /// Creates a new [SmartCard] instance with the system provided smart card inside.
    #[cfg(not(target_arch = "wasm32"))]
    fn new_system_provided(pkcs11_module_path: &Path, user_pin: Secret<Vec<u8>>, reader_name: String) -> Result<Self> {
        use cryptoki::context::CInitializeFlags;

        let pkcs11 = Pkcs11::new(pkcs11_module_path)?;
        pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;

        Ok(Self {
            smart_card_type: SmartCardApi::Pkcs11 {
                pkcs11_module: pkcs11,
                reader_name,
            },
            pin: user_pin,
        })
    }

    /// Signs the provided byte slice using smart card.
    pub(crate) fn sign(&mut self, digest: Vec<u8>) -> Result<Vec<u8>> {
        match &mut self.smart_card_type {
            SmartCardApi::PivEmulated(scard) => {
                scard.verify_pin(self.pin.as_ref())?;
                Ok(scard.sign_hashed(digest)?)
            }
            #[cfg(not(target_arch = "wasm32"))]
            SmartCardApi::Pkcs11 {
                pkcs11_module,
                reader_name,
            } => {
                let slot = 's: {
                    for slot in pkcs11_module.get_slots_with_token()? {
                        let slot_info = pkcs11_module.get_slot_info(slot)?;

                        if slot_info.slot_description() == reader_name {
                            break 's slot;
                        }
                    }

                    return Err(Error::new(
                        ErrorKind::NoCredentials,
                        format!("provided reader name ({reader_name}) does not match any smart card slots"),
                    ));
                };

                let session = pkcs11_module.open_ro_session(slot)?;

                let pin = String::from_utf8(self.pin.as_ref().to_vec())?;
                let pin = AuthPin::new(pin.into());
                session.login(UserType::User, Some(&pin))?;

                let objects = session.find_objects(&[
                    Attribute::Class(ObjectClass::PRIVATE_KEY),
                    Attribute::KeyType(KeyType::RSA),
                ])?;

                let data_to_sign = encode_digest(digest)?;

                for private_key in objects {
                    if let Ok(signature) = session.sign(&Mechanism::RsaPkcs, private_key, &data_to_sign) {
                        return Ok(signature);
                    }
                }

                Err(Error::new(
                    ErrorKind::NoCredentials,
                    format!(
                        "the selected PKCS11 slot ({reader_name}) does not have a suitable private key for data signing"
                    ),
                ))
            }
            #[cfg(target_os = "windows")]
            SmartCardApi::Windows { container_name } => sign_data_win_api(container_name, self.pin.as_ref(), &digest),
        }
    }
}

/// Constructs the [DigestInfo] structure and encodes it into byte vector.
///
/// During the RDP authorization, we need to sign the data digest using smart card. We must
/// use PKCS1 padding scheme. It means, that the [DigestInfo] structure must be constructed
/// with the digest inside. Smart card will sign encoded [DigestInfo] structure.
///
/// `sspi-rs` uses SHA1 during scard logon. Thus, input `digest` must be SHA1 hash of the data we want to sign.
fn encode_digest(digest: Vec<u8>) -> Result<Vec<u8>> {
    use picky_asn1::wrapper::OctetStringAsn1;
    use picky_asn1_x509::{AlgorithmIdentifier, DigestInfo};

    let digest_info = DigestInfo {
        oid: AlgorithmIdentifier::new_sha1(),
        digest: OctetStringAsn1::from(digest),
    };

    Ok(picky_asn1_der::to_vec(&digest_info)?)
}

/// Signs data using the Windows native API for smart cards.
///
/// This function uses the Cryptography Next Generation (CNG) API to sign the data: https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/.
#[cfg(target_os = "windows")]
fn sign_data_win_api(container_name: &str, pin: &[u8], data_to_sign: &[u8]) -> Result<Vec<u8>> {
    use std::ptr;

    use windows::Win32::Security::Cryptography::{
        BCRYPT_PKCS1_PADDING_INFO, BCRYPT_SHA1_ALGORITHM, CERT_KEY_SPEC, MS_SMART_CARD_KEY_STORAGE_PROVIDER,
        NCRYPT_FLAGS, NCRYPT_PAD_PKCS1_FLAG, NCRYPT_PIN_PROPERTY, NCRYPT_SILENT_FLAG, NCryptOpenKey,
        NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash,
    };
    use windows::core::{Owned, PCWSTR};

    use crate::{U16CString, U16CStringExt};

    let mut provider = Owned::default();
    // SAFETY: FFI call with no outstanding preconditions.
    unsafe { NCryptOpenStorageProvider(&mut *provider, MS_SMART_CARD_KEY_STORAGE_PROVIDER, 0) }.map_err(|err| {
        Error::new(
            ErrorKind::InternalError,
            format!(
                "failed to open smart card CNG key storage provider: {} ({:x})",
                err.message(),
                err.code().0
            ),
        )
    })?;

    let container_name = U16CString::from_str_truncate(container_name).into_vec_with_nul();
    let container_name = PCWSTR::from_raw(container_name.as_ptr());

    let mut key = Owned::default();
    // SAFETY:
    // - `provider` is a valid handle obtained from `NCryptOpenStorageProvider`.
    // - `container_name` is a valid UTF-16 string and null-terminated.
    unsafe {
        NCryptOpenKey(
            *provider,
            &mut *key,
            container_name,
            CERT_KEY_SPEC(0),
            NCRYPT_SILENT_FLAG,
        )
    }
    .map_err(|err| {
        Error::new(
            ErrorKind::InternalError,
            format!("failed to open smart card key: {} ({:x})", err.message(), err.code().0),
        )
    })?;

    // NCRYPT_PIN_PROPERTY: https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers
    // > A pointer to a null-terminated Unicode string that contains the PIN.
    let pin = U16CString::from_utf8_bytes(pin)?.to_bytes_with_nul();

    // SAFETY:
    // - `key` is a valid handle obtained from `NCryptOpenKey`.
    // - `pin` is a valid UTF-16 string and null-terminated.
    if let Err(err) = unsafe { NCryptSetProperty((*key).into(), NCRYPT_PIN_PROPERTY, pin.as_ref(), NCRYPT_FLAGS(0)) } {
        warn!(
            "Failed to set smart card PIN code: {} ({:x}) - this may cause issues with signing data.",
            err.message(),
            err.code().0
        );
    }

    let mut signature_len = 0;
    let padding_info = BCRYPT_PKCS1_PADDING_INFO {
        pszAlgId: BCRYPT_SHA1_ALGORITHM,
    };
    // SAFETY:
    // - `key` is a valid handle obtained from `NCryptOpenKey`.
    // - `padding_info`, and `signature_len` are local variables.
    // - `padding_info` has the `BCRYPT_PKCS1_PADDING_INFO` type which corresponds to the `NCRYPT_PAD_PKCS1_FLAG` flag.
    // - `pbSignature` is allowed to be NULL.
    //   > If this parameter is NULL, this function will calculate the size required for the signature and return the size in the location pointed to by the pcbResult parameter.
    unsafe {
        NCryptSignHash(
            *key,
            Some(ptr::from_ref(&padding_info).cast()),
            data_to_sign,
            None,
            &mut signature_len,
            NCRYPT_PAD_PKCS1_FLAG,
        )
    }
    .map_err(|err| {
        Error::new(
            ErrorKind::InternalError,
            format!("failed to get signature length: {} ({:x})", err.message(), err.code().0),
        )
    })?;

    let mut signature = vec![0_u8; usize::try_from(signature_len)?];
    // SAFETY:
    // - `key` is a valid handle obtained from `NCryptOpenKey`.
    // - `padding_info`, `signature`, and `signature_len` are local variables.
    // - `padding_info` has the `BCRYPT_PKCS1_PADDING_INFO` type which corresponds to the `NCRYPT_PAD_PKCS1_FLAG` flag.
    unsafe {
        NCryptSignHash(
            *key,
            Some(ptr::from_ref(&padding_info).cast()),
            data_to_sign,
            Some(&mut signature),
            &mut signature_len,
            NCRYPT_PAD_PKCS1_FLAG,
        )
    }
    .map_err(|err| {
        Error::new(
            ErrorKind::InternalError,
            format!("failed to sign data: {} ({:x})", err.message(), err.code().0),
        )
    })?;

    Ok(signature)
}
