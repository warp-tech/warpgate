use std::fs;

use picky::key::PrivateKey;
use picky::x509::Cert;

use crate::{Error, ErrorKind, WinScardResult};

/// Emulated smart card PIN code.
pub const WINSCARD_PIN_ENV: &str = "WINSCARD_SMARTCARD_PIN";
/// Path to the user certificate to be used in emulated smart card.
pub const WINSCARD_CERT_PATH_ENV: &str = "WINSCARD_CERTIFICATE_FILE_PATH";
/// Smart card certificate data.
///
/// *Note.* The variable value should be one-line base64 string containing ASN1 DER certificate data.
pub const WINSCARD_CERT_DATA_ENV: &str = "WINSCARD_CERTIFICATE_FILE_DATA";
/// Path to the certificate private key.
pub const WINSCARD_PK_PATH_ENV: &str = "WINSCARD_PRIVATE_KEY_FILE_PATH";
/// Smart card private key data.
///
/// *Note.* The variable value should be one-line base64 string containing ASN1 DER private key.
pub const WINSCARD_PK_DATA_ENV: &str = "WINSCARD_PRIVATE_KEY_FILE_DATA";
/// Emulated smart card container name.
pub const WINSCARD_CONTAINER_NAME_ENV: &str = "WINSCARD_SMARTCARD_CONTAINER_NAME";
/// Emulated smart card reader name.
pub const WINSCARD_READER_NAME_ENV: &str = "WINSCARD_SMARTCARD_READER_NAME";

/// Tries to get the smart card container name from the environment variable.
///
/// For the successful execution, the [WINSCARD_CONTAINER_NAME_ENV] variable should be set.
pub fn container_name() -> WinScardResult<String> {
    env!(WINSCARD_CONTAINER_NAME_ENV)
}

/// Tries to read the smart card auth certificate from the environment variable.
///
/// For the successful execution, either [WINSCARD_CERT_DATA_ENV] or [WINSCARD_CERT_PATH_ENV] variable should be set.
pub fn auth_cert_from_env() -> WinScardResult<Cert> {
    if let Ok(cert_data) = env!(WINSCARD_CERT_DATA_ENV) {
        use base64::Engine;

        let cert_der = base64::engine::general_purpose::STANDARD.decode(cert_data)?;

        Ok(Cert::from_der(&cert_der)?)
    } else if let Ok(cert_path) = env!(WINSCARD_CERT_PATH_ENV) {
        let raw_certificate = fs::read_to_string(cert_path).map_err(|e| {
            Error::new(
                ErrorKind::InvalidParameter,
                format!("Unable to read certificate from the provided file: {e}"),
            )
        })?;
        Ok(Cert::from_pem_str(&raw_certificate)?)
    } else {
        Err(Error::new(
            ErrorKind::InvalidParameter,
            format!(
                "Either \"{WINSCARD_CERT_DATA_ENV}\" or \"{WINSCARD_CERT_PATH_ENV}\" environment variable must be present"
            ),
        ))
    }
}

/// Tries to read the smart card certificate private key from the environment variable.
///
/// For the successful execution, either [WINSCARD_PK_DATA_ENV] or [WINSCARD_PK_PATH_ENV] variable should be set.
pub fn private_key_from_env() -> WinScardResult<(String, PrivateKey)> {
    if let Ok(private_key_data) = env!(WINSCARD_PK_DATA_ENV) {
        use base64::Engine;

        let private_key_der = base64::engine::general_purpose::STANDARD.decode(private_key_data)?;

        let private_key = PrivateKey::from_pkcs8(&private_key_der)?;
        let raw_private_key = private_key.to_pem_str()?;

        Ok((raw_private_key, private_key))
    } else if let Ok(pk_path) = env!(WINSCARD_PK_PATH_ENV) {
        let raw_private_key = fs::read_to_string(pk_path).map_err(|e| {
            Error::new(
                ErrorKind::InvalidParameter,
                format!("Unable to read private key from the provided file: {e}"),
            )
        })?;
        let private_key = PrivateKey::from_pem_str(&raw_private_key).map_err(|e| {
            Error::new(
                ErrorKind::InvalidParameter,
                format!("Error while trying to read a private key from a pem-encoded string: {e}"),
            )
        })?;

        Ok((raw_private_key, private_key))
    } else {
        Err(Error::new(
            ErrorKind::InvalidParameter,
            format!(
                "Either \"{WINSCARD_PK_DATA_ENV}\" or \"{WINSCARD_PK_PATH_ENV}\" environment variable must be present"
            ),
        ))
    }
}
