use std::ptr::NonNull;
use std::slice::from_raw_parts;
use std::sync::{Arc, Mutex};

use picky::hash::HashAlgorithm;
use picky_asn1_x509::{AttributeTypeAndValueParameters, Certificate, ExtensionView, oids};
use windows::Win32::Security::Cryptography::{
    BCRYPT_PKCS1_PADDING_INFO, BCRYPT_SHA1_ALGORITHM, CERT_CONTEXT, CERT_KEY_SPEC, CERT_OPEN_STORE_FLAGS,
    CERT_QUERY_ENCODING_TYPE, CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER_ID,
    CERT_SYSTEM_STORE_LOCATION_SHIFT, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, CertCloseStore,
    CertDuplicateCertificateContext, CertEnumCertificatesInStore, CertFreeCertificateContext, CertOpenStore,
    CryptAcquireCertificatePrivateKey, HCERTSTORE, HCRYPTPROV_LEGACY, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE, NCRYPT_HANDLE,
    NCRYPT_KEY_HANDLE, NCRYPT_PAD_PKCS1_FLAG, NCryptFreeObject, NCryptSignHash,
};

use crate::credssp::NStatusCode;
use crate::pku2u::Pku2uPrivateKey;
use crate::{Error, ErrorKind, Result};

#[derive(Debug)]
struct CngPrivateKey {
    handle: Mutex<usize>,
    free_on_drop: bool,
    certificate_context: Option<usize>,
}

impl CngPrivateKey {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let digest = HashAlgorithm::SHA1.digest(data);
        let padding = BCRYPT_PKCS1_PADDING_INFO {
            pszAlgId: BCRYPT_SHA1_ALGORITHM,
        };
        let handle = self
            .handle
            .lock()
            .map_err(|_| Error::new(ErrorKind::InternalError, "PKU2U CNG key lock is poisoned"))?;
        let handle = NCRYPT_KEY_HANDLE(*handle);
        let mut signature_len = 0;

        // SAFETY: `handle` is retained for this signer lifetime and the padding
        // structure and digest slices remain valid for both calls.
        unsafe {
            NCryptSignHash(
                handle,
                Some((&raw const padding).cast()),
                &digest,
                None,
                &mut signature_len,
                NCRYPT_PAD_PKCS1_FLAG,
            )
        }
        .map_err(|error| Error::new(ErrorKind::InternalError, format!("NCryptSignHash failed: {error}")))?;

        let mut signature = vec![0; signature_len.try_into()?];
        // SAFETY: the output buffer has the exact size requested by CNG.
        unsafe {
            NCryptSignHash(
                handle,
                Some((&raw const padding).cast()),
                &digest,
                Some(&mut signature),
                &mut signature_len,
                NCRYPT_PAD_PKCS1_FLAG,
            )
        }
        .map_err(|error| Error::new(ErrorKind::InternalError, format!("NCryptSignHash failed: {error}")))?;
        signature.truncate(signature_len.try_into()?);

        Ok(signature)
    }
}

impl Drop for CngPrivateKey {
    fn drop(&mut self) {
        if self.free_on_drop {
            let handle = match self.handle.lock() {
                Ok(handle) => *handle,
                Err(poisoned) => *poisoned.into_inner(),
            };
            // SAFETY: this handle was returned by
            // `CryptAcquireCertificatePrivateKey` with caller ownership.
            let _ = unsafe { NCryptFreeObject(NCRYPT_HANDLE(handle)) };
        }
        if let Some(certificate_context) = self.certificate_context {
            let certificate_context = std::ptr::with_exposed_provenance::<CERT_CONTEXT>(certificate_context);
            // SAFETY: this is a duplicated certificate-context reference retained
            // to preserve a provider-owned key handle.
            let _ = unsafe { CertFreeCertificateContext(Some(certificate_context)) };
        }
    }
}

/// Validates the device certificate.
///
/// Requirements for the device certificate:
/// 1. Issuer CN starts with 'MS-Organization-P2P-Access'
/// 2. ClientAuth extended key usage present
fn validate_client_p2p_certificate(certificate: &Certificate) -> bool {
    let mut cn = false;

    for attr_type_and_value in certificate.tbs_certificate.issuer.0.0.iter() {
        for v in attr_type_and_value.0.iter() {
            if v.ty.0 == oids::at_common_name()
                && let AttributeTypeAndValueParameters::CommonName(name) = &v.value
                && name.to_utf8_lossy().starts_with("MS-Organization-P2P-Access")
            {
                cn = true;
            }
        }
    }

    if !cn {
        return false;
    }

    let mut client_auth = false;

    for extension in &certificate.tbs_certificate.extensions.0.0 {
        if extension.extn_id().0 == oids::extended_key_usage()
            && let ExtensionView::ExtendedKeyUsage(ext_key_usage) = extension.extn_value()
            && ext_key_usage.contains(oids::kp_client_auth())
        {
            client_auth = true;
        }
    }

    client_auth
}

/// Acquires the certificate private key without exporting its key material.
///
/// # Safety
///
/// `cert` must be a valid, non-null pointer to a `CERT_CONTEXT` structure.
unsafe fn acquire_certificate_private_key(cert: NonNull<CERT_CONTEXT>) -> Result<Pku2uPrivateKey> {
    let mut private_key_handle = HCRYPTPROV_OR_NCRYPT_KEY_HANDLE::default();
    let mut spec = CERT_KEY_SPEC::default();
    let mut free = windows::core::BOOL::default();

    // SAFETY:
    // - `cert` is guaranteed to be non null and is valid.
    // - All other arguments are type checked.
    let status = unsafe {
        CryptAcquireCertificatePrivateKey(
            cert.as_ptr(),
            CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
            None,
            &mut private_key_handle,
            Some(&mut spec),
            Some(&mut free),
        )
    };

    if let Err(error) = status {
        let code = error.code();

        error!(
            code = code.0,
            private_key_handle = private_key_handle.0,
            "Cannot acquire certificate private key handle",
        );

        return Err(Error::new(
            ErrorKind::InvalidHandle,
            "Cannot extract certificate private key: invalid handle",
        ));
    }

    let free_on_drop = free.as_bool();
    let certificate_context = if free_on_drop {
        None
    } else {
        // SAFETY: `cert` is a live certificate context. The duplicate keeps any
        // provider-owned key handle alive after the enumeration reference is freed.
        let duplicate = unsafe { CertDuplicateCertificateContext(Some(cert.as_ptr())) };
        if duplicate.is_null() {
            return Err(Error::new(
                ErrorKind::InternalError,
                "Cannot retain certificate context for provider-owned PKU2U key",
            ));
        }
        Some(duplicate.expose_provenance())
    };
    let private_key = Arc::new(CngPrivateKey {
        handle: Mutex::new(private_key_handle.0),
        free_on_drop,
        certificate_context,
    });

    Ok(Pku2uPrivateKey::from_signer(move |data| private_key.sign(data)))
}

/// Extracts the client P2P certificate and its private key from the provided certificate store
///
/// # Safety
///
/// `cert_store` must be a valid, non-null certificate store handle obtained using the `CertOpenStore` function.
unsafe fn extract_client_p2p_certificate(cert_store: HCERTSTORE) -> Result<(Certificate, Pku2uPrivateKey)> {
    // SAFETY: `cert_store` is not null.
    let mut certificate = unsafe { CertEnumCertificatesInStore(cert_store, None) };

    while !certificate.is_null() {
        // SAFETY:
        // - `certificate` is not null.
        let certificate_data = unsafe { (*certificate).pbCertEncoded };
        // SAFETY:
        // - `certificate` is not null.
        let certificate_len: usize = unsafe { (*certificate).cbCertEncoded }.try_into()?;
        // SAFETY:
        // - `certificate` is not null.
        // - `(*certificate).pbCertEncoded` and `(*certificate).cbCertEncoded` are valid `data` and `len`.
        let cert_der = unsafe { from_raw_parts(certificate_data, certificate_len) };
        let cert: Certificate = picky_asn1_der::from_bytes(cert_der)?;

        if !validate_client_p2p_certificate(&cert) {
            // SAFETY:
            // - `cert_store` is not null.
            // - `certificate` is not null.
            let next_certificate = unsafe { CertEnumCertificatesInStore(cert_store, Some(certificate)) };

            certificate = next_certificate;

            continue;
        }

        debug!(
            serial_number = ?cert.tbs_certificate.serial_number.0,
            "Found suitable client p2p certificate",
        );

        // SAFETY: `certificate` is not null.
        let private_key = unsafe {
            acquire_certificate_private_key(NonNull::new(certificate).expect("certificate pointer to be valid"))
        };

        // The function always returns nonzero.
        // More info: https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfreecertificatecontext.
        // SAFETY: `certificate` is not null.
        let _ = unsafe { CertFreeCertificateContext(Some(certificate)) };

        return Ok((cert, private_key?));
    }

    Err(Error::new(
        ErrorKind::InternalError,
        "Cannot find appropriate device certificate",
    ))
}

// There is no specification/documentation that said where the P2P certificates should be installed.
// During dev testing, we notice that they always are in the Personal folder.
// So we assume that the needed certificates are placed in this folder
// It uses the "My" certificates store that has access to the Personal folder in order to extract those certificates.
pub(crate) fn extract_client_p2p_cert_and_key() -> Result<(Certificate, Pku2uPrivateKey)> {
    // "My\0" encoded as a wide string.
    // More info: https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopenstore#remarks
    let my: [u16; 3] = [77, 121, 0];

    // SAFETY: `my` is not null and is a correct wide string, and all other arguments are type-checked.
    let cert_store = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            CERT_QUERY_ENCODING_TYPE(0),
            Some(HCRYPTPROV_LEGACY(0)),
            CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT),
            Some(my.as_ptr().cast()),
        )
    };

    let cert_store = cert_store.map_err(|error| Error {
        error_type: ErrorKind::InternalError,
        description: "Cannot initialize certificate store".into(),
        nstatus: NStatusCode::try_from(error.code()).ok(),
    })?;

    // SAFETY: `cert_store` is not null. We've checked this above.
    let cert_and_key = unsafe { extract_client_p2p_certificate(cert_store) };

    // The function always returns nonzero.
    // More info: https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfreecertificatecontext.
    // SAFETY: `cert_store` is not null. We've checked this above.
    let _ = unsafe { CertCloseStore(Some(cert_store), 0) };

    cert_and_key
}

#[cfg(test)]
mod tests {
    use picky_asn1_x509::Certificate;

    use super::validate_client_p2p_certificate;

    #[test]
    fn test_client_p2p_certificate_validation() {
        let certificate: Certificate = picky_asn1_der::from_bytes(&[
            48, 130, 3, 213, 48, 130, 2, 189, 160, 3, 2, 1, 2, 2, 16, 51, 247, 184, 98, 224, 162, 21, 50, 174, 177,
            189, 96, 58, 124, 107, 164, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 77, 49, 75, 48,
            73, 6, 3, 85, 4, 3, 30, 66, 0, 77, 0, 83, 0, 45, 0, 79, 0, 114, 0, 103, 0, 97, 0, 110, 0, 105, 0, 122, 0,
            97, 0, 116, 0, 105, 0, 111, 0, 110, 0, 45, 0, 80, 0, 50, 0, 80, 0, 45, 0, 65, 0, 99, 0, 99, 0, 101, 0, 115,
            0, 115, 0, 32, 0, 91, 0, 50, 0, 48, 0, 50, 0, 50, 0, 93, 48, 30, 23, 13, 50, 50, 49, 48, 50, 54, 49, 51,
            50, 51, 53, 56, 90, 23, 13, 50, 50, 49, 48, 50, 54, 49, 52, 50, 56, 53, 56, 90, 48, 129, 142, 49, 52, 48,
            50, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 36, 97, 57, 50, 53, 50, 52, 52, 56, 45, 57, 97,
            98, 55, 45, 52, 57, 98, 48, 45, 98, 98, 53, 99, 45, 102, 50, 102, 57, 50, 51, 99, 56, 52, 54, 55, 50, 49,
            61, 48, 59, 6, 3, 85, 4, 3, 12, 52, 83, 45, 49, 45, 49, 50, 45, 49, 45, 51, 54, 53, 51, 50, 49, 49, 48, 50,
            50, 45, 49, 51, 51, 57, 48, 48, 54, 52, 50, 50, 45, 50, 54, 50, 55, 53, 55, 51, 57, 48, 48, 45, 49, 53, 54,
            48, 55, 51, 52, 57, 49, 57, 49, 23, 48, 21, 6, 3, 85, 4, 3, 12, 14, 115, 55, 64, 100, 97, 116, 97, 97, 110,
            115, 46, 99, 111, 109, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1,
            15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 199, 60, 253, 49, 157, 172, 15, 185, 180, 104, 241, 218, 22, 185,
            120, 213, 135, 223, 222, 100, 75, 148, 218, 177, 71, 131, 140, 8, 195, 173, 7, 244, 41, 200, 45, 77, 173,
            68, 205, 213, 27, 72, 246, 147, 167, 184, 52, 81, 44, 28, 143, 238, 201, 186, 143, 111, 62, 224, 73, 86,
            69, 249, 239, 44, 79, 115, 37, 185, 243, 1, 23, 234, 116, 28, 244, 221, 99, 62, 177, 39, 128, 239, 115, 47,
            184, 135, 25, 43, 109, 246, 200, 11, 116, 38, 99, 167, 136, 48, 59, 187, 188, 40, 216, 85, 133, 246, 5,
            130, 177, 220, 6, 210, 34, 164, 15, 207, 125, 223, 42, 190, 77, 109, 69, 224, 132, 147, 115, 110, 39, 205,
            112, 140, 44, 215, 43, 252, 206, 89, 55, 161, 210, 166, 234, 223, 0, 198, 24, 70, 158, 56, 78, 23, 76, 249,
            86, 198, 95, 207, 53, 220, 75, 246, 91, 138, 99, 193, 186, 97, 57, 207, 115, 14, 1, 251, 111, 180, 121, 41,
            132, 254, 82, 109, 66, 202, 11, 20, 14, 31, 242, 55, 225, 112, 210, 220, 229, 155, 152, 202, 92, 54, 223,
            38, 153, 248, 173, 168, 180, 70, 146, 219, 186, 166, 251, 234, 149, 41, 18, 61, 227, 148, 13, 141, 229, 1,
            49, 212, 128, 67, 225, 120, 7, 122, 41, 102, 241, 223, 249, 198, 117, 89, 37, 177, 142, 85, 24, 136, 230,
            160, 136, 43, 89, 66, 41, 220, 85, 85, 2, 3, 1, 0, 1, 163, 111, 48, 109, 48, 14, 6, 3, 85, 29, 15, 1, 1,
            255, 4, 4, 3, 2, 5, 160, 48, 41, 6, 3, 85, 29, 17, 4, 34, 48, 32, 160, 30, 6, 10, 43, 6, 1, 4, 1, 130, 55,
            20, 2, 3, 160, 16, 12, 14, 115, 55, 64, 100, 97, 116, 97, 97, 110, 115, 46, 99, 111, 109, 48, 19, 6, 3, 85,
            29, 37, 4, 12, 48, 10, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 27, 6, 9, 43, 6, 1, 4, 1, 130, 55, 21, 10, 4, 14,
            48, 12, 48, 10, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 3,
            130, 1, 1, 0, 71, 217, 65, 65, 121, 161, 60, 132, 114, 210, 31, 169, 34, 170, 87, 169, 50, 137, 52, 187,
            116, 98, 61, 8, 255, 89, 197, 131, 73, 33, 17, 136, 188, 42, 180, 22, 239, 101, 126, 28, 138, 35, 108, 101,
            138, 50, 54, 5, 105, 17, 85, 172, 239, 78, 21, 202, 246, 237, 51, 210, 17, 184, 39, 190, 135, 109, 73, 210,
            243, 138, 142, 72, 67, 206, 58, 129, 133, 215, 161, 103, 57, 97, 99, 131, 85, 45, 160, 129, 144, 5, 184,
            191, 7, 114, 24, 7, 237, 81, 246, 242, 94, 232, 161, 230, 108, 97, 184, 185, 182, 200, 178, 44, 7, 76, 10,
            47, 156, 88, 110, 198, 193, 125, 190, 84, 225, 93, 53, 87, 183, 14, 49, 118, 233, 217, 171, 139, 75, 131,
            8, 222, 241, 87, 3, 146, 243, 55, 69, 62, 204, 146, 92, 118, 241, 104, 209, 178, 228, 246, 199, 220, 104,
            32, 189, 125, 84, 82, 250, 215, 218, 10, 9, 21, 185, 251, 180, 51, 254, 67, 144, 78, 230, 201, 78, 127, 92,
            159, 26, 51, 223, 195, 192, 177, 251, 137, 234, 64, 37, 65, 76, 246, 118, 216, 224, 83, 152, 110, 67, 117,
            201, 2, 253, 173, 128, 73, 76, 26, 179, 93, 24, 227, 242, 121, 254, 170, 226, 31, 88, 196, 194, 58, 86,
            255, 192, 36, 221, 100, 20, 198, 221, 242, 249, 196, 211, 98, 111, 198, 220, 135, 239, 82, 74, 139, 243, 2,
            25, 215,
        ])
        .unwrap();

        assert!(validate_client_p2p_certificate(&certificate));
    }
}
