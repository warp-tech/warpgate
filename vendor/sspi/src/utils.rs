use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BoxedUint, Odd, Resize};
use picky_krb::crypto::CipherSuite;
use rand::rngs::StdRng;
use rand_core::Rng as _;

use crate::kerberos::EncryptionParams;
use crate::{BufferType, Error, ErrorKind, Result, Secret, SecurityBufferFlags, SecurityBufferRef};

/// Writes an error and its full source chain to `w`, separated by `": "`.
///
/// This is a temporary workaround until [`std::error::Report`] is stabilised
/// (tracking issue: <https://github.com/rust-lang/rust/issues/90272>), at which
/// point callers can be migrated to `format!("{:#}", std::error::Report::new(e))`.
#[cfg(feature = "network_client")]
pub(crate) fn write_error_chain(w: &mut impl std::fmt::Write, e: &dyn std::error::Error) -> std::fmt::Result {
    write!(w, "{e}")?;
    let mut source = e.source();
    while let Some(s) = source {
        write!(w, ": {s}")?;
        source = s.source();
    }
    Ok(())
}

#[cfg_attr(not(target_os = "windows"), allow(unused))]
pub(crate) fn is_azure_ad_domain(domain: &str) -> bool {
    domain == crate::pku2u::AZURE_AD_DOMAIN
}

pub(crate) fn generate_random_symmetric_key(cipher: &CipherSuite, rnd: &mut StdRng) -> Vec<u8> {
    let key_size = cipher.cipher().key_size();
    let mut key = vec![0; key_size];
    rnd.fill_bytes(&mut key);

    key
}

pub(crate) fn map_keb_error_code_to_sspi_error(krb_error_code: u32) -> (ErrorKind, String) {
    use picky_krb::constants::error_codes::*;

    match krb_error_code {
        KDC_ERR_NONE => (ErrorKind::Unknown, "No error".into()),
        KDC_ERR_NAME_EXP => (
            ErrorKind::InvalidParameter,
            "client's entry in database has expired".into(),
        ),
        KDC_ERR_SERVICE_EXP => (
            ErrorKind::InvalidParameter,
            "server's entry in database has expired".into(),
        ),
        KDC_ERR_BAD_PVNO => (
            ErrorKind::KdcInvalidRequest,
            "requested protocol version number not supported".into(),
        ),
        KDC_ERR_C_OLD_MAST_KVNO => (
            ErrorKind::EncryptFailure,
            "client's key encrypted in old master key".into(),
        ),
        KDC_ERR_S_OLD_MAST_KVNO => (
            ErrorKind::EncryptFailure,
            "server's key encrypted in old master key".into(),
        ),
        KDC_ERR_C_PRINCIPAL_UNKNOWN => (
            ErrorKind::UnknownCredentials,
            "client not found in Kerberos database".into(),
        ),
        KDC_ERR_S_PRINCIPAL_UNKNOWN => (
            ErrorKind::UnknownCredentials,
            "server not found in Kerberos database".into(),
        ),
        KDC_ERR_PRINCIPAL_NOT_UNIQUE => (
            ErrorKind::TooManyPrincipals,
            "multiple principal entries database".into(),
        ),
        KDC_ERR_NULL_KEY => (ErrorKind::EncryptFailure, "the client or server has null key".into()),
        KDC_ERR_CANNOT_POSTDATE => (
            ErrorKind::KdcInvalidRequest,
            "ticket not eligible for postdating".into(),
        ),
        KDC_ERR_NEVER_VALID => (
            ErrorKind::KdcInvalidRequest,
            "requested starttime is later than end time".into(),
        ),
        KDC_ERR_POLICY => (ErrorKind::KdcInvalidRequest, "KDC policy rejects request".into()),
        KDC_ERR_BADOPTION => (
            ErrorKind::KdcInvalidRequest,
            "KDC cannot accommodate request option".into(),
        ),
        KDC_ERR_ETYPE_NOSUPP => (
            ErrorKind::OperationNotSupported,
            "KDC has no support for encryption type".into(),
        ),
        KDC_ERR_SUMTYPE_NOSUPP => (
            ErrorKind::KdcInvalidRequest,
            "KDC has no support for checksum type".into(),
        ),
        KDC_ERR_PADATA_TYPE_NOSUPP => (
            ErrorKind::KdcInvalidRequest,
            "KDC has no support for padata type".into(),
        ),
        KDC_ERR_TRTYPE_NOSUPP => (
            ErrorKind::KdcInvalidRequest,
            "KDC has no support for transited type".into(),
        ),
        KDC_ERR_CLIENT_REVOKED => (
            ErrorKind::UnknownCredentials,
            "clients credentials have been revoked".into(),
        ),
        KDC_ERR_SERVICE_REVOKED => (
            ErrorKind::UnknownCredentials,
            "credentials for server have been revoked".into(),
        ),
        KDC_ERR_TGT_REVOKED => (ErrorKind::UnknownCredentials, "TGT has been revoked".into()),
        KDC_ERR_CLIENT_NOTYET => (
            ErrorKind::UnknownCredentials,
            "client not yet valid; try again later".into(),
        ),
        KDC_ERR_SERVICE_NOTYET => (
            ErrorKind::UnknownCredentials,
            "server not yet valid; try again later".into(),
        ),
        KDC_ERR_KEY_EXPIRED => (
            ErrorKind::InvalidParameter,
            "password has expired; change password to reset".into(),
        ),
        KDC_ERR_PREAUTH_FAILED => (
            ErrorKind::KdcInvalidRequest,
            "pre-authentication information was invalid".into(),
        ),
        KDC_ERR_PREAUTH_REQUIRED => (
            ErrorKind::KdcInvalidRequest,
            "additional preauthentication required".into(),
        ),
        KDC_ERR_SERVER_NOMATCH => (
            ErrorKind::KdcInvalidRequest,
            "requested server and ticket don't match".into(),
        ),
        KDC_ERR_MUST_USE_USER2USER => (
            ErrorKind::KdcInvalidRequest,
            "server principal valid for user2user only".into(),
        ),
        KDC_ERR_PATH_NOT_ACCEPTED => (ErrorKind::KdcInvalidRequest, "KDC Policy rejects transited path".into()),
        KDC_ERR_SVC_UNAVAILABLE => (ErrorKind::KdcInvalidRequest, "a service is not available".into()),
        KRB_AP_ERR_BAD_INTEGRITY => (
            ErrorKind::MessageAltered,
            "integrity check on decrypted field failed".into(),
        ),
        KRB_AP_ERR_TKT_EXPIRED => (ErrorKind::ContextExpired, "ticket expired".into()),
        KRB_AP_ERR_TKT_NYV => (ErrorKind::InvalidToken, "ticket not yet valid".into()),
        KRB_AP_ERR_REPEAT => (ErrorKind::KdcInvalidRequest, "request is a replay".into()),
        KRB_AP_ERR_NOT_US => (ErrorKind::InvalidToken, "the ticket isn't for us".into()),
        KRB_AP_ERR_BADMATCH => (
            ErrorKind::KdcInvalidRequest,
            "ticket and authenticator don't match".into(),
        ),
        KRB_AP_ERR_SKEW => (ErrorKind::TimeSkew, "clock skew too great".into()),
        KRB_AP_ERR_BADADDR => (ErrorKind::InvalidParameter, "incorrect net address".into()),
        KRB_AP_ERR_BADVERSION => (ErrorKind::KdcInvalidRequest, "protocol version mismatch".into()),
        KRB_AP_ERR_MSG_TYPE => (ErrorKind::InvalidToken, "invalid msg type".into()),
        KRB_AP_ERR_MODIFIED => (ErrorKind::MessageAltered, "message stream modified".into()),
        KRB_AP_ERR_BADORDER => (ErrorKind::OutOfSequence, "message out of order".into()),
        KRB_AP_ERR_BADKEYVER => (
            ErrorKind::KdcInvalidRequest,
            "specified version of key is not available".into(),
        ),
        KRB_AP_ERR_NOKEY => (ErrorKind::NoKerbKey, "service key not available".into()),
        KRB_AP_ERR_MUT_FAIL => (ErrorKind::MutualAuthFailed, "mutual authentication failed".into()),
        KRB_AP_ERR_BADDIRECTION => (ErrorKind::OutOfSequence, "incorrect message direction".into()),
        KRB_AP_ERR_METHOD => (
            ErrorKind::InvalidToken,
            "alternative authentication method required".into(),
        ),
        KRB_AP_ERR_BADSEQ => (ErrorKind::OutOfSequence, "incorrect sequence number in message".into()),
        KRB_AP_ERR_INAPP_CKSUM => (
            ErrorKind::InvalidToken,
            "inappropriate type of checksum in message".into(),
        ),
        KRB_AP_PATH_NOT_ACCEPTED => (ErrorKind::KdcInvalidRequest, "policy rejects transited path".into()),
        KRB_ERR_RESPONSE_TOO_BIG => (
            ErrorKind::InvalidParameter,
            "response too big for UDP; retry with TC".into(),
        ),
        KRB_ERR_GENERIC => (ErrorKind::InternalError, "generic error (description in e-text)".into()),
        KRB_ERR_FIELD_TOOLONG => (
            ErrorKind::KdcInvalidRequest,
            "field is too long for this implementation".into(),
        ),
        KDC_ERROR_CLIENT_NOT_TRUSTED => (ErrorKind::InvalidParameter, "client is not trusted".into()),
        KDC_ERROR_KDC_NOT_TRUSTED => (ErrorKind::InvalidParameter, "KDC is not trusted".into()),
        KDC_ERROR_INVALID_SIG => (ErrorKind::MessageAltered, "invalid signature".into()),
        KDC_ERR_KEY_TOO_WEAK => (ErrorKind::EncryptFailure, "key is too weak".into()),
        KDC_ERR_CERTIFICATE_MISMATCH => (ErrorKind::InvalidParameter, "certificated mismatch".into()),
        KRB_AP_ERR_NO_TGT => (
            ErrorKind::NoTgtReply,
            "no TGT available to validate USER-TO-USER".into(),
        ),
        KDC_ERR_WRONG_REALM => (ErrorKind::NoAuthenticatingAuthority, "wrong Realm".into()),
        KRB_AP_ERR_USER_TO_USER_REQUIRED => (ErrorKind::KdcInvalidRequest, "ticket must be for USER-TO-USER".into()),
        KDC_ERR_CANT_VERIFY_CERTIFICATE => (
            ErrorKind::KdcInvalidRequest,
            "KDC can not verify the certificate".into(),
        ),
        KDC_ERR_INVALID_CERTIFICATE => (ErrorKind::InvalidParameter, "invalid certificate".into()),
        KDC_ERR_REVOKED_CERTIFICATE => (ErrorKind::KdcCertRevoked, "revoked certificate".into()),
        KDC_ERR_REVOCATION_STATUS_UNKNOWN => (ErrorKind::InternalError, "revoked status unknown".into()),
        KDC_ERR_REVOCATION_STATUS_UNAVAILABLE => (ErrorKind::InternalError, "revoked status unavailable".into()),
        KDC_ERR_CLIENT_NAME_MISMATCH => (ErrorKind::InvalidParameter, "client name mismatch".into()),
        KDC_ERR_KDC_NAME_MISMATCH => (ErrorKind::InvalidParameter, "KDC name mismatch".into()),
        code => (ErrorKind::Unknown, format!("unknown Kerberos error: {code}")),
    }
}

pub(crate) fn get_encryption_key(enc_params: &EncryptionParams) -> Result<&Secret<Vec<u8>>> {
    // the sub-session key is always preferred over the session key
    if let Some(key) = enc_params.sub_session_key.as_ref() {
        debug!("Encryption using sub-session key");

        Ok(key)
    } else if let Some(key) = enc_params.session_key.as_ref() {
        warn!("Encryption using session key (not sub-session key)");

        Ok(key)
    } else {
        error!(
            "No encryption keys in the krb context. Maybe security context is not established, but encryption key is requested"
        );

        Err(Error::new(
            ErrorKind::OutOfSequence,
            "encryption key has not been found: no security context keys have been established",
        ))
    }
}

/// Copies a decrypted data into the [BufferType::Data] or [BufferType::Stream].
///
/// There are two choices for how we should save the decrypted data in security buffers:
/// * If the `SECBUFFER_STREAM` is present, we should save all data in the `SECBUFFER_DATA` buffer.
///   But in such a case, the `SECBUFFER_DATA` buffer is empty. So, we take the inner buffer from
///   the `SECBUFFER_STREAM` buffer, write decrypted data into it, and assign it to the `SECBUFFER_DATA` buffer.
/// * If the `SECBUFFER_STREAM` is not present, we should just save all data in the `SECBUFFER_DATA` buffer.
pub(crate) fn save_decrypted_data<'a>(decrypted: &'a [u8], buffers: &'a mut [SecurityBufferRef<'_>]) -> Result<()> {
    if let Ok(buffer) = SecurityBufferRef::find_buffer_mut(buffers, BufferType::Stream) {
        let decrypted_len = decrypted.len();

        if buffer.buf_len() < decrypted_len {
            return Err(Error::new(
                ErrorKind::DecryptFailure,
                format!(
                    "decrypted data length ({}) does not match the stream buffer length ({})",
                    decrypted_len,
                    buffer.buf_len(),
                ),
            ));
        }

        let stream_buffer = buffer.take_data();
        let stream_buffer_len = stream_buffer.len();

        let data_buffer = SecurityBufferRef::find_buffer_mut(buffers, BufferType::Data)?;

        let data = &mut stream_buffer[stream_buffer_len - decrypted_len..];
        data.copy_from_slice(decrypted);

        data_buffer.set_data(data)
    } else {
        let mut data_buffers =
            SecurityBufferRef::buffers_of_type_and_flags_mut(buffers, BufferType::Data, SecurityBufferFlags::NONE);
        let data_buffer = data_buffers.next().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidToken,
                "no buffer was provided with type Data and without READONLY_WITH_CHECKSUM flag",
            )
        })?;

        if data_buffer.buf_len() < decrypted.len() {
            return Err(Error::new(
                ErrorKind::DecryptFailure,
                format!(
                    "decrypted data length ({}) does not match the data buffer length ({})",
                    decrypted.len(),
                    data_buffer.buf_len(),
                ),
            ));
        }

        data_buffer.write_data(decrypted)
    }
}

/// Extracts data to decrypt from the incoming buffers.
///
/// Data to decrypt is `Token` + `Stream`/`Data` buffers concatenated together.
pub(crate) fn extract_encrypted_data(buffers: &[SecurityBufferRef<'_>]) -> Result<Vec<u8>> {
    let mut encrypted = SecurityBufferRef::buf_data(buffers, BufferType::Token)
        .unwrap_or_default()
        .to_vec();

    encrypted.extend_from_slice(
        if let Ok(buffer) = SecurityBufferRef::buf_data(buffers, BufferType::Stream) {
            buffer
        } else {
            use crate::SecurityBufferFlags;

            // Find `Data` buffers but skip `Data` buffers with the `READONLY_WITH_CHECKSUM`/`READONLY` flag.
            // The `Data` buffer without any flags is not mandatory. The user can specify only read-only buffers
            // for checksum computation (currently, supported only in NTLM).
            SecurityBufferRef::buffers_of_type_and_flags(buffers, BufferType::Data, SecurityBufferFlags::NONE)
                .next()
                .map(|buffer| buffer.data())
                .unwrap_or_default()
        },
    );

    Ok(encrypted)
}

pub(crate) fn parse_target_name(target_name: &str) -> Result<(&str, &str)> {
    let divider = target_name.find('/').ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidParameter,
            "invalid service principal name: missing '/'",
        )
    })?;

    if divider == 0 || divider == target_name.len() - 1 {
        return Err(Error::new(
            ErrorKind::InvalidParameter,
            "invalid service principal name",
        ));
    }

    let service_name = &target_name[0..divider];
    // `divider + 1` - do not include '/' char
    let service_principal_name = &target_name[(divider + 1)..];

    Ok((service_name, service_principal_name))
}

pub fn modpow(public_key: &BoxedUint, private_key: &BoxedUint, p: Odd<BoxedUint>) -> BoxedUint {
    let p = BoxedMontyParams::new_vartime(p);
    pow_mod_params(public_key, private_key, &p)
}

// Copied from `rsa` crate: https://github.com/RustCrypto/RSA/blob/eb1cca7b7ea42445dc874c1c1ce38873e4adade7/src/algorithms/rsa.rs#L232-L241
fn pow_mod_params(base: &BoxedUint, exp: &BoxedUint, n_params: &BoxedMontyParams) -> BoxedUint {
    let base = reduce_vartime(base, n_params);
    base.pow(exp).retrieve()
}

fn reduce_vartime(n: &BoxedUint, p: &BoxedMontyParams) -> BoxedMontyForm {
    let modulus = p.modulus().as_nz_ref().clone();
    let n_reduced = n.rem_vartime(&modulus).resize_unchecked(p.bits_precision());
    BoxedMontyForm::new(n_reduced, p)
}

#[cfg(test)]
mod tests {
    use super::parse_target_name;

    #[test]
    fn parse_valid_target_name() {
        assert_eq!(("EXAMPLE", "p10"), parse_target_name("EXAMPLE/p10").unwrap());
        assert_eq!(("E", "p10"), parse_target_name("E/p10").unwrap());
        assert_eq!(("EXAMPLE", "p"), parse_target_name("EXAMPLE/p").unwrap());
    }

    #[test]
    fn parse_invalid_target_name() {
        assert!(parse_target_name("EXAMPLEp10").is_err());
        assert!(parse_target_name("EXAMPLE/").is_err());
        assert!(parse_target_name("/p10").is_err());
        assert!(parse_target_name("/").is_err());
        assert!(parse_target_name("").is_err());
    }
}
