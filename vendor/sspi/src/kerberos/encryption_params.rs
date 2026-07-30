use picky_krb::constants::key_usages::{ACCEPTOR_SEAL, INITIATOR_SEAL};
use picky_krb::crypto::CipherSuite;
use picky_krb::crypto::aes::AesSize;

use crate::Secret;

#[derive(Debug, Clone)]
pub struct EncryptionParams {
    pub encryption_type: Option<CipherSuite>,
    pub session_key: Option<Secret<Vec<u8>>>,
    pub sub_session_key: Option<Secret<Vec<u8>>>,
    pub sspi_encrypt_key_usage: i32,
    pub sspi_decrypt_key_usage: i32,
    /// EC field of the Kerberos Wrap token.
    ///
    /// Related documentation:
    /// * [RFC 4121: EC Field](https://www.rfc-editor.org/rfc/rfc4121#section-4.2.3).
    /// * [3.4.5.4.1 Kerberos Binding of GSS_WrapEx()](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/e94b3acd-8415-4d0d-9786-749d0c39d550).
    ///
    /// This value is different during RDP and RPC authentication.
    /// We negotiate it during the authentication process.
    pub ec: u16,
}

impl EncryptionParams {
    pub fn default_for_client() -> Self {
        Self {
            encryption_type: None,
            session_key: None,
            sub_session_key: None,
            sspi_encrypt_key_usage: INITIATOR_SEAL,
            sspi_decrypt_key_usage: ACCEPTOR_SEAL,
            ec: 0,
        }
    }

    pub fn default_for_server() -> Self {
        Self {
            encryption_type: None,
            session_key: None,
            sub_session_key: None,
            sspi_encrypt_key_usage: ACCEPTOR_SEAL,
            sspi_decrypt_key_usage: INITIATOR_SEAL,
            ec: 0,
        }
    }

    pub fn aes_size(&self) -> Option<AesSize> {
        self.encryption_type.as_ref().and_then(|e_type| match e_type {
            CipherSuite::Aes256CtsHmacSha196 => Some(AesSize::Aes256),
            CipherSuite::Aes128CtsHmacSha196 => Some(AesSize::Aes128),
            CipherSuite::Des3CbcSha1Kd => None,
        })
    }
}
