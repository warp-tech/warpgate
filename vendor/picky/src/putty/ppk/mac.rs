//! PPK MAC calculation functions

use crate::putty::key_value::{PpkEncryptionValue, PpkLiteral, PpkVersionKey};
use crate::putty::{Ppk, PuttyError};

use digest::Digest;
use hmac::{KeyInit, Mac};

impl Ppk {
    pub(super) fn calculate_mac_v3(
        &self,
        mac_key: &[u8],
        private_key_data: &[u8],
        encryption: PpkEncryptionValue,
    ) -> Result<Vec<u8>, PuttyError> {
        let mut hmac = hmac::Hmac::<sha2::Sha256>::new_from_slice(mac_key).map_err(|_| PuttyError::MacValidation)?;

        let mut hash_bytes = |data: &[u8]| -> Result<(), PuttyError> {
            hmac.update(
                &u32::try_from(data.len())
                    .map_err(|_| PuttyError::MacValidation)?
                    .to_be_bytes(),
            );
            hmac.update(data);
            Ok(())
        };

        hash_bytes(self.algorithm.as_static_str().as_bytes())?;
        hash_bytes(encryption.as_static_str().as_bytes())?;
        hash_bytes(self.comment.as_bytes())?;
        hash_bytes(&self.public_key)?;
        hash_bytes(private_key_data)?;

        let mac = hmac.finalize().into_bytes().to_vec();
        Ok(mac)
    }

    pub(super) fn calculate_mac_v2(
        &self,
        passphrase: &str,
        private_key_data: &[u8],
        encryption: PpkEncryptionValue,
    ) -> Result<Vec<u8>, PuttyError> {
        let mac_key = {
            let mut digest = sha1::Sha1::new();
            digest.update(b"putty-private-key-file-mac-key");
            digest.update(passphrase.as_bytes());
            digest.finalize()
        };

        let mut hmac = hmac::Hmac::<sha1::Sha1>::new_from_slice(&mac_key).map_err(|_| PuttyError::MacValidation)?;

        let mut hash_bytes = |data: &[u8]| -> Result<(), PuttyError> {
            hmac.update(
                &u32::try_from(data.len())
                    .map_err(|_| PuttyError::MacValidation)?
                    .to_be_bytes(),
            );
            hmac.update(data);
            Ok(())
        };

        hash_bytes(self.algorithm.as_static_str().as_bytes())?;
        hash_bytes(encryption.as_static_str().as_bytes())?;
        hash_bytes(self.comment.as_bytes())?;
        hash_bytes(&self.public_key)?;
        hash_bytes(private_key_data)?;

        let mac = hmac.finalize().into_bytes().to_vec();
        Ok(mac)
    }

    pub(super) fn calculate_unencrypted_mac(&self, private_key_data: &[u8]) -> Result<Vec<u8>, PuttyError> {
        match self.version {
            PpkVersionKey::V2 => self.calculate_mac_v2("", private_key_data, PpkEncryptionValue::None),
            PpkVersionKey::V3 => self.calculate_mac_v3(&[], private_key_data, PpkEncryptionValue::None),
        }
    }
}
