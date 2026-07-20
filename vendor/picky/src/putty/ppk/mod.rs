mod aes;
mod encoding;
mod encryption;
mod kdf;
mod mac;

use crate::key::{EcCurve, PrivateKey, PublicKey};
use crate::putty::PuttyError;
use crate::putty::key_value::{PpkKeyAlgorithmValue, PpkVersionKey};
use crate::putty::private_key::{PuttyBasePrivateKey, PuttyPrivateKey};
use crate::putty::public_key::{PuttyBasePublicKey, PuttyPublicKey};
use crate::ssh::SshPrivateKey;

use self::encryption::PpkEncryptionKind;

pub use encryption::{PpkEncryptionConfig, PpkEncryptionConfigBuilder};
pub use kdf::Argon2Params;

/// PuTTY Private Key (PPK) format.
///
/// ### Functionality
/// - Generation of new keys.
/// - Conversion to/from OpenSSH format.
/// - Encoding/decoding to/from string.
/// - Version upgrade/downgrade.
///
/// ### Usage notes
/// - Ppk structure is immutable. All operations that modify the key return a new instance.
/// - When input file is encrypted, all operations with the private key will be unavailable until
///   ppk is decrypted via [`Ppk::decrypt`].
/// - Newly generated keys are always unencrypted. They should be encrypted via [`Ppk::encrypt`]
///   when required
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ppk {
    version: PpkVersionKey,
    algorithm: PpkKeyAlgorithmValue,
    encryption: Option<PpkEncryptionKind>,
    comment: String,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
    mac: Vec<u8>,
}

impl Ppk {
    pub fn generate_rsa(bits: usize, comment: Option<&str>) -> Result<Self, PuttyError> {
        let ssh_key = SshPrivateKey::generate_rsa(bits, None, comment.map(From::from))?;
        Self::from_openssh_private_key(&ssh_key)
    }

    pub fn generate_ec(curve: EcCurve, comment: Option<&str>) -> Result<Self, PuttyError> {
        let ssh_key = SshPrivateKey::generate_ec(curve, None, comment.map(From::from))?;
        Self::from_openssh_private_key(&ssh_key)
    }

    pub fn generate_ed25519(comment: Option<&str>) -> Result<Self, PuttyError> {
        let ssh_key = SshPrivateKey::generate_ed25519(None, comment.map(From::from))?;
        Self::from_openssh_private_key(&ssh_key)
    }

    /// Converts the OpenSSH private key to a PPK key.
    pub fn from_openssh_private_key(key: &SshPrivateKey) -> Result<Self, PuttyError> {
        let PuttyPrivateKey { base, comment }: PuttyPrivateKey = PuttyPrivateKey::from_openssh(key)?;

        let mut ppk = Ppk {
            version: PpkVersionKey::V3,
            algorithm: base.algorithm,
            encryption: None,
            comment,
            public_key: base.public_key.data,
            private_key: base.data,
            mac: vec![],
        };

        ppk.mac = ppk.calculate_unencrypted_mac(ppk.private_key.as_slice())?;

        Ok(ppk)
    }

    /// Converts the PPK key to an OpenSSH private key (with or without encryption).
    pub fn to_openssh_private_key(&self, passphrase: Option<&str>) -> Result<SshPrivateKey, PuttyError> {
        if self.is_encrypted() {
            return Err(PuttyError::Encrypted);
        }

        let base = PuttyBasePrivateKey {
            algorithm: self.algorithm,
            public_key: PuttyBasePublicKey {
                data: self.public_key.clone(),
            },
            data: self.private_key.clone(),
        };

        let key = PuttyPrivateKey {
            base,
            comment: self.comment.clone(),
        };

        key.to_openssh(passphrase)
    }

    /// Returns PPK public key.
    pub fn public_key(&self) -> Result<PublicKey, PuttyError> {
        PuttyBasePublicKey {
            data: self.public_key.clone(),
        }
        .to_inner_key()
    }

    /// Returns PPK private key.
    pub fn private_key(&self) -> Result<PrivateKey, PuttyError> {
        if self.is_encrypted() {
            return Err(PuttyError::Encrypted);
        }

        PuttyBasePrivateKey {
            algorithm: self.algorithm,
            public_key: PuttyBasePublicKey {
                data: self.public_key.clone(),
            },
            data: self.private_key.clone(),
        }
        .to_inner_key()
    }

    /// Returns extracted public key in PuTTY format.
    pub fn extract_putty_public_key(&self) -> Result<PuttyPublicKey, PuttyError> {
        Ok(PuttyPublicKey {
            base: PuttyBasePublicKey {
                data: self.public_key.clone(),
            },
            comment: self.comment.clone(),
        })
    }

    /// Returns a new PPK key instance with a different comment.
    pub fn with_comment(&self, comment: &str) -> Result<Self, PuttyError> {
        if self.is_encrypted() {
            // We need to decrypt the key to change the comment (MAC should be recalculated).
            return Err(PuttyError::Encrypted);
        }

        let mut ppk = Self {
            comment: comment.to_string(),
            ..self.clone()
        };

        ppk.mac = ppk.calculate_unencrypted_mac(ppk.private_key.as_slice())?;

        Ok(ppk)
    }

    /// Returns the version of the PPK file format.
    pub fn version(&self) -> PpkVersionKey {
        self.version
    }

    /// Returns the key algorithm.
    pub fn algorithm(&self) -> PpkKeyAlgorithmValue {
        self.algorithm
    }

    /// Returns key comment.
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Returns new PPK kew with the specified format version.
    ///
    /// NOTE: `PpkVersionKey::V2` is considered insecure and should not be used for new keys in
    /// normal circumstances.
    pub fn to_version(&self, version: PpkVersionKey) -> Result<Ppk, PuttyError> {
        if self.is_encrypted() {
            return Err(PuttyError::Encrypted);
        }

        let ppk = Ppk {
            version,
            algorithm: self.algorithm,
            encryption: None,
            comment: self.comment.clone(),
            public_key: self.public_key.clone(),
            private_key: self.private_key.clone(),
            mac: self.calculate_unencrypted_mac(self.private_key.as_slice())?,
        };

        Ok(ppk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    use picky_test_data::{
        PUTTY_KEY_ED25519, PUTTY_KEY_ED25519_ENCRYPTED, PUTTY_KEY_ED25519_V2, PUTTY_KEY_ED25519_V2_ENCRYPTED,
        SSH_PRIVATE_KEY_EC_P256, SSH_PRIVATE_KEY_EC_P384, SSH_PRIVATE_KEY_EC_P521, SSH_PRIVATE_KEY_ED25519,
        SSH_PRIVATE_KEY_RSA,
    };

    #[rstest]
    #[case(PUTTY_KEY_ED25519)]
    #[case(PUTTY_KEY_ED25519_ENCRYPTED)]
    #[case(PUTTY_KEY_ED25519_V2)]
    #[case(PUTTY_KEY_ED25519_V2_ENCRYPTED)]
    fn ppk_encode_decode_roundtrip(#[case] input: &str) {
        let key: Ppk = input.parse().unwrap();
        let encoded = key.to_string().unwrap();

        assert_eq!(encoded, input);
    }

    #[rstest]
    #[case(PUTTY_KEY_ED25519_ENCRYPTED, PUTTY_KEY_ED25519)]
    #[case(PUTTY_KEY_ED25519_V2_ENCRYPTED, PUTTY_KEY_ED25519_V2)]
    fn decrypt_produces_same_key_as_puttygen(#[case] encrypted: &str, #[case] decrypted: &str) {
        let mut key: Ppk = encrypted.parse().unwrap();
        assert!(key.is_encrypted());
        key = key.decrypt("test").unwrap();

        let encoded = key.to_string().unwrap();
        assert_eq!(encoded, decrypted);
        assert!(!key.is_encrypted());
    }

    #[rstest]
    #[case(PUTTY_KEY_ED25519, PpkVersionKey::V3, "eddsa-key-20240414")]
    #[case(PUTTY_KEY_ED25519_V2, PpkVersionKey::V2, "ed25519-key-20240418")]
    fn encrypt_decrypt_roundtrip(#[case] input: &str, #[case] version: PpkVersionKey, #[case] comment: &str) {
        let mut key: Ppk = input.parse().unwrap();
        key = key.encrypt("test", Default::default()).unwrap();
        assert!(key.is_encrypted());
        key = key.decrypt("test").unwrap();
        assert_eq!(key.to_string().unwrap(), input);
        assert!(!key.is_encrypted());
        assert_eq!(key.version(), version);
        assert_eq!(key.algorithm(), PpkKeyAlgorithmValue::Ed25519);
        assert_eq!(key.comment(), comment);
    }

    #[rstest]
    #[case(SSH_PRIVATE_KEY_RSA)]
    #[case(SSH_PRIVATE_KEY_EC_P256)]
    #[case(SSH_PRIVATE_KEY_EC_P384)]
    #[case(SSH_PRIVATE_KEY_EC_P521)]
    #[case(SSH_PRIVATE_KEY_ED25519)]
    fn test_openssh_roundtrip(#[case] input: &str) {
        let ssh_key = SshPrivateKey::from_pem_str(input, None).unwrap();
        let key = Ppk::from_openssh_private_key(&ssh_key).unwrap();
        let mut ssh_key2 = key.to_openssh_private_key(None).unwrap();

        // Check is re-generated when new ssh is created from scratch
        ssh_key2.check = ssh_key.check;

        let ssh_key_str = ssh_key2.to_string().unwrap();
        assert_eq!(ssh_key_str, input);
    }
}
