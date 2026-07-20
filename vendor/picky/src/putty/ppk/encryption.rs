//! PPK encryption/decryption types and fucntions

use crate::putty::PuttyError;
use crate::putty::key_value::{Argon2FlavourValue, PpkEncryptionValue, PpkVersionKey};
use crate::putty::ppk::kdf::{self, KeyMaterialV2};
use crate::putty::ppk::{Argon2Params, Ppk, aes as ppk_aes};
use crate::ssh::decode::SshReadExt;
use rand::rngs::{StdRng, SysRng};
use rand_core::SeedableRng as _;

/// PPK encryption configuration builder.
///
/// Could be constructed via [`PpkEncryptionConfig::builder()`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PpkEncryptionConfigBuilder {
    inner: PpkEncryptionConfig,
}

impl PpkEncryptionConfigBuilder {
    pub fn argon2_flavour(mut self, argon2_flavour: Argon2FlavourValue) -> Self {
        self.inner.argon2_flavour = argon2_flavour;
        self
    }

    pub fn argon2_memory(mut self, argon2_memory: u32) -> Self {
        self.inner.argon2_memory = argon2_memory;
        self
    }

    pub fn argon2_passes(mut self, argon2_passes: u32) -> Self {
        self.inner.argon2_passes = argon2_passes;
        self
    }

    pub fn argon2_parallelism(mut self, argon2_parallelism: u32) -> Self {
        self.inner.argon2_parallelism = argon2_parallelism;
        self
    }

    pub fn argon2_salt_size(mut self, argon2_salt_size: u32) -> Self {
        self.inner.argon2_salt_size = argon2_salt_size;
        self
    }

    pub fn build(self) -> PpkEncryptionConfig {
        self.inner
    }
}

/// PPK encryption configuration.
///
/// Could be either constructed via [`Default::default()`] or [`PpkEncryptionConfig::builder()`]
///
/// Defaults are the same as in PuTTY.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PpkEncryptionConfig {
    argon2_flavour: Argon2FlavourValue,
    argon2_memory: u32,
    argon2_passes: u32,
    argon2_parallelism: u32,
    argon2_salt_size: u32,
}

impl Default for PpkEncryptionConfig {
    fn default() -> Self {
        Self {
            argon2_flavour: Argon2FlavourValue::Argon2id,
            argon2_memory: 8192,
            argon2_passes: 34,
            argon2_parallelism: 1,
            argon2_salt_size: 16,
        }
    }
}

impl PpkEncryptionConfig {
    pub fn builder() -> PpkEncryptionConfigBuilder {
        PpkEncryptionConfigBuilder {
            inner: Default::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PpkEncryptionKind {
    Aes256CbcV2,
    Aes256CbcV3(Argon2Params),
}

impl From<Option<&PpkEncryptionKind>> for PpkEncryptionValue {
    fn from(params: Option<&PpkEncryptionKind>) -> Self {
        match params {
            None => PpkEncryptionValue::None,
            Some(PpkEncryptionKind::Aes256CbcV2) => PpkEncryptionValue::Aes256Cbc,
            Some(PpkEncryptionKind::Aes256CbcV3(_)) => PpkEncryptionValue::Aes256Cbc,
        }
    }
}

impl Ppk {
    /// Returns true if the key is encrypted
    pub fn is_encrypted(&self) -> bool {
        self.encryption.is_some()
    }

    /// Argon2 KDF parameters if encryption is used (V3 only)
    pub fn argon2_params(&self) -> Option<&Argon2Params> {
        match &self.encryption {
            Some(PpkEncryptionKind::Aes256CbcV3(params)) => Some(params),
            _ => None,
        }
    }

    /// Returns PPK key encrypted with the specified passphrase and config.
    pub fn encrypt(&self, passphrase: &str, config: PpkEncryptionConfig) -> Result<Self, PuttyError> {
        self.encrypt_with_rng(passphrase, config, StdRng::try_from_rng(&mut SysRng)?)
    }

    /// Returns PPK key encrypted with the specified passphrase, config and RNG.
    pub fn encrypt_with_rng(
        &self,
        passphrase: &str,
        config: PpkEncryptionConfig,
        mut rng: impl rand_core::Rng,
    ) -> Result<Ppk, PuttyError> {
        if self.encryption.is_some() {
            return Err(PuttyError::AlreadyEncrypted);
        }

        let ppk = match self.version {
            PpkVersionKey::V2 => {
                let key_material = kdf::derive_key_material_v2(passphrase)?;

                let mut private_key = ppk_aes::make_padding(self.private_key.clone(), rng);
                let mac = self.calculate_mac_v2(passphrase, &private_key, PpkEncryptionValue::Aes256Cbc)?;
                ppk_aes::encrypt(&mut private_key, key_material.key(), KeyMaterialV2::iv())?;

                Ppk {
                    version: self.version,
                    algorithm: self.algorithm,
                    encryption: Some(PpkEncryptionKind::Aes256CbcV2),
                    comment: self.comment.clone(),
                    public_key: self.public_key.clone(),
                    private_key,
                    mac,
                }
            }
            PpkVersionKey::V3 => {
                let mut argon2_salt = vec![0u8; config.argon2_salt_size as usize];
                rng.fill_bytes(&mut argon2_salt);
                let argon2_params = Argon2Params {
                    flavor: config.argon2_flavour,
                    memory: config.argon2_memory,
                    passes: config.argon2_passes,
                    parallelism: config.argon2_parallelism,
                    salt: argon2_salt,
                };

                let key_material = kdf::derive_key_material_v3(&argon2_params, passphrase)?;

                let mut private_key = ppk_aes::make_padding(self.private_key.clone(), rng);
                let mac =
                    self.calculate_mac_v3(key_material.hmac_key(), &private_key, PpkEncryptionValue::Aes256Cbc)?;
                ppk_aes::encrypt(&mut private_key, key_material.key(), key_material.iv())?;

                Ppk {
                    version: self.version,
                    algorithm: self.algorithm,
                    encryption: Some(PpkEncryptionKind::Aes256CbcV3(argon2_params)),
                    comment: self.comment.clone(),
                    public_key: self.public_key.clone(),
                    private_key,
                    mac,
                }
            }
        };

        Ok(ppk)
    }

    /// Returns PPK key decrypted with the specified passphrase
    pub fn decrypt(&self, passphrase: &str) -> Result<Self, PuttyError> {
        let encrytion = if let Some(encryption) = &self.encryption {
            encryption
        } else {
            return Err(PuttyError::AlreadyDecrypted);
        };

        let (mut private_key, mac) = match encrytion {
            PpkEncryptionKind::Aes256CbcV2 => {
                let key_material = kdf::derive_key_material_v2(passphrase)?;
                let mut private_key = self.private_key.clone();
                ppk_aes::decrypt(&mut private_key, key_material.key(), KeyMaterialV2::iv())?;
                let mac = self.calculate_mac_v2(passphrase, &private_key, PpkEncryptionValue::Aes256Cbc)?;
                (private_key, mac)
            }
            PpkEncryptionKind::Aes256CbcV3(argon2_params) => {
                let key_material = kdf::derive_key_material_v3(argon2_params, passphrase)?;
                let mut private_key = self.private_key.clone();
                ppk_aes::decrypt(&mut private_key, key_material.key(), key_material.iv())?;
                let mac =
                    self.calculate_mac_v3(key_material.hmac_key(), &private_key, PpkEncryptionValue::Aes256Cbc)?;
                (private_key, mac)
            }
        };

        // Verify MAC
        if mac.as_slice() != self.mac.as_slice() {
            return Err(PuttyError::MacValidation);
        }

        // Truncate private key padding if any
        let truncated_size = {
            let mut mpint_cursor = private_key.as_slice();
            for _ in 0..self.algorithm.key_mpint_values_count() {
                // NOTE: Bytes and mpint stored the same way, therefore to avoid BigUint
                // construction we can just read the bytes (we discard them either way)
                let _value = mpint_cursor.read_ssh_bytes()?;
            }

            private_key.len().wrapping_sub(mpint_cursor.len())
        };

        private_key.truncate(truncated_size);

        let mac = self.calculate_unencrypted_mac(private_key.as_slice())?;

        let ppk = Ppk {
            version: self.version,
            algorithm: self.algorithm,
            encryption: None,
            comment: self.comment.clone(),
            public_key: self.public_key.clone(),
            private_key,
            mac,
        };

        Ok(ppk)
    }
}
