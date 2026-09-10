//! Key derivation utilities for PPK files.

use crate::putty::key_value::Argon2FlavourValue;
use crate::putty::ppk::{PuttyError, aes as ppk_aes};

use digest::Digest;
use zeroize::Zeroizing;

const SHA256_DIGEST_SIZE: usize = 32;
const SHA1_DIGEST_SIZE: usize = 20;

pub const MAC_SIZE_V3: usize = SHA256_DIGEST_SIZE;

/// Argon2 key derivation function parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Argon2Params {
    pub flavor: Argon2FlavourValue,
    pub memory: u32,
    pub passes: u32,
    pub parallelism: u32,
    pub salt: Vec<u8>,
}

const V3_KEY_MATERIAL_SIZE: usize = ppk_aes::KEY_SIZE // AES key
    + ppk_aes::BLOCK_SIZE // AES IV
    + MAC_SIZE_V3; // HMAC key

pub(crate) struct KeyMaterialV3 {
    key: Zeroizing<[u8; ppk_aes::KEY_SIZE]>,
    iv: Zeroizing<[u8; ppk_aes::BLOCK_SIZE]>,
    hmac_key: Zeroizing<[u8; MAC_SIZE_V3]>,
}

impl KeyMaterialV3 {
    pub fn key(&self) -> &[u8] {
        self.key.as_ref()
    }

    pub fn iv(&self) -> &[u8] {
        self.iv.as_ref()
    }

    pub fn hmac_key(&self) -> &[u8] {
        self.hmac_key.as_ref()
    }
}

pub(crate) struct KeyMaterialV2 {
    key: Zeroizing<[u8; ppk_aes::KEY_SIZE]>,
}

impl KeyMaterialV2 {
    pub fn key(&self) -> &[u8] {
        self.key.as_ref()
    }

    pub fn iv() -> &'static [u8; ppk_aes::BLOCK_SIZE] {
        &[0u8; ppk_aes::BLOCK_SIZE]
    }
}

pub(crate) fn derive_key_material_v2(passphrase: &str) -> Result<KeyMaterialV2, PuttyError> {
    let tagged_hash = |tag: u32| -> [u8; SHA1_DIGEST_SIZE] {
        let mut digest = sha1::Sha1::new();
        digest.update(tag.to_be_bytes());
        digest.update(passphrase.as_bytes());
        digest.finalize().into()
    };

    let hash1 = tagged_hash(0);
    let hash2 = tagged_hash(1);

    let mut key = [0u8; ppk_aes::KEY_SIZE];
    key[..SHA1_DIGEST_SIZE].copy_from_slice(&hash1[..]);
    key[SHA1_DIGEST_SIZE..].copy_from_slice(&hash2[..ppk_aes::KEY_SIZE - SHA1_DIGEST_SIZE]);

    Ok(KeyMaterialV2 { key: key.into() })
}

pub(crate) fn derive_key_material_v3(
    argon2_params: &Argon2Params,
    passphrase: &str,
) -> Result<KeyMaterialV3, PuttyError> {
    let mut key_material = [0u8; V3_KEY_MATERIAL_SIZE];

    let kdf = argon2::Argon2::new(
        argon2_params.flavor.into(),
        argon2::Version::V0x13,
        argon2::Params::new(
            argon2_params.memory,
            argon2_params.passes,
            argon2_params.parallelism,
            Some(V3_KEY_MATERIAL_SIZE),
        )
        .map_err(|_| PuttyError::Argon2)?,
    );

    kdf.hash_password_into(passphrase.as_bytes(), &argon2_params.salt, &mut key_material)
        .map_err(|_| PuttyError::Argon2)?;

    let key_material = key_material.as_ref();

    const IV_OFFSET: usize = ppk_aes::KEY_SIZE;
    const HMAC_KEY_OFFSET: usize = IV_OFFSET + ppk_aes::BLOCK_SIZE;

    let mut key = [0u8; ppk_aes::KEY_SIZE];
    key.copy_from_slice(&key_material[..ppk_aes::KEY_SIZE]);

    let mut iv = [0u8; ppk_aes::BLOCK_SIZE];
    iv.copy_from_slice(&key_material[IV_OFFSET..IV_OFFSET + ppk_aes::BLOCK_SIZE]);

    let mut hmac_key = [0u8; MAC_SIZE_V3];
    hmac_key.copy_from_slice(&key_material[HMAC_KEY_OFFSET..]);

    Ok(KeyMaterialV3 {
        key: key.into(),
        iv: iv.into(),
        hmac_key: hmac_key.into(),
    })
}
