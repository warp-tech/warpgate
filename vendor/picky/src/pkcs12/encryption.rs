use crate::pkcs12::{Pbkdf1Usage, Pkcs12Error, Pkcs12HashAlgorithm, pbkdf1};
use picky_asn1::restricted_string::BmpString;
use picky_asn1::wrapper::OctetStringAsn1;
pub use picky_asn1_x509::pkcs12::Pbes1AlgorithmKind as Pbes1Cipher;
use picky_asn1_x509::pkcs12::{
    Pbes1Params as Pbes1ParamsAsn1, Pbes2AesCbcEncryption as Pbes2AesCbcEncryptionAsn1,
    Pbes2EncryptionScheme as Pbes2EncryptionSchemeAsn1, Pbes2KeyDerivationFunc as Pbes2KeyDerivationFuncAsn1,
    Pbes2Params as Pbes2ParamsAsn1, Pbkdf2Params as Pbkdf2ParamsAsn1, Pbkdf2Prf as Pbkdf2PrfAsn1,
    Pbkdf2SaltSource as Pbkdf2SaltSourceAsn1, Pkcs12EncryptionAlgorithm as Pkcs12EncryptionAsn1,
};
use rand::rngs::{StdRng, SysRng};
use rand_core::SeedableRng as _;
use std::str::FromStr as _;

/// Same default KDF iterations as in OpenSSL
const DEFAULT_KDF_ITERATIONS: usize = 2048;
const DEFAULT_SALT_SIZE: usize = 8;
const AES_BLOCK_SIZE: usize = 16;

/// Crypto operations context for PFX file parsing/building. Contains password inside as a secure
/// string and RNG.
pub struct Pkcs12CryptoContext {
    password: zeroize::Zeroizing<String>,
    rng: Box<dyn rand_core::Rng>,
}

impl Pkcs12CryptoContext {
    /// Creates new context with given password and default
    pub fn new_with_password(password: &str) -> Result<Self, Pkcs12Error> {
        Ok(Self {
            password: password.to_string().into(),
            rng: Box::new(StdRng::try_from_rng(&mut SysRng)?),
        })
    }

    /// Sets RNG for this context
    pub fn with_rng(mut self, rng: impl rand::CryptoRng + 'static) -> Self {
        self.rng = Box::new(rng);
        self
    }

    /// Creates new context with empty password and default RNG
    pub fn new_without_password() -> Result<Self, Pkcs12Error> {
        Ok(Self {
            password: String::new().into(),
            rng: Box::new(StdRng::try_from_rng(&mut SysRng)?),
        })
    }

    /// Returns password in PBES1 password representation - UCS2 encoded string with null terminator
    pub(crate) fn password_bytes_pbes1(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, Pkcs12Error> {
        let mut bmp = zeroize::Zeroizing::new(BmpString::from_str(&self.password)?.into_bytes());
        bmp.extend_from_slice(&[0, 0]);

        Ok(bmp)
    }

    /// Returns password in PBES2 password representation - UTF8 encoded string
    pub(crate) fn password_bytes_pbes2(&self) -> &[u8] {
        self.password.as_bytes()
    }

    pub(crate) fn generate_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut data = vec![0u8; len];
        self.rng.fill_bytes(&mut data);
        data
    }
}

/// This type holds all information required to encrypt/decrypt data in PKCS#12 file, including
/// encryption algorithm, salt, IV and KDF iterations.
///
/// This type is not cloneable, because it is intended to be used only once for each encryptable
/// object. If for some reason you need to have exactly the same salt/IV values for multiple
/// encryptable objects, you should create crypto context with custom RNG set to same seed and
/// create multiple Pkcs12Encryption objects from it.
#[derive(Debug, PartialEq, Eq)]
pub struct Pkcs12Encryption {
    kind: Pkcs12EncryptionKind,
    inner: Pkcs12EncryptionAsn1,
}

impl Pkcs12Encryption {
    /// Clone-like operation only could be performed internally when cloning higher level structures.
    /// Pkcs12Encryption non-cloneable nature is intentional to provide hint to the user that this
    /// structure should be used only once for each encryptable object.
    pub(crate) fn duplicate(&self) -> Self {
        Self {
            kind: self.kind.clone(),
            inner: self.inner.clone(),
        }
    }

    pub(crate) fn from_asn1(inner: Pkcs12EncryptionAsn1) -> Result<Self, Pkcs12Error> {
        let kind = match &inner {
            Pkcs12EncryptionAsn1::Pbes1 { kind, params } => Pkcs12EncryptionKind::Pbes1(Pbes1Encryption {
                cipher: *kind,
                kdf_iterations: Some(params.iterations),
            }),
            Pkcs12EncryptionAsn1::Pbes2(Pbes2ParamsAsn1 {
                key_derivation_func:
                    Pbes2KeyDerivationFuncAsn1::Pbkdf2(Pbkdf2ParamsAsn1 {
                        iteration_count, prf, ..
                    }),
                encryption_scheme: Pbes2EncryptionSchemeAsn1::AesCbc { kind, .. },
            }) => {
                let hmac_kdf = match &prf {
                    Some(algorithm) => Pkcs12HashAlgorithm::from_asn1_pbkdf2_prf(algorithm)?,
                    None => Pkcs12HashAlgorithm::Sha1,
                };
                Pkcs12EncryptionKind::Pbes2(Pbes2Encryption {
                    cipher: (*kind).into(),
                    hmac_kdf,
                    kdf_iterations: Some(*iteration_count),
                })
            }
            _ => Pkcs12EncryptionKind::Unknown,
        };

        Ok(Self { kind, inner })
    }

    /// Create new legacy PBES1 encryption (Not recommended for new files)
    pub fn new_pbes1(encryption: Pbes1Encryption, context: &mut Pkcs12CryptoContext) -> Self {
        let salt = context.generate_bytes(DEFAULT_SALT_SIZE);
        let inner = Pkcs12EncryptionAsn1::Pbes1 {
            kind: encryption.cipher,
            params: Pbes1ParamsAsn1 {
                salt: OctetStringAsn1(salt),
                iterations: encryption.kdf_iterations.unwrap_or(DEFAULT_KDF_ITERATIONS as u32),
            },
        };

        Self {
            kind: Pkcs12EncryptionKind::Pbes1(encryption),
            inner,
        }
    }

    /// Create new PBES2 encryption (It is advised to use PBES2 for new files)
    pub fn new_pbes2(encryption: Pbes2Encryption, context: &mut Pkcs12CryptoContext) -> Self {
        let iv = context.generate_bytes(AES_BLOCK_SIZE);
        let encryption_scheme = Pbes2EncryptionSchemeAsn1::AesCbc {
            kind: encryption.cipher.into(),
            iv: OctetStringAsn1(iv),
        };

        // Skip serialization if set to SHA1 as specified in RFC
        let prf = match Pbkdf2PrfAsn1::from(encryption.hmac_kdf) {
            Pbkdf2PrfAsn1::HmacWithSha1 => None,
            value => Some(value),
        };

        let kdf_params = Pbkdf2ParamsAsn1 {
            salt: Pbkdf2SaltSourceAsn1::Specified(OctetStringAsn1(context.generate_bytes(DEFAULT_SALT_SIZE))),
            iteration_count: encryption.kdf_iterations.unwrap_or(DEFAULT_KDF_ITERATIONS as u32),
            // key length is not set by most implementations
            key_length: None,
            prf,
        };

        let pbes2_params = Pbes2ParamsAsn1 {
            key_derivation_func: Pbes2KeyDerivationFuncAsn1::Pbkdf2(kdf_params),
            encryption_scheme,
        };

        let inner = Pkcs12EncryptionAsn1::Pbes2(pbes2_params);

        Self {
            kind: Pkcs12EncryptionKind::Pbes2(encryption),
            inner,
        }
    }

    /// Parsed encryption representation
    pub fn kind(&self) -> &Pkcs12EncryptionKind {
        &self.kind
    }

    pub fn inner(&self) -> &Pkcs12EncryptionAsn1 {
        &self.inner
    }

    pub(crate) fn decrypt(&self, data: &[u8], context: &Pkcs12CryptoContext) -> Result<Vec<u8>, Pkcs12Error> {
        match self.inner() {
            Pkcs12EncryptionAsn1::Pbes1 { kind, params } => {
                let password = context.password_bytes_pbes1()?;
                decrypt_pbes1(
                    *kind,
                    password.as_slice(),
                    params.salt.as_slice(),
                    params.iterations as usize,
                    data,
                )
            }
            Pkcs12EncryptionAsn1::Pbes2(params) => {
                let password = context.password_bytes_pbes2();
                decrypt_pbes2(params, password, data)
            }
            Pkcs12EncryptionAsn1::Unknown(raw) => {
                let oid = raw.algorithm().clone();
                Err(Pkcs12Error::NotSupportedAlgorithm {
                    algorithm: super::UnsupportedPkcs12Algorithm::Oid(oid),
                    context: "decryption".to_string(),
                })
            }
        }
    }

    pub(crate) fn encrypt(&self, data: &[u8], context: &Pkcs12CryptoContext) -> Result<Vec<u8>, Pkcs12Error> {
        match self.inner() {
            Pkcs12EncryptionAsn1::Pbes1 { kind, params } => {
                let password = context.password_bytes_pbes1()?;
                encrypt_pbes1(
                    *kind,
                    password.as_slice(),
                    params.salt.as_slice(),
                    params.iterations as usize,
                    data,
                )
            }
            Pkcs12EncryptionAsn1::Pbes2(params) => {
                let password = context.password_bytes_pbes2();
                encrypt_pbes2(params, password, data)
            }
            Pkcs12EncryptionAsn1::Unknown(raw) => {
                let oid = raw.algorithm().clone();
                Err(Pkcs12Error::NotSupportedAlgorithm {
                    algorithm: super::UnsupportedPkcs12Algorithm::Oid(oid),
                    context: "encryption".to_string(),
                })
            }
        }
    }
}

/// Supported PKCS12 encryption algorithm descriptor.
/// If parsed PFX file contains unknown encryption algorithm, [`Pkcs12EncryptionKind::Unknown`]
/// variant is returned instead. If such encryption is encountered, then we can't use encrypted PFX
/// nodes, but unencrypted data still could be extracted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pkcs12EncryptionKind {
    Pbes1(Pbes1Encryption),
    Pbes2(Pbes2Encryption),
    Unknown,
}

/// PBES1 encryption descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pbes1Encryption {
    cipher: Pbes1Cipher,
    kdf_iterations: Option<u32>,
}

impl Pbes1Encryption {
    /// Creates new PBES1 encryption descriptor with given cipher algorithm.
    pub fn new(cipher: Pbes1Cipher) -> Self {
        Self {
            cipher,
            kdf_iterations: None,
        }
    }

    /// Sets KDF iteraions count to `iterations`. If not set, [`DEFAULT_KDF_ITERATIONS`] is used
    /// instead.
    pub fn with_kdf_iterations(mut self, iterations: u32) -> Self {
        self.kdf_iterations = Some(iterations);
        self
    }
}

/// PBES2 encryption descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pbes2Encryption {
    cipher: Pbes2Cipher,
    hmac_kdf: Pkcs12HashAlgorithm,
    kdf_iterations: Option<u32>,
}

impl Pbes2Encryption {
    /// Creates new PBES2 encryption descriptor with given kdf and cipher algorithms.
    pub fn new(cipher: Pbes2Cipher, hmac_kdf: Pkcs12HashAlgorithm) -> Self {
        Self {
            cipher,
            hmac_kdf,
            kdf_iterations: None,
        }
    }

    /// Sets KDF iteraions count to `iterations`. If not set, [`DEFAULT_KDF_ITERATIONS`] is used
    /// instead.
    pub fn with_kdf_iterations(mut self, iterations: u32) -> Self {
        self.kdf_iterations = Some(iterations);
        self
    }
}

/// PBES2 cipher algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pbes2Cipher {
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
}

impl Pbes2Cipher {
    /// Returns cipher key size in bytes.
    pub fn key_size(self) -> usize {
        match self {
            Self::Aes128Cbc => 16,
            Self::Aes192Cbc => 24,
            Self::Aes256Cbc => 32,
        }
    }
}

impl From<Pbes2Cipher> for Pbes2AesCbcEncryptionAsn1 {
    fn from(value: Pbes2Cipher) -> Self {
        match value {
            Pbes2Cipher::Aes128Cbc => Self::Aes128,
            Pbes2Cipher::Aes192Cbc => Self::Aes192,
            Pbes2Cipher::Aes256Cbc => Self::Aes256,
        }
    }
}

impl From<Pbes2AesCbcEncryptionAsn1> for Pbes2Cipher {
    fn from(value: Pbes2AesCbcEncryptionAsn1) -> Self {
        match value {
            Pbes2AesCbcEncryptionAsn1::Aes128 => Self::Aes128Cbc,
            Pbes2AesCbcEncryptionAsn1::Aes192 => Self::Aes192Cbc,
            Pbes2AesCbcEncryptionAsn1::Aes256 => Self::Aes256Cbc,
        }
    }
}

impl From<Pkcs12HashAlgorithm> for Pbkdf2PrfAsn1 {
    fn from(value: Pkcs12HashAlgorithm) -> Self {
        match value {
            Pkcs12HashAlgorithm::Sha1 => Self::HmacWithSha1,
            Pkcs12HashAlgorithm::Sha224 => Self::HmacWithSha224,
            Pkcs12HashAlgorithm::Sha256 => Self::HmacWithSha256,
            Pkcs12HashAlgorithm::Sha384 => Self::HmacWithSha384,
            Pkcs12HashAlgorithm::Sha512 => Self::HmacWithSha512,
        }
    }
}

struct Pbes2CipherInputs {
    key: Vec<u8>,
    iv: Vec<u8>,
    cipher: Pbes2Cipher,
}

fn prepare_pbes2_cipher_inputs(
    params: &Pbes2ParamsAsn1,
    password: &[u8],
    cipher_context: &str,
) -> Result<Pbes2CipherInputs, Pkcs12Error> {
    let (salt, kdf_iterations, prf) = match &params.key_derivation_func {
        Pbes2KeyDerivationFuncAsn1::Pbkdf2(kdf) => {
            let salt = match &kdf.salt {
                Pbkdf2SaltSourceAsn1::Specified(salt) => salt.0.clone(),
                Pbkdf2SaltSourceAsn1::OtherSource(raw) => {
                    let oid = raw.algorithm().clone();
                    return Err(Pkcs12Error::NotSupportedAlgorithm {
                        algorithm: super::UnsupportedPkcs12Algorithm::Oid(oid),
                        context: format!("pbes2 {cipher_context} (kdf salt source)"),
                    });
                }
            };

            let prf = match &kdf.prf {
                None => Pkcs12HashAlgorithm::Sha1,
                Some(Pbkdf2PrfAsn1::HmacWithSha1) => Pkcs12HashAlgorithm::Sha1,
                Some(Pbkdf2PrfAsn1::HmacWithSha224) => Pkcs12HashAlgorithm::Sha224,
                Some(Pbkdf2PrfAsn1::HmacWithSha256) => Pkcs12HashAlgorithm::Sha256,
                Some(Pbkdf2PrfAsn1::HmacWithSha384) => Pkcs12HashAlgorithm::Sha384,
                Some(Pbkdf2PrfAsn1::HmacWithSha512) => Pkcs12HashAlgorithm::Sha512,
                Some(Pbkdf2PrfAsn1::Unknown(raw)) => {
                    let oid = raw.algorithm().clone();
                    return Err(Pkcs12Error::NotSupportedAlgorithm {
                        algorithm: super::UnsupportedPkcs12Algorithm::Oid(oid),
                        context: format!("pbes2 {cipher_context} (kdf prf)"),
                    });
                }
            };

            (salt, kdf.iteration_count, prf)
        }
        Pbes2KeyDerivationFuncAsn1::Unknown(raw) => {
            let oid = raw.algorithm().clone();
            return Err(Pkcs12Error::NotSupportedAlgorithm {
                algorithm: super::UnsupportedPkcs12Algorithm::Oid(oid),
                context: format!("pbes2 {cipher_context} (kdf)"),
            });
        }
    };

    let (cipher, iv) = match &params.encryption_scheme {
        Pbes2EncryptionSchemeAsn1::AesCbc { kind, iv } => (Pbes2Cipher::from(*kind), iv.0.clone()),
        Pbes2EncryptionSchemeAsn1::Unknown(raw) => {
            let oid = raw.algorithm().clone();
            return Err(Pkcs12Error::NotSupportedAlgorithm {
                algorithm: super::UnsupportedPkcs12Algorithm::Oid(oid),
                context: format!("pbes2 {cipher_context} (cipher)"),
            });
        }
    };

    let calculate_kdf = match prf {
        Pkcs12HashAlgorithm::Sha1 => pbkdf2::pbkdf2_hmac::<sha1::Sha1>,
        Pkcs12HashAlgorithm::Sha224 => pbkdf2::pbkdf2_hmac::<sha2::Sha224>,
        Pkcs12HashAlgorithm::Sha256 => pbkdf2::pbkdf2_hmac::<sha2::Sha256>,
        Pkcs12HashAlgorithm::Sha384 => pbkdf2::pbkdf2_hmac::<sha2::Sha384>,
        Pkcs12HashAlgorithm::Sha512 => pbkdf2::pbkdf2_hmac::<sha2::Sha512>,
    };

    let mut key = vec![0u8; cipher.key_size()];
    calculate_kdf(password, salt.as_slice(), kdf_iterations, key.as_mut_slice());

    Ok(Pbes2CipherInputs { key, iv, cipher })
}

fn decrypt_pbes2(params: &Pbes2ParamsAsn1, password: &[u8], data: &[u8]) -> Result<Vec<u8>, Pkcs12Error> {
    let Pbes2CipherInputs { key, iv, cipher } = prepare_pbes2_cipher_inputs(params, password, "decryption")?;

    use aes::cipher::BlockModeDecrypt;
    use cbc::Decryptor;
    use cbc::cipher::KeyIvInit;
    use cbc::cipher::block_padding::Pkcs7;

    let decrypted = match cipher {
        Pbes2Cipher::Aes128Cbc => {
            use aes::Aes128;
            type Aes128Cbc = Decryptor<Aes128>;

            let aes = Aes128Cbc::new_from_slices(key.as_slice(), iv.as_slice()).map_err(|_| Pkcs12Error::Pbes2 {
                context: "AES128 decryptor initialization failed".to_string(),
            })?;

            aes.decrypt_padded_vec::<Pkcs7>(data).map_err(|_| Pkcs12Error::Pbes2 {
                context: "AES128 decryption with padding failed".to_string(),
            })?
        }
        Pbes2Cipher::Aes192Cbc => {
            use aes::Aes192;
            type Aes192Cbc = Decryptor<Aes192>;

            let aes = Aes192Cbc::new_from_slices(key.as_slice(), iv.as_slice()).map_err(|_| Pkcs12Error::Pbes2 {
                context: "AES192 decryptor initialization failed".to_string(),
            })?;

            aes.decrypt_padded_vec::<Pkcs7>(data).map_err(|_| Pkcs12Error::Pbes2 {
                context: "AES192 decryption with padding failed".to_string(),
            })?
        }
        Pbes2Cipher::Aes256Cbc => {
            use aes::Aes256;
            type Aes256Cbc = Decryptor<Aes256>;

            let aes = Aes256Cbc::new_from_slices(key.as_slice(), iv.as_slice()).map_err(|_| Pkcs12Error::Pbes2 {
                context: "AES256 decryptor initialization failed".to_string(),
            })?;

            aes.decrypt_padded_vec::<Pkcs7>(data).map_err(|_| Pkcs12Error::Pbes2 {
                context: "AES256 decryption with padding failed".to_string(),
            })?
        }
    };

    Ok(decrypted)
}

fn encrypt_pbes2(params: &Pbes2ParamsAsn1, password: &[u8], data: &[u8]) -> Result<Vec<u8>, Pkcs12Error> {
    let Pbes2CipherInputs { key, iv, cipher } = prepare_pbes2_cipher_inputs(params, password, "encryption")?;

    use aes::cipher::BlockModeEncrypt;
    use cbc::Encryptor;
    use cbc::cipher::KeyIvInit;
    use cbc::cipher::block_padding::Pkcs7;

    let encrypted = match cipher {
        Pbes2Cipher::Aes128Cbc => {
            use aes::Aes128;
            type Aes128Cbc = Encryptor<Aes128>;

            let aes = Aes128Cbc::new_from_slices(key.as_slice(), iv.as_slice()).map_err(|_| Pkcs12Error::Pbes2 {
                context: "AES128 encryptor initialization failed".to_string(),
            })?;

            aes.encrypt_padded_vec::<Pkcs7>(data)
        }
        Pbes2Cipher::Aes192Cbc => {
            use aes::Aes192;
            type Aes192Cbc = Encryptor<Aes192>;

            let aes = Aes192Cbc::new_from_slices(key.as_slice(), iv.as_slice()).map_err(|_| Pkcs12Error::Pbes2 {
                context: "AES192 encryptor initialization failed".to_string(),
            })?;

            aes.encrypt_padded_vec::<Pkcs7>(data)
        }
        Pbes2Cipher::Aes256Cbc => {
            use aes::Aes256;
            type Aes256Cbc = Encryptor<Aes256>;

            let aes = Aes256Cbc::new_from_slices(key.as_slice(), iv.as_slice()).map_err(|_| Pkcs12Error::Pbes2 {
                context: "AES256 encryptor initialization failed".to_string(),
            })?;

            aes.encrypt_padded_vec::<Pkcs7>(data)
        }
    };

    Ok(encrypted)
}

fn generate_pbes1_key_and_iv(
    cipher: Pbes1Cipher,
    password: &[u8],
    salt: &[u8],
    kdf_iterations: usize,
) -> (Vec<u8>, Vec<u8>) {
    let (key_size, iv_size) = match cipher {
        Pbes1Cipher::ShaAnd40BitRc2Cbc => (5, 8),
        Pbes1Cipher::ShaAnd3Key3DesCbc => (24, 8),
    };

    let key = pbkdf1(
        Pkcs12HashAlgorithm::Sha1,
        password,
        salt,
        kdf_iterations,
        Pbkdf1Usage::Key,
        key_size,
    );
    let iv = pbkdf1(
        Pkcs12HashAlgorithm::Sha1,
        password,
        salt,
        kdf_iterations,
        Pbkdf1Usage::Iv,
        iv_size,
    );

    (key, iv)
}

fn encrypt_pbes1(
    scheme: Pbes1Cipher,
    password: &[u8],
    salt: &[u8],
    kdf_iterations: usize,
    data: &[u8],
) -> Result<Vec<u8>, Pkcs12Error> {
    use cbc::Encryptor;
    use cbc::cipher::block_padding::Pkcs7;
    use cbc::cipher::{BlockModeEncrypt, KeyIvInit};

    let (dk, iv) = generate_pbes1_key_and_iv(scheme, password, salt, kdf_iterations);

    match scheme {
        Pbes1Cipher::ShaAnd40BitRc2Cbc => {
            use rc2::Rc2;
            type Rc2Cbc = Encryptor<Rc2>;

            let rc2 = Rc2Cbc::new_from_slices(&dk, &iv).map_err(|_| Pkcs12Error::Pbes1 {
                context: "RC2 encryption initialization failed".to_string(),
            })?;
            Ok(rc2.encrypt_padded_vec::<Pkcs7>(data))
        }
        Pbes1Cipher::ShaAnd3Key3DesCbc => {
            use des::TdesEde3;
            type TDesCbc = Encryptor<TdesEde3>;

            let tdes = TDesCbc::new_from_slices(&dk, &iv).map_err(|_| Pkcs12Error::Pbes1 {
                context: "3DES encryptor initialization failed".to_string(),
            })?;
            Ok(tdes.encrypt_padded_vec::<Pkcs7>(data))
        }
    }
}

fn decrypt_pbes1(
    scheme: Pbes1Cipher,
    password: &[u8],
    salt: &[u8],
    kdf_iterations: usize,
    data: &[u8],
) -> Result<Vec<u8>, Pkcs12Error> {
    use cbc::Decryptor;
    use cbc::cipher::block_padding::Pkcs7;
    use cbc::cipher::{BlockModeDecrypt, KeyIvInit};

    let (dk, iv) = generate_pbes1_key_and_iv(scheme, password, salt, kdf_iterations);

    match scheme {
        Pbes1Cipher::ShaAnd40BitRc2Cbc => {
            use rc2::Rc2;
            type Rc2Cbc = Decryptor<Rc2>;

            let rc2 = Rc2Cbc::new_from_slices(&dk, &iv).map_err(|_| Pkcs12Error::Pbes1 {
                context: "RC2 decryptor initialization failed".to_string(),
            })?;
            rc2.decrypt_padded_vec::<Pkcs7>(data).map_err(|_| Pkcs12Error::Pbes1 {
                context: "RC2 decryption with padding failed".to_string(),
            })
        }
        Pbes1Cipher::ShaAnd3Key3DesCbc => {
            use des::TdesEde3;
            type TDesCbc = Decryptor<TdesEde3>;

            let tdes = TDesCbc::new_from_slices(&dk, &iv).map_err(|_| Pkcs12Error::Pbes1 {
                context: "3DES decryptor initialization failed".to_string(),
            })?;
            tdes.decrypt_padded_vec::<Pkcs7>(data).map_err(|_| Pkcs12Error::Pbes1 {
                context: "3DES decryption with padding failed".to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn pbes1_3des_roundtrip() {
        let password = b"\0a\0b\0c\0\0";
        let salt = (0..8).collect::<Vec<u8>>();
        let iterations = 2000;
        let data = (0..123).collect::<Vec<u8>>();
        let encrypted = encrypt_pbes1(Pbes1Cipher::ShaAnd3Key3DesCbc, password, &salt, iterations, &data).unwrap();
        let decrypted = decrypt_pbes1(Pbes1Cipher::ShaAnd3Key3DesCbc, password, &salt, iterations, &encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn pbes1_rc2_roundtrip() {
        let password = b"\0b\0c\0a\0\0";
        let salt = (0..8).collect::<Vec<u8>>();
        let iterations = 2048;
        let data = (0..124).collect::<Vec<u8>>();
        let encrypted = encrypt_pbes1(Pbes1Cipher::ShaAnd40BitRc2Cbc, password, &salt, iterations, &data).unwrap();
        let decrypted = decrypt_pbes1(Pbes1Cipher::ShaAnd40BitRc2Cbc, password, &salt, iterations, &encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[rstest]
    #[case(Pbes2AesCbcEncryptionAsn1::Aes128)]
    #[case(Pbes2AesCbcEncryptionAsn1::Aes192)]
    #[case(Pbes2AesCbcEncryptionAsn1::Aes256)]
    fn pbes2_aes256_roundtrip(#[case] aes: Pbes2AesCbcEncryptionAsn1) {
        let password = b"test";
        let data = (0..123).collect::<Vec<u8>>();
        let params = Pbes2ParamsAsn1 {
            key_derivation_func: Pbes2KeyDerivationFuncAsn1::Pbkdf2(Pbkdf2ParamsAsn1 {
                salt: Pbkdf2SaltSourceAsn1::Specified(OctetStringAsn1((0..8).collect())),
                iteration_count: 2000,
                key_length: None,
                prf: Some(Pbkdf2PrfAsn1::HmacWithSha256),
            }),
            encryption_scheme: Pbes2EncryptionSchemeAsn1::AesCbc {
                kind: aes,
                iv: OctetStringAsn1((0..16).collect()),
            },
        };
        let encrypted = encrypt_pbes2(&params, password, &data).unwrap();
        let decrypted = decrypt_pbes2(&params, password, &encrypted).unwrap();
        assert_eq!(decrypted, data);
    }
}
