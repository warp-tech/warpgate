use crate::pkcs12::{Pbkdf1Usage, Pkcs12CryptoContext, Pkcs12Error, Pkcs12HashAlgorithm, pbkdf1};
use hmac::KeyInit;
use picky_asn1::wrapper::OctetStringAsn1;
use picky_asn1_x509::pkcs12::{MacData as MacDataAsn1, Pkcs12DigestInfo as Pkcs12DigestInfoAsn1};
use thiserror::Error;

const DEFAULT_MAC_KDF_ITERATIONS: u32 = 1;
const DEFAULT_SALT_SIZE: usize = 20;

#[derive(Debug, Clone, Error)]
pub enum Pkcs12MacError {
    #[error("Invalid hmac input size")]
    InvalidHmacInputSize,
    #[error("MAC validation failed (wrong password or corrupted data)")]
    MacValidation,
}

/// HMAC algorithm parameters (used for PFX integrity data)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkcs12MacAlgorithmHmac {
    hash_algorithm: Pkcs12HashAlgorithm,
    iterations: Option<u32>,
}

impl Pkcs12MacAlgorithmHmac {
    pub fn new(hash_algorithm: Pkcs12HashAlgorithm) -> Self {
        Self {
            hash_algorithm,
            iterations: None,
        }
    }

    pub fn with_iterations(mut self, iterations: u32) -> Self {
        self.iterations = Some(iterations);
        self
    }

    pub fn hash_algorithm(&self) -> Pkcs12HashAlgorithm {
        self.hash_algorithm
    }

    pub fn iterations(&self) -> Option<u32> {
        self.iterations
    }
}

/// Parsed MAC algorithm parameters
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pkcs12MacAlgorithm {
    Hmac(Pkcs12MacAlgorithmHmac),
    Unknown,
}

/// Parsed PFX MAC data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkcs12MacData {
    algorithm: Pkcs12MacAlgorithm,
    inner: MacDataAsn1,
}

impl Pkcs12MacData {
    pub(crate) fn from_asn1(inner: MacDataAsn1, skip_unknown_hash_algorithm: bool) -> Result<Self, Pkcs12Error> {
        let hash_algorithm = match Pkcs12HashAlgorithm::from_asn1_digest_algorithm(&inner.mac.digest_algorithm) {
            Ok(algorithm) => algorithm,
            Err(_) if skip_unknown_hash_algorithm => {
                return Ok(Self {
                    algorithm: Pkcs12MacAlgorithm::Unknown,
                    inner,
                });
            }
            Err(e) => {
                return Err(e);
            }
        };

        let kdf_iterations = inner.iterations.unwrap_or(DEFAULT_MAC_KDF_ITERATIONS);

        Ok(Self {
            algorithm: Pkcs12MacAlgorithm::Hmac(Pkcs12MacAlgorithmHmac {
                hash_algorithm,
                iterations: Some(kdf_iterations),
            }),
            inner,
        })
    }

    pub(crate) fn new_hmac(
        algorithm: Pkcs12MacAlgorithmHmac,
        context: &mut Pkcs12CryptoContext,
        data: &[u8],
    ) -> Result<Self, Pkcs12Error> {
        let hash_algorithm = algorithm.hash_algorithm;
        let kdf_iterations = algorithm.iterations.unwrap_or(DEFAULT_MAC_KDF_ITERATIONS);
        let salt = context.generate_bytes(DEFAULT_SALT_SIZE);

        // PKCS12 MAC uses BMPString as password representation
        let password = context.password_bytes_pbes1()?;

        let digest = Self::calculate_digest(
            hash_algorithm,
            kdf_iterations,
            password.as_slice(),
            salt.as_slice(),
            data,
        )?;

        Ok(Self {
            algorithm: Pkcs12MacAlgorithm::Hmac(algorithm),
            inner: MacDataAsn1 {
                mac: Pkcs12DigestInfoAsn1 {
                    digest_algorithm: hash_algorithm.into(),
                    digest: OctetStringAsn1(digest),
                },
                salt: OctetStringAsn1(salt),
                iterations: Some(kdf_iterations),
            },
        })
    }

    pub(crate) fn validate(&self, context: &Pkcs12CryptoContext, data: &[u8]) -> Result<(), Pkcs12Error> {
        let hash_algorithm = Pkcs12HashAlgorithm::from_asn1_digest_algorithm(&self.inner.mac.digest_algorithm)?;
        let kdf_iterations = self.inner.iterations.unwrap_or(DEFAULT_MAC_KDF_ITERATIONS);
        let salt = self.inner.salt.0.as_slice();

        // PKCS12 MAC uses BMPString as password representation
        let password = context.password_bytes_pbes1()?;

        let digest = Self::calculate_digest(hash_algorithm, kdf_iterations, password.as_slice(), salt, data)?;

        if digest == self.inner.mac.digest.0.as_slice() {
            Ok(())
        } else {
            Err(Pkcs12MacError::MacValidation.into())
        }
    }

    fn calculate_digest(
        hash_algorithm: Pkcs12HashAlgorithm,
        kdf_iterations: u32,
        password: &[u8],
        salt: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, Pkcs12Error> {
        let key = pbkdf1(
            hash_algorithm,
            password,
            salt,
            kdf_iterations as usize,
            Pbkdf1Usage::Mac,
            hash_algorithm.digest_size(),
        );

        use hmac::Mac;

        let map_hmac_err = |_| Pkcs12MacError::InvalidHmacInputSize;

        let mac = match hash_algorithm {
            Pkcs12HashAlgorithm::Sha1 => {
                let mut hmac = hmac::Hmac::<sha1::Sha1>::new_from_slice(&key).map_err(map_hmac_err)?;
                hmac.update(data);
                hmac.finalize().into_bytes().to_vec()
            }
            Pkcs12HashAlgorithm::Sha224 => {
                let mut hmac = hmac::Hmac::<sha2::Sha224>::new_from_slice(&key).map_err(map_hmac_err)?;
                hmac.update(data);
                hmac.finalize().into_bytes().to_vec()
            }
            Pkcs12HashAlgorithm::Sha256 => {
                let mut hmac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&key).map_err(map_hmac_err)?;
                hmac.update(data);
                hmac.finalize().into_bytes().to_vec()
            }
            Pkcs12HashAlgorithm::Sha384 => {
                let mut hmac = hmac::Hmac::<sha2::Sha384>::new_from_slice(&key).map_err(map_hmac_err)?;
                hmac.update(data);
                hmac.finalize().into_bytes().to_vec()
            }
            Pkcs12HashAlgorithm::Sha512 => {
                let mut hmac = hmac::Hmac::<sha2::Sha512>::new_from_slice(&key).map_err(map_hmac_err)?;
                hmac.update(data);
                hmac.finalize().into_bytes().to_vec()
            }
        };

        Ok(mac)
    }

    pub fn inner(&self) -> &MacDataAsn1 {
        &self.inner
    }

    /// Parsed MAC algorithm parameters
    pub fn algorithm(&self) -> &Pkcs12MacAlgorithm {
        &self.algorithm
    }
}
