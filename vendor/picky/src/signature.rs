//! Signature algorithms supported by picky

use crate::hash::HashAlgorithm;
use crate::key::ec::{EcComponent, EcCurve, NamedEcCurve};
use crate::key::{KeyError, PrivateKey, PublicKey};

use picky_asn1_x509::{AlgorithmIdentifier, oids};
use rsa::signature::{SignatureEncoding as _, Signer};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SignatureError {
    /// Key error
    #[error("Key error: {source}")]
    Key { source: KeyError },

    /// RSA error
    #[error("RSA error: {context}")]
    Rsa { context: String },

    /// EC error
    #[error("EC error: {context}")]
    Ec { context: String },

    /// ED error
    #[error("ED error: {context}")]
    Ed { context: String },

    /// invalid signature
    #[error("invalid signature")]
    BadSignature,

    /// unsupported algorithm
    #[error("unsupported algorithm: {algorithm}")]
    UnsupportedAlgorithm { algorithm: String },
}

impl From<rsa::errors::Error> for SignatureError {
    fn from(e: rsa::errors::Error) -> Self {
        SignatureError::Rsa { context: e.to_string() }
    }
}

impl From<rsa::signature::Error> for SignatureError {
    fn from(e: rsa::signature::Error) -> Self {
        SignatureError::Rsa { context: e.to_string() }
    }
}

impl From<KeyError> for SignatureError {
    fn from(e: KeyError) -> Self {
        SignatureError::Key { source: e }
    }
}

/// Supported signature algorithms
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    RsaPkcs1v15(HashAlgorithm),
    Ecdsa(HashAlgorithm),
    Ed25519,
}

impl TryFrom<&'_ AlgorithmIdentifier> for SignatureAlgorithm {
    type Error = SignatureError;

    fn try_from(v: &AlgorithmIdentifier) -> Result<Self, Self::Error> {
        let oid_string: String = v.oid().into();
        match oid_string.as_str() {
            oids::MD5_WITH_RSA_ENCRYPTHION => Ok(Self::RsaPkcs1v15(HashAlgorithm::MD5)),
            oids::SHA1_WITH_RSA_ENCRYPTION => Ok(Self::RsaPkcs1v15(HashAlgorithm::SHA1)),
            oids::SHA224_WITH_RSA_ENCRYPTION => Ok(Self::RsaPkcs1v15(HashAlgorithm::SHA2_224)),
            oids::SHA256_WITH_RSA_ENCRYPTION => Ok(Self::RsaPkcs1v15(HashAlgorithm::SHA2_256)),
            oids::SHA384_WITH_RSA_ENCRYPTION => Ok(Self::RsaPkcs1v15(HashAlgorithm::SHA2_384)),
            oids::SHA512_WITH_RSA_ENCRYPTION => Ok(Self::RsaPkcs1v15(HashAlgorithm::SHA2_512)),
            oids::ID_RSASSA_PKCS1_V1_5_WITH_SHA3_384 => Ok(Self::RsaPkcs1v15(HashAlgorithm::SHA3_384)),
            oids::ID_RSASSA_PKCS1_V1_5_WITH_SHA3_512 => Ok(Self::RsaPkcs1v15(HashAlgorithm::SHA3_512)),
            oids::ECDSA_WITH_SHA256 => Ok(Self::Ecdsa(HashAlgorithm::SHA2_256)),
            oids::ECDSA_WITH_SHA384 => Ok(Self::Ecdsa(HashAlgorithm::SHA2_384)),
            oids::ED25519 => Ok(Self::Ed25519),
            _ => Err(SignatureError::UnsupportedAlgorithm { algorithm: oid_string }),
        }
    }
}

impl TryFrom<SignatureAlgorithm> for AlgorithmIdentifier {
    type Error = SignatureError;

    fn try_from(ty: SignatureAlgorithm) -> Result<Self, Self::Error> {
        match ty {
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::MD5) => {
                Ok(AlgorithmIdentifier::new_md5_with_rsa_encryption())
            }
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA1) => {
                Ok(AlgorithmIdentifier::new_sha1_with_rsa_encryption())
            }
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_224) => {
                Ok(AlgorithmIdentifier::new_sha224_with_rsa_encryption())
            }
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_256) => {
                Ok(AlgorithmIdentifier::new_sha256_with_rsa_encryption())
            }
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_384) => {
                Ok(AlgorithmIdentifier::new_sha384_with_rsa_encryption())
            }
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_512) => {
                Ok(AlgorithmIdentifier::new_sha512_with_rsa_encryption())
            }
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA3_384) => {
                Ok(AlgorithmIdentifier::new_sha3_384_with_rsa_encryption())
            }
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA3_512) => {
                Ok(AlgorithmIdentifier::new_sha3_512_with_rsa_encryption())
            }
            SignatureAlgorithm::Ecdsa(HashAlgorithm::SHA2_256) => Ok(AlgorithmIdentifier::new_ecdsa_with_sha256()),
            SignatureAlgorithm::Ecdsa(HashAlgorithm::SHA2_384) => Ok(AlgorithmIdentifier::new_ecdsa_with_sha384()),
            SignatureAlgorithm::Ecdsa(HashAlgorithm::SHA2_512) => Ok(AlgorithmIdentifier::new_ecdsa_with_sha512()),
            SignatureAlgorithm::Ecdsa(hash) => {
                let msg = format!("ECDSA doesn't support {hash:?} hashing algorithm");
                Err(SignatureError::Ec { context: msg })
            }
            SignatureAlgorithm::Ed25519 => Ok(AlgorithmIdentifier::new_ed25519()),
        }
    }
}

impl SignatureAlgorithm {
    pub fn from_algorithm_identifier(algorithm_identifier: &AlgorithmIdentifier) -> Result<Self, SignatureError> {
        Self::try_from(algorithm_identifier)
    }

    pub fn sign(self, msg: &[u8], private_key: &PrivateKey) -> Result<Vec<u8>, SignatureError> {
        match self {
            SignatureAlgorithm::RsaPkcs1v15(picky_hash_algo) => {
                use rsa::signature::SignatureEncoding as _;
                use rsa::{RsaPrivateKey, pkcs1v15};

                let rsa_private_key = RsaPrivateKey::try_from(private_key)?;

                let signature = match picky_hash_algo {
                    HashAlgorithm::MD5 => pkcs1v15::SigningKey::<md5::Md5>::new(rsa_private_key).try_sign(msg)?,
                    HashAlgorithm::SHA1 => pkcs1v15::SigningKey::<sha1::Sha1>::new(rsa_private_key).try_sign(msg)?,
                    HashAlgorithm::SHA2_224 => {
                        pkcs1v15::SigningKey::<sha2::Sha224>::new(rsa_private_key).try_sign(msg)?
                    }
                    HashAlgorithm::SHA2_256 => {
                        pkcs1v15::SigningKey::<sha2::Sha256>::new(rsa_private_key).try_sign(msg)?
                    }
                    HashAlgorithm::SHA2_384 => {
                        pkcs1v15::SigningKey::<sha2::Sha384>::new(rsa_private_key).try_sign(msg)?
                    }
                    HashAlgorithm::SHA2_512 => {
                        pkcs1v15::SigningKey::<sha2::Sha512>::new(rsa_private_key).try_sign(msg)?
                    }
                    HashAlgorithm::SHA3_384 => {
                        pkcs1v15::SigningKey::<sha3::Sha3_384>::new(rsa_private_key).try_sign(msg)?
                    }
                    HashAlgorithm::SHA3_512 => {
                        pkcs1v15::SigningKey::<sha3::Sha3_512>::new(rsa_private_key).try_sign(msg)?
                    }
                };

                Ok(signature.to_vec())
            }
            SignatureAlgorithm::Ecdsa(picky_hash_algo) => {
                use crate::key::ec::EcdsaKeypair;
                use p256::ecdsa::signature::Signer;

                let ec_keypair = EcdsaKeypair::try_from(private_key)?;

                match ec_keypair.curve() {
                    NamedEcCurve::Known(EcCurve::NistP256) => match picky_hash_algo {
                        HashAlgorithm::SHA2_256 => {
                            let secret_validated =
                                EcCurve::NistP256.validate_component(EcComponent::Secret(ec_keypair.secret()))?;

                            let key_bytes =
                                p256::elliptic_curve::array::Array::try_from(secret_validated).map_err(|_| {
                                    SignatureError::Ec {
                                        context: format!(
                                            "validated secret is not the right size(expected: {}, actual: {})",
                                            EcCurve::NistP256.field_bytes_size(),
                                            secret_validated.len(),
                                        ),
                                    }
                                })?;
                            let key =
                                p256::ecdsa::SigningKey::from_bytes(&key_bytes).map_err(|e| SignatureError::Ec {
                                    context: format!("Cannot decode p256 EC keypair: {e}"),
                                })?;
                            let sig: p256::ecdsa::Signature = key.try_sign(msg).map_err(|e| SignatureError::Ec {
                                context: format!("Cannot produce p256 signature: {e}"),
                            })?;

                            Ok(sig.to_der().as_bytes().to_vec())
                        }
                        _ => Err(SignatureError::UnsupportedAlgorithm {
                            algorithm: format!(
                                "ECDSA P-256 curve with {picky_hash_algo:?} hash algorithm is not supported"
                            ),
                        }),
                    },
                    NamedEcCurve::Known(EcCurve::NistP384) => match picky_hash_algo {
                        HashAlgorithm::SHA2_384 => {
                            let secret_validated =
                                EcCurve::NistP384.validate_component(EcComponent::Secret(ec_keypair.secret()))?;

                            let key_bytes =
                                p384::elliptic_curve::array::Array::try_from(secret_validated).map_err(|_| {
                                    SignatureError::Ec {
                                        context: format!(
                                            "validated secret is not the right size(expected: {}, actual: {})",
                                            EcCurve::NistP384.field_bytes_size(),
                                            secret_validated.len(),
                                        ),
                                    }
                                })?;

                            let key =
                                p384::ecdsa::SigningKey::from_bytes(&key_bytes).map_err(|e| SignatureError::Ec {
                                    context: format!("Cannot decode p384 EC keypair: {e}"),
                                })?;
                            let sig: p384::ecdsa::Signature = key.try_sign(msg).map_err(|e| SignatureError::Ec {
                                context: format!("Cannot produce p384 signature: {e}"),
                            })?;
                            Ok(sig.to_der().as_bytes().to_vec())
                        }
                        _ => Err(SignatureError::UnsupportedAlgorithm {
                            algorithm: format!(
                                "ECDSA P-384 curve with {picky_hash_algo:?} hash algorithm is not supported"
                            ),
                        }),
                    },
                    NamedEcCurve::Known(EcCurve::NistP521) => match picky_hash_algo {
                        HashAlgorithm::SHA2_512 => {
                            let secret_validated =
                                EcCurve::NistP521.validate_component(EcComponent::Secret(ec_keypair.secret()))?;

                            let key_bytes =
                                p521::elliptic_curve::array::Array::try_from(secret_validated).map_err(|_| {
                                    SignatureError::Ec {
                                        context: format!(
                                            "validated secret is not the right size(expected: {}, actual: {})",
                                            EcCurve::NistP521.field_bytes_size(),
                                            secret_validated.len(),
                                        ),
                                    }
                                })?;

                            let key =
                                p521::ecdsa::SigningKey::from_bytes(&key_bytes).map_err(|e| SignatureError::Ec {
                                    context: format!("Cannot decode p521 EC keypair: {e}"),
                                })?;
                            let sig: p521::ecdsa::Signature = key.try_sign(msg).map_err(|e| SignatureError::Ec {
                                context: format!("Cannot produce p521 signature: {e}"),
                            })?;
                            Ok(sig.to_der().as_bytes().to_vec())
                        }
                        _ => Err(SignatureError::UnsupportedAlgorithm {
                            algorithm: format!(
                                "ECDSA P-521 curve with {picky_hash_algo:?} hash algorithm is not supported"
                            ),
                        }),
                    },
                    NamedEcCurve::Unsupported(oid) => Err(KeyError::unsupported_curve(oid, "signing").into()),
                }
            }
            SignatureAlgorithm::Ed25519 => {
                use crate::key::ed::{EdAlgorithm, EdKeypair, EdPublicKey, NamedEdAlgorithm};

                let keypair = EdKeypair::try_from(private_key)?;

                let public_key = EdPublicKey::try_from(&keypair)?;

                match keypair.algorithm() {
                    NamedEdAlgorithm::Known(EdAlgorithm::Ed25519) => {
                        let public_key = public_key.data().try_into().map_err(|e| SignatureError::Ed {
                            context: format!("invalid key size: {e}"),
                        })?;
                        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key).map_err(
                            |e: ed25519_dalek::ed25519::Error| SignatureError::Ed {
                                context: format!("Cannot decode ed25519 public key: {e}"),
                            },
                        )?;

                        let secret_key: ed25519_dalek::SecretKey =
                            keypair.secret().try_into().map_err(|e| SignatureError::Ed {
                                context: format!("invalid secret key size: {e}"),
                            })?;

                        let esk = ed25519_dalek::hazmat::ExpandedSecretKey::from(&secret_key);

                        let signature = ed25519_dalek::hazmat::raw_sign::<sha2::Sha512>(&esk, msg, &verifying_key);

                        Ok(signature.to_vec())
                    }
                    NamedEdAlgorithm::Known(EdAlgorithm::X25519) => Err(SignatureError::Ed {
                        context: "X25519 algorithm is not designed for signing".to_string(),
                    }),
                    NamedEdAlgorithm::Unsupported(oid) => {
                        Err(KeyError::unsupported_ed_algorithm(oid, "signing").into())
                    }
                }
            }
        }
    }

    pub fn verify(self, public_key: &PublicKey, msg: &[u8], signature: &[u8]) -> Result<(), SignatureError> {
        match self {
            SignatureAlgorithm::RsaPkcs1v15(picky_hash_algo) => {
                use rsa::signature::Verifier as _;
                use rsa::{RsaPublicKey, pkcs1v15};

                let rsa_public_key = RsaPublicKey::try_from(public_key)?;
                let signature = pkcs1v15::Signature::try_from(signature)?;

                match picky_hash_algo {
                    HashAlgorithm::MD5 => {
                        pkcs1v15::VerifyingKey::<md5::Md5>::new(rsa_public_key).verify(msg, &signature)
                    }
                    HashAlgorithm::SHA1 => {
                        pkcs1v15::VerifyingKey::<sha1::Sha1>::new(rsa_public_key).verify(msg, &signature)
                    }
                    HashAlgorithm::SHA2_224 => {
                        pkcs1v15::VerifyingKey::<sha2::Sha224>::new(rsa_public_key).verify(msg, &signature)
                    }
                    HashAlgorithm::SHA2_256 => {
                        pkcs1v15::VerifyingKey::<sha2::Sha256>::new(rsa_public_key).verify(msg, &signature)
                    }
                    HashAlgorithm::SHA2_384 => {
                        pkcs1v15::VerifyingKey::<sha2::Sha384>::new(rsa_public_key).verify(msg, &signature)
                    }
                    HashAlgorithm::SHA2_512 => {
                        pkcs1v15::VerifyingKey::<sha2::Sha512>::new(rsa_public_key).verify(msg, &signature)
                    }
                    HashAlgorithm::SHA3_384 => {
                        pkcs1v15::VerifyingKey::<sha3::Sha3_384>::new(rsa_public_key).verify(msg, &signature)
                    }
                    HashAlgorithm::SHA3_512 => {
                        pkcs1v15::VerifyingKey::<sha3::Sha3_512>::new(rsa_public_key).verify(msg, &signature)
                    }
                }
                .map_err(|_| SignatureError::BadSignature)?;
            }
            SignatureAlgorithm::Ecdsa(picky_hash_algo) => {
                let ec_pub_key = crate::key::ec::EcdsaPublicKey::try_from(public_key)?;

                let curve = match ec_pub_key.curve() {
                    NamedEcCurve::Known(curve) => curve,
                    NamedEcCurve::Unsupported(oid) => return Err(KeyError::unsupported_curve(oid, "verifying").into()),
                };

                match picky_hash_algo {
                    HashAlgorithm::SHA2_256 => {
                        use p256::ecdsa::signature::Verifier;

                        match curve {
                            EcCurve::NistP256 => {}
                            curve => {
                                return Err(SignatureError::UnsupportedAlgorithm {
                                    algorithm: format!("SHA256 hash algorithm can't be used with `{curve}` curve"),
                                });
                            }
                        };

                        let encoded_point = p256::Sec1Point::from_bytes(ec_pub_key.encoded_point()).map_err(|e| {
                            SignatureError::Ec {
                                context: format!("Cannot parse p256 public key from der bytes: {e}"),
                            }
                        })?;

                        let vkey = p256::ecdsa::VerifyingKey::from_sec1_point(&encoded_point).map_err(|e| {
                            SignatureError::Ec {
                                context: format!("Cannot parse p256 encoded point: {e}"),
                            }
                        })?;

                        let signature =
                            p256::ecdsa::Signature::from_der(signature).map_err(|e| SignatureError::Ec {
                                context: format!("Cannot parse p256 signature: {e}"),
                            })?;
                        vkey.verify(msg, &signature).map_err(|_| SignatureError::BadSignature)?
                    }
                    HashAlgorithm::SHA2_384 => {
                        use p384::ecdsa::signature::Verifier;

                        match curve {
                            EcCurve::NistP384 => {}
                            curve => {
                                return Err(SignatureError::UnsupportedAlgorithm {
                                    algorithm: format!("SHA384 hash algorithm can't be used with `{curve}` curve"),
                                });
                            }
                        };

                        let encoded_point = p384::Sec1Point::from_bytes(ec_pub_key.encoded_point()).map_err(|e| {
                            SignatureError::Ec {
                                context: format!("Cannot parse p384 public key from der bytes: {e}"),
                            }
                        })?;

                        let vkey = p384::ecdsa::VerifyingKey::from_sec1_point(&encoded_point).map_err(|e| {
                            SignatureError::Ec {
                                context: format!("Cannot parse p384 encoded point: {e}"),
                            }
                        })?;

                        let signature =
                            p384::ecdsa::Signature::from_der(signature).map_err(|e| SignatureError::Ec {
                                context: format!("Cannot parse p384 signature: {e}"),
                            })?;
                        vkey.verify(msg, &signature).map_err(|_| SignatureError::BadSignature)?
                    }
                    HashAlgorithm::SHA2_512 => {
                        use p521::ecdsa::signature::Verifier;

                        match curve {
                            EcCurve::NistP521 => {}
                            curve => {
                                return Err(SignatureError::UnsupportedAlgorithm {
                                    algorithm: format!("SHA512 hash algorithm can't be used with `{curve}` curve"),
                                });
                            }
                        };

                        let encoded_point = p521::Sec1Point::from_bytes(ec_pub_key.encoded_point()).map_err(|e| {
                            SignatureError::Ec {
                                context: format!("Cannot parse p521 public key from der bytes: {e}"),
                            }
                        })?;

                        let vkey = p521::ecdsa::VerifyingKey::from_sec1_point(&encoded_point).map_err(|e| {
                            SignatureError::Ec {
                                context: format!("Cannot parse p521 encoded point: {e}"),
                            }
                        })?;

                        let signature =
                            p521::ecdsa::Signature::from_der(signature).map_err(|e| SignatureError::Ec {
                                context: format!("Cannot parse p521 signature: {e}"),
                            })?;
                        vkey.verify(msg, &signature).map_err(|_| SignatureError::BadSignature)?
                    }
                    _ => {
                        return Err(SignatureError::UnsupportedAlgorithm {
                            algorithm: format!("ECDSA with {picky_hash_algo:?} hash algorithm is not supported"),
                        });
                    }
                }
            }
            SignatureAlgorithm::Ed25519 => {
                use crate::key::ed::{EdAlgorithm, EdPublicKey, NamedEdAlgorithm};
                use ed25519_dalek::Verifier;

                let public_key = EdPublicKey::try_from(public_key)?;

                match public_key.algorithm() {
                    NamedEdAlgorithm::Known(EdAlgorithm::Ed25519) => {
                        let public_key = public_key.data().try_into().map_err(|e| SignatureError::Ed {
                            context: format!("invalid key size: {e}"),
                        })?;
                        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key).map_err(
                            |e: ed25519_dalek::ed25519::Error| SignatureError::Ed {
                                context: format!("Cannot decode ed25519 public key: {e}"),
                            },
                        )?;

                        let signature = signature.try_into().map_err(|e| SignatureError::Ed {
                            context: format!("invalid signature size: {e}"),
                        })?;
                        let signature = ed25519_dalek::Signature::from_bytes(signature);

                        verifying_key
                            .verify(msg, &signature)
                            .map_err(|_| SignatureError::BadSignature)?;
                    }
                    NamedEdAlgorithm::Known(EdAlgorithm::X25519) => {
                        return Err(SignatureError::Ed {
                            context: "X25519 algorithm is not designed for signing".to_string(),
                        });
                    }
                    NamedEdAlgorithm::Unsupported(oid) => {
                        return Err(KeyError::unsupported_ed_algorithm(oid, "verifying").into());
                    }
                }
            }
        }

        Ok(())
    }

    pub fn hash_algorithm(&self) -> HashAlgorithm {
        match &self {
            SignatureAlgorithm::RsaPkcs1v15(hash_algo) => *hash_algo,
            SignatureAlgorithm::Ecdsa(hash_algo) => *hash_algo,
            SignatureAlgorithm::Ed25519 => HashAlgorithm::SHA2_512,
        }
    }
}

#[cfg(test)]
mod ec_tests {
    use super::*;
    use rstest::*;

    const EC_PRIVATE_KEY_NIST256_PEM: &str = r#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICHio5XUa+RbeFfGtGHfbPWehTFJJtCB4/izKHJ9Vm+goAoGCCqGSM49
AwEHoUQDQgAEh7ZqcI6f0tgqq7nqdcxWM6P4GGCfkWc4q11uXFjtXOKHKCV3LzMY
g8/V1PD/YOh0HodRJAjkjXub8AmYxiTcXw==
-----END EC PRIVATE KEY-----"#;

    const EC_PRIVATE_KEY_NIST384_PEM: &str = r#"-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDT8VOfdzHbIRaWOO1F0vgotY2qM2FfYS3zpdKE7Vqbh26hFsUw+iaG
GmGnT+29kg+gBwYFK4EEACKhZANiAAQFvVVUKRdN3/bqaEpDA1aHu8FEd3ujuyS0
AadG6QAiZxH37BGumBcyTTeGHyArqb+GTpsHTUXASbP+P+p5JgkfF9wBMF1SVTvu
ACZOYcqzGbsAXXdMYqewckhc42ye0u0=
-----END EC PRIVATE KEY-----"#;

    #[rstest]
    #[case(HashAlgorithm::MD5, false)]
    #[case(HashAlgorithm::SHA1, false)]
    #[case(HashAlgorithm::SHA2_224, false)]
    #[case(HashAlgorithm::SHA2_256, true)]
    #[case(HashAlgorithm::SHA2_384, true)]
    #[case(HashAlgorithm::SHA2_512, true)]
    #[case(HashAlgorithm::SHA3_384, false)]
    #[case(HashAlgorithm::SHA3_512, false)]
    fn algorithm_identifier_conversions(#[case] hash: HashAlgorithm, #[case] success: bool) {
        let signature_algorithm = SignatureAlgorithm::Ecdsa(hash);
        let algorithm_identifier = AlgorithmIdentifier::try_from(signature_algorithm);
        if success {
            assert!(algorithm_identifier.is_ok());
        } else {
            assert!(matches!(algorithm_identifier, Err(SignatureError::Ec { context: _ })));
        }
    }

    #[test]
    fn verify_bad_signature() {
        let private_key_signature = PrivateKey::from_pem_str(EC_PRIVATE_KEY_NIST256_PEM).unwrap();
        let signature_algorithm = SignatureAlgorithm::Ecdsa(HashAlgorithm::SHA2_256);

        let msg = b"hello world";
        let signature = signature_algorithm.sign(msg, &private_key_signature).unwrap();

        let another_ec_private_key_nist256_pem = r#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBVYtZ17YMj89Kuu47TOxJlLVlk7MDUuAlFrVXxexgkSoAoGCCqGSM49
AwEHoUQDQgAE/irzdOJk28zjVv3sov15/NLIOxoIwL9kM2p/RfQAslATwHpD/T79
csaQwO9jFvbQFIpCvcMRjaunLfhIWiYDdg==
-----END EC PRIVATE KEY-----"#;

        let another_private_key = PrivateKey::from_pem_str(another_ec_private_key_nist256_pem).unwrap();
        let wrong_public_key = PublicKey::try_from(another_private_key).unwrap();
        assert!(matches!(
            signature_algorithm.verify(&wrong_public_key, msg, &signature),
            Err(SignatureError::BadSignature)
        ));
    }

    #[rstest]
    #[case(picky_test_data::EC_NIST256_PK_1, HashAlgorithm::SHA2_256, true)]
    #[case(picky_test_data::EC_NIST384_PK_1, HashAlgorithm::SHA2_384, true)]
    #[case(picky_test_data::EC_NIST521_PK_1, HashAlgorithm::SHA2_512, true)]
    fn sign_and_verify(#[case] key_pem: &str, #[case] hash: HashAlgorithm, #[case] sign_successful: bool) {
        let private_key = PrivateKey::from_pem_str(key_pem).unwrap();

        let signature_algorithm = SignatureAlgorithm::Ecdsa(hash);

        let msg = b"hello world";
        let signature = signature_algorithm.sign(msg, &private_key);
        assert_eq!(signature.is_ok(), sign_successful);

        if !sign_successful {
            return;
        }

        let public_key = PublicKey::try_from(private_key).unwrap();
        signature_algorithm
            .verify(&public_key, msg, &signature.unwrap())
            .unwrap();
    }

    #[rstest]
    #[case(EC_PRIVATE_KEY_NIST256_PEM, &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING, HashAlgorithm::SHA2_256)]
    #[case(EC_PRIVATE_KEY_NIST384_PEM, &ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING, HashAlgorithm::SHA2_384)]
    fn sign_and_verify_compatibility_with_ring(
        #[case] key_pem: &str,
        #[case] algorithm: &'static ring::signature::EcdsaSigningAlgorithm,
        #[case] hash: HashAlgorithm,
    ) {
        // sign using ring
        let private_key = PrivateKey::from_pem_str(key_pem).unwrap();
        let public_key = PublicKey::try_from(private_key).unwrap();
        let msg = b"hello world";

        let (privk, pubk) = match hash {
            HashAlgorithm::SHA2_256 => {
                use p256::Sec1Point;
                let k = p256::SecretKey::from_sec1_pem(key_pem).unwrap();
                (
                    k.to_bytes().as_slice().to_vec(),
                    Into::<Sec1Point>::into(k.public_key()).as_bytes().to_vec(),
                )
            }
            HashAlgorithm::SHA2_384 => {
                use p384::Sec1Point;
                let k = p384::SecretKey::from_sec1_pem(key_pem).unwrap();
                (
                    k.to_bytes().as_slice().to_vec(),
                    Into::<Sec1Point>::into(k.public_key()).as_bytes().to_vec(),
                )
            }
            _ => panic!("no this condition"),
        };

        let rng = ring::rand::SystemRandom::new();

        let keypair =
            ring::signature::EcdsaKeyPair::from_private_key_and_public_key(algorithm, &privk, &pubk, &rng).unwrap();

        let rng = ring::rand::SystemRandom::new();
        let signature = keypair.sign(&rng, msg).unwrap();
        let sig = signature.as_ref().to_vec();

        // verify using rust-crypto
        let signature_algorithm = SignatureAlgorithm::Ecdsa(hash);

        signature_algorithm.verify(&public_key, msg, &sig).unwrap();
    }
}
