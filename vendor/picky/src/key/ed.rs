use crate::key::{KeyError, PrivateKey, PrivateKeyKind, PublicKey};
use crate::oid::ObjectIdentifier;

use picky_asn1::wrapper::BitStringAsn1;
use picky_asn1_x509::oids;
use std::fmt::Display;
use zeroize::Zeroize;

pub(crate) const X25519_FIELD_ELEMENT_SIZE: usize = 32;
pub(crate) type X25519FieldElement = [u8; X25519_FIELD_ELEMENT_SIZE];

/// Name of supported Curve25519 and Curve448 based algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EdAlgorithm {
    /// Curve25519-based EdDSA algorithm
    Ed25519,
    /// Curve25519-based ECDH algorithm (mainly used for jwe key agreement)
    X25519,
    // (Unsupported) Ed448 -- Curve448-based EdDSA algorithm
    // (Unsupported) X448 -- Curve448-based ECDH algorithm (mainly used for jwe key agreement)
}

// Describes Edwards curve-based EC algorithm
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum NamedEdAlgorithm {
    Known(EdAlgorithm),
    Unsupported(ObjectIdentifier),
}

impl Display for NamedEdAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NamedEdAlgorithm::Known(alg) => write!(f, "{alg}"),
            NamedEdAlgorithm::Unsupported(oid) => {
                // We don't support Ed448 and X448 algorithms, but we can still print their named
                // representation of OID to make errrs more readable.
                if oid == &oids::ed448() {
                    write!(f, "Ed448")
                } else if oid == &oids::x448() {
                    write!(f, "X448")
                } else {
                    let oid: String = oid.into();
                    write!(f, "Unsupported(OID: {oid})")
                }
            }
        }
    }
}

impl Display for EdAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ed25519 => write!(f, "Ed25519"),
            Self::X25519 => write!(f, "X25519"),
        }
    }
}

impl From<&'_ ObjectIdentifier> for NamedEdAlgorithm {
    fn from(value: &'_ ObjectIdentifier) -> Self {
        let oid: String = value.into();
        match oid.as_str() {
            oids::ED25519 => NamedEdAlgorithm::Known(EdAlgorithm::Ed25519),
            oids::X25519 => NamedEdAlgorithm::Known(EdAlgorithm::X25519),
            _ => NamedEdAlgorithm::Unsupported(value.clone()),
        }
    }
}

impl From<EdAlgorithm> for ObjectIdentifier {
    fn from(value: EdAlgorithm) -> Self {
        match value {
            EdAlgorithm::Ed25519 => oids::ed25519(),
            EdAlgorithm::X25519 => oids::x25519(),
        }
    }
}

impl From<NamedEdAlgorithm> for ObjectIdentifier {
    fn from(value: NamedEdAlgorithm) -> Self {
        match value {
            NamedEdAlgorithm::Known(alg) => alg.into(),
            NamedEdAlgorithm::Unsupported(oid) => oid,
        }
    }
}

#[derive(Debug)]
pub(crate) struct EdKeypair {
    algorithm: NamedEdAlgorithm,
    private_key: Vec<u8>,
    public_key: Option<Vec<u8>>,
}

impl EdKeypair {
    pub fn algorithm(&self) -> &NamedEdAlgorithm {
        &self.algorithm
    }

    pub fn secret(&self) -> &[u8] {
        &self.private_key
    }
}

impl Drop for EdKeypair {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl<'a> TryFrom<&'a PrivateKey> for EdKeypair {
    type Error = KeyError;

    fn try_from(value: &'a PrivateKey) -> Result<Self, Self::Error> {
        match &value.kind {
            PrivateKeyKind::Ed {
                public_key,
                private_key,
                algorithm_oid,
            } => Ok(Self {
                algorithm: NamedEdAlgorithm::from(algorithm_oid),
                private_key: private_key.clone(),
                public_key: public_key.clone(),
            }),
            _ => Err(KeyError::ED {
                context: "Ed keypair cannot be constructed from non-Ed private key".to_string(),
            }),
        }
    }
}

#[derive(Debug)]
pub(crate) struct EdPublicKey<'a> {
    data: &'a [u8],
    algorithm: NamedEdAlgorithm,
}

impl EdPublicKey<'_> {
    pub fn algorithm(&self) -> &NamedEdAlgorithm {
        &self.algorithm
    }

    pub fn data(&self) -> &[u8] {
        self.data
    }
}

impl<'a> TryFrom<&'a EdKeypair> for EdPublicKey<'a> {
    type Error = KeyError;

    fn try_from(v: &'a EdKeypair) -> Result<Self, Self::Error> {
        match v.public_key.as_ref() {
            Some(key) => Ok(Self {
                data: key.as_slice(),
                algorithm: v.algorithm.clone(),
            }),
            None => Err(KeyError::ED {
                context: "Ed public key cannot be constructed from Ed private key without public key".to_string(),
            }),
        }
    }
}

impl<'a> TryFrom<&'a PublicKey> for EdPublicKey<'a> {
    type Error = KeyError;

    fn try_from(v: &'a PublicKey) -> Result<Self, Self::Error> {
        use picky_asn1_x509::PublicKey as InnerPublicKey;

        let oid = v.as_inner().algorithm.oid();

        match &v.as_inner().subject_public_key {
            InnerPublicKey::Rsa(_) => Err(KeyError::ED {
                context: "Ed public key cannot be constructed from RSA public key".to_string(),
            }),
            InnerPublicKey::Ec(_) => Err(KeyError::ED {
                context: "Ed public key cannot be constructed from Ec public key".to_string(),
            }),
            InnerPublicKey::Ed(BitStringAsn1(bitstring)) => {
                let data = bitstring.payload_view();

                Ok(EdPublicKey {
                    data,
                    algorithm: NamedEdAlgorithm::from(oid),
                })
            }
            InnerPublicKey::Mldsa(_) => Err(KeyError::ED {
                context: "Ed public key cannot be constructed from Mldsa public key".to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::key::{PrivateKey, PublicKey};
    use rstest::rstest;

    #[rstest]
    #[case(picky_test_data::ED25519_PEM_PK_1)]
    #[case(picky_test_data::X25519_PEM_PK_1)]
    // Although X448 and ED448 are not supported, we should still be able to decode and encode them
    #[case(picky_test_data::ED448_PEM_PK_1)]
    #[case(picky_test_data::X448_PEM_PK_1)]
    fn private_key_roundtrip(#[case] key_pem: &str) {
        let decoded = PrivateKey::from_pem_str(key_pem).unwrap();
        let encoded = decoded.to_pem_str().unwrap();
        assert_eq!(encoded.as_str(), key_pem);
    }

    #[rstest]
    #[case(picky_test_data::ED25519_PEM_PK_1_PUB)]
    #[case(picky_test_data::X25519_PEM_PK_1_PUB)]
    // Although X448 and ED448 are not supported, we should still be able to decode and encode them
    #[case(picky_test_data::ED448_PEM_PK_1_PUB)]
    #[case(picky_test_data::X448_PEM_PK_1_PUB)]
    fn public_key_roundtrip(#[case] key_pem: &str) {
        let decoded = PublicKey::from_pem_str(key_pem).unwrap();
        let encoded = decoded.to_pem_str().unwrap();
        assert_eq!(encoded.as_str(), key_pem);
    }

    #[rstest]
    #[case(picky_test_data::ED25519_PEM_PK_1, picky_test_data::ED25519_PEM_PK_1_PUB)]
    #[case(picky_test_data::X25519_PEM_PK_1, picky_test_data::X25519_PEM_PK_1_PUB)]
    fn extract_public_key(#[case] key_pem: &str, #[case] expected_public_pem: &str) {
        let private = PrivateKey::from_pem_str(key_pem).unwrap();
        let public = private.to_public_key().unwrap();
        let public_expected = PublicKey::from_pem_str(expected_public_pem).unwrap();
        assert_eq!(public, public_expected);
    }

    #[rstest]
    #[case(picky_test_data::ED448_PEM_PK_1)]
    #[case(picky_test_data::X448_PEM_PK_1)]
    fn extract_public_key_for_unsupported_algorithm_fails(#[case] key_pem: &str) {
        let private = PrivateKey::from_pem_str(key_pem).unwrap();
        assert!(private.to_public_key().is_err());
    }
}
