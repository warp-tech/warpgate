use crate::key::{KeyError, PrivateKey, PrivateKeyKind, PublicKey};
use crate::oid::ObjectIdentifier;

use picky_asn1::wrapper::BitStringAsn1;
use picky_asn1_x509::{EcParameters, oids};
use std::fmt::Display;
use zeroize::Zeroize;

#[derive(Debug)]
pub(crate) struct EcdsaKeypair {
    curve: NamedEcCurve,
    private_key: Vec<u8>,
    public_key: Option<Vec<u8>>,
}

impl EcdsaKeypair {
    pub fn curve(&self) -> &NamedEcCurve {
        &self.curve
    }

    pub fn secret(&self) -> &[u8] {
        &self.private_key
    }
}

impl Drop for EcdsaKeypair {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

pub(crate) enum EcComponent<'a> {
    PointX(&'a [u8]),
    PointY(&'a [u8]),
    Secret(&'a [u8]),
}

/// Elliptic curve name to use for curve operations which require curve-specific arithmetic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EcCurve {
    /// NIST P-256 curve (secp256r1)
    NistP256,
    /// NIST P-384 curve (secp384r1)
    NistP384,
    /// NIST P-521 curve (secp521r1)
    NistP521,
}

impl EcCurve {
    /// Get size of field compoennet in bytes (e.g. X and Y point values, Secret key,
    /// R and S signature values)
    pub(crate) fn field_bytes_size(self) -> usize {
        match self {
            EcCurve::NistP256 => {
                use p256::elliptic_curve::FieldBytesSize;
                use p256::elliptic_curve::array::typenum::Unsigned;
                <FieldBytesSize<p256::NistP256> as Unsigned>::USIZE
            }
            EcCurve::NistP384 => {
                use p384::elliptic_curve::FieldBytesSize;
                use p384::elliptic_curve::array::typenum::Unsigned;
                <FieldBytesSize<p384::NistP384> as Unsigned>::USIZE
            }
            EcCurve::NistP521 => {
                use p521::elliptic_curve::FieldBytesSize;
                use p521::elliptic_curve::array::typenum::Unsigned;
                <FieldBytesSize<p521::NistP521> as Unsigned>::USIZE
            }
        }
    }

    /// We need to validate input data sizes to prevent panics in the underlying `generic_array`
    /// library code.
    pub(crate) fn validate_component<'a>(&self, component: EcComponent<'a>) -> Result<&'a [u8], KeyError> {
        let (buffer, error_message) = match component {
            EcComponent::PointX(buf) => (buf, "Invalid `point.x` component size"),
            EcComponent::PointY(buf) => (buf, "Invalid `point.y` component size"),
            EcComponent::Secret(buf) => (buf, "Invalid `secret` component size"),
        };

        if buffer.len() != self.field_bytes_size() {
            return Err(KeyError::EC {
                context: error_message.to_string(),
            });
        }

        Ok(buffer)
    }
}

/// Describes the curve type of an ECDSA keypair
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum NamedEcCurve {
    Known(EcCurve),
    Unsupported(ObjectIdentifier),
}

impl Display for EcCurve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NistP256 => write!(f, "NIST-P256"),
            Self::NistP384 => write!(f, "NIST-P384"),
            Self::NistP521 => write!(f, "NIST-P521"),
        }
    }
}

impl Display for NamedEcCurve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Known(curve) => curve.fmt(f),
            Self::Unsupported(oid) => {
                let oid: String = oid.into();
                write!(f, "Unsupported(OID: {oid})")
            }
        }
    }
}

impl From<&'_ ObjectIdentifier> for NamedEcCurve {
    fn from(value: &ObjectIdentifier) -> Self {
        let oid: String = value.into();
        match oid.as_str() {
            oids::SECP256R1 => NamedEcCurve::Known(EcCurve::NistP256),
            oids::SECP384R1 => NamedEcCurve::Known(EcCurve::NistP384),
            oids::SECP521R1 => NamedEcCurve::Known(EcCurve::NistP521),
            _ => NamedEcCurve::Unsupported(value.clone()),
        }
    }
}

impl From<NamedEcCurve> for ObjectIdentifier {
    fn from(value: NamedEcCurve) -> Self {
        match value {
            NamedEcCurve::Known(curve) => match curve {
                EcCurve::NistP256 => oids::secp256r1(),
                EcCurve::NistP384 => oids::secp384r1(),
                EcCurve::NistP521 => oids::secp521r1(),
            },
            NamedEcCurve::Unsupported(oid) => oid,
        }
    }
}

impl<'a> TryFrom<&'a PrivateKey> for EcdsaKeypair {
    type Error = KeyError;

    fn try_from(v: &'a PrivateKey) -> Result<Self, Self::Error> {
        match &v.kind {
            PrivateKeyKind::Ec {
                public_key,
                private_key,
                curve_oid,
                ..
            } => Ok(Self {
                curve: NamedEcCurve::from(curve_oid),
                private_key: private_key.clone(),
                public_key: public_key.clone(),
            }),
            _ => Err(KeyError::EC {
                context: "EC keypair cannot be built from Non-EC private key".to_string(),
            }),
        }
    }
}

pub(crate) fn calculate_public_ec_key(
    curve_oid: &ObjectIdentifier,
    private_key: &[u8],
    compress: bool,
) -> Result<Option<Vec<u8>>, KeyError> {
    let curve = NamedEcCurve::from(curve_oid);

    match curve {
        NamedEcCurve::Known(EcCurve::NistP256) => {
            use p256::elliptic_curve::sec1::ToSec1Point as _;

            let private_key_validated = EcCurve::NistP256.validate_component(EcComponent::Secret(private_key))?;

            let secret_bytes =
                p256::elliptic_curve::array::Array::try_from(private_key_validated).map_err(|_| KeyError::EC {
                    context: format!(
                        "validated private key is the not right length(expected: {}, actual: {})",
                        EcCurve::NistP256.field_bytes_size(),
                        private_key_validated.len()
                    ),
                })?;
            let secret_key = p256::SecretKey::from_bytes(&secret_bytes).map_err(|_| KeyError::EC {
                context: "Failed to construct P256 SecretKey from private key bytes".to_string(),
            })?;

            // Calculate public key from secret key
            let public_key = secret_key.public_key().as_affine().to_sec1_point(compress);

            Ok(Some(public_key.to_bytes().to_vec()))
        }
        NamedEcCurve::Known(EcCurve::NistP384) => {
            use p384::elliptic_curve::sec1::ToSec1Point as _;

            let private_key_validated = EcCurve::NistP384.validate_component(EcComponent::Secret(private_key))?;

            let secret_bytes =
                p384::elliptic_curve::array::Array::try_from(private_key_validated).map_err(|_| KeyError::EC {
                    context: format!(
                        "validated private key is the not right length(expected: {}, actual: {})",
                        EcCurve::NistP384.field_bytes_size(),
                        private_key_validated.len()
                    ),
                })?;
            let secret_key = p384::SecretKey::from_bytes(&secret_bytes).map_err(|_| KeyError::EC {
                context: "Failed to construct P384 SecretKey from private key bytes".to_string(),
            })?;

            // Calculate public key from secret key
            let public_key = secret_key.public_key().as_affine().to_sec1_point(compress);

            Ok(Some(public_key.to_bytes().to_vec()))
        }
        NamedEcCurve::Known(EcCurve::NistP521) => {
            use p521::elliptic_curve::sec1::ToSec1Point as _;

            let private_key_validated = EcCurve::NistP521.validate_component(EcComponent::Secret(private_key))?;

            let secret_bytes =
                p521::elliptic_curve::array::Array::try_from(private_key_validated).map_err(|_| KeyError::EC {
                    context: format!(
                        "validated private key is the not right length(expected: {}, actual: {})",
                        EcCurve::NistP521.field_bytes_size(),
                        private_key_validated.len()
                    ),
                })?;
            let secret_key = p521::SecretKey::from_bytes(&secret_bytes).map_err(|_| KeyError::EC {
                context: "Failed to construct P521 SecretKey from private key bytes".to_string(),
            })?;

            // Calculate public key from secret key
            let public_key = secret_key.public_key().as_affine().to_sec1_point(compress);

            Ok(Some(public_key.to_bytes().to_vec()))
        }
        NamedEcCurve::Unsupported(_) => Ok(None),
    }
}

#[derive(Debug)]
pub(crate) struct EcdsaPublicKey<'a> {
    data: &'a [u8],
    curve: NamedEcCurve,
}

impl EcdsaPublicKey<'_> {
    pub fn curve(&self) -> &NamedEcCurve {
        &self.curve
    }

    pub fn encoded_point(&self) -> &[u8] {
        self.data
    }
}

impl<'a> TryFrom<&'a PublicKey> for EcdsaPublicKey<'a> {
    type Error = KeyError;

    fn try_from(v: &'a PublicKey) -> Result<Self, Self::Error> {
        use picky_asn1_x509::PublicKey as InnerPublicKey;

        let curve_oid = match &v.as_inner().algorithm.parameters() {
            picky_asn1_x509::AlgorithmIdentifierParameters::Ec(EcParameters::NamedCurve(curve_oid)) => {
                curve_oid.0.clone()
            }
            _ => {
                return Err(KeyError::EC {
                    context: "EC public key cannot be constructed from non-EC public key".to_string(),
                });
            }
        };

        match &v.as_inner().subject_public_key {
            InnerPublicKey::Rsa(_) => Err(KeyError::EC {
                context: "EC public key cannot be constructed from RSA public key".to_string(),
            }),
            InnerPublicKey::Ec(BitStringAsn1(bitstring)) => {
                let data = bitstring.payload_view();

                Ok(EcdsaPublicKey {
                    data,
                    curve: NamedEcCurve::from(&curve_oid),
                })
            }
            InnerPublicKey::Ed(_) => Err(KeyError::EC {
                context: "EC public key cannot be constructed from ED25519 public key".to_string(),
            }),
            InnerPublicKey::Mldsa(_) => Err(KeyError::EC {
                context: "EC public key cannot be constructed from MLDSA public key".to_string(),
            }),
        }
    }
}

impl<'a> TryFrom<&'a EcdsaKeypair> for EcdsaPublicKey<'a> {
    type Error = KeyError;

    fn try_from(v: &'a EcdsaKeypair) -> Result<Self, Self::Error> {
        match v.public_key.as_ref() {
            Some(key) => Ok(Self {
                data: key.as_slice(),
                curve: v.curve.clone(),
            }),
            None => Err(KeyError::EC {
                context: "EC public key cannot be constructed from EC private key without public key".to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    const RSA_PUBLIC_KEY_PEM: &str = "-----BEGIN RSA PUBLIC KEY-----\n\
                                      MIIBCgKCAQEA61BjmfXGEvWmegnBGSuS+rU9soUg2FnODva32D1AqhwdziwHINFa\n\
                                      D1MVlcrYG6XRKfkcxnaXGfFDWHLEvNBSEVCgJjtHAGZIm5GL/KA86KDp/CwDFMSw\n\
                                      luowcXwDwoyinmeOY9eKyh6aY72xJh7noLBBq1N0bWi1e2i+83txOCg4yV2oVXhB\n\
                                      o8pYEJ8LT3el6Smxol3C1oFMVdwPgc0vTl25XucMcG/ALE/KNY6pqC2AQ6R2ERlV\n\
                                      gPiUWOPatVkt7+Bs3h5Ramxh7XjBOXeulmCpGSynXNcpZ/06+vofGi/2MlpQZNhH\n\
                                      Ao8eayMp6FcvNucIpUndo1X8dKMv3Y26ZQIDAQAB\n\
                                      -----END RSA PUBLIC KEY-----";

    #[rstest]
    #[case(picky_test_data::EC_NIST256_DER_PK_1)]
    #[case(picky_test_data::EC_NIST384_DER_PK_1)]
    #[case(picky_test_data::EC_NIST521_DER_PK_1)]
    #[case(picky_test_data::EC_NIST256_PK_1)] // PKCS8
    fn private_key_from_ec_pem(#[case] key_pem: &str) {
        PrivateKey::from_pem_str(key_pem).unwrap();
    }

    #[rstest]
    #[case(picky_test_data::EC_NIST256_NOPUBLIC_DER_PK_1)]
    #[case(picky_test_data::EC_NIST384_NOPUBLIC_DER_PK_1)]
    #[case(picky_test_data::EC_NIST521_NOPUBLIC_DER_PK_1)]
    fn ecdsa_private_key_without_public(#[case] key_pem: &str) {
        // This should succeed for supported curves
        let key = PrivateKey::from_pem_str(key_pem).unwrap();
        key.to_public_key().unwrap().to_pem_str().unwrap();
    }

    #[rstest]
    // Known curves
    #[case(picky_test_data::EC_NIST256_PK_1_PUB)]
    #[case(picky_test_data::EC_NIST384_PK_1_PUB)]
    #[case(picky_test_data::EC_NIST521_PK_1_PUB)]
    // Unsupported curve, should still work as long as pem contains the public key
    // (in that case no arithmetic operations are performed on the key)
    #[case(picky_test_data::EC_PUBLIC_KEY_SECP256K1_PEM)]
    fn ecdsa_public_valid_key_conversions(#[case] key_pem: &str) {
        let pk: &PublicKey = &PublicKey::from_pem_str(key_pem).unwrap();
        let epk: Result<EcdsaPublicKey, KeyError> = pk.try_into();
        assert!(epk.is_ok());
    }

    #[test]
    fn ecdsa_public_invalid_key_conversions() {
        // PEM public key conversion fails with an error
        let pk: &PublicKey = &PublicKey::from_pem_str(RSA_PUBLIC_KEY_PEM).unwrap();
        let epk: Result<EcdsaPublicKey, KeyError> = pk.try_into();
        assert!(epk.is_err());
        assert!(matches!(epk, Err(KeyError::EC { context: _ })));

        // TODO: add check for attempted conversion from ED keys - which are not supported yet
    }

    #[rstest]
    #[case(picky_test_data::EC_NIST256_DER_PK_1, NamedEcCurve::Known(EcCurve::NistP256))]
    #[case(picky_test_data::EC_NIST384_DER_PK_1, NamedEcCurve::Known(EcCurve::NistP384))]
    #[case(picky_test_data::EC_NIST521_DER_PK_1, NamedEcCurve::Known(EcCurve::NistP521))]
    fn ecdsa_key_pair_from_ec_private_key(#[case] key: &str, #[case] curve: NamedEcCurve) {
        let pk = PrivateKey::from_pem_str(key).unwrap();
        let pair = EcdsaKeypair::try_from(&pk).unwrap();
        assert_eq!(curve, pair.curve);
    }

    #[test]
    fn ring_ecdsa_pkcs8_keys_could_be_parsed() {
        let algo = &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;
        let rng = ring::rand::SystemRandom::new();
        let pkcs8_bytes = ring::signature::EcdsaKeyPair::generate_pkcs8(algo, &rng).unwrap();
        // Validate that missing `parameters` field from ECPriavteKeyInfo is handled correctly.
        // rings skips it during pkcs8 serialization
        let key = PrivateKey::from_pkcs8(&pkcs8_bytes).unwrap();
        let pair = EcdsaKeypair::try_from(&key).unwrap();

        assert_eq!(pair.curve(), &NamedEcCurve::Known(EcCurve::NistP256))
    }
}
