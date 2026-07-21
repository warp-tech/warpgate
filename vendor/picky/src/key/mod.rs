//! Wrappers around public and private keys raw data providing an easy to use API
pub(crate) mod ec;
pub(crate) mod ed;

use crate::oid::ObjectIdentifier;
use crate::pem::{Pem, PemError, parse_pem};
use crypto_bigint::{BoxedUint, NonZero};
use crypto_common::Generate as _;
use picky_asn1::bit_string::BitString;
use picky_asn1::wrapper::{BitStringAsn1Container, IntegerAsn1, OctetStringAsn1Container};
use picky_asn1_der::Asn1DerError;
use picky_asn1_x509::{
    ECPrivateKey, PRIVATE_KEY_INFO_VERSION_1, PrivateKeyInfo, PrivateKeyValue, SubjectPublicKeyInfo, private_key_info,
};
use rand::rngs::{StdRng, SysRng};
use rand_core::SeedableRng as _;
use rsa::traits::{PrivateKeyParts as _, PublicKeyParts as _};
use rsa::{RsaPrivateKey, RsaPublicKey};
use thiserror::Error;
use zeroize::Zeroize;

use ec::{EcComponent, NamedEcCurve, calculate_public_ec_key};
use ed::{NamedEdAlgorithm, X25519_FIELD_ELEMENT_SIZE, X25519FieldElement};

pub use ec::EcCurve;
pub use ed::EdAlgorithm;

#[derive(Debug, Error)]
pub enum KeyError {
    /// ASN1 serialization error
    #[error("(ASN1) couldn't serialize {element}: {source}")]
    Asn1Serialization {
        element: &'static str,
        source: Asn1DerError,
    },

    /// ASN1 deserialization error
    #[error("(ASN1) couldn't deserialize {element}: {source}")]
    Asn1Deserialization {
        element: &'static str,
        source: Asn1DerError,
    },

    /// RSA error
    #[error("RSA error: {context}")]
    Rsa { context: String },

    /// EC error
    #[error("EC error: {context}")]
    EC { context: String },

    /// ED error
    #[error("ED error: {context}")]
    ED { context: String },

    /// invalid PEM label error
    #[error("invalid PEM label: {label}")]
    InvalidPemLabel { label: String },

    /// unsupported algorithm
    #[error("unsupported algorithm: {algorithm}")]
    UnsupportedAlgorithm { algorithm: &'static str },

    /// invalid PEM provided
    #[error("invalid PEM provided: {source}")]
    Pem { source: PemError },

    #[error(transparent)]
    RandError(#[from] rand::rngs::SysError),
}

impl KeyError {
    pub(crate) fn unsupported_curve(curve_oid: &ObjectIdentifier, context: &'static str) -> Self {
        let curve_oid: String = curve_oid.into();
        Self::EC {
            context: format!("EC curve with oid `{curve_oid}` is not supported in context of {context}"),
        }
    }

    pub(crate) fn unsupported_ed_algorithm(oid: &ObjectIdentifier, context: &'static str) -> Self {
        let oid: String = oid.into();
        Self::ED {
            context: format!(
                "Algorithm with oid `{oid}` based on Edwards curves is not supported in context of {context}",
            ),
        }
    }
}

impl From<rsa::errors::Error> for KeyError {
    fn from(e: rsa::errors::Error) -> Self {
        Self::Rsa { context: e.to_string() }
    }
}

impl From<PemError> for KeyError {
    fn from(e: PemError) -> Self {
        Self::Pem { source: e }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyKind {
    Rsa,
    Ec,
    Ed,
    Mldsa,
}

// === private key === //

const PRIVATE_KEY_PEM_LABEL: &str = "PRIVATE KEY";
const RSA_PRIVATE_KEY_PEM_LABEL: &str = "RSA PRIVATE KEY";
const EC_PRIVATE_KEY_LABEL: &str = "EC PRIVATE KEY";

// We dont compress EC points by default to avoid potential interoperability issues.
// Namely, `ring` library has bug in it, which causes it to fail when validating
// encoded public key, comparing it with generated one (It assumes uncompressed point).
// [https://github.com/briansmith/ring/blob/155231fb017acaaa94a044f124bb34a777d115ef/src/ec/suite_b.rs#L221-L225]
const COMPRESS_EC_POINT_BY_DEFAULT: bool = false;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PrivateKeyKind {
    Rsa,
    Ec {
        public_key: Option<Vec<u8>>,
        private_key: Vec<u8>,
        curve_oid: ObjectIdentifier,
    },
    Ed {
        public_key: Option<Vec<u8>>,
        private_key: Vec<u8>,
        algorithm_oid: ObjectIdentifier,
    },
}

impl Drop for PrivateKeyKind {
    fn drop(&mut self) {
        match self {
            PrivateKeyKind::Rsa => {}
            PrivateKeyKind::Ec { private_key, .. } => {
                private_key.zeroize();
            }
            PrivateKeyKind::Ed { private_key, .. } => {
                private_key.zeroize();
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKey {
    /// Inner key details. This should never be puiblicly exposed.
    kind: PrivateKeyKind,
    /// Inner representation in Pkcs8
    inner: PrivateKeyInfo,
}

impl TryFrom<&'_ PrivateKey> for RsaPrivateKey {
    type Error = KeyError;

    fn try_from(v: &PrivateKey) -> Result<Self, Self::Error> {
        match &v.as_inner().private_key {
            private_key_info::PrivateKeyValue::Rsa(OctetStringAsn1Container(key)) => {
                let p1 = BoxedUint::from_be_slice_vartime(key.prime_1.as_unsigned_bytes_be());
                let p2 = BoxedUint::from_be_slice_vartime(key.prime_2.as_unsigned_bytes_be());

                RsaPrivateKey::from_components(
                    BoxedUint::from_be_slice_vartime(key.modulus.as_unsigned_bytes_be()),
                    BoxedUint::from_be_slice_vartime(key.public_exponent.as_unsigned_bytes_be()),
                    BoxedUint::from_be_slice_vartime(key.private_exponent.as_unsigned_bytes_be()),
                    vec![p1, p2],
                )
                .map_err(|e| KeyError::Rsa {
                    context: format!("failed to construct private key from components: {e}"),
                })
            }
            _ => Err(KeyError::Rsa {
                context: "RSA private key cannot be constructed from non-RSA private key.".to_owned(),
            }),
        }
    }
}

impl TryFrom<&'_ PrivateKey> for RsaPublicKey {
    type Error = KeyError;

    fn try_from(v: &PrivateKey) -> Result<Self, Self::Error> {
        match &v.as_inner().private_key {
            private_key_info::PrivateKeyValue::Rsa(OctetStringAsn1Container(key)) => {
                Ok(RsaPublicKey::new_with_max_size(
                    BoxedUint::from_be_slice_vartime(key.modulus.as_unsigned_bytes_be()),
                    BoxedUint::from_be_slice_vartime(key.public_exponent.as_unsigned_bytes_be()),
                    8192,
                )?)
            }
            _ => Err(KeyError::Rsa {
                context: "RSA public key cannot be constructed from non-RSA private key.".to_string(),
            }),
        }
    }
}

impl PrivateKey {
    pub fn from_rsa_components(
        modulus: &BoxedUint,
        public_exponent: &BoxedUint,
        private_exponent: &BoxedUint,
        primes: &[BoxedUint],
    ) -> Result<Self, KeyError> {
        let mut primes_it = primes.iter();
        let prime_1 = primes_it.next().ok_or_else(|| KeyError::Rsa {
            context: format!("invalid number of primes provided: expected 2, got: {}", primes.len()),
        })?;
        let prime_2 = primes_it.next().ok_or_else(|| KeyError::Rsa {
            context: format!("invalid number of primes provided: expected 2, got: {}", primes.len()),
        })?;

        let exponent_1 = private_exponent
            % NonZero::new(prime_1 - 1u8).into_option().ok_or_else(|| KeyError::Rsa {
                context: "the first prime is not valid".to_string(),
            })?;
        let exponent_2 = private_exponent
            % NonZero::new(prime_2 - 1u8).into_option().ok_or_else(|| KeyError::Rsa {
                context: "the second prime is not valid".to_string(),
            })?;

        let prime_1 = NonZero::new(prime_1.clone())
            .into_option()
            .ok_or_else(|| KeyError::Rsa {
                context: "the first prime is not valid".to_string(),
            })?;
        let coefficient = prime_2
            .invert_mod(&prime_1)
            .into_option()
            .ok_or_else(|| KeyError::Rsa {
                context: "no modular inverse for prime 1".to_string(),
            })?;

        let inner = PrivateKeyInfo::new_rsa_encryption(
            IntegerAsn1::from_bytes_be_unsigned(modulus.to_be_bytes_trimmed_vartime().into_vec()),
            IntegerAsn1::from_bytes_be_unsigned(public_exponent.to_be_bytes_trimmed_vartime().into_vec()),
            IntegerAsn1::from_bytes_be_unsigned(private_exponent.to_be_bytes_trimmed_vartime().into_vec()),
            (
                // primes
                IntegerAsn1::from_bytes_be_unsigned(prime_1.to_be_bytes_trimmed_vartime().into_vec()),
                IntegerAsn1::from_bytes_be_unsigned(prime_2.to_be_bytes_trimmed_vartime().into_vec()),
            ),
            (
                // exponents
                IntegerAsn1::from_bytes_be_unsigned(exponent_1.to_be_bytes_trimmed_vartime().into_vec()),
                IntegerAsn1::from_bytes_be_unsigned(exponent_2.to_be_bytes_trimmed_vartime().into_vec()),
            ),
            IntegerAsn1::from_bytes_be_unsigned(coefficient.to_be_bytes_trimmed_vartime().into_vec()),
        );

        Ok(Self {
            kind: PrivateKeyKind::Rsa,
            inner,
        })
    }

    /// Builds new EC key from given components. Note that only curves, declared in [`EcCurve`]
    /// are supported for key generation.
    pub fn from_ec_components(
        curve: EcCurve,
        secret: &BoxedUint,
        point_x: &BoxedUint,
        point_y: &BoxedUint,
    ) -> Result<Self, KeyError> {
        let curve_oid: ObjectIdentifier = NamedEcCurve::Known(curve).into();
        let px_bytes = point_x.to_be_bytes_trimmed_vartime().into_vec();
        let py_bytes = point_y.to_be_bytes_trimmed_vartime().into_vec();

        let px_validated = curve.validate_component(EcComponent::PointX(&px_bytes))?;
        let py_validated = curve.validate_component(EcComponent::PointY(&py_bytes))?;

        let point_bytes = match curve {
            EcCurve::NistP256 => {
                let x = p256::elliptic_curve::array::Array::try_from(px_validated).map_err(|_| KeyError::EC {
                    context: format!(
                        "validated PX slice is not right length(expected: {}, actual: {})",
                        curve.field_bytes_size(),
                        px_validated.len(),
                    ),
                })?;
                let y = p256::elliptic_curve::array::Array::try_from(py_validated).map_err(|_| KeyError::EC {
                    context: format!(
                        "validated PY slice is not right length(expected: {}, actual: {})",
                        curve.field_bytes_size(),
                        py_validated.len(),
                    ),
                })?;
                let point = p256::Sec1Point::from_affine_coordinates(&x, &y, COMPRESS_EC_POINT_BY_DEFAULT);
                point.as_bytes().to_vec()
            }
            EcCurve::NistP384 => {
                let x = p384::elliptic_curve::array::Array::try_from(px_validated).map_err(|_| KeyError::EC {
                    context: format!(
                        "validated PX slice is not right length(expected: {}, actual: {})",
                        curve.field_bytes_size(),
                        px_validated.len(),
                    ),
                })?;
                let y = p384::elliptic_curve::array::Array::try_from(py_validated).map_err(|_| KeyError::EC {
                    context: format!(
                        "validated PY slice is not right length(expected: {}, actual: {})",
                        curve.field_bytes_size(),
                        py_validated.len(),
                    ),
                })?;
                let point = p384::Sec1Point::from_affine_coordinates(&x, &y, COMPRESS_EC_POINT_BY_DEFAULT);
                point.as_bytes().to_vec()
            }
            EcCurve::NistP521 => {
                let x = p521::elliptic_curve::array::Array::try_from(px_validated).map_err(|_| KeyError::EC {
                    context: format!(
                        "validated PX slice is not right length(expected: {}, actual: {})",
                        curve.field_bytes_size(),
                        px_validated.len(),
                    ),
                })?;
                let y = p521::elliptic_curve::array::Array::try_from(py_validated).map_err(|_| KeyError::EC {
                    context: format!(
                        "validated PY slice is not right length(expected: {}, actual: {})",
                        curve.field_bytes_size(),
                        py_validated.len(),
                    ),
                })?;
                let point = p521::Sec1Point::from_affine_coordinates(&x, &y, COMPRESS_EC_POINT_BY_DEFAULT);
                point.to_bytes().into_vec()
            }
        };

        let secret = secret.to_be_bytes_trimmed_vartime().into_vec();

        let inner = PrivateKeyInfo::new_ec_encryption(
            curve_oid.clone(),
            secret.clone(),
            Some(BitString::with_bytes(point_bytes.as_slice())),
            false,
        );

        let kind = PrivateKeyKind::Ec {
            curve_oid,
            public_key: Some(point_bytes),
            private_key: secret,
        };

        Ok(Self { kind, inner })
    }

    /// Infallible method to create new EC key from given components. Note that no checks performed
    /// on the validity of the secret and point bytes representation in regards to selected
    /// curve oid.
    pub fn from_ec_encoded_components(curve_oid: ObjectIdentifier, secret: &[u8], point: Option<&[u8]>) -> Self {
        let inner = PrivateKeyInfo::new_ec_encryption(
            curve_oid.clone(),
            secret.to_vec(),
            point.map(BitString::with_bytes),
            false,
        );

        let kind = PrivateKeyKind::Ec {
            curve_oid,
            public_key: point.map(|point| point.to_vec()),
            private_key: secret.to_vec(),
        };

        Self { kind, inner }
    }

    pub fn from_ed_encoded_components(
        algorithm_oid: ObjectIdentifier,
        secret: &[u8],
        public_key: Option<&[u8]>,
    ) -> Self {
        let public_key_bit_string = public_key.map(BitString::with_bytes);

        let inner = PrivateKeyInfo::new_ed_encryption(algorithm_oid.clone(), secret.to_vec(), public_key_bit_string);

        let kind = PrivateKeyKind::Ed {
            algorithm_oid,
            public_key: public_key.map(|key| key.to_vec()),
            private_key: secret.to_vec(),
        };

        Self { kind, inner }
    }

    pub fn from_pem(pem: &Pem) -> Result<Self, KeyError> {
        match pem.label() {
            PRIVATE_KEY_PEM_LABEL => Self::from_pkcs8(pem.data()),
            RSA_PRIVATE_KEY_PEM_LABEL => Self::from_pkcs1(pem.data()),
            EC_PRIVATE_KEY_LABEL => Self::from_ec_der(pem.data()),
            _ => Err(KeyError::InvalidPemLabel {
                label: pem.label().to_owned(),
            }),
        }
    }

    pub fn from_pem_str(pem_str: &str) -> Result<Self, KeyError> {
        let pem = parse_pem(pem_str)?;
        Self::from_pem(&pem)
    }

    pub fn from_pkcs8<T: ?Sized + AsRef<[u8]>>(pkcs8: &T) -> Result<Self, KeyError> {
        let inner: PrivateKeyInfo =
            picky_asn1_der::from_bytes(pkcs8.as_ref()).map_err(|e| KeyError::Asn1Deserialization {
                source: e,
                element: "private key info (pkcs8)",
            })?;

        match &inner.private_key {
            PrivateKeyValue::Rsa(_) => Ok(Self {
                kind: PrivateKeyKind::Rsa,
                inner,
            }),
            PrivateKeyValue::EC(OctetStringAsn1Container(key)) => {
                let curve_oid = match inner.private_key_algorithm.parameters() {
                    picky_asn1_x509::AlgorithmIdentifierParameters::Ec(params) => params.curve_oid().clone(),
                    _ => {
                        return Err(KeyError::EC {
                            context: "Specified private key parameters are not EC parameters".to_string(),
                        });
                    }
                };

                Self::from_ec_decoded_der_with_curve_oid(curve_oid, key)
            }
            PrivateKeyValue::ED(OctetStringAsn1Container(key)) => {
                let algorithm = NamedEdAlgorithm::from(inner.private_key_algorithm.oid());
                let private_key = key.0.clone();
                let public_key = match &algorithm {
                    NamedEdAlgorithm::Known(EdAlgorithm::Ed25519) => {
                        let private_key = private_key.as_slice().try_into().map_err(|e| KeyError::ED {
                            context: format!("invalid size for private key: {e}"),
                        })?;
                        let private_key = ed25519_dalek::SigningKey::from_bytes(private_key);

                        let public_key = private_key.verifying_key();

                        Some(public_key.to_bytes().to_vec())
                    }
                    NamedEdAlgorithm::Known(EdAlgorithm::X25519) => {
                        let len = private_key.len();

                        let secret: X25519FieldElement =
                            private_key.as_slice().try_into().map_err(|_| KeyError::ED {
                                context: format!(
                                "Invalid X25519 private key size. Expected: {X25519_FIELD_ELEMENT_SIZE}, actual: {len}"
                            ),
                            })?;

                        let secret = x25519_dalek::StaticSecret::from(secret);
                        let public_key = x25519_dalek::PublicKey::from(&secret);

                        Some(public_key.to_bytes().to_vec())
                    }
                    NamedEdAlgorithm::Unsupported(_) => {
                        // We can't generate public key from private key for unsupported algorithms
                        None
                    }
                };

                Ok(Self {
                    kind: PrivateKeyKind::Ed {
                        algorithm_oid: algorithm.into(),
                        public_key,
                        private_key,
                    },
                    inner,
                })
            }
        }
    }

    /// Decodes a DER-encoded RSA private key
    pub fn from_pkcs1<T: ?Sized + AsRef<[u8]>>(der: &T) -> Result<Self, KeyError> {
        use picky_asn1_x509::{AlgorithmIdentifier, RsaPrivateKey};

        let private_key =
            picky_asn1_der::from_bytes::<RsaPrivateKey>(der.as_ref()).map_err(|e| KeyError::Asn1Deserialization {
                source: e,
                element: "rsa private key",
            })?;

        let inner = PrivateKeyInfo {
            version: PRIVATE_KEY_INFO_VERSION_1,
            private_key_algorithm: AlgorithmIdentifier::new_rsa_encryption(),
            private_key: PrivateKeyValue::Rsa(private_key.into()),
            public_key: None,
        };

        Ok(Self {
            kind: PrivateKeyKind::Rsa,
            inner,
        })
    }

    /// Loads an EC private key from a DER-encoded private key with supported curve. Also see
    /// [`Self::from_ec_der_with_curve_oid`] for loading keys with unsupported curves.
    pub fn from_ec_der_with_curve<T: ?Sized + AsRef<[u8]>>(der: &T, curve: EcCurve) -> Result<Self, KeyError> {
        Self::from_ec_der_with_curve_oid(der, NamedEcCurve::Known(curve).into())
    }

    /// Internal method to load an EC private key from ASN.1 structure [`ECPrivateKey`] and the
    /// given curve OID. (Curve id is required as [`ECPrivateKey`] does not guarantee that the
    /// cureve parameters are present). If public key is absent in the ASN.1 structure, it will be
    /// calculated from the private key (Only if curve is supported. In other case - throws error)
    fn from_ec_decoded_der_with_curve_oid(
        curve_oid: ObjectIdentifier,
        decoded: &ECPrivateKey,
    ) -> Result<Self, KeyError> {
        // Generate the public key if it's not present in the `ECPrivateKey` representation
        let (public_key, public_key_is_generated) = match &decoded.public_key.0.0 {
            Some(bit_string) => (Some(bit_string.payload_view().to_vec()), false),
            None => (
                calculate_public_ec_key(&curve_oid, &decoded.private_key.0, COMPRESS_EC_POINT_BY_DEFAULT)?,
                true,
            ),
        };
        let private_key = decoded.private_key.0.clone();
        // if the public key is generated, we need to skip it when encoding, to preserve the
        // original `ECPrivateKey` structure in encoded representation
        let public_key_encoded = public_key
            .as_deref()
            .and_then(|public_key| (!public_key_is_generated).then(|| BitString::with_bytes(public_key)));
        // if the parameters are missing during parsing, we need to skip them when encoding
        let der_skip_parameters = decoded.parameters.0.is_none();

        let inner = PrivateKeyInfo::new_ec_encryption(
            curve_oid.clone(),
            private_key.clone(),
            public_key_encoded,
            der_skip_parameters,
        );

        let kind = PrivateKeyKind::Ec {
            curve_oid,
            public_key,
            private_key,
        };

        Ok(Self { kind, inner })
    }

    /// Same as [`Self::from_ec_der_with_curve`], but with manually specified curve OID. Arithmetic
    /// operations are not available for unknown curves, but this method allows to load key from
    /// DER-encoded data to perfor non-arithmetic operations like extracting public key or
    /// re-encoding into pkcs8.
    pub fn from_ec_der_with_curve_oid<T: ?Sized + AsRef<[u8]>>(
        der: &T,
        curve_oid: ObjectIdentifier,
    ) -> Result<Self, KeyError> {
        let private_key =
            picky_asn1_der::from_bytes::<ECPrivateKey>(der.as_ref()).map_err(|e| KeyError::Asn1Deserialization {
                source: e,
                element: "ec private key",
            })?;

        Self::from_ec_decoded_der_with_curve_oid(curve_oid, &private_key)
    }

    /// Returns the private key as a DER-encoded EC private key. Note that generally, DER-encoded
    /// EC keys do not contain the curve parameters, so this method will return if it cannot find
    /// such parameters.
    ///
    /// Usually, EC keys are encoded in PKCS#8 format, which contain all required
    /// information to reconstruct the key. See [`Self::from_pkcs8`]
    ///
    /// However, if the key is encoded in the DER format, and the curve parameters are missing, you
    /// could load it via [`Self::from_ec_der_with_curve`] and specify the curve manually.
    ///
    /// Also, if public key is absent is missing in the parsed file, it will be calculated from the
    /// private key (Only if curve is supported. In other case - throws error)
    pub fn from_ec_der<T: ?Sized + AsRef<[u8]>>(der: &T) -> Result<Self, KeyError> {
        let private_key =
            picky_asn1_der::from_bytes::<ECPrivateKey>(der.as_ref()).map_err(|e| KeyError::Asn1Deserialization {
                source: e,
                element: "ec private key",
            })?;

        // By specification (https://www.rfc-editor.org/rfc/rfc5915) `parameters` files SHOULD
        // be present when EC key is encoded as standalone DER. However, some implementations
        // do not include parameters, so we have to check for that.
        let curve_oid = match &private_key.parameters.0.0 {
            Some(params) => params.curve_oid().clone(),
            None => {
                return Err(KeyError::EC {
                    context: "EC parameters are missing from DER-encoded private key".into(),
                });
            }
        };

        Self::from_ec_decoded_der_with_curve_oid(curve_oid, &private_key)
    }

    pub fn to_pkcs8(&self) -> Result<Vec<u8>, KeyError> {
        picky_asn1_der::to_vec(self.as_inner()).map_err(|e| KeyError::Asn1Serialization {
            source: e,
            element: "private key info (pkcs8)",
        })
    }

    pub fn to_pkcs1(&self) -> Result<Vec<u8>, KeyError> {
        let picky_asn1_x509::PrivateKeyValue::Rsa(OctetStringAsn1Container(rsa_private_key)) = &self.inner.private_key
        else {
            return Err(KeyError::Rsa {
                context: String::from("can’t export a non-RSA key to PKCS#1 format"),
            });
        };

        picky_asn1_der::to_vec(rsa_private_key).map_err(|e| KeyError::Asn1Serialization {
            source: e,
            element: "RSA private key (pkcs1)",
        })
    }

    pub fn to_pem(&self) -> Result<Pem<'static>, KeyError> {
        let pkcs8 = self.to_pkcs8()?;
        Ok(Pem::new(PRIVATE_KEY_PEM_LABEL, pkcs8))
    }

    pub fn to_pem_str(&self) -> Result<String, KeyError> {
        self.to_pem().map(|pem| pem.to_string())
    }

    pub fn to_pkcs1_pem(&self) -> Result<Pem<'static>, KeyError> {
        let pkcs1 = self.to_pkcs1()?;
        Ok(Pem::new(RSA_PRIVATE_KEY_PEM_LABEL, pkcs1))
    }

    pub fn to_pkcs1_pem_str(&self) -> Result<String, KeyError> {
        self.to_pkcs1_pem().map(|pem| pem.to_string())
    }

    pub fn to_public_key(&self) -> Result<PublicKey, KeyError> {
        let key = match &self.kind {
            PrivateKeyKind::Rsa => match &self.inner.private_key {
                PrivateKeyValue::Rsa(OctetStringAsn1Container(key)) => {
                    SubjectPublicKeyInfo::new_rsa_key(key.modulus.clone(), key.public_exponent.clone()).into()
                }
                _ => unreachable!("BUG: Non-RSA key data in RSA private key"),
            },
            PrivateKeyKind::Ec {
                public_key, curve_oid, ..
            } => match public_key {
                Some(data) => {
                    let point = picky_asn1::bit_string::BitString::with_bytes(data.as_slice());
                    SubjectPublicKeyInfo::new_ec_key(curve_oid.clone(), point).into()
                }
                None => {
                    return Err(KeyError::EC {
                        context: "Public key can't be calculated for unknown EC algorithms".into(),
                    });
                }
            },
            PrivateKeyKind::Ed {
                public_key,
                algorithm_oid,
                ..
            } => match public_key {
                Some(data) => {
                    let point = picky_asn1::bit_string::BitString::with_bytes(data.as_slice());
                    SubjectPublicKeyInfo::new_ed_key(algorithm_oid.clone(), point).into()
                }
                None => {
                    return Err(KeyError::ED {
                        context: "Public key can't be calculated for unknown edwards curves-based algorithms".into(),
                    });
                }
            },
        };

        Ok(key)
    }

    /// **Beware**: this is insanely slow in debug builds.
    pub fn generate_rsa(bits: usize) -> Result<Self, KeyError> {
        let key = RsaPrivateKey::new(&mut StdRng::try_from_rng(&mut SysRng)?, bits)?;

        let modulus = key.n();
        let public_exponent = key.e();
        let private_exponent = key.d();

        Self::from_rsa_components(modulus, public_exponent, private_exponent, key.primes())
    }

    /// Generates new ec key pair with specified supported curve.
    pub fn generate_ec(curve: EcCurve) -> Result<Self, KeyError> {
        let curve_oid: ObjectIdentifier = NamedEcCurve::Known(curve).into();

        let (secret, point) = match curve {
            EcCurve::NistP256 => {
                use p256::elliptic_curve::sec1::ToSec1Point;

                let key = p256::SecretKey::generate_from_rng(&mut StdRng::try_from_rng(&mut SysRng)?);
                let secret = key.to_bytes().to_vec();
                let point = key
                    .public_key()
                    .to_sec1_point(COMPRESS_EC_POINT_BY_DEFAULT)
                    .as_bytes()
                    .to_vec();
                (secret, point)
            }
            EcCurve::NistP384 => {
                use p384::elliptic_curve::sec1::ToSec1Point;

                let key = p384::SecretKey::generate_from_rng(&mut StdRng::try_from_rng(&mut SysRng)?);
                let secret = key.to_bytes().to_vec();
                let point = key
                    .public_key()
                    .to_sec1_point(COMPRESS_EC_POINT_BY_DEFAULT)
                    .as_bytes()
                    .to_vec();
                (secret, point)
            }
            EcCurve::NistP521 => {
                use p521::elliptic_curve::sec1::ToSec1Point;

                let key = p521::SecretKey::generate_from_rng(&mut StdRng::try_from_rng(&mut SysRng)?);
                let secret = key.to_bytes().to_vec();
                let point = key
                    .public_key()
                    .to_sec1_point(COMPRESS_EC_POINT_BY_DEFAULT)
                    .as_bytes()
                    .to_vec();
                (secret, point)
            }
        };

        let inner = PrivateKeyInfo::new_ec_encryption(
            curve_oid.clone(),
            secret.clone(),
            Some(BitString::with_bytes(point.as_slice())),
            false,
        );

        let kind = PrivateKeyKind::Ec {
            curve_oid,
            public_key: Some(point),
            private_key: secret,
        };

        Ok(Self { kind, inner })
    }

    /// Generates new ed key pair with specified supported algorithm.
    ///
    /// `write_public_key` specifies whether to include public key in the private key file.
    /// Note that OpenSSL does not support ed keys with public key included.
    pub fn generate_ed(algorithm: EdAlgorithm, write_public_key: bool) -> Result<Self, KeyError> {
        let algorithm_oid: ObjectIdentifier = NamedEdAlgorithm::Known(algorithm).into();

        let (private_key, public_key) = match algorithm {
            EdAlgorithm::Ed25519 => {
                let private = ed25519_dalek::SigningKey::generate(&mut StdRng::try_from_rng(&mut SysRng)?);
                let public = private.verifying_key();
                (private.to_bytes().to_vec(), public.to_bytes().to_vec())
            }
            EdAlgorithm::X25519 => {
                let private = x25519_dalek::StaticSecret::random_from_rng(&mut StdRng::try_from_rng(&mut SysRng)?);
                let public = x25519_dalek::PublicKey::from(&private);
                (private.to_bytes().to_vec(), public.to_bytes().to_vec())
            }
        };

        let public_key_bit_string = write_public_key.then(|| BitString::with_bytes(public_key.as_slice()));

        let inner =
            PrivateKeyInfo::new_ed_encryption(algorithm_oid.clone(), private_key.clone(), public_key_bit_string);

        let kind = PrivateKeyKind::Ed {
            algorithm_oid,
            public_key: Some(public_key),
            private_key,
        };

        Ok(Self { kind, inner })
    }

    pub fn kind(&self) -> KeyKind {
        match self.kind {
            PrivateKeyKind::Rsa => KeyKind::Rsa,
            PrivateKeyKind::Ec { .. } => KeyKind::Ec,
            PrivateKeyKind::Ed { .. } => KeyKind::Ed,
        }
    }

    pub(crate) fn as_inner(&self) -> &PrivateKeyInfo {
        &self.inner
    }

    #[cfg(any(feature = "ssh", feature = "jose"))]
    pub(crate) fn as_kind(&self) -> &PrivateKeyKind {
        &self.kind
    }
}

// === public key === //

const PUBLIC_KEY_PEM_LABEL: &str = "PUBLIC KEY";
const RSA_PUBLIC_KEY_PEM_LABEL: &str = "RSA PUBLIC KEY";
const EC_PUBLIC_KEY_PEM_LABEL: &str = "EC PUBLIC KEY";

#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct PublicKey(SubjectPublicKeyInfo);

impl<'a> From<&'a SubjectPublicKeyInfo> for &'a PublicKey {
    #[inline]
    fn from(spki: &'a SubjectPublicKeyInfo) -> Self {
        unsafe { &*(spki as *const SubjectPublicKeyInfo as *const PublicKey) }
    }
}

impl<'a> From<&'a PublicKey> for &'a SubjectPublicKeyInfo {
    #[inline]
    fn from(key: &'a PublicKey) -> Self {
        unsafe { &*(key as *const PublicKey as *const SubjectPublicKeyInfo) }
    }
}

impl From<SubjectPublicKeyInfo> for PublicKey {
    #[inline]
    fn from(spki: SubjectPublicKeyInfo) -> Self {
        Self(spki)
    }
}

impl From<PublicKey> for SubjectPublicKeyInfo {
    #[inline]
    fn from(key: PublicKey) -> Self {
        key.0
    }
}
impl TryFrom<PrivateKey> for PublicKey {
    type Error = KeyError;

    #[inline]
    fn try_from(key: PrivateKey) -> Result<Self, Self::Error> {
        key.to_public_key()
    }
}

impl AsRef<SubjectPublicKeyInfo> for PublicKey {
    #[inline]
    fn as_ref(&self) -> &SubjectPublicKeyInfo {
        self.into()
    }
}

impl AsRef<PublicKey> for PublicKey {
    #[inline]
    fn as_ref(&self) -> &PublicKey {
        self
    }
}

impl TryFrom<&'_ PublicKey> for RsaPublicKey {
    type Error = KeyError;

    fn try_from(v: &PublicKey) -> Result<Self, Self::Error> {
        use picky_asn1_x509::PublicKey as InnerPublicKey;

        match &v.as_inner().subject_public_key {
            InnerPublicKey::Rsa(BitStringAsn1Container(key)) => Ok(RsaPublicKey::new_with_max_size(
                BoxedUint::from_be_slice_vartime(key.modulus.as_unsigned_bytes_be()),
                BoxedUint::from_be_slice_vartime(key.public_exponent.as_unsigned_bytes_be()),
                8192,
            )?),
            InnerPublicKey::Ec(_) => Err(KeyError::UnsupportedAlgorithm {
                algorithm: "elliptic curves",
            }),
            InnerPublicKey::Ed(_) => Err(KeyError::UnsupportedAlgorithm {
                algorithm: "edwards curves",
            }),
            InnerPublicKey::Mldsa(_) => Err(KeyError::UnsupportedAlgorithm { algorithm: "mldsa" }),
        }
    }
}

impl PublicKey {
    pub fn from_rsa_components(modulus: &BoxedUint, public_exponent: &BoxedUint) -> Self {
        PublicKey(SubjectPublicKeyInfo::new_rsa_key(
            IntegerAsn1::from_bytes_be_unsigned(modulus.to_be_bytes_trimmed_vartime().into_vec()),
            IntegerAsn1::from_bytes_be_unsigned(public_exponent.to_be_bytes_trimmed_vartime().into_vec()),
        ))
    }

    /// `point` is SEC1 encoded point data
    pub fn from_ec_encoded_components(curve: &ObjectIdentifier, point: &[u8]) -> Self {
        let point = picky_asn1::bit_string::BitString::with_bytes(point);
        PublicKey(SubjectPublicKeyInfo::new_ec_key(curve.clone(), point))
    }

    /// `public_key` is raw edwards curve public key
    pub fn from_ed_encoded_components(algorithm: &ObjectIdentifier, public_key: &[u8]) -> Self {
        let point = picky_asn1::bit_string::BitString::with_bytes(public_key);
        PublicKey(SubjectPublicKeyInfo::new_ed_key(algorithm.clone(), point))
    }

    /// Creates public key from its raw components. Only curves declared in [`EcCurve`] are
    /// supported. For correct encoding of the point, we need to know which curve-specific
    /// arithmetic crate to use. If you want to use a curve that is not declared in [`EcCurve`],
    /// and encoded representation of the point is available - use [`Self::from_ec_encoded_components`]
    pub fn from_ec_components(curve: EcCurve, x: &BoxedUint, y: &BoxedUint) -> Result<Self, KeyError> {
        let px_bytes = x.to_be_bytes_trimmed_vartime();
        let py_bytes = y.to_be_bytes_trimmed_vartime();

        let px_validated = curve.validate_component(EcComponent::PointX(&px_bytes))?;
        let py_validated = curve.validate_component(EcComponent::PointY(&py_bytes))?;

        match curve {
            EcCurve::NistP256 => {
                let p = p256::Sec1Point::from_affine_coordinates(
                    &p256::elliptic_curve::array::Array::try_from(px_validated).map_err(|_| KeyError::EC {
                        context: format!(
                            "validated PX slice is not right length(expected: {}, actual: {})",
                            curve.field_bytes_size(),
                            px_validated.len(),
                        ),
                    })?,
                    &p256::elliptic_curve::array::Array::try_from(py_validated).map_err(|_| KeyError::EC {
                        context: format!(
                            "validated PY slice is not right length(expected: {}, actual: {})",
                            curve.field_bytes_size(),
                            py_validated.len(),
                        ),
                    })?,
                    COMPRESS_EC_POINT_BY_DEFAULT,
                );

                Ok(Self::from_ec_encoded_components(
                    &NamedEcCurve::Known(curve).into(),
                    p.as_bytes(),
                ))
            }
            EcCurve::NistP384 => {
                let p = p384::Sec1Point::from_affine_coordinates(
                    &p384::elliptic_curve::array::Array::try_from(px_validated).map_err(|_| KeyError::EC {
                        context: format!(
                            "validated PX slice is not right length(expected: {}, actual: {})",
                            curve.field_bytes_size(),
                            px_validated.len(),
                        ),
                    })?,
                    &p384::elliptic_curve::array::Array::try_from(py_validated).map_err(|_| KeyError::EC {
                        context: format!(
                            "validated PY slice is not right length(expected: {}, actual: {})",
                            curve.field_bytes_size(),
                            py_validated.len(),
                        ),
                    })?,
                    COMPRESS_EC_POINT_BY_DEFAULT,
                );

                Ok(Self::from_ec_encoded_components(
                    &NamedEcCurve::Known(curve).into(),
                    p.as_bytes(),
                ))
            }
            EcCurve::NistP521 => {
                let p = p521::Sec1Point::from_affine_coordinates(
                    &p521::elliptic_curve::array::Array::try_from(px_validated).map_err(|_| KeyError::EC {
                        context: format!(
                            "validated PX slice is not right length(expected: {}, actual: {})",
                            curve.field_bytes_size(),
                            px_validated.len(),
                        ),
                    })?,
                    &p521::elliptic_curve::array::Array::try_from(py_validated).map_err(|_| KeyError::EC {
                        context: format!(
                            "validated PY slice is not right length(expected: {}, actual: {})",
                            curve.field_bytes_size(),
                            py_validated.len(),
                        ),
                    })?,
                    COMPRESS_EC_POINT_BY_DEFAULT,
                );

                Ok(Self::from_ec_encoded_components(
                    &NamedEcCurve::Known(curve).into(),
                    p.as_bytes(),
                ))
            }
        }
    }

    pub fn to_der(&self) -> Result<Vec<u8>, KeyError> {
        picky_asn1_der::to_vec(&self.0).map_err(|e| KeyError::Asn1Serialization {
            source: e,
            element: "subject public key info",
        })
    }

    pub fn to_pkcs1(&self) -> Result<Vec<u8>, KeyError> {
        let picky_asn1_x509::PublicKey::Rsa(BitStringAsn1Container(rsa_public_key)) = &self.0.subject_public_key else {
            return Err(KeyError::Rsa {
                context: String::from("can’t export a non-RSA key to PKCS#1 format"),
            });
        };

        picky_asn1_der::to_vec(rsa_public_key).map_err(|e| KeyError::Asn1Serialization {
            source: e,
            element: "RSA public key",
        })
    }

    pub fn to_pem(&self) -> Result<Pem<'static>, KeyError> {
        let der = self.to_der()?;
        Ok(Pem::new(PUBLIC_KEY_PEM_LABEL, der))
    }

    pub fn to_pem_str(&self) -> Result<String, KeyError> {
        self.to_pem().map(|pem| pem.to_string())
    }

    pub fn to_pkcs1_pem(&self) -> Result<Pem<'static>, KeyError> {
        let pkcs1 = self.to_pkcs1()?;
        Ok(Pem::new(RSA_PUBLIC_KEY_PEM_LABEL, pkcs1))
    }

    pub fn to_pkcs1_pem_str(&self) -> Result<String, KeyError> {
        self.to_pkcs1_pem().map(|pem| pem.to_string())
    }

    pub fn from_pem(pem: &Pem) -> Result<Self, KeyError> {
        match pem.label() {
            PUBLIC_KEY_PEM_LABEL | EC_PUBLIC_KEY_PEM_LABEL => Self::from_der(pem.data()),
            RSA_PUBLIC_KEY_PEM_LABEL => Self::from_pkcs1(pem.data()),
            _ => Err(KeyError::InvalidPemLabel {
                label: pem.label().to_owned(),
            }),
        }
    }

    pub fn from_pem_str(pem_str: &str) -> Result<Self, KeyError> {
        let pem = parse_pem(pem_str)?;
        Self::from_pem(&pem)
    }

    pub fn from_der<T: ?Sized + AsRef<[u8]>>(der: &T) -> Result<Self, KeyError> {
        Ok(Self(picky_asn1_der::from_bytes(der.as_ref()).map_err(|e| {
            KeyError::Asn1Deserialization {
                source: e,
                element: "subject public key info",
            }
        })?))
    }

    pub fn from_pkcs1<T: ?Sized + AsRef<[u8]>>(der: &T) -> Result<Self, KeyError> {
        use picky_asn1_x509::{AlgorithmIdentifier, PublicKey, RsaPublicKey};

        let public_key =
            picky_asn1_der::from_bytes::<RsaPublicKey>(der.as_ref()).map_err(|e| KeyError::Asn1Deserialization {
                source: e,
                element: "rsa public key",
            })?;

        Ok(Self(SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier::new_rsa_encryption(),
            subject_public_key: PublicKey::Rsa(public_key.into()),
        }))
    }

    pub fn kind(&self) -> KeyKind {
        match self.0.subject_public_key {
            picky_asn1_x509::PublicKey::Rsa(_) => KeyKind::Rsa,
            picky_asn1_x509::PublicKey::Ec(_) => KeyKind::Ec,
            picky_asn1_x509::PublicKey::Ed(_) => KeyKind::Ed,
            picky_asn1_x509::PublicKey::Mldsa(_) => KeyKind::Mldsa,
        }
    }

    pub(crate) fn as_inner(&self) -> &SubjectPublicKeyInfo {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::HashAlgorithm;
    use crate::key::ed::EdKeypair;
    use crate::signature::SignatureAlgorithm;
    use rsa::traits::PublicKeyParts;
    use rstest::rstest;

    cfg_if::cfg_if! { if #[cfg(feature = "x509")] {
        use crate::x509::{certificate::CertificateBuilder, date::UtcDate, name::DirectoryName};

        fn generate_certificate_from_pk(private_key: PrivateKey) {
            // validity
            let valid_from = UtcDate::ymd(2019, 10, 10).unwrap();
            let valid_to = UtcDate::ymd(2019, 10, 11).unwrap();

            CertificateBuilder::new()
                .validity(valid_from, valid_to)
                .self_signed(DirectoryName::new_common_name("Test Root CA"), &private_key)
                .ca(true)
                .build()
                .expect("couldn't build root ca");
        }
    } else {
        fn generate_certificate_from_pk(_: PrivateKey) {}
    }}

    /// Generating RSA keys in debug is very slow. Therefore, this test is ignored in debug builds
    #[test]
    #[cfg_attr(debug_assertions, ignore)]
    fn generate_rsa_key() {
        let private_key = PrivateKey::generate_rsa(4096).expect("couldn't generate rsa key");
        generate_certificate_from_pk(private_key);
    }

    const PKCS1_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
                            MIIEpAIBAAKCAQEA5Kz4i/+XZhiE+fyrgtx/4yI3i6C6HXbC4QJYpDuSUEKN2bO9\n\
                            RsE+Fnds/FizHtJVWbvya9ktvKdDPBdy58+CIM46HEKJhYLnBVlkEcg9N2RNgR3x\n\
                            HnpRbKfv+BmWjOpSmWrmJSDLY0dbw5X5YL8TU69ImoouCUfStyCgrpwkctR0GD3G\n\
                            fcGjbZRucV7VvVH9bS1jyaT/9yORyzPOSTwb+K9vOr6XlJX0CGvzQeIOcOimejHx\n\
                            ACFOCnhEKXiwMsmL8FMz0drkGeMuCODY/OHVmAdXDE5UhroL0oDhSmIrdZ8CxngO\n\
                            xHr1WD2yC0X0jAVP/mrxjSSfBwmmqhSMmONlvQIDAQABAoIBAQCJrBl3L8nWjayB\n\
                            VL1ta5MTC+alCX8DfhyVmvQC7FqKN4dvKecqUe0vWXcj9cLhK4B3JdAtXfNLQOgZ\n\
                            pYRoS2XsmjwiB20EFGtBrS+yBPvV/W0r7vrbfojHAdRXahBZhjl0ZAdrEvNgMfXt\n\
                            Kr2YoXDhUQZFBCvzKmqSFfKnLRpEhsCBOsp+Sx0ZbP3yVPASXnqiZmKblpY4qcE5\n\
                            KfYUO0nUWBSzY8I5c/29IY5oBbOUGS1DTMkx3R7V0BzbH/xmskVACn+cMzf467vp\n\
                            yupTKG9hIX8ff0QH4Ggx88uQTRTI9IvfrAMnICFtR6U7g70hLN6j9ujXkPNhmycw\n\
                            E5nQCmuBAoGBAPVbYtGBvnlySN73UrlyJ1NItUmOGhBt/ezpRjMIdMkJ6dihq7i2\n\
                            RpE76sRvwHY9Tmw8oxR/V1ITK3dM2jZP1SRcm1mn5Y1D3K38jwFS0C47AXzIN2N+\n\
                            LExekI1J4YOPV9o378vUKQuWpbQrQOOvylQBkRJ0Cd8DI3xhiBT/AVGbAoGBAO6Y\n\
                            WBP3GMloO2v6PHijhRqrNdaI0qht8tDhO5L1troFLst3sfpK9fUP/KTlhHOzNVBF\n\
                            fIJnNdcYAe9BISBbfSat+/R9F+GoUvpoC4j8ygHTQkT6ZMcMDfR8RQ4BlqGHIDKZ\n\
                            YaAJoPZVkg7hNRMcvIruYpzFrheDE/4xvnC51GeHAoGAHzCFyFIw72lKwCU6e956\n\
                            B0lH2ljZEVuaGuKwjM43YlMDSgmLNcjeAZpXRq9aDO3QKUwwAuwJIqLTNLAtURgm\n\
                            5R9slCIWuTV2ORvQ5f8r/aR8lOsyt1ATu4WN5JgOtdWj+laAAi4vJYz59YRGFGuF\n\
                            UdZ9JZZgptvUR/xx+xFLjp8CgYBMRzghaeXqvgABTUb36o8rL4FOzP9MCZqPXPKG\n\
                            0TdR0UZcli+4LS7k4e+LaDUoKCrrNsvPhN+ZnHtB2jiU96rTKtxaFYQFCKM+mvTV\n\
                            HrwWSUvucX62hAwSFYieKbPWgDSy+IZVe76SAllnmGg3bAB7CitMo4Y8zhMeORkB\n\
                            QOe/EQKBgQDgeNgRud7S9BvaT3iT7UtizOr0CnmMfoF05Ohd9+VE4ogvLdAoDTUF\n\
                            JFtdOT/0naQk0yqIwLDjzCjhe8+Ji5Y/21pjau8bvblTnASq26FRRjv5+hV8lmcR\n\
                            zzk3Y05KXvJL75ksJdomkzZZb0q+Omf3wyjMR8Xl5WueJH1fh4hpBw==\n\
                            -----END RSA PRIVATE KEY-----";

    #[test]
    fn private_key_from_rsa_pem() {
        PrivateKey::from_pem(&PKCS1_PEM.parse::<Pem>().expect("pem")).expect("private key");
    }

    #[test]
    fn check_pkcs1() {
        let private_pkcs1_pem = PKCS1_PEM.parse::<Pem>().expect("pem");
        let private = PrivateKey::from_pem(&private_pkcs1_pem).expect("private key");

        let private_pkcs1 = private.to_pkcs1().unwrap();
        PrivateKey::from_pkcs1(&private_pkcs1).unwrap();
        assert_eq!(private_pkcs1, private_pkcs1_pem.data());

        let public = private.to_public_key().unwrap();
        let public_pkcs1 = public.to_pkcs1().unwrap();
        PublicKey::from_pkcs1(&public_pkcs1).unwrap();
    }

    const PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
                                  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA61BjmfXGEvWmegnBGSuS\n\
                                  +rU9soUg2FnODva32D1AqhwdziwHINFaD1MVlcrYG6XRKfkcxnaXGfFDWHLEvNBS\n\
                                  EVCgJjtHAGZIm5GL/KA86KDp/CwDFMSwluowcXwDwoyinmeOY9eKyh6aY72xJh7n\n\
                                  oLBBq1N0bWi1e2i+83txOCg4yV2oVXhBo8pYEJ8LT3el6Smxol3C1oFMVdwPgc0v\n\
                                  Tl25XucMcG/ALE/KNY6pqC2AQ6R2ERlVgPiUWOPatVkt7+Bs3h5Ramxh7XjBOXeu\n\
                                  lmCpGSynXNcpZ/06+vofGi/2MlpQZNhHAo8eayMp6FcvNucIpUndo1X8dKMv3Y26\n\
                                  ZQIDAQAB\n\
                                  -----END PUBLIC KEY-----";

    #[test]
    fn public_key_from_pem() {
        PublicKey::from_pem(&PUBLIC_KEY_PEM.parse::<Pem>().expect("pem")).expect("public key");
    }

    #[test]
    fn public_key_to_and_from_pkcs1() {
        let public_key = PublicKey::from_pem(&PUBLIC_KEY_PEM.parse::<Pem>().expect("pem")).expect("public key");
        let pkcs1 = public_key.to_pkcs1().expect("PKCS1");
        let public_key_round_trip = PublicKey::from_pkcs1(&pkcs1).expect("round trip parse");
        assert_eq!(public_key_round_trip, public_key);
    }

    const RSA_PUBLIC_KEY_PEM: &str = "-----BEGIN RSA PUBLIC KEY-----\n\
                                      MIIBCgKCAQEA61BjmfXGEvWmegnBGSuS+rU9soUg2FnODva32D1AqhwdziwHINFa\n\
                                      D1MVlcrYG6XRKfkcxnaXGfFDWHLEvNBSEVCgJjtHAGZIm5GL/KA86KDp/CwDFMSw\n\
                                      luowcXwDwoyinmeOY9eKyh6aY72xJh7noLBBq1N0bWi1e2i+83txOCg4yV2oVXhB\n\
                                      o8pYEJ8LT3el6Smxol3C1oFMVdwPgc0vTl25XucMcG/ALE/KNY6pqC2AQ6R2ERlV\n\
                                      gPiUWOPatVkt7+Bs3h5Ramxh7XjBOXeulmCpGSynXNcpZ/06+vofGi/2MlpQZNhH\n\
                                      Ao8eayMp6FcvNucIpUndo1X8dKMv3Y26ZQIDAQAB\n\
                                      -----END RSA PUBLIC KEY-----";

    #[test]
    fn public_key_from_rsa_pem() {
        PublicKey::from_pem(&RSA_PUBLIC_KEY_PEM.parse::<Pem>().expect("pem")).expect("public key");
    }

    const GARBAGE_PEM: &str = "-----BEGIN GARBAGE-----R0FSQkFHRQo=-----END GARBAGE-----";

    #[test]
    fn public_key_from_garbage_pem_err() {
        let err = PublicKey::from_pem(&GARBAGE_PEM.parse::<Pem>().expect("pem")).expect_err("key error");
        assert_eq!(err.to_string(), "invalid PEM label: GARBAGE");
    }

    fn check_pk(pem_str: &str) {
        const MSG: &[u8] = b"abcde";

        let pem = pem_str.parse::<Pem>().expect("pem");
        let pk = PrivateKey::from_pem(&pem).expect("private key");
        let algo = SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_256);
        let signed_rsa = algo.sign(MSG, &pk).expect("rsa sign");
        algo.verify(&pk.to_public_key().unwrap(), MSG, &signed_rsa)
            .expect("rsa verify rsa");

        println!("Success!");
    }

    #[test]
    fn invalid_coeff_private_key_regression() {
        println!("2048 PK 7");
        check_pk(picky_test_data::RSA_2048_PK_7);
        println!("4096 PK 3");
        check_pk(picky_test_data::RSA_4096_PK_3);
    }

    #[test]
    fn rsa_crate_private_key_conversion() {
        use rsa::pkcs8::DecodePrivateKey;

        let pk_pem = picky_test_data::RSA_2048_PK_1.parse::<crate::pem::Pem>().unwrap();
        let pk = PrivateKey::from_pem(&pk_pem).unwrap();
        let converted_rsa_private_key = RsaPrivateKey::try_from(&pk).unwrap();
        let expected_rsa_private_key = RsaPrivateKey::from_pkcs8_der(pk_pem.data()).unwrap();

        assert_eq!(converted_rsa_private_key.n(), expected_rsa_private_key.n());
        assert_eq!(converted_rsa_private_key.e(), expected_rsa_private_key.e());
        assert_eq!(converted_rsa_private_key.d(), expected_rsa_private_key.d());

        let converted_primes = converted_rsa_private_key.primes();
        let expected_primes = expected_rsa_private_key.primes();
        assert_eq!(converted_primes.len(), expected_primes.len());
        for (converted_prime, expected_prime) in converted_primes.iter().zip(expected_primes.iter()) {
            assert_eq!(converted_prime, expected_prime);
        }
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore)] // this test is slow in debug
    fn ring_understands_picky_pkcs8_rsa() {
        // Make sure we're generating pkcs8 understood by the `ring` crate
        let key = PrivateKey::generate_rsa(2048).unwrap();
        let pkcs8 = key.to_pkcs8().unwrap();
        ring::signature::RsaKeyPair::from_pkcs8(&pkcs8).unwrap();
    }

    #[rstest]
    #[case(EcCurve::NistP256, &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING)]
    #[case(EcCurve::NistP384, &ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING)]
    fn ring_understands_picky_pkcs8_ec(
        #[case] curve: EcCurve,
        #[case] signing_alg: &'static ring::signature::EcdsaSigningAlgorithm,
    ) {
        // Make sure we're generating pkcs8 understood by the `ring` crate
        let key = PrivateKey::generate_ec(curve).unwrap();
        let pkcs8 = key.to_pkcs8().unwrap();
        let rng = ring::rand::SystemRandom::new();

        ring::signature::EcdsaKeyPair::from_pkcs8(signing_alg, &pkcs8, &rng).unwrap();
    }

    // Read from x25519 keys is not supported in `ring`, because it is mainly used for key
    // exchange for which key serialization/deserialization is not needed at all. But we support,
    // just to be consistent with OpenSSL and RFC https://www.rfc-editor.org/rfc/rfc8410
    #[test]
    fn ring_understands_picky_pkcs8_ed25519() {
        // Make sure we're generating pkcs8 understood by the `ring` crate.
        // `ring` is very specific about the format of the ED25519 private key, and in contrast
        // to OpenSSL, it uses newer v2 version of `PrivateKeyInfo` structure (`OneAsymmetricKey`)
        // which always includes public key in the private key structure.
        let key = PrivateKey::generate_ed(EdAlgorithm::Ed25519, true).unwrap();
        let pkcs8 = key.to_pkcs8().unwrap();

        ring::signature::Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();
    }

    #[test]
    fn ring_ed25519_pkcs8_keys_could_be_parsed() {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();

        let key = PrivateKey::from_pkcs8(&pkcs8_bytes).unwrap();
        let _pair = EdKeypair::try_from(&key).unwrap();
    }
}
