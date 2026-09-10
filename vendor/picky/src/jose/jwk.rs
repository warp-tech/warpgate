//! A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key.
//!
//! See [RFC7517](https://tools.ietf.org/html/rfc7517).

use crate::jose::jwe::{JweAlg, JweEnc};
use crate::jose::jws::JwsAlg;
use crate::key::ec::{EcdsaPublicKey, NamedEcCurve};
use crate::key::ed::{EdPublicKey, NamedEdAlgorithm};
use crate::key::{EcCurve, EdAlgorithm, PublicKey};
use base64::engine::general_purpose;
use base64::{DecodeError, Engine as _};
use crypto_bigint::BoxedUint;
use picky_asn1::wrapper::IntegerAsn1;
use picky_asn1_x509::SubjectPublicKeyInfo;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// === error type === //

#[derive(Debug, Error)]
pub enum JwkError {
    /// Json error
    #[error("JSON error: {source}")]
    Json { source: serde_json::Error },

    /// couldn't decode base64
    #[error("couldn't decode base64: {source}")]
    Base64Decoding { source: DecodeError },

    /// unsupported algorithm
    #[error("unsupported algorithm: {algorithm}")]
    UnsupportedAlgorithm { algorithm: &'static str },

    #[error("invalid ec public key: {cause}")]
    InvalidEcPublicKey { cause: String },

    #[error("invalid ec point coordinates in JWK")]
    InvalidEcPointCoordinates,

    #[error("invalid ed public key: {cause}")]
    InvalidEdPublicKey { cause: String },
}

impl From<serde_json::Error> for JwkError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json { source: e }
    }
}

impl From<DecodeError> for JwkError {
    fn from(e: DecodeError) -> Self {
        Self::Base64Decoding { source: e }
    }
}

// === key type === //

/// Algorithm type for JWK
///
/// See [RFC7518 #6](https://tools.ietf.org/html/rfc7518#section-6.1)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kty")]
pub enum JwkKeyType {
    /// Edwards curve-based cryptography
    ///
    /// Defined by separate [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037)
    #[serde(rename = "OKP")]
    Ed(JwkPublicEdKey),
    /// Elliptic Curve
    ///
    /// Recommended+ by RFC
    #[serde(rename = "EC")]
    Ec(JwkPublicEcKey),
    /// Elliptic Curve
    ///
    /// Required by RFC
    #[serde(rename = "RSA")]
    Rsa(JwkPublicRsaKey),
    /// Octet sequence (used to represent symmetric keys) (unsupported)
    ///
    /// Required by RFC
    #[serde(rename = "oct")]
    Oct,
}

impl JwkKeyType {
    /// Build a JWK key from RSA components.
    ///
    /// Each argument is the unsigned big-endian representation as an octet sequence of the value.
    /// If a signed representation is provided, leading zero is removed for any number bigger than 0x7F.
    pub fn new_rsa_key(modulus: &[u8], public_exponent: &[u8]) -> Self {
        let modulus = h_strip_unrequired_leading_zero(modulus);
        let public_exponent = h_strip_unrequired_leading_zero(public_exponent);
        Self::Rsa(JwkPublicRsaKey {
            n: general_purpose::URL_SAFE_NO_PAD.encode(modulus),
            e: general_purpose::URL_SAFE_NO_PAD.encode(public_exponent),
        })
    }

    /// Build a JWK key from EC components.
    ///
    /// `x` and `y` are big-endian representation of the affine point coordinates.
    pub fn new_ec_key(curve: JwkEcPublicKeyCurve, x: &[u8], y: &[u8]) -> Self {
        let x = h_strip_unrequired_leading_zero(x);
        let y = h_strip_unrequired_leading_zero(y);
        Self::Ec(JwkPublicEcKey {
            crv: curve,
            x: general_purpose::URL_SAFE_NO_PAD.encode(x),
            y: general_purpose::URL_SAFE_NO_PAD.encode(y),
        })
    }

    /// Build a JWK key from Edwards curve components.
    ///
    /// `crv` is ed-based algorithm name.
    /// `x` is raw public key bytes.
    pub fn new_ed_key(crv: JwkEdPublicKeyAlgorithm, x: &[u8]) -> Self {
        Self::Ed(JwkPublicEdKey {
            crv,
            x: general_purpose::URL_SAFE_NO_PAD.encode(x),
        })
    }

    /// Build a JWK key from RSA components already encoded following base64 url format.
    ///
    /// Each argument is the unsigned big-endian representation as an octet sequence of the value.
    /// The octet sequence MUST utilize the minimum number of octets needed to represent the value.
    /// That is: **no leading zero** must be present.
    ///
    /// See definition for term `Base64urlUInt` in [RFC7518 section 2](https://datatracker.ietf.org/doc/html/rfc7518#section-2)
    pub fn new_rsa_key_from_base64_url(modulus: String, public_exponent: String) -> Self {
        Self::Rsa(JwkPublicRsaKey {
            n: modulus,
            e: public_exponent,
        })
    }

    pub fn as_rsa(&self) -> Option<&JwkPublicRsaKey> {
        match self {
            JwkKeyType::Rsa(rsa) => Some(rsa),
            _ => None,
        }
    }

    pub fn as_ec(&self) -> Option<&JwkPublicEcKey> {
        match self {
            JwkKeyType::Ec(ec) => Some(ec),
            _ => None,
        }
    }

    pub fn as_ed(&self) -> Option<&JwkPublicEdKey> {
        match self {
            JwkKeyType::Ed(ed) => Some(ed),
            _ => None,
        }
    }

    pub fn is_rsa(&self) -> bool {
        self.as_rsa().is_some()
    }

    pub fn is_ec(&self) -> bool {
        self.as_ec().is_some()
    }

    pub fn is_ed(&self) -> bool {
        self.as_ed().is_some()
    }
}

/// Strips leading zero for any number bigger than 0x7F.
fn h_strip_unrequired_leading_zero(value: &[u8]) -> &[u8] {
    if let [0x00, rest @ ..] = value { rest } else { value }
}

/// Big integers from 0x00 to 0x7F are all base64-encoded using two ASCII characters ranging from "AA" to "fw".
/// We know the required capacity is _exactly_ of one byte.
/// The value 0 is valid and is represented as the array [0x00] ("AA").
/// For numbers greater than 0x7F, logic is a bit more complex.
/// There is no leading zero in JWK keys because _unsigned_ numbers are used.
/// As such, there is no need to disambiguate the high-order bit (0x80)
/// which is used as the sign bit for _signed_ numbers.
/// The high-order bit is set when base64 encoding's leading character matches [g-z0-9_-].
fn h_allocate_signed_big_int_buffer(base64_url_encoding: &str) -> Vec<u8> {
    match base64_url_encoding.chars().next() {
        // The leading zero is re-introduced for any number whose high-order bit is set
        Some('g'..='z' | '0'..='9' | '_' | '-') => vec![0],
        // Otherwise, there is nothing more to do
        _ => Vec::with_capacity(1),
    }
}

// === public key use === //

/// Public Key Use, identifies the intended use of the public key.
///
/// See [RFC7517 #4](https://tools.ietf.org/html/rfc7517#section-4.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JwkPubKeyUse {
    #[serde(rename = "sig")]
    Signature,
    #[serde(rename = "enc")]
    Encryption,
}

// === key operations === //

/// Key Operations, identifies the operation(s) for which the key is intended to be used.
///
/// See [RFC7517 #4](https://tools.ietf.org/html/rfc7517#section-4.3)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JwkKeyOps {
    #[serde(rename = "sign")]
    Sign,
    #[serde(rename = "verify")]
    Verify,
    #[serde(rename = "encrypt")]
    Encrypt,
    #[serde(rename = "decrypt")]
    Decrypt,
    #[serde(rename = "wrapKey")]
    WrapKey,
    #[serde(rename = "unwrapKey")]
    UnwrapKey,
    #[serde(rename = "deriveKey")]
    DeriveKey,
    #[serde(rename = "deriveBits")]
    DeriveBits,
}

// === algorithms === //

/// JOSE algorithms names as defined by [RFC7518](https://tools.ietf.org/html/rfc7518)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Jwa {
    Sig(JwsAlg),
    Enc(JweEnc),
    CEKAlg(JweAlg),
}

// === json web key === //

/// Represents a cryptographic key as defined by [RFC7517](https://tools.ietf.org/html/rfc7517).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Jwk {
    // -- specific to JWK -- //
    #[serde(flatten)]
    pub key: JwkKeyType,

    /// Identifies the algorithm intended for use with the key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<Jwa>,

    /// Public Key Use
    ///
    /// Intended use of the public key.
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub key_use: Option<JwkPubKeyUse>,

    /// Key Operations
    ///
    /// identifies the operation(s) for which the key is intended to be used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<JwkKeyOps>>,

    // -- common with all -- //
    /// Key ID Header
    ///
    /// A hint indicating which key was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// X.509 URL Header
    ///
    /// URI that refers to a resource for an X.509 public key certificate or certificate chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,

    /// X.509 Certificate Chain
    ///
    /// Chain of one or more PKIX certificates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,

    /// X.509 Certificate SHA-1 Thumbprint
    ///
    /// base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,

    /// X.509 Certificate SHA-256 Thumbprint
    ///
    /// base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate.
    #[serde(rename = "x5t#S256", alias = "x5t#s256", skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
}

impl Jwk {
    pub fn new(key: JwkKeyType) -> Self {
        Jwk {
            key,
            alg: None,
            key_use: None,
            key_ops: None,
            kid: None,
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
        }
    }

    pub fn from_json(json: &str) -> Result<Self, JwkError> {
        Ok(serde_json::from_str(json)?)
    }

    pub fn from_public_key(public_key: &PublicKey) -> Result<Self, JwkError> {
        use picky_asn1::wrapper::BitStringAsn1Container;
        use picky_asn1_x509::PublicKey as SerdePublicKey;

        match &public_key.as_inner().subject_public_key {
            SerdePublicKey::Rsa(BitStringAsn1Container(rsa)) => {
                let modulus = rsa.modulus.as_signed_bytes_be();
                let public_exponent = rsa.public_exponent.as_signed_bytes_be();
                Ok(Self::new(JwkKeyType::new_rsa_key(modulus, public_exponent)))
            }
            SerdePublicKey::Ec(_) => {
                let ec_key = EcdsaPublicKey::try_from(public_key)
                    .map_err(|e| JwkError::InvalidEcPublicKey { cause: e.to_string() })?;

                match ec_key.curve() {
                    NamedEcCurve::Known(EcCurve::NistP256) => {
                        let point = p256::Sec1Point::from_bytes(ec_key.encoded_point()).map_err(|_| {
                            JwkError::InvalidEcPublicKey {
                                cause: "invalid P-256 EC point encoding".to_string(),
                            }
                        })?;

                        match (point.x(), point.y()) {
                            (Some(x), Some(y)) => Ok(Self::new(JwkKeyType::new_ec_key(
                                JwkEcPublicKeyCurve::P256,
                                x.as_slice(),
                                y.as_slice(),
                            ))),
                            _ => Err(JwkError::InvalidEcPublicKey {
                                cause: "Invalid P-256 curve EC public point coordinates".to_string(),
                            }),
                        }
                    }
                    NamedEcCurve::Known(EcCurve::NistP384) => {
                        let point = p384::Sec1Point::from_bytes(ec_key.encoded_point()).map_err(|_| {
                            JwkError::InvalidEcPublicKey {
                                cause: "invalid P-384 EC point encoding".to_string(),
                            }
                        })?;

                        match (point.x(), point.y()) {
                            (Some(x), Some(y)) => Ok(Self::new(JwkKeyType::new_ec_key(
                                JwkEcPublicKeyCurve::P384,
                                x.as_slice(),
                                y.as_slice(),
                            ))),
                            _ => Err(JwkError::InvalidEcPublicKey {
                                cause: "Invalid P-384 curve EC public point coordinates".to_string(),
                            }),
                        }
                    }
                    NamedEcCurve::Known(EcCurve::NistP521) => {
                        let point = p521::Sec1Point::from_bytes(ec_key.encoded_point()).map_err(|_| {
                            JwkError::InvalidEcPublicKey {
                                cause: "invalid P-521 EC point encoding".to_string(),
                            }
                        })?;

                        match (point.x(), point.y()) {
                            (Some(x), Some(y)) => Ok(Self::new(JwkKeyType::new_ec_key(
                                JwkEcPublicKeyCurve::P521,
                                x.as_slice(),
                                y.as_slice(),
                            ))),
                            _ => Err(JwkError::InvalidEcPublicKey {
                                cause: "Invalid P-521 curve EC public point coordinates".to_string(),
                            }),
                        }
                    }
                    NamedEcCurve::Unsupported(_) => Err(JwkError::UnsupportedAlgorithm {
                        algorithm: "Unsupported EC curve",
                    }),
                }
            }
            SerdePublicKey::Ed(_) => {
                let ed_key = EdPublicKey::try_from(public_key)
                    .map_err(|e| JwkError::InvalidEdPublicKey { cause: e.to_string() })?;

                let algorithm = match ed_key.algorithm() {
                    NamedEdAlgorithm::Known(EdAlgorithm::Ed25519) => JwkEdPublicKeyAlgorithm::Ed25519,
                    NamedEdAlgorithm::Known(EdAlgorithm::X25519) => JwkEdPublicKeyAlgorithm::X25519,
                    NamedEdAlgorithm::Unsupported(_) => {
                        return Err(JwkError::UnsupportedAlgorithm {
                            algorithm: "Unsupported ED algorithm",
                        });
                    }
                };

                Ok(Self::new(JwkKeyType::new_ed_key(algorithm, ed_key.data())))
            }
            SerdePublicKey::Mldsa(_) => Err(JwkError::UnsupportedAlgorithm {
                algorithm: "JWK unsupported with MLDSA keys",
            }),
        }
    }

    pub fn to_json(&self) -> Result<String, JwkError> {
        Ok(serde_json::to_string(self)?)
    }

    pub fn to_json_pretty(&self) -> Result<String, JwkError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn to_public_key(&self) -> Result<PublicKey, JwkError> {
        match &self.key {
            JwkKeyType::Rsa(rsa) => {
                let modulus = IntegerAsn1::from_bytes_be_signed(rsa.modulus_signed_bytes_be()?);
                let public_exponent = IntegerAsn1::from_bytes_be_signed(rsa.public_exponent_signed_bytes_be()?);
                let spki = SubjectPublicKeyInfo::new_rsa_key(modulus, public_exponent);
                Ok(spki.into())
            }
            JwkKeyType::Ec(ec) => {
                let curve = match ec.crv {
                    JwkEcPublicKeyCurve::P256 => EcCurve::NistP256,
                    JwkEcPublicKeyCurve::P384 => EcCurve::NistP384,
                    JwkEcPublicKeyCurve::P521 => EcCurve::NistP521,
                };

                let x = BoxedUint::from_be_slice_vartime(&ec.x_signed_bytes_be()?);
                let y = BoxedUint::from_be_slice_vartime(&ec.y_signed_bytes_be()?);

                PublicKey::from_ec_components(curve, &x, &y).map_err(|_| JwkError::InvalidEcPointCoordinates)
            }
            JwkKeyType::Ed(ed) => {
                let algorithm = match ed.crv {
                    JwkEdPublicKeyAlgorithm::Ed25519 => Ok(EdAlgorithm::Ed25519),
                    JwkEdPublicKeyAlgorithm::X25519 => Ok(EdAlgorithm::X25519),
                    JwkEdPublicKeyAlgorithm::Ed448 => Err("ed448 algorithm"),
                    JwkEdPublicKeyAlgorithm::X448 => Err("x448 algorithm"),
                }
                .map_err(|algorithm| JwkError::UnsupportedAlgorithm { algorithm })?;

                Ok(PublicKey::from_ed_encoded_components(
                    &algorithm.into(),
                    ed.public_key_bytes()?.as_ref(),
                ))
            }
            JwkKeyType::Oct => Err(JwkError::UnsupportedAlgorithm {
                algorithm: "octet sequence",
            }),
        }
    }
}

// === jwk set === //

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    pub fn from_json(json: &str) -> Result<Self, JwkError> {
        Ok(serde_json::from_str(json)?)
    }

    pub fn to_json(&self) -> Result<String, JwkError> {
        Ok(serde_json::to_string(self)?)
    }

    pub fn to_json_pretty(&self) -> Result<String, JwkError> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

// === public rsa key === //

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JwkPublicRsaKey {
    n: String,
    e: String,
}

impl JwkPublicRsaKey {
    pub fn modulus_signed_bytes_be(&self) -> Result<Vec<u8>, JwkError> {
        let mut buf = h_allocate_signed_big_int_buffer(&self.n);
        general_purpose::URL_SAFE_NO_PAD
            .decode_vec(&self.n, &mut buf)
            .map_err(JwkError::from)?;
        Ok(buf)
    }

    pub fn modulus_unsigned_bytes_be(&self) -> Result<Vec<u8>, JwkError> {
        general_purpose::URL_SAFE_NO_PAD.decode(&self.n).map_err(JwkError::from)
    }

    pub fn public_exponent_signed_bytes_be(&self) -> Result<Vec<u8>, JwkError> {
        let mut buf = h_allocate_signed_big_int_buffer(&self.e);
        general_purpose::URL_SAFE_NO_PAD
            .decode_vec(&self.e, &mut buf)
            .map_err(JwkError::from)?;
        Ok(buf)
    }

    pub fn public_exponent_unsigned_bytes_be(&self) -> Result<Vec<u8>, JwkError> {
        general_purpose::URL_SAFE_NO_PAD.decode(&self.e).map_err(JwkError::from)
    }
}

/// The key type of a JWK defined in
/// [RFC 7518, section 6.1](https://tools.ietf.org/html/rfc7518#section-6.1).
///
/// Note that P521 is not supported yet for signning and verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JwkEcPublicKeyCurve {
    #[serde(rename = "P-256")]
    P256,
    #[serde(rename = "P-384")]
    P384,
    #[serde(rename = "P-521")]
    P521,
}

// === public ec key === //
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JwkPublicEcKey {
    crv: JwkEcPublicKeyCurve,
    x: String,
    y: String,
}

impl JwkPublicEcKey {
    pub fn x_signed_bytes_be(&self) -> Result<Vec<u8>, JwkError> {
        let mut buf = h_allocate_signed_big_int_buffer(&self.x);
        general_purpose::URL_SAFE_NO_PAD
            .decode_vec(&self.x, &mut buf)
            .map_err(JwkError::from)?;
        Ok(buf)
    }

    pub fn y_signed_bytes_be(&self) -> Result<Vec<u8>, JwkError> {
        let mut buf = h_allocate_signed_big_int_buffer(&self.y);
        general_purpose::URL_SAFE_NO_PAD
            .decode_vec(&self.y, &mut buf)
            .map_err(JwkError::from)?;
        Ok(buf)
    }
}

/// Defined in [RFC 8037](https://tools.ietf.org/html/rfc8037)
///
/// Note that X25519, Ed448 and X448 are not yet supported by picky for jws/jwe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JwkEdPublicKeyAlgorithm {
    #[serde(rename = "Ed25519")]
    Ed25519,
    #[serde(rename = "Ed448")]
    Ed448,
    #[serde(rename = "X25519")]
    X25519,
    #[serde(rename = "X448")]
    X448,
}

// === public ed key === //

/// Defined in [RFC 8037](https://tools.ietf.org/html/rfc8037)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JwkPublicEdKey {
    /// NOTE: "crv" defines not exactly the curve but the algorithm.
    crv: JwkEdPublicKeyAlgorithm,
    /// In contrast to EC keys, the `x` coordinate is an octet string, not an encoded big integer.
    x: String,
}

impl JwkPublicEdKey {
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, JwkError> {
        let mut buf = Vec::new();
        general_purpose::URL_SAFE_NO_PAD
            .decode_vec(&self.x, &mut buf)
            .map_err(JwkError::from)?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jose::jws::JwsAlg;
    use crate::pem::Pem;
    use rstest::rstest;

    const RSA_MODULUS: &str = "rpJjxW0nNZiq1mPC3ZAxqf9qNjmKurP7XuKrpWrfv3IOUldqChQVPNg8zCvDOMZIO-ZDuRmVH\
                               EZ5E1vz5auHNACnpl6AvDGJ-4qyX42vfUDMNZx8i86d7bQpwJkO_MVMLj8qMGmTVbQ8zqVw2z\
                               MyKUFfa2V83nvx2wz4FJh2Thw2uZX2P7h8nlDVSuXO0wJ_OY_2qtqRIAnNXMzL5BF5pEFh4hi\
                               JIFiMTNkhVtUjT1QSB9E8DtDme8g4u769Oc0My45fgqSNE7kKKyaDhTfqSovyhj-qWiD-X_Gw\
                               pWkW4ungpHzz_97-ZDB3yQ7AMwKAsw5EW2cMqseAp3f-kf159w";

    const RSA_PUBLIC_EXPONENT: &str = "AQAB";

    const X509_SHA1_THUMBPRINT: &str = "N3ORVnr9T6opxpS9iRbkKGwKiQI";

    const X509_CERT_0: &str = "MIIDWjCCAkKgAwIBAgIUWRsBqKmpXGP/OwrwLWicwxhuCFowDQYJKoZIhvc\
                               NAQELBQAwKjEoMCYGA1UEAwwfbG9naW4uZGV2b2x1dGlvbnMuY29tIEF1dG\
                               hvcml0eTAeFw0xOTAzMTMxMzE1MzVaFw0yMDAzMTIxMzE1MzVaMCYxJDAiB\
                               gNVBAMMG2xvZ2luLmRldm9sdXRpb25zLmNvbSBUb2tlbjCCASIwDQYJKoZI\
                               hvcNAQEBBQADggEPADCCAQoCggEBAK6SY8VtJzWYqtZjwt2QMan/ajY5irq\
                               z+17iq6Vq379yDlJXagoUFTzYPMwrwzjGSDvmQ7kZlRxGeRNb8+WrhzQAp6\
                               ZegLwxifuKsl+Nr31AzDWcfIvOne20KcCZDvzFTC4/KjBpk1W0PM6lcNszM\
                               ilBX2tlfN578dsM+BSYdk4cNrmV9j+4fJ5Q1UrlztMCfzmP9qrakSAJzVzM\
                               y+QReaRBYeIYiSBYjEzZIVbVI09UEgfRPA7Q5nvIOLu+vTnNDMuOX4KkjRO\
                               5Cismg4U36kqL8oY/qlog/l/xsKVpFuLp4KR88//e/mQwd8kOwDMCgLMORF\
                               tnDKrHgKd3/pH9efcCAwEAAaN8MHowCQYDVR0TBAIwADAOBgNVHQ8BAf8EB\
                               AMCBeAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQW\
                               BBQQW2Cx8HUpXfFM3B76WzBb/BhCBDAfBgNVHSMEGDAWgBRWAUlOiE4Z3ww\
                               aHgz284/sYB9NaDANBgkqhkiG9w0BAQsFAAOCAQEAkliCiJF9Z/Y57V6Rrn\
                               gHCBBWtqR+N/A+KHQqWxP2MmJiHVBBnZAueVPsvykO+EfbazNEkUoPVKhUd\
                               5NxEmTEMOBu9HUEzlmA5xDjl5xS7fejJIr7pgbxIup4m+DsNsPVnF1Snk56\
                               F6660RhRb9fsHQ0pgvWuG+tQXJ4J1Zi0cp+xi4yze6hJGAyAqj6wU46AUiL\
                               6kUr9GUVHqEsl5mNMIW18JT4KM/s5DWxFGO2soSTkaVHwGSkMBQSTgHMWs0\
                               L3bBfimjw9FwjwwHAbe1W5QU6uVXGApuKANRsXxgCn566QkE/BuV3WVR6uy\
                               n2P1J/vU9hxasgRIcjf3jHC4lGpew==";

    const X509_CERT_1: &str = "MIIDRjCCAi6gAwIBAgIUUqhc3/U6OhKtEk1b8JfX3GL0FPYwDQYJKoZIhvc\
                               NAQELBQAwKDEmMCQGA1UEAwwdbG9naW4uZGV2b2x1dGlvbnMuY29tIFJvb3\
                               QgQ0EwHhcNMTkwMzEzMTMxNTM1WhcNMjAwMzEyMTMxNTM1WjAqMSgwJgYDV\
                               QQDDB9sb2dpbi5kZXZvbHV0aW9ucy5jb20gQXV0aG9yaXR5MIIBIjANBgkq\
                               hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlbRwXVPc/WH4t/Yti5qv24pAu8Q\
                               m0eOVvbum23bYtfJDbCSDh7sY/vvQXgIkM8/0C3tFZ3XaXHbyDHAMn6OC+S\
                               Obzs6SjpfKk9s69Yo/aWFl9oRnAK/+dZ0Y6MTdZO1w+PpR81q5QOFMLpWX1\
                               YNdahaZec31sBmsHqlW04OrHUhGOTGdWNots9/PWvN//x++FL+Sqgh/jxF7\
                               khbgfAuz1QKa8P0ZlE4cOcRIs5bSnUFwtoytKH02/YZnCJD7I/iXFuCPV/+\
                               LZO6yobkTREE3npeXvAKr1OKF2F0JVORMhHiYyguh9t3bMwHTCFqmfQkIMD\
                               GjaTJD7bd8y2Au+eDzgwIDAQABo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDV\
                               R0TAQH/BAgwBgEB/wIBAjAdBgNVHQ4EFgQUVgFJTohOGd8MGh4M9vOP7GAf\
                               TWgwHwYDVR0jBBgwFoAU42BA1coGHUUPUSeacQfTzicjosgwDQYJKoZIhvc\
                               NAQELBQADggEBAKyyDs+uIughmloEmlf8s1cSP8cLtC1Di2TfYSG0bpEM3B\
                               EPTond/7ujDlv0eug9NRurvWd5v7bWvy9VlJo+x2rLBmkzaNcBSVHZ4UbFU\
                               90MSvHjxNZ7VbUfbWsJVeaYHtqf1m3z0fYT0tUor3chD+wbSqraWw4+t54h\
                               fJl22jExTWS9X0F5/Gf3LQOiOvtjHP+b3VkpXkEPIBbvIO/X6kgoGDLm/lA\
                               IPdZmpI956z5+acLHu3AQkxNXQPzCjSSdJphLVU1XeHXOMWldVtE9BqSMVI\
                               HZ6oCz/FtMA4F6R7WiVXXGR+ywRwFyeiFoRea2ImUK9TRWFsaXKeOBMm+TL\
                               bk=";

    const X509_CERT_2: &str = "MIIDRDCCAiygAwIBAgIUCAKwhsjTttdG4koEAV7zqlnI7wkwDQYJKoZIhvc\
                               NAQELBQAwKDEmMCQGA1UEAwwdbG9naW4uZGV2b2x1dGlvbnMuY29tIFJvb3\
                               QgQ0EwHhcNMTkwMzEzMTMxNTM1WhcNMjQwMzExMTMxNTM1WjAoMSYwJAYDV\
                               QQDDB1sb2dpbi5kZXZvbHV0aW9ucy5jb20gUm9vdCBDQTCCASIwDQYJKoZI\
                               hvcNAQEBBQADggEPADCCAQoCggEBANRZxxg9eTCMVr4DsIUcytQOLnlZ7tl\
                               uliP+jM76mjJEuWqizHzZ1ZoPcEbdW9sV8kgWdPHL3KOlXAr0DEobnhQsNx\
                               uzJ8B73TcV7AKp2HR+xCTKPEha1gVHgQMmzQyCIgLEsdcjhsFeFYqMflELZ\
                               rMy+7DBSZWWf3wCnxiKbzTL01wKqylVWeSiXsniTpsoUSSk8Fe2/Li8dBMY\
                               he1vTb57GI8ta24P4lfJv6CPTNTVsr+6ue3lRuY/UIMNTybhBSc00qbuo0K\
                               ahWHyzDgY+iNEaALbyWeNOoTBQIO8lp4mhHcO/Znh2PxdqCi/FSCB2+A1Xd\
                               uOArn+MKegU5aVJN0CAwEAAaNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBAjAOB\
                               gNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFONgQNXKBh1FD1EnmnEH084nI6LI\
                               MB8GA1UdIwQYMBaAFONgQNXKBh1FD1EnmnEH084nI6LIMA0GCSqGSIb3DQE\
                               BCwUAA4IBAQB+v34Vk/+qQgA7eWlczWNVWM0J67om+QwtMEo+VgzE2OHNID\
                               2o5QXsxcck0j8dANutkoqsUXpos/RG+QPNng5RBWA/sWUYWdfwZgrE30rBK\
                               waP8Yi8gVsZpz3/RClbPcfkUXI12ANw3bRI1TscOK165p1TV6nmeEus5LZq\
                               CJV37/WRt47CccsDNZaqSN7T5lQ045jsZVYpfgx/I1l9Q/fICrTOFwqYbXJ\
                               9DTe1v8C+LFbtTNcEzRGwZefLTNH2yuZjGy1/t4+cnmFJUzmC4abOoZcpkr\
                               z6U68caCbQA+wdmFs4XaO2bFaiyM+m0LVMOQfLuX/0RZc2KB7fAbb7oHQl";

    fn get_jwk_set() -> JwkSet {
        JwkSet {
            keys: vec![Jwk {
                alg: Some(Jwa::Sig(JwsAlg::RS256)),
                key_ops: Some(vec![JwkKeyOps::Verify]),
                kid: Some("bG9naW4uZGV2b2x1dGlvbnMuY29tIFRva2VuLk1hciAxMyAxMzoxNTozNSAyMDE5IEdNVA".to_owned()),
                x5t: Some(X509_SHA1_THUMBPRINT.to_owned()),
                x5c: Some(vec![
                    X509_CERT_0.to_owned(),
                    X509_CERT_1.to_owned(),
                    X509_CERT_2.to_owned(),
                ]),
                ..Jwk::new(JwkKeyType::new_rsa_key_from_base64_url(
                    RSA_MODULUS.into(),
                    RSA_PUBLIC_EXPONENT.into(),
                ))
            }],
        }
    }

    #[test]
    fn rsa_key() {
        let expected = get_jwk_set();
        let decoded = JwkSet::from_json(picky_test_data::JOSE_JWK_SET).unwrap();
        pretty_assertions::assert_eq!(decoded, expected);

        let encoded = expected.to_json_pretty().unwrap();
        let decoded = JwkSet::from_json(&encoded).unwrap();
        pretty_assertions::assert_eq!(decoded, expected);
    }

    #[rstest]
    #[case(picky_test_data::JOSE_JWK_EC_P256_JSON)]
    #[case(picky_test_data::JOSE_JWK_EC_P384_JSON)]
    #[case(picky_test_data::JOSE_JWK_EC_P521_JSON)]
    fn ecdsa_key_roundtrip(#[case] json: &str) {
        let decoded = Jwk::from_json(json).unwrap();
        let encoded = decoded.to_json().unwrap();
        pretty_assertions::assert_eq!(encoded, json);
    }

    #[rstest]
    #[case(picky_test_data::JOSE_JWK_ED25519_JSON)]
    #[case(picky_test_data::JOSE_JWK_X25519_JSON)]
    fn ed_key_roundtrip(#[case] json: &str) {
        let decoded = Jwk::from_json(json).unwrap();
        let encoded = decoded.to_json().unwrap();
        pretty_assertions::assert_eq!(encoded, json);
    }

    const PUBLIC_KEY_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA61BjmfXGEvWmegnBGSuS
+rU9soUg2FnODva32D1AqhwdziwHINFaD1MVlcrYG6XRKfkcxnaXGfFDWHLEvNBS
EVCgJjtHAGZIm5GL/KA86KDp/CwDFMSwluowcXwDwoyinmeOY9eKyh6aY72xJh7n
oLBBq1N0bWi1e2i+83txOCg4yV2oVXhBo8pYEJ8LT3el6Smxol3C1oFMVdwPgc0v
Tl25XucMcG/ALE/KNY6pqC2AQ6R2ERlVgPiUWOPatVkt7+Bs3h5Ramxh7XjBOXeu
lmCpGSynXNcpZ/06+vofGi/2MlpQZNhHAo8eayMp6FcvNucIpUndo1X8dKMv3Y26
ZQIDAQAB
-----END PUBLIC KEY-----"#;

    #[test]
    fn x509_and_jwk_conversion_rsa() {
        let initial_key = PublicKey::from_pem(&PUBLIC_KEY_PEM.parse::<Pem>().expect("pem")).expect("public key");
        let jwk = Jwk::from_public_key(&initial_key).unwrap();
        if let JwkKeyType::Rsa(rsa_key) = &jwk.key {
            let modulus = general_purpose::URL_SAFE_NO_PAD.decode(&rsa_key.n).unwrap();
            assert_ne!(modulus[0], 0x00);
            let public_exponent = general_purpose::URL_SAFE_NO_PAD.decode(&rsa_key.e).unwrap();
            assert_ne!(public_exponent[0], 0x00);
        } else {
            panic!("Unexpected key type");
        }
        let from_jwk_key = jwk.to_public_key().unwrap();
        assert_eq!(from_jwk_key, initial_key);
    }

    #[rstest]
    #[case(picky_test_data::EC_NIST256_PK_1_PUB)]
    #[case(picky_test_data::EC_NIST384_PK_1_PUB)]
    fn x509_and_jwk_conversion_ec(#[case] pem: &str) {
        let initial_key = PublicKey::from_pem(&pem.parse::<Pem>().expect("pem")).expect("public key");
        let jwk = Jwk::from_public_key(&initial_key).unwrap();
        if let JwkKeyType::Ec(rsa_key) = &jwk.key {
            let x = general_purpose::URL_SAFE_NO_PAD.decode(&rsa_key.x).unwrap();
            assert_ne!(x[0], 0x00);
            let y = general_purpose::URL_SAFE_NO_PAD.decode(&rsa_key.y).unwrap();
            assert_ne!(y[0], 0x00);
        } else {
            panic!("Unexpected key type");
        }
        let from_jwk_key = jwk.to_public_key().unwrap();
        assert_eq!(from_jwk_key, initial_key);
    }
}
