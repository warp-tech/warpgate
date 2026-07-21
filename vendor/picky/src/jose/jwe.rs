//! JSON Web Encryption (JWE) represents encrypted content using JSON-based data structures.
//!
//! See [RFC7516](https://tools.ietf.org/html/rfc7516).

use crate::jose::jwk::{Jwk, JwkError};
use crate::key::ec::{EcComponent, EcdsaKeypair, EcdsaPublicKey, NamedEcCurve};
use crate::key::ed::{EdKeypair, EdPublicKey, NamedEdAlgorithm, X25519_FIELD_ELEMENT_SIZE};
use crate::key::{EcCurve, EdAlgorithm, KeyError, PrivateKey, PrivateKeyKind, PublicKey};

use aes::cipher::Array;
use aes::cipher::typenum::Unsigned;
use aes_gcm::{AeadInOut, Aes128Gcm, Aes256Gcm, KeyInit, KeySizeUser};
use aes_kw::AesKw;
use base64::engine::general_purpose;
use base64::{DecodeError, Engine as _};
use crypto_common::Generate as _;
use rand::rngs::{StdRng, SysRng};
use rand_core::{Rng as _, SeedableRng as _};
use rsa::{Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use thiserror::Error;
use zeroize::Zeroizing;

type Aes192Gcm = aes_gcm::AesGcm<aes_gcm::aes::Aes192, aes_gcm::aes::cipher::consts::U12>;

// === error type === //

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum JweError {
    /// JWK conversion error
    #[error("JWK conversion error")]
    Jwk {
        #[from]
        source: JwkError,
    },

    /// RSA error
    #[error("RSA error: {context}")]
    Rsa { context: String },

    /// AES-GCM error (opaque)
    #[error("AES-GCM error (opaque)")]
    AesGcm,

    /// AES-KW error
    #[error("AES-KW error")]
    AesKw { source: aes_kw::Error },

    /// Json error
    #[error("JSON error: {source}")]
    Json { source: serde_json::Error },

    /// Key error
    #[error("Key error: {source}")]
    Key { source: crate::key::KeyError },

    /// Invalid token encoding
    #[error("input isn't a valid token string: {input}")]
    InvalidEncoding { input: String },

    /// Couldn't decode base64
    #[error("couldn't decode base64: {source}")]
    Base64Decoding { source: DecodeError },

    /// Input isn't valid utf8
    #[error("input isn't valid utf8: {source}, input: {input:?}")]
    InvalidUtf8 {
        source: std::string::FromUtf8Error,
        input: Vec<u8>,
    },

    /// Unsupported algorithm
    #[error("unsupported algorithm: {algorithm}")]
    UnsupportedAlgorithm { algorithm: String },

    /// Invalid size
    #[error("invalid size for {ty}: expected {expected}, got {got}")]
    InvalidSize {
        ty: &'static str,
        expected: usize,
        got: usize,
    },

    #[error("private and public key algorithms don't match: {context}")]
    KeyAlgorithmsMismatch { context: String },

    #[error("missing `epk` header parameter required for ECDH-ES algorithm")]
    MissingEpk,

    #[error("invalid encrypted key size: expected {expected}, got {got}")]
    InvalidEncryptedKeySize { expected: usize, got: usize },

    #[error("invalid decryption key size: expected {expected}, got {got}")]
    InvalidDecryptionKeySize { expected: usize, got: usize },

    #[error(transparent)]
    RandError(#[from] rand::rngs::SysError),
}

impl From<rsa::errors::Error> for JweError {
    fn from(e: rsa::errors::Error) -> Self {
        Self::Rsa { context: e.to_string() }
    }
}

impl From<aes_gcm::Error> for JweError {
    fn from(_: aes_gcm::Error) -> Self {
        Self::AesGcm
    }
}

impl From<serde_json::Error> for JweError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json { source: e }
    }
}

impl From<crate::key::KeyError> for JweError {
    fn from(e: crate::key::KeyError) -> Self {
        Self::Key { source: e }
    }
}

impl From<DecodeError> for JweError {
    fn from(e: DecodeError) -> Self {
        Self::Base64Decoding { source: e }
    }
}

impl From<aes_kw::Error> for JweError {
    fn from(e: aes_kw::Error) -> Self {
        Self::AesKw { source: e }
    }
}

type KekAes128 = AesKw<aes::Aes128>;
type KekAes192 = AesKw<aes::Aes192>;
type KekAes256 = AesKw<aes::Aes256>;

// === JWE algorithms === //

/// `alg` header parameter values for JWE used to determine the Content Encryption Key (CEK)
///
/// [JSON Web Algorithms (JWA) draft-ietf-jose-json-web-algorithms-40 #4](https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#section-4.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JweAlg {
    /// RSAES-PKCS1-V1_5
    ///
    /// Recommended- by RFC
    #[serde(rename = "RSA1_5")]
    RsaPkcs1v15,

    /// RSAES OAEP using default parameters
    ///
    /// Recommended+ by RFC
    #[serde(rename = "RSA-OAEP")]
    RsaOaep,

    /// RSAES OAEP using SHA-256 and MGF1 with SHA-256
    #[serde(rename = "RSA-OAEP-256")]
    RsaOaep256,

    /// AES Key Wrap with default initial value using 128 bit key (unsupported)
    ///
    /// Recommended by RFC
    #[serde(rename = "A128KW")]
    AesKeyWrap128,

    /// AES Key Wrap with default initial value using 192 bit key (unsupported)
    #[serde(rename = "A192KW")]
    AesKeyWrap192,

    /// AES Key Wrap with default initial value using 256 bit key (unsupported)
    ///
    /// Recommended by RFC
    #[serde(rename = "A256KW")]
    AesKeyWrap256,

    /// Direct use of a shared symmetric key as the CEK
    #[serde(rename = "dir")]
    Direct,

    /// Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF (unsupported)
    ///
    /// Recommended+ by RFC
    #[serde(rename = "ECDH-ES")]
    EcdhEs,

    /// ECDH-ES using Concat KDF and CEK wrapped with "A128KW" (unsupported)
    ///
    /// Recommended by RFC
    ///
    /// Additional header used: "epk", "apu", "apv"
    #[serde(rename = "ECDH-ES+A128KW")]
    EcdhEsAesKeyWrap128,

    /// ECDH-ES using Concat KDF and CEK wrapped with "A192KW" (unsupported)
    ///
    /// Additional header used: "epk", "apu", "apv"
    #[serde(rename = "ECDH-ES+A192KW")]
    EcdhEsAesKeyWrap192,

    /// ECDH-ES using Concat KDF and CEK wrapped with "A256KW" (unsupported)
    ///
    /// Recommended by RFC
    ///
    /// Additional header used: "epk", "apu", "apv"
    #[serde(rename = "ECDH-ES+A256KW")]
    EcdhEsAesKeyWrap256,
}

#[derive(Debug, Clone, Copy)]
enum KeyWrappingAlg {
    Aes128,
    Aes192,
    Aes256,
}

impl KeyWrappingAlg {
    fn key_size(self) -> usize {
        match self {
            KeyWrappingAlg::Aes128 => 16,
            KeyWrappingAlg::Aes192 => 24,
            KeyWrappingAlg::Aes256 => 32,
        }
    }

    /// Decrypts wrapped CEK using the given AES decryption key
    ///
    /// ### Panics:
    ///
    ///   - Caller must unsure `decryption_key` size matches the wrapping algorithm
    fn decrypt_key(
        &self,
        cek_alg: JweEnc,
        encrypted_cek: &[u8],
        decryption_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, JweError> {
        let mut cek = Zeroizing::new(vec![0u8; cek_alg.key_size()]);

        let expected_wrapped_cek_size = cek.len() + aes_kw::IV_LEN;
        if encrypted_cek.len() != expected_wrapped_cek_size {
            return Err(JweError::InvalidEncryptedKeySize {
                expected: expected_wrapped_cek_size,
                got: encrypted_cek.len(),
            });
        }

        match self {
            KeyWrappingAlg::Aes128 => {
                let kek =
                    KekAes128::new_from_slice(decryption_key).map_err(|_| JweError::InvalidDecryptionKeySize {
                        expected: self.key_size(),
                        got: decryption_key.len(),
                    })?;
                kek.unwrap_key(encrypted_cek, &mut cek)?;
            }
            KeyWrappingAlg::Aes192 => {
                let kek =
                    KekAes192::new_from_slice(decryption_key).map_err(|_| JweError::InvalidDecryptionKeySize {
                        expected: self.key_size(),
                        got: decryption_key.len(),
                    })?;
                kek.unwrap_key(encrypted_cek, &mut cek)?;
            }
            KeyWrappingAlg::Aes256 => {
                let kek =
                    KekAes256::new_from_slice(decryption_key).map_err(|_| JweError::InvalidDecryptionKeySize {
                        expected: self.key_size(),
                        got: decryption_key.len(),
                    })?;
                kek.unwrap_key(encrypted_cek, &mut cek)?;
            }
        };

        Ok(cek)
    }

    /// Encrypts the given CEK using the given AES encryption key
    ///
    /// ### Panics:
    ///
    ///   - Caller must ensure `encryption_key` size matches the wrapping algorithm
    fn encrypt_key(&self, cek_alg: JweEnc, cek: &[u8], encryption_key: &[u8]) -> Result<Vec<u8>, JweError> {
        let mut wrapped_key = vec![0u8; cek_alg.key_size() + aes_kw::IV_LEN];
        match self {
            KeyWrappingAlg::Aes128 => {
                let kek = KekAes128::new_from_slice(encryption_key).map_err(|_| JweError::InvalidEncryptedKeySize {
                    expected: self.key_size(),
                    got: encryption_key.len(),
                })?;
                kek.wrap_key(cek, &mut wrapped_key)?;
            }
            KeyWrappingAlg::Aes192 => {
                let kek = KekAes192::new_from_slice(encryption_key).map_err(|_| JweError::InvalidEncryptedKeySize {
                    expected: self.key_size(),
                    got: encryption_key.len(),
                })?;
                kek.wrap_key(cek, &mut wrapped_key)?;
            }
            KeyWrappingAlg::Aes256 => {
                let kek = KekAes256::new_from_slice(encryption_key).map_err(|_| JweError::InvalidEncryptedKeySize {
                    expected: self.key_size(),
                    got: encryption_key.len(),
                })?;
                kek.wrap_key(cek, &mut wrapped_key)?;
            }
        };

        Ok(wrapped_key)
    }
}

impl JweAlg {
    /// Get algorithm string representation
    fn name(&self) -> String {
        serde_json::to_value(self)
            .expect("BUG: JweAlg is always convertible to serde_json::Value")
            .as_str()
            .expect("BUG: JweAlg is always represented as a string in JSON")
            .to_string()
    }

    fn key_wrapping_alg(&self) -> Option<KeyWrappingAlg> {
        let alg = match self {
            JweAlg::AesKeyWrap128 => KeyWrappingAlg::Aes128,
            JweAlg::AesKeyWrap192 => KeyWrappingAlg::Aes192,
            JweAlg::AesKeyWrap256 => KeyWrappingAlg::Aes256,
            JweAlg::EcdhEsAesKeyWrap128 => KeyWrappingAlg::Aes128,
            JweAlg::EcdhEsAesKeyWrap192 => KeyWrappingAlg::Aes192,
            JweAlg::EcdhEsAesKeyWrap256 => KeyWrappingAlg::Aes256,
            _ => {
                return None;
            }
        };

        Some(alg)
    }
}

// === JWE header === //

/// `enc` header parameter values for JWE to encrypt content
///
/// [JSON Web Algorithms (JWA) draft-ietf-jose-json-web-algorithms-40 #5](https://www.rfc-editor.org/rfc/rfc7518.html#section-5.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JweEnc {
    /// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm. (unsupported)
    ///
    /// Required by RFC
    #[serde(rename = "A128CBC-HS256")]
    Aes128CbcHmacSha256,

    /// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm. (unsupported)
    #[serde(rename = "A192CBC-HS384")]
    Aes192CbcHmacSha384,

    /// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm. (unsupported)
    ///
    /// Required by RFC
    #[serde(rename = "A256CBC-HS512")]
    Aes256CbcHmacSha512,

    /// AES GCM using 128-bit key.
    ///
    /// Recommended by RFC
    #[serde(rename = "A128GCM")]
    Aes128Gcm,

    /// AES GCM using 192-bit key.
    #[serde(rename = "A192GCM")]
    Aes192Gcm,

    /// AES GCM using 256-bit key.
    ///
    /// Recommended by RFC
    #[serde(rename = "A256GCM")]
    Aes256Gcm,
}

impl JweEnc {
    /// Get algorithm string representation
    fn name(&self) -> String {
        serde_json::to_value(self)
            .expect("BUG: JweEnc is always convertible to serde_json::Value")
            .as_str()
            .expect("BUG: JweEnc is always represented as a string in JSON")
            .to_string()
    }

    pub fn key_size(self) -> usize {
        match self {
            Self::Aes128CbcHmacSha256 | Self::Aes128Gcm => <Aes128Gcm as KeySizeUser>::KeySize::to_usize(),
            Self::Aes192CbcHmacSha384 | Self::Aes192Gcm => <Aes192Gcm as KeySizeUser>::KeySize::to_usize(),
            Self::Aes256CbcHmacSha512 | Self::Aes256Gcm => <Aes256Gcm as KeySizeUser>::KeySize::to_usize(),
        }
    }

    pub fn nonce_size(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes192Gcm | Self::Aes256Gcm => 12usize,
            Self::Aes128CbcHmacSha256 | Self::Aes192CbcHmacSha384 | Self::Aes256CbcHmacSha512 => 16usize,
        }
    }

    pub fn tag_size(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes192Gcm | Self::Aes256Gcm => 16usize,
            Self::Aes128CbcHmacSha256 => 32usize,
            Self::Aes192CbcHmacSha384 => 48usize,
            Self::Aes256CbcHmacSha512 => 64usize,
        }
    }
}

// === JWE header === //

/// JWE specific part of JOSE header
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JweHeader {
    // -- specific to JWE -- //
    /// Algorithm used to encrypt or determine the Content Encryption Key (CEK) (key wrapping...)
    pub alg: JweAlg,

    /// Content encryption algorithm to use
    ///
    /// This must be a *symmetric* Authenticated Encryption with Associated Data (AEAD) algorithm.
    pub enc: JweEnc,

    // -- common with JWS -- //
    /// JWK Set URL
    ///
    /// URI that refers to a resource for a set of JSON-encoded public keys,
    /// one of which corresponds to the key used to digitally sign the JWK.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jku: Option<String>,

    /// JSON Web Key
    ///
    /// The public key that corresponds to the key used to digitally sign the JWS.
    /// This key is represented as a JSON Web Key (JWK).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Jwk>,

    /// Type header
    ///
    /// Used by JWE applications to declare the media type [IANA.MediaTypes] of this complete JWE.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,

    /// Content Type header
    ///
    /// Used by JWE applications to declare the media type [IANA.MediaTypes] of the secured content (the payload).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cty: Option<String>,

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

    /// Ephemeral Public Key for `ECDH-ES` encryption algorithm. It is generated by the sender
    /// during JWT generation and set automatically.
    pub epk: Option<Jwk>,

    /// Agreement PartyUInfo value for key agreement algorithms
    /// using it (such as "ECDH-ES"), represented as a base64url-encoded
    /// string. When used, the PartyUInfo value contains information about
    /// the producer.  Use of this Header Parameter is OPTIONAL.
    pub apu: Option<String>,

    /// Agreement PartyVInfo value for key agreement algorithms
    /// using it (such as "ECDH-ES"), represented as a base64url encoded
    /// string.  When used, the PartyVInfo value contains information about
    /// the recipient.  Use of this Header Parameter is OPTIONAL.
    pub apv: Option<String>,

    // -- extra parameters -- //
    /// Additional header parameters (both public and private)
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

impl JweHeader {
    pub fn new(alg: JweAlg, enc: JweEnc) -> Self {
        Self {
            alg,
            enc,
            jku: None,
            jwk: None,
            typ: None,
            cty: None,
            kid: None,
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
            apu: None,
            apv: None,
            epk: None,
            additional: HashMap::default(),
        }
    }

    pub fn new_with_cty(alg: JweAlg, enc: JweEnc, cty: impl Into<String>) -> Self {
        Self {
            cty: Some(cty.into()),
            ..Self::new(alg, enc)
        }
    }
}

// === json web encryption === //

/// Provides an API to encrypt any kind of data (binary). JSON claims are part of `Jwt` only.
#[derive(Debug, Clone)]
pub struct Jwe {
    pub header: JweHeader,
    pub payload: Vec<u8>,
}

impl Jwe {
    pub fn new(alg: JweAlg, enc: JweEnc, payload: Vec<u8>) -> Self {
        Self {
            header: JweHeader::new(alg, enc),
            payload,
        }
    }

    /// Encodes with CEK encrypted and included in the token using asymmetric cryptography.
    pub fn encode(self, asymmetric_key: &PublicKey) -> Result<String, JweError> {
        encode_impl(self, EncoderMode::Asymmetric(asymmetric_key))
    }

    /// Encodes with provided CEK (a symmetric key). This will ignore `alg` value and override it with "dir".
    pub fn encode_direct(self, cek: &[u8]) -> Result<String, JweError> {
        encode_impl(self, EncoderMode::Direct(cek))
    }

    /// Decodes with CEK encrypted and included in the token using asymmetric cryptography.
    pub fn decode(compact_repr: &str, key: &PrivateKey) -> Result<Jwe, JweError> {
        RawJwe::decode(compact_repr).and_then(|jwe| jwe.decrypt(key))
    }

    /// Decodes with provided CEK (a symmetric key).
    pub fn decode_direct(compact_repr: &str, cek: &[u8]) -> Result<Jwe, JweError> {
        RawJwe::decode(compact_repr).and_then(|jwe| jwe.decrypt_direct(cek))
    }
}

/// Raw low-level interface to the yet to be decoded JWE token.
///
/// This is useful to inspect the structure before performing further processing.
/// For most usecases, use `Jwe` directly.
#[derive(Debug, Clone)]
pub struct RawJwe<'repr> {
    pub compact_repr: Cow<'repr, str>,
    pub header: JweHeader,
    pub encrypted_key: Vec<u8>,
    pub initialization_vector: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub authentication_tag: Vec<u8>,
}

/// An owned `RawJws` for convenience.
pub type OwnedRawJwe = RawJwe<'static>;

impl<'repr> RawJwe<'repr> {
    /// Decodes a JWE in compact representation.
    pub fn decode(compact_repr: impl Into<Cow<'repr, str>>) -> Result<Self, JweError> {
        decode_impl(compact_repr.into())
    }

    /// Decrypts the ciphertext using asymmetric cryptography and returns a verified `Jwe` structure.
    pub fn decrypt(self, key: &PrivateKey) -> Result<Jwe, JweError> {
        decrypt_impl(self, DecoderMode::Normal(key))
    }

    /// Decrypts the ciphertext using the provided CEK (a symmetric key).
    pub fn decrypt_direct(self, cek: &[u8]) -> Result<Jwe, JweError> {
        decrypt_impl(self, DecoderMode::Direct(cek))
    }
}

fn decode_impl(compact_repr: Cow<'_, str>) -> Result<RawJwe<'_>, JweError> {
    fn parse_compact_repr(compact_repr: &str) -> Option<(&str, &str, &str, &str, &str)> {
        let mut split = compact_repr.splitn(5, '.');

        let protected_header = split.next()?;
        let encrypted_key = split.next()?;
        let initialization_vector = split.next()?;
        let ciphertext = split.next()?;
        let authentication_tag = split.next()?;

        Some((
            protected_header,
            encrypted_key,
            initialization_vector,
            ciphertext,
            authentication_tag,
        ))
    }

    let (protected_header, encrypted_key, initialization_vector, ciphertext, authentication_tag) =
        parse_compact_repr(&compact_repr).ok_or_else(|| JweError::InvalidEncoding {
            input: compact_repr.clone().into_owned(),
        })?;

    let protected_header = general_purpose::URL_SAFE_NO_PAD.decode(protected_header)?;
    let header = serde_json::from_slice::<JweHeader>(&protected_header)?;

    Ok(RawJwe {
        header,
        encrypted_key: general_purpose::URL_SAFE_NO_PAD.decode(encrypted_key)?,
        initialization_vector: general_purpose::URL_SAFE_NO_PAD.decode(initialization_vector)?,
        ciphertext: general_purpose::URL_SAFE_NO_PAD.decode(ciphertext)?,
        authentication_tag: general_purpose::URL_SAFE_NO_PAD.decode(authentication_tag)?,
        compact_repr,
    })
}

// encoder

#[derive(Debug, Clone)]
enum EncoderMode<'a> {
    Asymmetric(&'a PublicKey),
    Direct(&'a [u8]),
}

fn encode_impl(mut jwe: Jwe, mode: EncoderMode) -> Result<String, JweError> {
    use picky_asn1_x509::PublicKey as RfcPublicKey;

    let (encrypted_key_base64, jwe_cek) = match mode {
        EncoderMode::Direct(symmetric_key) => {
            if symmetric_key.len() != jwe.header.enc.key_size() {
                return Err(JweError::InvalidSize {
                    ty: "symmetric key",
                    expected: jwe.header.enc.key_size(),
                    got: symmetric_key.len(),
                });
            }

            // Override `alg` header with "dir"
            jwe.header.alg = JweAlg::Direct;

            (String::new(), Zeroizing::new(symmetric_key.to_vec()))
        }
        EncoderMode::Asymmetric(public_key) => match &public_key.as_inner().subject_public_key {
            RfcPublicKey::Rsa(_) => {
                let rsa_public_key = RsaPublicKey::try_from(public_key)?;

                let padding = match jwe.header.alg {
                    JweAlg::RsaPkcs1v15 => RsaPaddingScheme::Pkcs1v15Encrypt,
                    JweAlg::RsaOaep => RsaPaddingScheme::Oaep(Oaep::<sha1::Sha1>::new()),
                    JweAlg::RsaOaep256 => RsaPaddingScheme::Oaep256(Oaep::<sha2::Sha256>::new()),
                    unsupported => {
                        return Err(JweError::UnsupportedAlgorithm {
                            algorithm: format!("{unsupported:?}"),
                        });
                    }
                };

                let cek = generate_cek(jwe.header.enc)?;

                let encrypted_key = match rsa_public_key.encrypt(&mut StdRng::try_from_rng(&mut SysRng)?, padding, &cek)
                {
                    Ok(encrypted_key) => encrypted_key,
                    Err(err) => {
                        return Err(err.into());
                    }
                };

                (general_purpose::URL_SAFE_NO_PAD.encode(encrypted_key), cek)
            }
            RfcPublicKey::Ec(_) | RfcPublicKey::Ed(_) => {
                let JweEcdhEncryptionContext {
                    jwe_cek,
                    encrypted_key,
                    epk,
                } = prepare_ecdh_encryption_key(&jwe, public_key)?;

                jwe.header.epk = Some(Jwk::from_public_key(&epk)?);
                let encrypted_key_base64 = if encrypted_key.is_empty() {
                    String::new()
                } else {
                    general_purpose::URL_SAFE_NO_PAD.encode(encrypted_key)
                };

                (encrypted_key_base64, jwe_cek)
            }
            RfcPublicKey::Mldsa(_) => {
                return Err(JweError::UnsupportedAlgorithm {
                    algorithm: "mldsa".to_string(),
                });
            }
        },
    };

    // Note that header could be modified by code above:
    // - `alg` header could be overridden with "dir"
    // - `epk` header could be set for ECDH-ES
    let protected_header_base64 = general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&jwe.header)?);

    let mut buffer = jwe.payload;
    let nonce = <aes_gcm::aead::Nonce<Aes128Gcm> as From<[u8; 12]>>::from(rand::random()); // 96-bits nonce for all AES-GCM variants
    let aad = protected_header_base64.as_bytes(); // The Additional Authenticated Data value used for AES-GCM.
    let authentication_tag = match jwe.header.enc {
        JweEnc::Aes128Gcm => {
            let algo = Aes128Gcm::new_from_slice(&jwe_cek).map_err(|_| JweError::AesGcm)?;
            algo.encrypt_inout_detached(&nonce, aad, buffer.as_mut_slice().into())?
        }
        JweEnc::Aes192Gcm => {
            let algo = Aes192Gcm::new_from_slice(&jwe_cek).map_err(|_| JweError::AesGcm)?;
            algo.encrypt_inout_detached(&nonce, aad, buffer.as_mut_slice().into())?
        }
        JweEnc::Aes256Gcm => {
            let algo = Aes256Gcm::new_from_slice(&jwe_cek).map_err(|_| JweError::AesGcm)?;
            algo.encrypt_inout_detached(&nonce, aad, buffer.as_mut_slice().into())?
        }
        unsupported => {
            return Err(JweError::UnsupportedAlgorithm {
                algorithm: format!("{unsupported:?}"),
            });
        }
    };

    let initialization_vector_base64 = general_purpose::URL_SAFE_NO_PAD.encode(nonce.as_slice());
    let ciphertext_base64 = general_purpose::URL_SAFE_NO_PAD.encode(&buffer);
    let authentication_tag_base64 = general_purpose::URL_SAFE_NO_PAD.encode(authentication_tag);

    Ok([
        protected_header_base64,
        encrypted_key_base64,
        initialization_vector_base64,
        ciphertext_base64,
        authentication_tag_base64,
    ]
    .join("."))
}

struct JweEcdhEncryptionContext {
    jwe_cek: Zeroizing<Vec<u8>>,
    encrypted_key: Vec<u8>,
    epk: PublicKey,
}

fn prepare_ecdh_encryption_key(jwe: &Jwe, public_key: &PublicKey) -> Result<JweEcdhEncryptionContext, JweError> {
    let header = &jwe.header;

    let (encrypted_key, jwe_cek, epk) = match header.alg {
        JweAlg::EcdhEs => {
            // In case of ECDH Direct mode, we use JweEnc algorithm name for KDF
            let alg_name = header.enc.name();
            // Use DH shared secret as CEK
            let (cek, epk) = generate_ecdh_shared_secret(
                header.apu.as_deref(),
                header.apv.as_deref(),
                &alg_name,
                public_key,
                header.enc.key_size(),
            )?;
            // Encrypted key should be empty octet sequence in direct mode
            (vec![], cek, epk)
        }
        JweAlg::EcdhEsAesKeyWrap128 | JweAlg::EcdhEsAesKeyWrap192 | JweAlg::EcdhEsAesKeyWrap256 => {
            let alg_name = header.alg.name();

            let wrapping_alg = header
                .alg
                .key_wrapping_alg()
                .expect("BUG: ECDH-ES+AxKW algorithm should have a wrapping algorithm");

            // Generate share key with size equal to wrapping algorithm key size
            let (shared_secret, epk) = generate_ecdh_shared_secret(
                header.apu.as_deref(),
                header.apv.as_deref(),
                &alg_name,
                public_key,
                wrapping_alg.key_size(),
            )?;

            let cek = generate_cek(header.enc)?;
            let wrapped_key = wrapping_alg.encrypt_key(header.enc, &cek, &shared_secret)?;

            (wrapped_key, cek, epk)
        }
        _ => {
            return Err(JweError::UnsupportedAlgorithm {
                algorithm: format!("Algorithm `{}` is not supported for EC & ED keys", header.alg.name()),
            });
        }
    };

    Ok(JweEcdhEncryptionContext {
        jwe_cek,
        encrypted_key,
        epk,
    })
}

// decoder

#[derive(Clone)]
enum DecoderMode<'a> {
    Normal(&'a PrivateKey),
    Direct(&'a [u8]),
}

fn decrypt_impl(raw: RawJwe<'_>, mode: DecoderMode<'_>) -> Result<Jwe, JweError> {
    let RawJwe {
        compact_repr,
        header,
        encrypted_key,
        initialization_vector,
        ciphertext,
        authentication_tag,
    } = raw;

    let protected_header_base64 = compact_repr
        .split('.')
        .next()
        .ok_or_else(|| JweError::InvalidEncoding {
            input: compact_repr.clone().into_owned(),
        })?;

    let jwe_cek = match mode {
        DecoderMode::Direct(symmetric_key) => Zeroizing::new(symmetric_key.to_vec()),
        DecoderMode::Normal(private_key) => match &private_key.as_kind() {
            PrivateKeyKind::Rsa => {
                let rsa_private_key = RsaPrivateKey::try_from(private_key)?;

                let padding = match header.alg {
                    JweAlg::RsaPkcs1v15 => RsaPaddingScheme::Pkcs1v15Encrypt,
                    JweAlg::RsaOaep => RsaPaddingScheme::Oaep(Oaep::<sha1::Sha1>::new()),
                    JweAlg::RsaOaep256 => RsaPaddingScheme::Oaep256(Oaep::<sha2::Sha256>::new()),
                    unsupported => {
                        return Err(JweError::UnsupportedAlgorithm {
                            algorithm: format!("{unsupported:?}"),
                        });
                    }
                };

                Zeroizing::new(rsa_private_key.decrypt(padding, &encrypted_key)?)
            }
            PrivateKeyKind::Ec { .. } | PrivateKeyKind::Ed { .. } => {
                let sender_public_key = header
                    .epk
                    .as_ref()
                    .ok_or_else(|| JweError::MissingEpk)?
                    .to_public_key()?;

                prepare_ecdh_decryption_key(&header, &encrypted_key, &sender_public_key, private_key)?
            }
        },
    };

    if jwe_cek.len() != header.enc.key_size() {
        return Err(JweError::InvalidSize {
            ty: "symmetric key",
            expected: header.enc.key_size(),
            got: jwe_cek.len(),
        });
    }

    if initialization_vector.len() != header.enc.nonce_size() {
        return Err(JweError::InvalidSize {
            ty: "initialization vector (nonce)",
            expected: header.enc.nonce_size(),
            got: initialization_vector.len(),
        });
    }

    if authentication_tag.len() != header.enc.tag_size() {
        return Err(JweError::InvalidSize {
            ty: "authentication tag",
            expected: header.enc.tag_size(),
            got: authentication_tag.len(),
        });
    }

    let mut buffer = ciphertext;
    let nonce = Array::try_from(&initialization_vector).expect("can't panic since the size is checked before");
    let aad = protected_header_base64.as_bytes(); // The Additional Authenticated Data value used for AES-GCM.
    let authentication_tag =
        Array::try_from(&authentication_tag).expect("can't panic since the size is checked before");
    match header.enc {
        JweEnc::Aes128Gcm => {
            let algo = Aes128Gcm::new_from_slice(&jwe_cek).map_err(|_| JweError::AesGcm)?;
            algo.decrypt_inout_detached(&nonce, aad, buffer.as_mut_slice().into(), &authentication_tag)?;
        }
        JweEnc::Aes192Gcm => {
            let algo = Aes192Gcm::new_from_slice(&jwe_cek).map_err(|_| JweError::AesGcm)?;
            algo.decrypt_inout_detached(&nonce, aad, buffer.as_mut_slice().into(), &authentication_tag)?;
        }
        JweEnc::Aes256Gcm => {
            let algo = Aes256Gcm::new_from_slice(&jwe_cek).map_err(|_| JweError::AesGcm)?;
            algo.decrypt_inout_detached(&nonce, aad, buffer.as_mut_slice().into(), &authentication_tag)?;
        }
        unsupported => {
            return Err(JweError::UnsupportedAlgorithm {
                algorithm: format!("{unsupported:?}"),
            });
        }
    };

    Ok(Jwe {
        header,
        payload: buffer,
    })
}

fn prepare_ecdh_decryption_key(
    header: &JweHeader,
    encrypted_key: &[u8],
    sender_public_key: &PublicKey,
    receiver_private_key: &PrivateKey,
) -> Result<Zeroizing<Vec<u8>>, JweError> {
    let apu = header.apu.as_deref();
    let apv = header.apv.as_deref();

    match header.alg {
        JweAlg::EcdhEs => {
            let alg_name = header.enc.name();
            // Use DH shared secret as CEK directly
            calculate_ecdh_shared_secret(
                apu,
                apv,
                &alg_name,
                sender_public_key,
                receiver_private_key,
                header.enc.key_size(),
            )
        }
        JweAlg::EcdhEsAesKeyWrap128 | JweAlg::EcdhEsAesKeyWrap192 | JweAlg::EcdhEsAesKeyWrap256 => {
            let wrapping_alg = header
                .alg
                .key_wrapping_alg()
                .expect("BUG: ECDH-ES+AxKW algorithm should have a wrapping algorithm");

            let alg_name = header.alg.name();

            // We need to unwrap CEK from encrypted key
            let shared_secret = calculate_ecdh_shared_secret(
                apu,
                apv,
                &alg_name,
                sender_public_key,
                receiver_private_key,
                wrapping_alg.key_size(),
            )?;

            wrapping_alg.decrypt_key(header.enc, encrypted_key, &shared_secret)
        }
        _ => Err(JweError::UnsupportedAlgorithm {
            algorithm: format!("Algorithm `{}` is not supported for EC & ED keys", header.alg.name()),
        }),
    }
}

/// Expands the shared secret into a key of the desired size using the ECDH Concat KDF
fn ecdh_concat_kdf(
    alg: &str,
    shared_key_len: usize,
    derived_key: &[u8],
    apu: Option<&str>,
    apv: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>, JweError> {
    use sha2::{Digest, Sha256};

    let apu = apu
        .map(|val| general_purpose::URL_SAFE_NO_PAD.decode(val))
        .transpose()?;

    let apv = apv
        .map(|val| general_purpose::URL_SAFE_NO_PAD.decode(val))
        .transpose()?;

    // Size of the resulting key in BITS
    let shared_key_len_bytes = ((shared_key_len * 8) as u32).to_be_bytes();

    let alg = alg.as_bytes();
    let alg_len_bytes = (alg.len() as u32).to_be_bytes();

    let apu_len_bytes = apu.as_ref().map(|val| val.len() as u32).unwrap_or(0).to_be_bytes();
    let apv_len_bytes = apv.as_ref().map(|val| val.len() as u32).unwrap_or(0).to_be_bytes();

    let block_size = Sha256::output_size();

    let count = shared_key_len.div_ceil(block_size);
    let mut shared_key = Zeroizing::new(Vec::with_capacity(block_size * count));

    let mut hasher = Sha256::new();

    for i in 0..count {
        hasher.update(((i + 1) as u32).to_be_bytes());
        hasher.update(derived_key);
        hasher.update(alg_len_bytes);
        hasher.update(alg);
        hasher.update(apu_len_bytes);
        if let Some(val) = apu.as_deref() {
            hasher.update(val);
        }
        hasher.update(apv_len_bytes);
        if let Some(val) = apv.as_deref() {
            hasher.update(val);
        }
        hasher.update(shared_key_len_bytes);

        shared_key.extend_from_slice(hasher.finalize_reset().as_slice());
    }

    if shared_key.len() > shared_key_len {
        shared_key.truncate(shared_key_len);
    }

    // `sha2` crate currently doesn't perform any zeroize operations on finalization/reset, so we
    // doing a hack here, messing up with internal state of the hasher to make its data useless
    hasher.update(&shared_key);

    Ok(shared_key)
}

/// Returns ECDH ephemeral public key and shared secret required to build encrypted JWE
fn generate_ecdh_shared_secret(
    apu: Option<&str>,
    apv: Option<&str>,
    alg: &str,
    receiver_public_key: &PublicKey,
    cek_key_len: usize,
) -> Result<(Zeroizing<Vec<u8>>, PublicKey), JweError> {
    use picky_asn1_x509::PublicKey as RfcPublicKey;

    let (shared_secret, epk) = match &receiver_public_key.as_inner().subject_public_key {
        RfcPublicKey::Ec(_) => {
            let ec = EcdsaPublicKey::try_from(receiver_public_key)?;

            match ec.curve() {
                NamedEcCurve::Known(EcCurve::NistP256) => {
                    let public_key = p256::PublicKey::from_sec1_bytes(ec.encoded_point()).map_err(|e| {
                        let source = KeyError::EC {
                            context: format!("Cannot parse p256 encoded point from bytes: {e}"),
                        };
                        JweError::Key { source }
                    })?;

                    let secret =
                        p256::ecdh::EphemeralSecret::generate_from_rng(&mut StdRng::try_from_rng(&mut SysRng)?);

                    let shared_secret = Zeroizing::new(secret.diffie_hellman(&public_key).raw_secret_bytes().to_vec());
                    let epk = PublicKey::from_ec_encoded_components(
                        &NamedEcCurve::Known(EcCurve::NistP256).into(),
                        secret.public_key().to_sec1_bytes().as_ref(),
                    );

                    (shared_secret, epk)
                }
                NamedEcCurve::Known(EcCurve::NistP384) => {
                    let public_key = p384::PublicKey::from_sec1_bytes(ec.encoded_point()).map_err(|e| {
                        let source = KeyError::EC {
                            context: format!("Cannot parse p384 encoded point from bytes: {e}"),
                        };
                        JweError::Key { source }
                    })?;

                    let secret =
                        p384::ecdh::EphemeralSecret::generate_from_rng(&mut StdRng::try_from_rng(&mut SysRng)?);

                    let shared_secret = Zeroizing::new(secret.diffie_hellman(&public_key).raw_secret_bytes().to_vec());
                    let epk = PublicKey::from_ec_encoded_components(
                        &NamedEcCurve::Known(EcCurve::NistP384).into(),
                        secret.public_key().to_sec1_bytes().as_ref(),
                    );

                    (shared_secret, epk)
                }
                NamedEcCurve::Known(EcCurve::NistP521) => {
                    let public_key = p521::PublicKey::from_sec1_bytes(ec.encoded_point()).map_err(|e| {
                        let source = KeyError::EC {
                            context: format!("Cannot parse p521 encoded point from bytes: {e}"),
                        };
                        JweError::Key { source }
                    })?;

                    let secret =
                        p521::ecdh::EphemeralSecret::generate_from_rng(&mut StdRng::try_from_rng(&mut SysRng)?);

                    let shared_secret = Zeroizing::new(secret.diffie_hellman(&public_key).raw_secret_bytes().to_vec());
                    let epk = PublicKey::from_ec_encoded_components(
                        &NamedEcCurve::Known(EcCurve::NistP521).into(),
                        secret.public_key().to_sec1_bytes().as_ref(),
                    );

                    (shared_secret, epk)
                }
                NamedEcCurve::Unsupported(oid) => {
                    let source = KeyError::unsupported_curve(oid, "ECDH-ES JWE algorithm");
                    return Err(JweError::Key { source });
                }
            }
        }
        RfcPublicKey::Ed(_) => {
            let ed = EdPublicKey::try_from(receiver_public_key)?;

            match ed.algorithm() {
                NamedEdAlgorithm::Known(EdAlgorithm::X25519) => {
                    let public_key_data: [u8; X25519_FIELD_ELEMENT_SIZE] = ed.data().try_into().map_err(|e| {
                        let source = KeyError::ED {
                            context: format!("Cannot parse x25519 encoded point from bytes: {e}"),
                        };
                        JweError::Key { source }
                    })?;

                    let public_key = x25519_dalek::PublicKey::from(public_key_data);

                    let secret =
                        x25519_dalek::EphemeralSecret::random_from_rng(&mut StdRng::try_from_rng(&mut SysRng)?);

                    let epk = PublicKey::from_ed_encoded_components(
                        &EdAlgorithm::X25519.into(),
                        x25519_dalek::PublicKey::from(&secret).as_bytes().as_slice(),
                    );
                    let shared_secret = Zeroizing::new(secret.diffie_hellman(&public_key).as_bytes().to_vec());

                    (shared_secret, epk)
                }
                NamedEdAlgorithm::Known(EdAlgorithm::Ed25519) => {
                    return Err(JweError::UnsupportedAlgorithm {
                        algorithm: "Ed25519 can't be used for ECDH".to_string(),
                    });
                }
                NamedEdAlgorithm::Unsupported(oid) => {
                    let source = KeyError::unsupported_ed_algorithm(oid, "ECDH-ES JWE algorithm");
                    return Err(JweError::Key { source });
                }
            }
        }
        RfcPublicKey::Rsa(_) => {
            return Err(JweError::UnsupportedAlgorithm {
                algorithm: format!("RSA key can't be used with `{alg:?}` algorithm"),
            });
        }
        RfcPublicKey::Mldsa(_) => {
            return Err(JweError::UnsupportedAlgorithm {
                algorithm: format!("MLDSA key can't be used with `{alg:?}` algorithm"),
            });
        }
    };

    // Apply concact KDF to raw shared secret
    Ok((ecdh_concat_kdf(alg, cek_key_len, &shared_secret, apu, apv)?, epk))
}

/// Calculates ECDH shared secret using given keys and jwe header fields
fn calculate_ecdh_shared_secret(
    apu: Option<&str>,
    apv: Option<&str>,
    alg: &str,
    sender_public_key: &PublicKey,
    receiver_private_key: &PrivateKey,
    cek_key_len: usize,
) -> Result<Zeroizing<Vec<u8>>, JweError> {
    let shared_secret = match &receiver_private_key.as_kind() {
        PrivateKeyKind::Ec { .. } => {
            let private_key = EcdsaKeypair::try_from(receiver_private_key)?;

            let public_key =
                EcdsaPublicKey::try_from(sender_public_key).map_err(|source| JweError::KeyAlgorithmsMismatch {
                    context: source.to_string(),
                })?;

            if private_key.curve() != public_key.curve() {
                return Err(JweError::KeyAlgorithmsMismatch {
                    context: format!(
                        "Receiver key have EC curve `{}`, but sender key have `{}` curve",
                        private_key.curve(),
                        public_key.curve()
                    ),
                });
            }

            match private_key.curve() {
                NamedEcCurve::Known(EcCurve::NistP256) => {
                    let public_key = p256::PublicKey::from_sec1_bytes(public_key.encoded_point()).map_err(|e| {
                        let source = KeyError::EC {
                            context: format!("Cannot parse p256 encoded point from bytes: {e}"),
                        };
                        JweError::Key { source }
                    })?;

                    let secret_bytes_validated =
                        EcCurve::NistP256.validate_component(EcComponent::Secret(private_key.secret()))?;

                    let secret = p256::SecretKey::from_slice(secret_bytes_validated).map_err(|e| KeyError::EC {
                        context: format!("Cannot parse p256 secret from bytes: {e}"),
                    })?;

                    // p256 crate doesn't have high level API for static ECDH secrets
                    let shared_secret =
                        p256::elliptic_curve::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public_key.as_affine())
                            .raw_secret_bytes()
                            .to_vec();

                    Zeroizing::new(shared_secret)
                }
                NamedEcCurve::Known(EcCurve::NistP384) => {
                    let public_key = p384::PublicKey::from_sec1_bytes(public_key.encoded_point()).map_err(|e| {
                        let source = KeyError::EC {
                            context: format!("Cannot parse p384 encoded point from bytes: {e}"),
                        };
                        JweError::Key { source }
                    })?;

                    let secret_bytes_validated =
                        EcCurve::NistP384.validate_component(EcComponent::Secret(private_key.secret()))?;

                    let secret = p384::SecretKey::from_slice(secret_bytes_validated).map_err(|e| KeyError::EC {
                        context: format!("Cannot parse p384 secret from bytes: {e}"),
                    })?;

                    // p384 crate doesn't have high level API for static ECDH secrets
                    let shared_secret =
                        p384::elliptic_curve::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public_key.as_affine())
                            .raw_secret_bytes()
                            .to_vec();

                    Zeroizing::new(shared_secret)
                }
                NamedEcCurve::Known(EcCurve::NistP521) => {
                    let public_key = p521::PublicKey::from_sec1_bytes(public_key.encoded_point()).map_err(|e| {
                        let source = KeyError::EC {
                            context: format!("Cannot parse p521 encoded point from bytes: {e}"),
                        };
                        JweError::Key { source }
                    })?;

                    let secret_bytes_validated =
                        EcCurve::NistP521.validate_component(EcComponent::Secret(private_key.secret()))?;

                    let secret = p521::SecretKey::from_slice(secret_bytes_validated).map_err(|e| KeyError::EC {
                        context: format!("Cannot parse p521 secret from bytes: {e}"),
                    })?;

                    // p521 crate doesn't have high level API for static ECDH secrets
                    let shared_secret =
                        p521::elliptic_curve::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public_key.as_affine())
                            .raw_secret_bytes()
                            .to_vec();

                    Zeroizing::new(shared_secret)
                }
                NamedEcCurve::Unsupported(oid) => {
                    let source = KeyError::unsupported_curve(oid, "ECDH-ES JWE algorithm");
                    return Err(JweError::Key { source });
                }
            }
        }
        PrivateKeyKind::Ed { .. } => {
            let public_key = EdPublicKey::try_from(sender_public_key).map_err(|source| JweError::Key { source })?;

            let private_key =
                EdKeypair::try_from(receiver_private_key).map_err(|source| JweError::KeyAlgorithmsMismatch {
                    context: source.to_string(),
                })?;

            if private_key.algorithm() != public_key.algorithm() {
                return Err(JweError::KeyAlgorithmsMismatch {
                    context: format!(
                        "Receiver key have ED algorithm `{}`, but sender key have `{}` algorithm",
                        private_key.algorithm(),
                        public_key.algorithm()
                    ),
                });
            }

            match private_key.algorithm() {
                NamedEdAlgorithm::Known(EdAlgorithm::X25519) => {
                    let public_key_data: [u8; X25519_FIELD_ELEMENT_SIZE] =
                        public_key.data().try_into().map_err(|e| {
                            let source = KeyError::ED {
                                context: format!("Cannot parse x25519 encoded point from bytes: {e}"),
                            };
                            JweError::Key { source }
                        })?;

                    let public_key = x25519_dalek::PublicKey::from(public_key_data);

                    let private_key_data: [u8; X25519_FIELD_ELEMENT_SIZE] =
                        private_key.secret().try_into().map_err(|e| {
                            let source = KeyError::ED {
                                context: format!("Cannot parse x25519 secret from bytes: {e}"),
                            };
                            JweError::Key { source }
                        })?;

                    let secret = x25519_dalek::StaticSecret::from(private_key_data);

                    let shared_secret = secret.diffie_hellman(&public_key).as_bytes().to_vec();

                    Zeroizing::new(shared_secret)
                }
                NamedEdAlgorithm::Known(EdAlgorithm::Ed25519) => {
                    return Err(JweError::UnsupportedAlgorithm {
                        algorithm: "Ed25519 can't be used for ECDH".to_string(),
                    });
                }
                NamedEdAlgorithm::Unsupported(oid) => {
                    return Err(KeyError::unsupported_ed_algorithm(oid, "ECDH-ES JWE algorithm").into());
                }
            }
        }
        PrivateKeyKind::Rsa => {
            return Err(JweError::UnsupportedAlgorithm {
                algorithm: format!("RSA key can't be used with `{alg:?}` algorithm"),
            });
        }
    };

    // Apply concact KDF to raw shared secret
    ecdh_concat_kdf(alg, cek_key_len, &shared_secret, apu, apv)
}

/// Generate content encryption key (CEK) for given algorithm and wraps it with zeroize-on-drop container
fn generate_cek(alg: JweEnc) -> Result<Zeroizing<Vec<u8>>, JweError> {
    let mut cek = Zeroizing::new(vec![0u8; alg.key_size()]);
    let mut rng = StdRng::try_from_rng(&mut SysRng)?;
    rng.fill_bytes(&mut cek);
    Ok(cek)
}

enum RsaPaddingScheme {
    Pkcs1v15Encrypt,
    Oaep(Oaep<sha1::Sha1>),
    Oaep256(Oaep<sha2::Sha256>),
}

impl rsa::traits::PaddingScheme for RsaPaddingScheme {
    fn decrypt<Rng: rand_core::TryCryptoRng + ?Sized>(
        self,
        rng: Option<&mut Rng>,
        priv_key: &RsaPrivateKey,
        ciphertext: &[u8],
    ) -> rsa::Result<Vec<u8>> {
        match self {
            RsaPaddingScheme::Pkcs1v15Encrypt => {
                rsa::traits::PaddingScheme::decrypt(Pkcs1v15Encrypt, rng, priv_key, ciphertext)
            }
            RsaPaddingScheme::Oaep(oaep) => rsa::traits::PaddingScheme::decrypt(oaep, rng, priv_key, ciphertext),
            RsaPaddingScheme::Oaep256(oaep) => rsa::traits::PaddingScheme::decrypt(oaep, rng, priv_key, ciphertext),
        }
    }

    fn encrypt<Rng: rand_core::TryCryptoRng + ?Sized>(
        self,
        rng: &mut Rng,
        pub_key: &RsaPublicKey,
        msg: &[u8],
    ) -> rsa::Result<Vec<u8>> {
        match self {
            RsaPaddingScheme::Pkcs1v15Encrypt => {
                rsa::traits::PaddingScheme::encrypt(Pkcs1v15Encrypt, rng, pub_key, msg)
            }
            RsaPaddingScheme::Oaep(oaep) => rsa::traits::PaddingScheme::encrypt(oaep, rng, pub_key, msg),
            RsaPaddingScheme::Oaep256(oaep) => rsa::traits::PaddingScheme::encrypt(oaep, rng, pub_key, msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::PrivateKey;
    use crate::pem::Pem;
    use rstest::rstest;

    fn get_private_key_1() -> PrivateKey {
        let pk_pem = picky_test_data::RSA_2048_PK_1.parse::<Pem>().unwrap();
        PrivateKey::from_pem(&pk_pem).expect("private_key 1")
    }

    fn get_private_key_2() -> PrivateKey {
        let pk_pem = picky_test_data::RSA_2048_PK_7.parse::<Pem>().unwrap();
        PrivateKey::from_pem(&pk_pem).expect("private_key 7")
    }

    #[test]
    fn rsa_oaep_aes_128_gcm() {
        let payload = "何だと？……無駄な努力だ？……百も承知だ！だがな、勝つ望みがある時ばかり、戦うのとは訳が違うぞ！"
            .as_bytes()
            .to_vec();

        let private_key = get_private_key_1();
        let public_key = private_key.to_public_key().unwrap();

        let jwe = Jwe::new(JweAlg::RsaOaep, JweEnc::Aes128Gcm, payload);
        let encoded = jwe.clone().encode(&public_key).unwrap();

        let decoded = Jwe::decode(&encoded, &private_key).unwrap();

        assert_eq!(jwe.payload, decoded.payload);
        assert_eq!(jwe.header, decoded.header);
    }

    #[test]
    fn rsa_pkcs1v15_aes_128_gcm_bad_key() {
        let payload = "そうとも！ 負けると知って戦うのが、遙かに美しいのだ！"
            .as_bytes()
            .to_vec();

        let private_key = get_private_key_1();
        let public_key = get_private_key_2().to_public_key().unwrap();

        let jwe = Jwe::new(JweAlg::RsaPkcs1v15, JweEnc::Aes128Gcm, payload);
        let encoded = jwe.encode(&public_key).unwrap();

        let err = Jwe::decode(&encoded, &private_key).err().unwrap();
        assert_eq!(err.to_string(), "RSA error: decryption error");
    }

    #[test]
    fn direct_aes_256_gcm() {
        let payload = "さあ、取れ、取るがいい！だがな、貴様たちがいくら騒いでも、あの世へ、俺が持って行くものが一つある！それはな…".as_bytes().to_vec();

        let key = "わたしの……心意気だ!!";

        let jwe = Jwe::new(JweAlg::Direct, JweEnc::Aes256Gcm, payload);
        let encoded = jwe.clone().encode_direct(key.as_bytes()).unwrap();

        let decoded = Jwe::decode_direct(&encoded, key.as_bytes()).unwrap();

        assert_eq!(jwe.payload, decoded.payload);
        assert_eq!(jwe.header, decoded.header);
    }

    #[test]
    fn direct_aes_192_gcm_bad_key() {
        let payload = "和解をしよう？ 俺が？ 真っ平だ！ 真っ平御免だ！".as_bytes().to_vec();

        let jwe = Jwe::new(JweAlg::Direct, JweEnc::Aes192Gcm, payload);
        let encoded = jwe.encode_direct(b"abcdefghabcdefghabcdefgh").unwrap();

        let err = Jwe::decode_direct(&encoded, b"zzzzzzzzabcdefghzzzzzzzz").err().unwrap();
        assert_eq!(err.to_string(), "AES-GCM error (opaque)");
    }

    #[test]
    #[ignore = "this is not directly using picky code"]
    fn rfc7516_example_using_rsaes_oaep_and_aes_gcm() {
        // See: https://tools.ietf.org/html/rfc7516#appendix-A.1

        let plaintext = b"The true sign of intelligence is not knowledge but imagination.";
        let jwe = Jwe::new(JweAlg::RsaOaep, JweEnc::Aes256Gcm, plaintext.to_vec());

        // 1: JOSE header

        let protected_header_base64 = general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&jwe.header).unwrap());
        assert_eq!(
            protected_header_base64,
            "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ"
        );

        // 2: Content Encryption Key (CEK)

        let cek = [
            177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154, 212, 246, 138, 7, 110, 91, 112, 46, 34,
            105, 47, 130, 203, 46, 122, 234, 64, 252,
        ];

        // 3: Key Encryption

        let encrypted_key_base64 = "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg";

        // 4: Initialization Vector

        let iv_base64 = "48V1_ALb6US04U3b";
        let iv = general_purpose::URL_SAFE_NO_PAD.decode(iv_base64).unwrap();

        // 5: AAD

        let aad = protected_header_base64.as_bytes();

        // 6: Content Encryption

        let mut buffer = plaintext.to_vec();
        let algo = Aes256Gcm::new_from_slice(&cek).unwrap();
        let tag = algo
            .encrypt_inout_detached(&Array::try_from(iv).unwrap(), aad, buffer.as_mut_slice().into())
            .unwrap();
        let ciphertext = buffer;

        assert_eq!(
            ciphertext,
            [
                229, 236, 166, 241, 53, 191, 115, 196, 174, 43, 73, 109, 39, 122, 233, 96, 140, 206, 120, 52, 51, 237,
                48, 11, 190, 219, 186, 80, 111, 104, 50, 142, 47, 167, 59, 61, 181, 127, 196, 21, 40, 82, 242, 32, 123,
                143, 168, 226, 73, 216, 176, 144, 138, 247, 106, 60, 16, 205, 160, 109, 64, 63, 192
            ]
            .to_vec()
        );
        assert_eq!(
            tag.as_slice(),
            &[
                92, 80, 104, 49, 133, 25, 161, 215, 173, 101, 219, 211, 136, 91, 210, 145
            ]
        );

        // 7: Complete Representation

        let token = format!(
            "{}.{}.{}.{}.{}",
            protected_header_base64,
            encrypted_key_base64,
            iv_base64,
            general_purpose::URL_SAFE_NO_PAD.encode(&ciphertext),
            general_purpose::URL_SAFE_NO_PAD.encode(tag),
        );

        assert_eq!(
            token,
            "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ"
        );
    }

    #[rstest]
    // Different asymmetrical keys and different symmetrical key sizes
    #[case(picky_test_data::EC_NIST256_PK_1, JweAlg::EcdhEs, JweEnc::Aes256Gcm)]
    #[case(picky_test_data::EC_NIST384_PK_1, JweAlg::EcdhEs, JweEnc::Aes192Gcm)]
    #[case(picky_test_data::X25519_PEM_PK_1, JweAlg::EcdhEs, JweEnc::Aes128Gcm)]
    // With key wrapping
    #[case(picky_test_data::X25519_PEM_PK_1, JweAlg::EcdhEsAesKeyWrap128, JweEnc::Aes256Gcm)]
    #[case(picky_test_data::EC_NIST256_PK_1, JweAlg::EcdhEsAesKeyWrap128, JweEnc::Aes128Gcm)]
    #[case(picky_test_data::EC_NIST384_PK_1, JweAlg::EcdhEsAesKeyWrap192, JweEnc::Aes256Gcm)]
    #[case(picky_test_data::X25519_PEM_PK_1, JweAlg::EcdhEsAesKeyWrap192, JweEnc::Aes128Gcm)]
    #[case(picky_test_data::EC_NIST256_PK_1, JweAlg::EcdhEsAesKeyWrap256, JweEnc::Aes256Gcm)]
    #[case(picky_test_data::X25519_PEM_PK_1, JweAlg::EcdhEsAesKeyWrap256, JweEnc::Aes128Gcm)]
    fn jwe_ecdh_es_roundtrip(#[case] key_pem: &str, #[case] alg: JweAlg, #[case] enc: JweEnc) {
        let private = PrivateKey::from_pem_str(key_pem).unwrap();
        let public = private.to_public_key().unwrap();

        let payload = b"Hello, world!".to_vec();

        let encoded = Jwe::new(alg, enc, payload.clone())
            .encode(&public)
            .expect("JWE encode failed");

        let decoded = Jwe::decode(&encoded, &private).expect("JWE decode failed");

        assert_eq!(decoded.payload, payload);
    }

    #[rstest]
    #[case(picky_test_data::JOSE_JWE_GCM256_EC_P256_ECDH, picky_test_data::EC_NIST256_PK_1)]
    #[case(
        picky_test_data::JOSE_JWE_GCM128_EC_P384_ECDH_KW192,
        picky_test_data::EC_NIST384_PK_1
    )]
    fn picky_understands_jwcrypto(#[case] token: &str, #[case] key_pem: &str) {
        // Tokens were generated via `jwcrypto` library. To generate tokens use the following
        // code snippet:
        // ```python
        // from jwcrypto import jwe, jwk
        // from jwcrypto.common import json_encode
        // pem = "<PEM_DATA>"
        // jwk = jwk.JWK.from_pem(pem)
        // jwe = jwe.JWE(b'Hello world!', json_encode({'alg': 'ECDH-ES+A256KW', 'enc': 'A192GCM'}))
        // jwe.add_recipient(jwk)
        // print(jwe.serialize(compact=True))
        // ```

        let private = PrivateKey::from_pem_str(key_pem).unwrap();
        let decoded = Jwe::decode(token, &private).expect("JWE decode failed");
        assert_eq!(String::from_utf8(decoded.payload).unwrap(), "Hello world!");
    }
}
