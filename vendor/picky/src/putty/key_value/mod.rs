//! This module provides a set of traits and macros and types to parse and write PuTTY key-value
//! format in strongly-typed manner.

mod macros;
mod reader;
mod writer;

use std::fmt;
use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;

use self::macros::*;

pub(crate) use reader::PuttyKvReader;
pub(crate) use writer::PuttyKvWriter;

pub struct PpkValueParsingError {
    pub expected: &'static str,
    pub actual: String,
}

const KV_DELIMITER: &str = ": ";

/// Trait for keys/values that could be represented as singular or set of static strings.
pub(crate) trait PpkLiteral {
    fn context() -> &'static str;
    fn as_static_str(&self) -> &'static str;
}

/// Trait for key-value pairs that use multiline format.
pub(crate) trait PpkMultilineKeyValue {
    type Key: FromStr<Err = PpkValueParsingError> + ToString + PpkLiteral;
    type Value: FromStr<Err = PpkValueParsingError> + ToString;
}

/// Trait for key-value pairs that use single-line format.
pub(crate) trait PpkKeyValue {
    type Key: FromStr<Err = PpkValueParsingError> + ToString + PpkLiteral;
    type Value: FromStr<Err = PpkValueParsingError> + ToString;
}

/// Wrapper type for base64 multiline data inside PPK file.
pub(crate) struct Base64PpkValue(Vec<u8>);

impl FromStr for Base64PpkValue {
    type Err = PpkValueParsingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        BASE64_ENGINE
            .decode(s)
            .map_err(|_| PpkValueParsingError {
                expected: "<valid base64 data>",
                actual: s.to_string(),
            })
            .map(Self)
    }
}

impl fmt::Display for Base64PpkValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", BASE64_ENGINE.encode(&self.0))
    }
}

impl From<Vec<u8>> for Base64PpkValue {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<Base64PpkValue> for Vec<u8> {
    fn from(value: Base64PpkValue) -> Self {
        value.0
    }
}

/// Wrapper type for hex-string multiline data inside PPK file.
pub(crate) struct HexPpkValue(Vec<u8>);

impl FromStr for HexPpkValue {
    type Err = PpkValueParsingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex::decode(s)
            .map_err(|_| PpkValueParsingError {
                expected: "<valid hex data>",
                actual: s.to_string(),
            })
            .map(Self)
    }
}

impl fmt::Display for HexPpkValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl From<Vec<u8>> for HexPpkValue {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<HexPpkValue> for Vec<u8> {
    fn from(value: HexPpkValue) -> Self {
        value.0
    }
}

// Key value type definitions

ppk_enum!(
    PpkVersionKey,
    V2 => "PuTTY-User-Key-File-2",
    V3 => "PuTTY-User-Key-File-3"
);
ppk_enum!(
    PpkKeyAlgorithmValue,
    Rsa => "ssh-rsa",
    Dss => "ssh-dss",
    EcdsaSha2Nistp256 => "ecdsa-sha2-nistp256",
    EcdsaSha2Nistp384 => "ecdsa-sha2-nistp384",
    EcdsaSha2Nistp521 => "ecdsa-sha2-nistp521",
    Ed25519 => "ssh-ed25519",
    Ed448 => "ssh-ed448"
);
ppk_key_value!(PpkHeader, PpkVersionKey, PpkKeyAlgorithmValue);

ppk_const!(PpkEncryptionKey, "Encryption");
ppk_enum!(
    PpkEncryptionValue,
    None => "none",
    Aes256Cbc => "aes256-cbc"
);
ppk_key_value!(PpkEncryption, PpkEncryptionKey, PpkEncryptionValue);

ppk_const!(PpkCommentKey, "Comment");
ppk_generic_value!(PpkCommentValue, String);
ppk_key_value!(PpkComment, PpkCommentKey, PpkCommentValue);

ppk_const!(PpkPublicLinesKey, "Public-Lines");
ppk_multiline_key_value!(PpkPublicLines, PpkPublicLinesKey, Base64PpkValue);

ppk_const!(PpkKeyDerivationKey, "Key-Derivation");
ppk_enum!(
    Argon2FlavourValue,
    Argon2d => "Argon2d",
    Argon2i => "Argon2i",
    Argon2id => "Argon2id"
);
ppk_key_value!(PpkKeyDerivation, PpkKeyDerivationKey, Argon2FlavourValue);
ppk_const!(PpkArgon2MemoryKey, "Argon2-Memory");
ppk_generic_value!(PpkArgon2MemoryValue, u32);
ppk_key_value!(PpkArgon2Memory, PpkArgon2MemoryKey, PpkArgon2MemoryValue);
ppk_const!(PpkArgon2PassesKey, "Argon2-Passes");
ppk_generic_value!(PpkArgon2PassesValue, u32);
ppk_key_value!(PpkArgon2Passes, PpkArgon2PassesKey, PpkArgon2PassesValue);
ppk_const!(PpkArgon2ParallelismKey, "Argon2-Parallelism");
ppk_generic_value!(PpkArgon2ParallelismValue, u32);
ppk_key_value!(PpkArgon2Parallelism, PpkArgon2ParallelismKey, PpkArgon2ParallelismValue);
ppk_const!(PpkArgon2SaltKey, "Argon2-Salt");
ppk_key_value!(PpkArgon2Salt, PpkArgon2SaltKey, HexPpkValue);

ppk_const!(PpkPrivateLinesKey, "Private-Lines");
ppk_multiline_key_value!(PpkPrivateLines, PpkPrivateLinesKey, Base64PpkValue);

ppk_const!(PpkPrivateMacKey, "Private-MAC");
ppk_key_value!(PpkPrivateMac, PpkPrivateMacKey, HexPpkValue);

impl From<Argon2FlavourValue> for argon2::Algorithm {
    fn from(value: Argon2FlavourValue) -> Self {
        match value {
            Argon2FlavourValue::Argon2d => argon2::Algorithm::Argon2d,
            Argon2FlavourValue::Argon2i => argon2::Algorithm::Argon2i,
            Argon2FlavourValue::Argon2id => argon2::Algorithm::Argon2id,
        }
    }
}

impl PpkKeyAlgorithmValue {
    pub fn key_mpint_values_count(&self) -> usize {
        match self {
            PpkKeyAlgorithmValue::Rsa => 4,
            PpkKeyAlgorithmValue::Dss
            | PpkKeyAlgorithmValue::EcdsaSha2Nistp256
            | PpkKeyAlgorithmValue::EcdsaSha2Nistp384
            | PpkKeyAlgorithmValue::EcdsaSha2Nistp521
            | PpkKeyAlgorithmValue::Ed25519
            | PpkKeyAlgorithmValue::Ed448 => 1,
        }
    }
}
