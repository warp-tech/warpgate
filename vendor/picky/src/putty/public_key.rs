use crate::key::PublicKey;
use crate::putty::PuttyError;
use crate::ssh::SshPublicKey;
use crate::ssh::decode::SshComplexTypeDecode;
use crate::ssh::encode::SshComplexTypeEncode;
use crate::ssh::public_key::SshBasePublicKey;
use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;

const PUTTY_PUBKEY_HEADER: &str = "---- BEGIN SSH2 PUBLIC KEY ----";
const PUTTY_PUBKEY_FOOTER: &str = "---- END SSH2 PUBLIC KEY ----";

/// PuTTY public key format.
///
/// ### Functionality:
/// - Conversion to/from OpenSSH format.
/// - Encoding/decoding to/from string.
/// - Could be extracted from [`crate::putty::Ppk`] private keys.
///
/// ### Notes
/// - Although top-level containeris similar to PEM, it is not compatible with it because of
///   additional comment field after the header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PuttyPublicKey {
    pub(crate) base: PuttyBasePublicKey,
    pub(crate) comment: String,
}

impl PuttyPublicKey {
    /// Converts an OpenSSH public key to a PuTTY public key.
    pub fn from_openssh(key: &SshPublicKey) -> Result<Self, PuttyError> {
        let base = PuttyBasePublicKey::from_openssh(&key.inner_key)?;

        Ok(Self {
            base,
            comment: key.comment.clone(),
        })
    }

    /// Converts the key to an OpenSSH public key.
    pub fn to_openssh(&self) -> Result<SshPublicKey, PuttyError> {
        let base = self.base.to_openssh()?;
        Ok(SshPublicKey {
            inner_key: base,
            comment: self.comment.clone(),
        })
    }

    /// Returns key comment.
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Returns a new public key instance with a different comment.
    pub fn with_comment(&self, comment: &str) -> Self {
        Self {
            comment: comment.to_string(),
            ..self.clone()
        }
    }

    /// Parses and returns the inner key as standard picky key type.
    pub fn to_inner_key(&self) -> Result<PublicKey, PuttyError> {
        self.base.to_inner_key()
    }
}

impl std::fmt::Display for PuttyPublicKey {
    // False positive, clippy does not take into account that [`String::replace`] requires both
    // arguments to be the same type, e.g. we can't use `&str` as a replacement for `char`.
    #[allow(clippy::single_char_pattern)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const MAX_CHARS_PER_LINE: usize = 64;
        const LINE_END: &str = "\r\n";

        let encoded_key = BASE64_ENGINE.encode(&self.base.data);
        let escaped_comment = self.comment.replace("\\", "\\\\").replace("\"", "\\\"");

        let mut output = String::new();
        output.push_str(PUTTY_PUBKEY_HEADER);
        output.push_str(LINE_END);
        output.push_str("Comment: \"");
        output.push_str(&escaped_comment);
        output.push('"');
        output.push_str(LINE_END);

        let mut value_remaining = encoded_key.as_str();

        while !value_remaining.is_empty() {
            let line_len = value_remaining.len().min(MAX_CHARS_PER_LINE);
            let (line, remaining) = value_remaining.split_at(line_len);
            value_remaining = remaining;

            output.push_str(line);
            output.push_str(LINE_END);
        }

        output.push_str(PUTTY_PUBKEY_FOOTER);
        output.push_str(LINE_END);

        f.write_str(&output)
    }
}

impl FromStr for PuttyPublicKey {
    type Err = PuttyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut lines = s.lines();
        let header = lines.next().ok_or(PuttyError::EndOfInput)?;
        if header != PUTTY_PUBKEY_HEADER {
            return Err(PuttyError::InvalidPublicKeyContainer);
        }

        let comment_line = lines.next().ok_or(PuttyError::EndOfInput)?;
        if !comment_line.starts_with("Comment: ") {
            return Err(PuttyError::InvalidPublicKeyComment);
        }

        let unescaped_comment = comment_line
            .split_once('"')
            .and_then(|(_, remainder)| remainder.rsplit_once('"'))
            .map(|(comment, _)| comment)
            .ok_or(PuttyError::InvalidPublicKeyComment)?;

        let comment = unescaped_comment.replace("\\\"", "\"").replace("\\\\", "\\");

        let mut encoded_key = String::new();
        for line in lines {
            if line == PUTTY_PUBKEY_FOOTER {
                let decoded = BASE64_ENGINE
                    .decode(encoded_key)
                    .map_err(|_| PuttyError::InvalidPublicKeyData)?;

                return Ok(PuttyPublicKey {
                    base: PuttyBasePublicKey { data: decoded },
                    comment,
                });
            }

            encoded_key.push_str(line);
        }

        Err(PuttyError::EndOfInput)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PuttyBasePublicKey {
    pub(crate) data: Vec<u8>,
}

impl PuttyBasePublicKey {
    pub fn from_openssh(key: &SshBasePublicKey) -> Result<Self, PuttyError> {
        match key {
            SshBasePublicKey::SkEcdsaSha2NistP256 { .. } | SshBasePublicKey::SkEd25519 { .. } => {
                // Putty does not support SK keys
                return Err(PuttyError::NotSupported { feature: "SK keys" });
            }
            _ => {}
        };

        let mut data = Vec::new();
        SshBasePublicKey::encode(key, &mut data)?;

        Ok(Self { data })
    }

    pub fn to_openssh(&self) -> Result<SshBasePublicKey, PuttyError> {
        let key = SshBasePublicKey::decode(self.data.as_slice())?;
        Ok(key)
    }

    pub fn to_inner_key(&self) -> Result<PublicKey, PuttyError> {
        let inner = match self.to_openssh()? {
            SshBasePublicKey::Rsa(key) => key,
            SshBasePublicKey::Ec(key) => key,
            SshBasePublicKey::Ed(key) => key,
            SshBasePublicKey::SkEcdsaSha2NistP256 { .. } | SshBasePublicKey::SkEd25519 { .. } => {
                return Err(PuttyError::NotSupported { feature: "SK keys" });
            }
        };

        Ok(inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use picky_test_data::{
        PUTTY_KEY_ED25519_PUBLIC, PUTTY_KEY_RSA_PUBLIC_EMPTY_COMMENT, PUTTY_KEY_RSA_PUBLIC_ESCAPED_COMMENT,
        SSH_PUBLIC_KEY_EC_P256, SSH_PUBLIC_KEY_EC_P384, SSH_PUBLIC_KEY_EC_P521, SSH_PUBLIC_KEY_ED25519,
        SSH_PUBLIC_KEY_RSA,
    };
    use rstest::rstest;

    #[rstest]
    #[case(PUTTY_KEY_ED25519_PUBLIC)]
    #[case(PUTTY_KEY_RSA_PUBLIC_EMPTY_COMMENT)]
    #[case(PUTTY_KEY_RSA_PUBLIC_ESCAPED_COMMENT)]
    fn public_key_rountrip(#[case] input: &str) {
        let key: PuttyPublicKey = input.parse().unwrap();
        let output = key.to_string();
        assert_eq!(input, output);
    }

    #[rstest]
    #[case(SSH_PUBLIC_KEY_RSA)]
    #[case(SSH_PUBLIC_KEY_EC_P256)]
    #[case(SSH_PUBLIC_KEY_EC_P384)]
    #[case(SSH_PUBLIC_KEY_EC_P521)]
    #[case(SSH_PUBLIC_KEY_ED25519)]
    fn ssh_key_roundtrip(#[case] input: &str) {
        let ssh_key: SshPublicKey = input.parse().unwrap();
        let key = PuttyPublicKey::from_openssh(&ssh_key).unwrap();
        let ssh_key2 = key.to_openssh().unwrap();

        let ssh_key_str = ssh_key2.to_string().unwrap();
        assert_eq!(ssh_key_str, input);
    }
}
