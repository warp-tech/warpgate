use russh::keys::{Algorithm, HashAlg, PrivateKey, decode_secret_key, encode_pkcs8_pem};

use crate::WarpgateError;
use crate::helpers::rng::get_crypto_rng;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshHostKeyKind {
    Ed25519,
    Rsa,
}

impl SshHostKeyKind {
    pub const ALL: [Self; 2] = [Self::Ed25519, Self::Rsa];

    /// matching both host-xxx filenames and ssh_host_key_xxx columns
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::Rsa => "rsa",
        }
    }

    pub fn algorithm(self) -> Algorithm {
        match self {
            Self::Ed25519 => Algorithm::Ed25519,
            Self::Rsa => Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
        }
    }

    pub fn generate_pem(self) -> Result<String, WarpgateError> {
        let key = PrivateKey::random(&mut get_crypto_rng(), self.algorithm())
            .map_err(russh::keys::Error::from)?;
        pkcs8_pem_string(&key)
    }
}

pub fn pkcs8_pem_string(key: &PrivateKey) -> Result<String, WarpgateError> {
    let mut buf = Vec::new();
    encode_pkcs8_pem(key, &mut buf)?;
    Ok(String::from_utf8(buf)?)
}

/// `<algo> <base64>` only — the OpenSSH comment is dropped so that the same
/// key always serializes identically for de-duplication.
pub fn public_key_line(key: &PrivateKey) -> Result<String, WarpgateError> {
    Ok(key
        .public_key()
        .to_openssh()
        .map_err(russh::keys::Error::from)?
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" "))
}

/// The [`public_key_line`] of a private key in OpenSSH or PKCS#8 PEM format
pub fn public_key_of_pem(pem: &str) -> Result<String, WarpgateError> {
    public_key_line(&decode_secret_key(pem, None)?)
}
