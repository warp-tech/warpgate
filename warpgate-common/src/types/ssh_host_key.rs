use russh::keys::{Algorithm, HashAlg, PrivateKey, encode_pkcs8_pem};

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
        let mut buf = Vec::new();
        encode_pkcs8_pem(&key, &mut buf)?;
        String::from_utf8(buf).map_err(WarpgateError::other)
    }
}
