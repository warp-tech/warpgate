#[derive(thiserror::Error, Debug)]
pub enum PuttyError {
    #[error("end of input")]
    EndOfInput,
    #[error("invalid input")]
    InvalidInput {
        context: &'static str,
        expected: &'static str,
        actual: String,
    },
    #[error("invalid key value format")]
    InvalidKeyValueFormat,
    #[error("AES encryption failed")]
    Aes,
    #[error("invalid argon2 params")]
    Argon2,
    #[error("MAC validation failed (wrong password or corrupted data)")]
    MacValidation,
    #[error("public and private key mismatch")]
    PublicAndPrivateKeyMismatch,
    #[error("invalid private key data")]
    InvalidPrivateKeyData,
    #[error("invalid public key data")]
    InvalidPublicKeyData,
    #[error("invalid public key container")]
    InvalidPublicKeyContainer,
    #[error("invalid public key comment")]
    InvalidPublicKeyComment,
    #[error("private key is already decrypted")]
    AlreadyDecrypted,
    #[error("private key is already encrypted")]
    AlreadyEncrypted,
    #[error("private key decryption is required prior to this operation")]
    Encrypted,
    #[error("unsupported feature")]
    NotSupported { feature: &'static str },
    #[error("RSA params precomputation failed")]
    RsaPrecompute,
    #[error("RSA primes count should be exactly 2")]
    RsaInvalidPrimesCount { count: usize },
    #[error(transparent)]
    SshPublicKey(#[from] crate::ssh::public_key::SshPublicKeyError),
    #[error(transparent)]
    SshPivateKey(#[from] crate::ssh::private_key::SshPrivateKeyError),
    #[error(transparent)]
    KeyError(#[from] crate::key::KeyError),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    OutIsTooSmallError(#[from] inout::OutIsTooSmallError),
    #[error(transparent)]
    RandError(#[from] rand::rngs::SysError),
}
