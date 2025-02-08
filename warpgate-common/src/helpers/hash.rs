use anyhow::Result;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{Error, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use data_encoding::HEXLOWER;
use rand::Rng;

use crate::Secret;

pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    // Only panics for invalid hash parameters
    #[allow(clippy::unwrap_used)]
    argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

pub fn parse_hash(hash: &str) -> Result<PasswordHash<'_>, Error> {
    PasswordHash::new(hash)
}

pub fn verify_password_hash(password: &str, hash: &str) -> Result<bool> {
    let parsed_hash = parse_hash(hash).map_err(|e| anyhow::anyhow!(e))?;
    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(Error::Password) => Ok(false),
        Err(e) => Err(anyhow::anyhow!(e)),
    }
}

pub fn generate_ticket_secret() -> Secret<String> {
    let mut bytes = [0; 32];
    rand::thread_rng().fill(&mut bytes[..]);
    Secret::new(HEXLOWER.encode(&bytes))
}
