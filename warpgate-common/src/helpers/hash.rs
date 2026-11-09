use anyhow::Result;
use argon2::Argon2;
use argon2::password_hash::{Error, PasswordHasher, PasswordVerifier};
use data_encoding::HEXLOWER;
use rand::RngExt;
use sha2::{Digest, Sha256};

use crate::Secret;

pub fn hash_password(password: &str) -> String {
    let argon2 = if std::env::var("WARPGATE_UNDER_TEST")
        .unwrap_or_default()
        .is_empty()
    {
        Argon2::default()
    } else {
        #[allow(clippy::unwrap_used, reason = "tests")]
        Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(1000, 1, 1, None).unwrap(),
        )
    };
    // Only panics for invalid hash parameters or an OS RNG failure
    #[allow(clippy::unwrap_used)]
    argon2
        .hash_password(password.as_bytes())
        .unwrap()
        .to_string()
}

pub fn verify_password_hash(password: &str, hash: &str) -> Result<bool> {
    match Argon2::default().verify_password(password.as_bytes(), hash) {
        Ok(()) => Ok(true),
        Err(Error::PasswordInvalid) => Ok(false),
        Err(e) => Err(anyhow::anyhow!(e)),
    }
}

pub fn generate_ticket_secret() -> Secret<String> {
    let mut bytes = [0; 32];
    rand::rng().fill(&mut bytes[..]);
    Secret::new(HEXLOWER.encode(&bytes))
}

/// Deterministic hash for high-entropy secrets (tokens/tickets)
pub fn hash_secret(secret: &str) -> String {
    HEXLOWER.encode(&Sha256::digest(secret.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_existing_phc_hashes() {
        // Argon2 reference-implementation vector; stands in for hashes already stored in the DB.
        let stored =
            "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4";
        assert!(verify_password_hash("password", stored).unwrap());
        assert!(!verify_password_hash("wrong", stored).unwrap());
        assert!(verify_password_hash("password", "not a hash").is_err());
    }

    #[test]
    fn round_trips() {
        let hash = hash_password("hunter42");
        assert!(verify_password_hash("hunter42", &hash).unwrap());
        assert!(!verify_password_hash("hunter43", &hash).unwrap());
    }
}
