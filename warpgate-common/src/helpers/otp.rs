use std::time::SystemTime;

use super::rng::get_crypto_rng;
use crate::types::Secret;
use bytes::Bytes;
use rand::Rng;
use totp_rs::{Algorithm, TOTP};

pub type OtpExposedSecretKey = Bytes;
pub type OtpSecretKey = Secret<OtpExposedSecretKey>;

pub fn generate_key() -> OtpSecretKey {
    Secret::new(Bytes::from_iter(get_crypto_rng().gen::<[u8; 32]>()))
}

pub fn generate_setup_url(key: &OtpSecretKey, label: &str) -> Secret<String> {
    let totp = get_totp(key);
    Secret::new(totp.get_url(label, "Warpgate"))
}

fn get_totp(key: &OtpSecretKey) -> TOTP<OtpExposedSecretKey> {
    TOTP::new(Algorithm::SHA1, 6, 1, 30, key.expose_secret().clone())
}

pub fn verify_totp(code: &str, key: &OtpSecretKey) -> bool {
    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    get_totp(key).check(code, time)
}
