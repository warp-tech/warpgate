use std::time::SystemTime;

use bytes::Bytes;
use rand::Rng;
use totp_rs::{Algorithm, TOTP};

use super::rng::get_crypto_rng;
use crate::types::Secret;

pub type OtpExposedSecretKey = Bytes;
pub type OtpSecretKey = Secret<OtpExposedSecretKey>;

pub fn generate_key() -> OtpSecretKey {
    Secret::new(Bytes::from_iter(get_crypto_rng().gen::<[u8; 32]>()))
}

pub fn generate_setup_url(key: &OtpSecretKey, label: &str) -> Secret<String> {
    let totp = get_totp(key, Some(label));
    Secret::new(totp.get_url())
}

fn get_totp(key: &OtpSecretKey, label: Option<&str>) -> TOTP<OtpExposedSecretKey> {
    TOTP {
        algorithm: Algorithm::SHA1,
        digits: 6,
        skew: 1,
        step: 30,
        secret: key.expose_secret().clone(),
        issuer: Some("Warpgate".to_string()),
        account_name: label.unwrap_or("").to_string(),
    }
}

pub fn verify_totp(code: &str, key: &OtpSecretKey) -> bool {
    #[allow(clippy::unwrap_used)]
    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    get_totp(key, None).check(code, time)
}
