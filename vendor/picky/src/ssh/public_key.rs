use crate::key::{KeyError, PublicKey};
use crate::ssh::decode::SshComplexTypeDecode;
use crate::ssh::encode::SshComplexTypeEncode;

use std::io;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SshPublicKeyError {
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error("invalid UTF-8")]
    InvalidUtf8,
    #[error(transparent)]
    RsaError(#[from] rsa::errors::Error),
    #[error(transparent)]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("Unknown key type. We only support RSA")]
    UnknownKeyType,
    #[error(transparent)]
    KeyError(#[from] KeyError),
}

impl From<core::str::Utf8Error> for SshPublicKeyError {
    fn from(_: core::str::Utf8Error) -> Self {
        Self::InvalidUtf8
    }
}

impl From<std::string::FromUtf8Error> for SshPublicKeyError {
    fn from(_: std::string::FromUtf8Error) -> Self {
        Self::InvalidUtf8
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshBasePublicKey {
    Rsa(PublicKey),
    Ec(PublicKey),
    Ed(PublicKey),
    /// U2F ecdsa SSH key
    SkEcdsaSha2NistP256 {
        base_key: PublicKey,
        application: String,
    },
    /// U2F ed25519 SSH key
    SkEd25519 {
        base_key: PublicKey,
        application: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshPublicKey {
    pub inner_key: SshBasePublicKey,
    pub comment: String,
}

impl SshPublicKey {
    pub fn to_string(&self) -> Result<String, SshPublicKeyError> {
        let mut buffer = Vec::with_capacity(1024);
        self.encode(&mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    }

    pub fn inner_key(&self) -> &PublicKey {
        match &self.inner_key {
            SshBasePublicKey::Rsa(key) => key,
            SshBasePublicKey::Ec(key) => key,
            SshBasePublicKey::Ed(key) => key,
            SshBasePublicKey::SkEcdsaSha2NistP256 { base_key, .. } => base_key,
            SshBasePublicKey::SkEd25519 { base_key, .. } => base_key,
        }
    }

    pub fn fingerprint_md5(&self) -> Result<[u8; 16], SshPublicKeyError> {
        use md5::{Digest, Md5};

        let mut encoded = Vec::new();
        self.inner_key.encode(&mut encoded)?;

        let mut hasher = Md5::new();
        hasher.update(&encoded);
        let fingerprint = hasher.finalize();

        Ok(fingerprint.into())
    }

    pub fn fingerprint_sha1(&self) -> Result<[u8; 20], SshPublicKeyError> {
        use sha1::{Digest, Sha1};

        let mut encoded = Vec::new();
        self.inner_key.encode(&mut encoded)?;

        let mut hasher = Sha1::new();
        hasher.update(&encoded);
        let fingerprint = hasher.finalize();

        Ok(fingerprint.into())
    }

    pub fn fingerprint_sha256(&self) -> Result<[u8; 32], SshPublicKeyError> {
        use sha2::{Digest, Sha256};

        let mut encoded = Vec::new();
        self.inner_key.encode(&mut encoded)?;

        let mut hasher = Sha256::new();
        hasher.update(&encoded);
        let fingerprint = hasher.finalize();

        Ok(fingerprint.into())
    }
}

impl FromStr for SshPublicKey {
    type Err = SshPublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SshComplexTypeDecode::decode(s.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    use crypto_bigint::BoxedUint;
    use rstest::rstest;

    #[test]
    fn decode_ssh_rsa_4096_public_key() {
        // ssh-keygen -t rsa -b 4096 -C "test@picky.com"
        let ssh_public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDbUCK4dH1n4dOFBv/sjfMma4q5qe7SZ49j2GODGKr8DueZMWYLTck61uUMMlVBT3XyX6me6X4WsBoijzQWvgwpLCGTqlhQTntm5FphXHHkKxFvjMhPzCnHNS+L0ebzewcecsY5rtgw+6BhFwdZGhFBfif1/6s9q7y7+8Ge3hUIEqLdiMDDzxc66zIaW26jZxO4BMHuKp7Xln2JeDjsRHvz0vBNAddOfkvtp+gM72OH4tm9wS/V8bVOZ68oU0os8DuiEGnwA5RnjOjaFdHWt1mD8B+nRINxI8zYyQcqp3t4p552P0Frhvjgixi67Ryax0DUNuzN2MpQ0ORUgRkfy/xWvImUseP/BfqvNiWkFAWHNDDSsc50Wmr+g0JicG2gowHLYPxKRjLIbOq+JgxHrE4TdaA2NJoeUppJgWU4yuGl5fx1G+Bcdr0C+lsMj14Hp+aGajEOLQ7Mq3HzWEox9G1KgN4r266Mofd8T4vrjF6Ja9E+pp0pXgEv2cvtYJLP0qdrHWafb3lWsP4hJWnv/NaXP6ZAxiEeHsigrY98kmgZbHm/6AmiBJ7bKQ/S/PelYj3mTL0aYkGF79qVtAzSl7yI9yVyHsl7dt5jdmp6+IofuEtNfnAcfoaSLu0Ojotp9VBMvil6ojScbJNLBL8tGN4+urIcsNUvVjAOnwc3nothKw== test@picky.com\r\n";

        let public_key = SshPublicKey::from_str(ssh_public_key).unwrap();

        assert_eq!("test@picky.com".to_owned(), public_key.comment);
        assert_eq!(
            SshBasePublicKey::Rsa(PublicKey::from_rsa_components(
                &BoxedUint::from_be_slice_vartime(&[
                    219, 80, 34, 184, 116, 125, 103, 225, 211, 133, 6, 255, 236, 141, 243, 38, 107, 138, 185, 169, 238,
                    210, 103, 143, 99, 216, 99, 131, 24, 170, 252, 14, 231, 153, 49, 102, 11, 77, 201, 58, 214, 229,
                    12, 50, 85, 65, 79, 117, 242, 95, 169, 158, 233, 126, 22, 176, 26, 34, 143, 52, 22, 190, 12, 41,
                    44, 33, 147, 170, 88, 80, 78, 123, 102, 228, 90, 97, 92, 113, 228, 43, 17, 111, 140, 200, 79, 204,
                    41, 199, 53, 47, 139, 209, 230, 243, 123, 7, 30, 114, 198, 57, 174, 216, 48, 251, 160, 97, 23, 7,
                    89, 26, 17, 65, 126, 39, 245, 255, 171, 61, 171, 188, 187, 251, 193, 158, 222, 21, 8, 18, 162, 221,
                    136, 192, 195, 207, 23, 58, 235, 50, 26, 91, 110, 163, 103, 19, 184, 4, 193, 238, 42, 158, 215,
                    150, 125, 137, 120, 56, 236, 68, 123, 243, 210, 240, 77, 1, 215, 78, 126, 75, 237, 167, 232, 12,
                    239, 99, 135, 226, 217, 189, 193, 47, 213, 241, 181, 78, 103, 175, 40, 83, 74, 44, 240, 59, 162,
                    16, 105, 240, 3, 148, 103, 140, 232, 218, 21, 209, 214, 183, 89, 131, 240, 31, 167, 68, 131, 113,
                    35, 204, 216, 201, 7, 42, 167, 123, 120, 167, 158, 118, 63, 65, 107, 134, 248, 224, 139, 24, 186,
                    237, 28, 154, 199, 64, 212, 54, 236, 205, 216, 202, 80, 208, 228, 84, 129, 25, 31, 203, 252, 86,
                    188, 137, 148, 177, 227, 255, 5, 250, 175, 54, 37, 164, 20, 5, 135, 52, 48, 210, 177, 206, 116, 90,
                    106, 254, 131, 66, 98, 112, 109, 160, 163, 1, 203, 96, 252, 74, 70, 50, 200, 108, 234, 190, 38, 12,
                    71, 172, 78, 19, 117, 160, 54, 52, 154, 30, 82, 154, 73, 129, 101, 56, 202, 225, 165, 229, 252,
                    117, 27, 224, 92, 118, 189, 2, 250, 91, 12, 143, 94, 7, 167, 230, 134, 106, 49, 14, 45, 14, 204,
                    171, 113, 243, 88, 74, 49, 244, 109, 74, 128, 222, 43, 219, 174, 140, 161, 247, 124, 79, 139, 235,
                    140, 94, 137, 107, 209, 62, 166, 157, 41, 94, 1, 47, 217, 203, 237, 96, 146, 207, 210, 167, 107,
                    29, 102, 159, 111, 121, 86, 176, 254, 33, 37, 105, 239, 252, 214, 151, 63, 166, 64, 198, 33, 30,
                    30, 200, 160, 173, 143, 124, 146, 104, 25, 108, 121, 191, 232, 9, 162, 4, 158, 219, 41, 15, 210,
                    252, 247, 165, 98, 61, 230, 76, 189, 26, 98, 65, 133, 239, 218, 149, 180, 12, 210, 151, 188, 136,
                    247, 37, 114, 30, 201, 123, 118, 222, 99, 118, 106, 122, 248, 138, 31, 184, 75, 77, 126, 112, 28,
                    126, 134, 146, 46, 237, 14, 142, 139, 105, 245, 80, 76, 190, 41, 122, 162, 52, 156, 108, 147, 75,
                    4, 191, 45, 24, 222, 62, 186, 178, 28, 176, 213, 47, 86, 48, 14, 159, 7, 55, 158, 139, 97, 43
                ]),
                &BoxedUint::from_be_slice_vartime(&[1, 0, 1])
            )),
            public_key.inner_key
        );
    }

    #[test]
    fn decode_ssh_rsa_2048_public_key() {
        // ssh-keygen -t rsa -b 2048 -C "test2@picky.com"
        let ssh_public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDI9ht2g2qOPgSG5huVYjFUouyaw59/6QuQqUVGwgnITlhRbM+bkvJQfcuiqcv+vD9/86Dfugk79sSfg/aVK+V/plqAAZoujz/wALDjEphSxAUcAR+t4i2F39Pa71MSc37I9L30z31tcba1X7od7hzrVMl9iurkOyBC4xcIWa1H8h0mDyoXyWPTqoTONDUe9dB1eu6GbixCfUcxvdVt0pAVJTdOmbNXKwRo5WXfMrsqKsFT2Acg4Vm4TfLShSSUW4rqM6GOBCfF6jnxFvTSDentH5hykjWL3lMCghD+1hJyOdnMHJC/5qTUGOB86MxsR4RCXqS+LZrGpMScVyDQge7r test2@picky.com\r\n";

        let public_key: SshPublicKey = SshPublicKey::from_str(ssh_public_key).unwrap();

        assert_eq!("test2@picky.com".to_owned(), public_key.comment);
        assert_eq!(
            SshBasePublicKey::Rsa(PublicKey::from_rsa_components(
                &BoxedUint::from_be_slice_vartime(&[
                    200, 246, 27, 118, 131, 106, 142, 62, 4, 134, 230, 27, 149, 98, 49, 84, 162, 236, 154, 195, 159,
                    127, 233, 11, 144, 169, 69, 70, 194, 9, 200, 78, 88, 81, 108, 207, 155, 146, 242, 80, 125, 203,
                    162, 169, 203, 254, 188, 63, 127, 243, 160, 223, 186, 9, 59, 246, 196, 159, 131, 246, 149, 43, 229,
                    127, 166, 90, 128, 1, 154, 46, 143, 63, 240, 0, 176, 227, 18, 152, 82, 196, 5, 28, 1, 31, 173, 226,
                    45, 133, 223, 211, 218, 239, 83, 18, 115, 126, 200, 244, 189, 244, 207, 125, 109, 113, 182, 181,
                    95, 186, 29, 238, 28, 235, 84, 201, 125, 138, 234, 228, 59, 32, 66, 227, 23, 8, 89, 173, 71, 242,
                    29, 38, 15, 42, 23, 201, 99, 211, 170, 132, 206, 52, 53, 30, 245, 208, 117, 122, 238, 134, 110, 44,
                    66, 125, 71, 49, 189, 213, 109, 210, 144, 21, 37, 55, 78, 153, 179, 87, 43, 4, 104, 229, 101, 223,
                    50, 187, 42, 42, 193, 83, 216, 7, 32, 225, 89, 184, 77, 242, 210, 133, 36, 148, 91, 138, 234, 51,
                    161, 142, 4, 39, 197, 234, 57, 241, 22, 244, 210, 13, 233, 237, 31, 152, 114, 146, 53, 139, 222,
                    83, 2, 130, 16, 254, 214, 18, 114, 57, 217, 204, 28, 144, 191, 230, 164, 212, 24, 224, 124, 232,
                    204, 108, 71, 132, 66, 94, 164, 190, 45, 154, 198, 164, 196, 156, 87, 32, 208, 129, 238, 235
                ]),
                &BoxedUint::from_be_slice_vartime(&[1, 0, 1])
            )),
            public_key.inner_key
        );
    }

    #[test]
    fn encode_ssh_rsa_4096_public_key() {
        // ssh-keygen -t rsa -b 4096 -C "test@picky.com"
        let ssh_public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDbUCK4dH1n4dOFBv/sjfMma4q5qe7SZ49j2GODGKr8DueZMWYLTck61uUMMlVBT3XyX6me6X4WsBoijzQWvgwpLCGTqlhQTntm5FphXHHkKxFvjMhPzCnHNS+L0ebzewcecsY5rtgw+6BhFwdZGhFBfif1/6s9q7y7+8Ge3hUIEqLdiMDDzxc66zIaW26jZxO4BMHuKp7Xln2JeDjsRHvz0vBNAddOfkvtp+gM72OH4tm9wS/V8bVOZ68oU0os8DuiEGnwA5RnjOjaFdHWt1mD8B+nRINxI8zYyQcqp3t4p552P0Frhvjgixi67Ryax0DUNuzN2MpQ0ORUgRkfy/xWvImUseP/BfqvNiWkFAWHNDDSsc50Wmr+g0JicG2gowHLYPxKRjLIbOq+JgxHrE4TdaA2NJoeUppJgWU4yuGl5fx1G+Bcdr0C+lsMj14Hp+aGajEOLQ7Mq3HzWEox9G1KgN4r266Mofd8T4vrjF6Ja9E+pp0pXgEv2cvtYJLP0qdrHWafb3lWsP4hJWnv/NaXP6ZAxiEeHsigrY98kmgZbHm/6AmiBJ7bKQ/S/PelYj3mTL0aYkGF79qVtAzSl7yI9yVyHsl7dt5jdmp6+IofuEtNfnAcfoaSLu0Ojotp9VBMvil6ojScbJNLBL8tGN4+urIcsNUvVjAOnwc3nothKw== test@picky.com\r\n";
        let public_key = SshPublicKey::from_str(ssh_public_key).unwrap();

        let ssh_public_key_after = public_key.to_string().unwrap();

        assert_eq!(ssh_public_key, ssh_public_key_after.as_str());
    }

    #[test]
    fn encode_ssh_rsa_2048_public_key() {
        // ssh-keygen -t rsa -b 4096 -C "test@picky.com"
        let ssh_public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDI9ht2g2qOPgSG5huVYjFUouyaw59/6QuQqUVGwgnITlhRbM+bkvJQfcuiqcv+vD9/86Dfugk79sSfg/aVK+V/plqAAZoujz/wALDjEphSxAUcAR+t4i2F39Pa71MSc37I9L30z31tcba1X7od7hzrVMl9iurkOyBC4xcIWa1H8h0mDyoXyWPTqoTONDUe9dB1eu6GbixCfUcxvdVt0pAVJTdOmbNXKwRo5WXfMrsqKsFT2Acg4Vm4TfLShSSUW4rqM6GOBCfF6jnxFvTSDentH5hykjWL3lMCghD+1hJyOdnMHJC/5qTUGOB86MxsR4RCXqS+LZrGpMScVyDQge7r test2@picky.com\r\n";
        let public_key = SshPublicKey::from_str(ssh_public_key).unwrap();

        let ssh_public_key_after = public_key.to_string().unwrap();

        assert_eq!(ssh_public_key, ssh_public_key_after.as_str());
    }

    #[test]
    fn rsa_roundtrip() {
        let public_key = SshPublicKey::from_str(picky_test_data::SSH_PUBLIC_KEY_RSA).unwrap();
        let ssh_public_key_after = public_key.to_string().unwrap();
        assert_eq!(picky_test_data::SSH_PUBLIC_KEY_RSA, ssh_public_key_after.as_str());
    }

    #[rstest]
    #[case(picky_test_data::SSH_PUBLIC_KEY_EC_P256)]
    #[case(picky_test_data::SSH_PUBLIC_KEY_EC_P384)]
    #[case(picky_test_data::SSH_PUBLIC_KEY_EC_P521)]
    fn ecdsa_roundtrip(#[case] key_str: &str) {
        let public_key = SshPublicKey::from_str(key_str).unwrap();
        let ssh_public_key_after = public_key.to_string().unwrap();
        assert_eq!(key_str, ssh_public_key_after.as_str());
    }

    #[test]
    fn ed25519_roundtrip() {
        let public_key = SshPublicKey::from_str(picky_test_data::SSH_PUBLIC_KEY_ED25519).unwrap();
        let ssh_public_key_after = public_key.to_string().unwrap();
        assert_eq!(picky_test_data::SSH_PUBLIC_KEY_ED25519, ssh_public_key_after.as_str());
    }

    #[test]
    fn sk_ed25519_roundtrip() {
        let public_key: SshPublicKey = SshPublicKey::from_str(picky_test_data::SSH_PUBLIC_KEY_SK_ED25519).unwrap();
        let ssh_public_key_after = public_key.to_string().unwrap();
        assert_eq!(
            picky_test_data::SSH_PUBLIC_KEY_SK_ED25519,
            ssh_public_key_after.as_str()
        );
    }

    #[test]
    fn sk_ecdsa_roundtrip() {
        let public_key = SshPublicKey::from_str(picky_test_data::SSH_PUBLIC_KEY_SK_ECDSA).unwrap();
        let ssh_public_key_after = public_key.to_string().unwrap();
        assert_eq!(picky_test_data::SSH_PUBLIC_KEY_SK_ECDSA, ssh_public_key_after.as_str());
    }

    #[test]
    fn fingerprint_md5_ssh_rsa_2048_public_key() {
        let ssh_public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDI9ht2g2qOPgSG5huVYjFUouyaw59/6QuQqUVGwgnITlhRbM+bkvJQfcuiqcv+vD9/86Dfugk79sSfg/aVK+V/plqAAZoujz/wALDjEphSxAUcAR+t4i2F39Pa71MSc37I9L30z31tcba1X7od7hzrVMl9iurkOyBC4xcIWa1H8h0mDyoXyWPTqoTONDUe9dB1eu6GbixCfUcxvdVt0pAVJTdOmbNXKwRo5WXfMrsqKsFT2Acg4Vm4TfLShSSUW4rqM6GOBCfF6jnxFvTSDentH5hykjWL3lMCghD+1hJyOdnMHJC/5qTUGOB86MxsR4RCXqS+LZrGpMScVyDQge7r test2@picky.com\r\n";

        let public_key: SshPublicKey = SshPublicKey::from_str(ssh_public_key).unwrap();
        let md5 = hex::encode(public_key.fingerprint_md5().unwrap());

        assert_eq!(md5, "7b6b9cc2e44452aec58c3a0a31d6258d");
    }

    #[test]
    fn fingerprint_sha1_ssh_rsa_2048_public_key() {
        let ssh_public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDI9ht2g2qOPgSG5huVYjFUouyaw59/6QuQqUVGwgnITlhRbM+bkvJQfcuiqcv+vD9/86Dfugk79sSfg/aVK+V/plqAAZoujz/wALDjEphSxAUcAR+t4i2F39Pa71MSc37I9L30z31tcba1X7od7hzrVMl9iurkOyBC4xcIWa1H8h0mDyoXyWPTqoTONDUe9dB1eu6GbixCfUcxvdVt0pAVJTdOmbNXKwRo5WXfMrsqKsFT2Acg4Vm4TfLShSSUW4rqM6GOBCfF6jnxFvTSDentH5hykjWL3lMCghD+1hJyOdnMHJC/5qTUGOB86MxsR4RCXqS+LZrGpMScVyDQge7r test2@picky.com\r\n";

        let public_key: SshPublicKey = SshPublicKey::from_str(ssh_public_key).unwrap();
        let sha1 = STANDARD_NO_PAD.encode(public_key.fingerprint_sha1().unwrap());

        assert_eq!(sha1, "ezHoULh4V/R9NybfxCW2pL9ADcU");
    }

    #[test]
    fn fingerprint_sha256_ssh_rsa_2048_public_key() {
        let ssh_public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDI9ht2g2qOPgSG5huVYjFUouyaw59/6QuQqUVGwgnITlhRbM+bkvJQfcuiqcv+vD9/86Dfugk79sSfg/aVK+V/plqAAZoujz/wALDjEphSxAUcAR+t4i2F39Pa71MSc37I9L30z31tcba1X7od7hzrVMl9iurkOyBC4xcIWa1H8h0mDyoXyWPTqoTONDUe9dB1eu6GbixCfUcxvdVt0pAVJTdOmbNXKwRo5WXfMrsqKsFT2Acg4Vm4TfLShSSUW4rqM6GOBCfF6jnxFvTSDentH5hykjWL3lMCghD+1hJyOdnMHJC/5qTUGOB86MxsR4RCXqS+LZrGpMScVyDQge7r test2@picky.com\r\n";

        let public_key: SshPublicKey = SshPublicKey::from_str(ssh_public_key).unwrap();

        let sha256 = STANDARD_NO_PAD.encode(public_key.fingerprint_sha256().unwrap());

        assert_eq!(sha256, "cTXkM4frGl07u46Bhzy+YMOS01lX51oE2j6STi7g568");
    }

    #[test]
    fn decode_ssh_rsa_2024_public_key_with_multiwords_comment() {
        // ssh-keygen -t rsa -b 2048 -C "test using several words"
        let ssh_public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC+76yL1+ocu4iuVam4VO5YlODohmHbIuhjyQgiMGS8ZtdFKcltzAH0ot4zJDH/Z3ja6xO2IOc/4+UMABgPOgFwmzyl414/Zo42CYqk9OB5GJylFYI99HrATqH03Wz2qJ3dzP6QJVf8g05hY27RKaU5H+0fo471SACeHet9uqstRecsUcauPS91xwpPhrcpRXjGH1yLBdWTpDq5R6c1Wgh9SVuzY/ITMB3pq8rzwal8e2rR4T+wHc48l61LGwmuOTkhAo5/0sn72CzKWQZVd0CarfCr3biCW7cUai0FvH79aAfIBV/FIMXgtgqdpY/Qg7v+JWIyJk/OB8Be1ix8YVRV test using several words\r\n";

        let public_key = SshPublicKey::from_str(ssh_public_key).unwrap();

        assert_eq!(public_key.comment, "test using several words");
    }
}
