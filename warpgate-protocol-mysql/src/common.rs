use sha1::{Digest, Sha1};
use sha2::Sha256;
use warpgate_common::ProtocolName;

pub const PROTOCOL_NAME: ProtocolName = "MySQL";

/// mysql_native_password scramble:
/// SHA1(password) XOR SHA1(challenge || SHA1(SHA1(password)))
pub fn compute_auth_challenge_response(challenge: [u8; 20], password: &str) -> [u8; 20] {
    let password_sha: [u8; 20] = Sha1::digest(password).into();
    let password_sha_sha: [u8; 20] = Sha1::digest(password_sha).into();
    let password_seed_2sha_sha: [u8; 20] =
        Sha1::digest([challenge, password_sha_sha].concat()).into();

    let mut result = password_sha;
    result
        .iter_mut()
        .zip(password_seed_2sha_sha.iter())
        .for_each(|(x1, x2)| *x1 ^= *x2);
    result
}

/// caching_sha2_password scramble:
/// SHA256(password) XOR SHA256(challenge || SHA256(SHA256(password)))
pub fn compute_sha2_auth_challenge_response(challenge: &[u8], password: &str) -> [u8; 32] {
    let password_sha: [u8; 32] = Sha256::digest(password).into();
    let password_sha_sha: [u8; 32] = Sha256::digest(password_sha).into();
    let challenge_hash: [u8; 32] =
        Sha256::digest([challenge, &password_sha_sha[..]].concat()).into();

    let mut result = password_sha;
    result
        .iter_mut()
        .zip(challenge_hash.iter())
        .for_each(|(x1, x2)| *x1 ^= *x2);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_challenge_response() {
        let challenge: [u8; 20] = core::array::from_fn(|i| i as u8);
        assert_eq!(
            compute_auth_challenge_response(challenge, "123"),
            [
                175, 47, 63, 96, 21, 233, 168, 162, 47, 157, 142, 246, 208, 83, 83, 95, 77, 43,
                192, 65
            ]
        );
    }

    #[test]
    fn test_sha2_auth_challenge_response() {
        let challenge: Vec<u8> = (0..20).collect();
        assert_eq!(
            compute_sha2_auth_challenge_response(&challenge, "123"),
            [
                179, 76, 210, 221, 176, 27, 171, 93, 94, 134, 35, 137, 30, 212, 147, 161, 200, 20,
                105, 29, 137, 8, 15, 176, 155, 21, 88, 219, 62, 46, 92, 70
            ]
        );
    }
}
