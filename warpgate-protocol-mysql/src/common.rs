use sha1::Digest;
use warpgate_common::ProtocolName;

pub const PROTOCOL_NAME: ProtocolName = "MySQL";

pub fn compute_auth_challenge_response(
    challenge: [u8; 20],
    password: &str,
) -> Result<password_hash::Output, password_hash::Error> {
    password_hash::Output::new(
        &{
            let password_sha: [u8; 20] = sha1::Sha1::digest(password).into();
            let password_sha_sha: [u8; 20] = sha1::Sha1::digest(password_sha).into();
            let password_seed_2sha_sha: [u8; 20] =
                sha1::Sha1::digest([challenge, password_sha_sha].concat()).into();

            let mut result = password_sha;
            result
                .iter_mut()
                .zip(password_seed_2sha_sha.iter())
                .for_each(|(x1, x2)| *x1 ^= *x2);
            result
        }[..],
    )
}
