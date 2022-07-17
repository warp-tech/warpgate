use sha1::Digest;
use sqlx_core_guts::error::Error as SqlxError;
use sqlx_core_guts::mysql::MySqlConnectOptions;
use warpgate_common::ProtocolName;

use crate::error::InvalidMySqlTargetConfig;

pub const PROTOCOL_NAME: ProtocolName = "MySQL";

pub fn parse_mysql_uri(uri: &str) -> Result<MySqlConnectOptions, InvalidMySqlTargetConfig> {
    uri.parse().map_err(|e| match e {
        SqlxError::Configuration(e) => InvalidMySqlTargetConfig::UriParse(e),
        _ => InvalidMySqlTargetConfig::Unknown,
    })
}

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
