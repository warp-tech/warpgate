use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use md5::{Digest, Md5};

use crate::VncError;

pub(super) const CREDENTIAL_BLOCK_LEN: usize = 128;
const FIELD_LEN: usize = 64;

/// MD5 of the Diffie-Hellman shared secret is the AES-128 session key.
pub(super) fn session_key(shared: &[u8]) -> [u8; 16] {
    let digest = Md5::digest(shared);
    let mut key = [0u8; 16];
    key.copy_from_slice(&digest);
    key
}

/// Pack `username` and `password` into the fixed 128-byte layout
/// `username[64] || password[64]`, NUL-terminated, and encrypt it with
/// AES-128-ECB without padding.
pub(super) fn encrypt_credentials(
    username: &str,
    password: &str,
    key: &[u8; 16],
) -> Result<[u8; CREDENTIAL_BLOCK_LEN], VncError> {
    let mut block = [0u8; CREDENTIAL_BLOCK_LEN];
    getrandom::getrandom(&mut block)
        .map_err(|e| VncError::General(format!("ARD: no randomness available: {e}")))?;
    write_field(&mut block[..FIELD_LEN], username);
    write_field(&mut block[FIELD_LEN..], password);

    let cipher = Aes128::new(GenericArray::from_slice(key));
    for chunk in block.as_chunks_mut::<16>().0 {
        cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
    }
    Ok(block)
}

fn write_field(field: &mut [u8], value: &str) {
    let bytes = value.as_bytes();
    let length = bytes.len().min(field.len() - 1);
    if bytes.len() > length {
        tracing::warn!("ARD: credential field truncated to {length} bytes");
    }
    field[..length].copy_from_slice(&bytes[..length]);
    field[length] = 0;
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockDecrypt;

    const KEY: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    fn decrypt(
        mut block: [u8; CREDENTIAL_BLOCK_LEN],
        key: &[u8; 16],
    ) -> [u8; CREDENTIAL_BLOCK_LEN] {
        let cipher = Aes128::new(GenericArray::from_slice(key));
        for chunk in block.as_chunks_mut::<16>().0 {
            cipher.decrypt_block(GenericArray::from_mut_slice(chunk));
        }
        block
    }

    #[test]
    fn credentials_are_packed_and_encrypted() {
        let encrypted = encrypt_credentials("vncuser", "s3cret!", &KEY).unwrap();
        let block = decrypt(encrypted, &KEY);
        assert_eq!(&block[..7], b"vncuser");
        assert_eq!(block[7], 0);
        assert_eq!(&block[64..71], b"s3cret!");
        assert_eq!(block[71], 0);
        assert!(block[72..].iter().any(|&byte| byte != 0));
    }

    #[test]
    fn long_fields_are_truncated_to_63_bytes() {
        let username = "u".repeat(80);
        let password = "p".repeat(70);
        let encrypted = encrypt_credentials(&username, &password, &KEY).unwrap();
        let block = decrypt(encrypted, &KEY);
        assert!(block[..63].iter().all(|&byte| byte == b'u'));
        assert_eq!(block[63], 0);
        assert!(block[64..127].iter().all(|&byte| byte == b'p'));
        assert_eq!(block[127], 0);
    }
}
