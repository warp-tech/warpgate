//! Low-level crypto primitives shared by both O5LOGON legs.
//!
//! These mirror python-oracledb thin `impl/thin/crypto.pyx`
//! (<https://github.com/oracle/python-oracledb/blob/main/src/oracledb/impl/thin/crypto.pyx>):
//! AES is **always** CBC with a fixed all-zero 16-byte IV, and encryption
//! applies PKCS#7 padding (`n = 16 - len % 16`, that many bytes of value `n`,
//! and a full block of padding when the input is already block-aligned).
//! Decryption does **not** strip padding — callers slice known offsets — so the
//! raw decryptor here returns the full plaintext including any padding.
//!
//! Only the format-independent primitives live here; the O5LOGON assembly that
//! uses them is in [`crate::o5logon`] and [`crate::client_crypto`].

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes256, Block};
use sha2::{Digest, Sha512};

const BLOCK: usize = 16;
const ZERO_IV: [u8; BLOCK] = [0u8; BLOCK];

/// PBKDF2-HMAC-SHA512, as used for the 12c verifier key and `combo_key`.
pub fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32, dklen: usize) -> Vec<u8> {
    let mut out = vec![0u8; dklen];
    pbkdf2_hmac_sha512_into(password, salt, iterations, &mut out);
    out
}

/// [`pbkdf2_hmac_sha512`] filling `out` (its length is the derived key length).
pub fn pbkdf2_hmac_sha512_into(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    pbkdf2::pbkdf2_hmac::<Sha512>(password, salt, iterations, out);
}

/// The first 32 bytes of SHA-512 over the concatenation of `parts`: the AES-256
/// key O5LOGON wraps the session-key halves with.
pub fn sha512_prefix32(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    for part in parts {
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    for (o, d) in out.iter_mut().zip(digest.iter()) {
        *o = *d;
    }
    out
}

/// AES-256-CBC encrypt with a zero IV and PKCS#7 padding (Oracle's scheme).
pub fn aes256_cbc_encrypt(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let pad = BLOCK - (data.len() % BLOCK); // 1..=16, always a full block when aligned
    let mut buf = Vec::with_capacity(data.len() + pad);
    buf.extend_from_slice(data);
    buf.extend(std::iter::repeat_n(pad as u8, pad));
    cbc_encrypt_in_place(key, &mut buf);
    buf
}

/// AES-256-CBC encrypt with a zero IV and **no** padding. Oracle's 12c server
/// `AUTH_SESSKEY` is exactly this: a 32-byte session key enciphered as two raw
/// blocks (no PKCS#7), which strict thick/OCI clients require (they reject the
/// padded 64-byte form). `None` if `data` is not a whole number of blocks.
pub fn aes256_cbc_encrypt_raw(key: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
    if !data.len().is_multiple_of(BLOCK) {
        return None;
    }
    let mut buf = data.to_vec();
    cbc_encrypt_in_place(key, &mut buf);
    Some(buf)
}

/// CBC-encrypt `buf`, a whole number of blocks, in place with a zero IV.
fn cbc_encrypt_in_place(key: &[u8; 32], buf: &mut [u8]) {
    let cipher = Aes256::new(key.into());
    let mut prev = ZERO_IV;
    for chunk in buf.as_chunks_mut::<BLOCK>().0 {
        let mut block = Block::default();
        for ((b, &c), &p) in block.iter_mut().zip(chunk.iter()).zip(prev.iter()) {
            *b = c ^ p;
        }
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
        prev.copy_from_slice(chunk);
    }
}

/// AES-256-CBC decrypt with a zero IV, returning the raw plaintext **without**
/// stripping padding (callers slice fixed offsets, as python-oracledb does).
/// `None` if `data` is not a whole number of 16-byte blocks.
pub fn aes256_cbc_decrypt_raw(key: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
    if !data.len().is_multiple_of(BLOCK) {
        return None;
    }
    let cipher = Aes256::new(key.into());
    let mut out = data.to_vec();
    let mut prev = ZERO_IV;
    for chunk in out.as_chunks_mut::<BLOCK>().0 {
        let mut cur = [0u8; BLOCK];
        cur.copy_from_slice(chunk);
        let mut block = Block::from(cur);
        cipher.decrypt_block(&mut block);
        for ((o, &d), &p) in chunk.iter_mut().zip(block.iter()).zip(prev.iter()) {
            *o = d ^ p;
        }
        prev = cur;
    }
    Some(out)
}

/// Uppercase hex, the encoding Oracle uses for the auth key/value byte strings.
pub fn hex_upper(bytes: &[u8]) -> String {
    hex::encode_upper(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_hmac_sha512_known_answer() {
        // RFC-style KAT: P="password", S="salt", c=1, dkLen=64.
        let out = pbkdf2_hmac_sha512(b"password", b"salt", 1, 64);
        let expected = hex::decode(
            "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252\
             c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce",
        )
        .unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn pbkdf2_is_deterministic_and_sized() {
        let a = pbkdf2_hmac_sha512(b"pw", b"salt", 4096, 32);
        let b = pbkdf2_hmac_sha512(b"pw", b"salt", 4096, 32);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn aes_cbc_round_trips_with_pkcs7() {
        let key = [7u8; 32];
        let plain = b"select 1 from dual"; // 18 bytes -> pad = 16 - 2 = 14
        let ct = aes256_cbc_encrypt(&key, plain);
        assert_eq!(ct.len() % 16, 0);
        assert_eq!(ct.len(), 32); // 18 padded up to two blocks

        let pt = aes256_cbc_decrypt_raw(&key, &ct).unwrap();
        assert_eq!(&pt[..plain.len()], plain);
        // PKCS#7: the trailing `pad` bytes all equal `pad`.
        let pad = pt[pt.len() - 1] as usize;
        assert_eq!(pad, 14);
        assert!(pt[pt.len() - pad..].iter().all(|&b| b as usize == pad));
    }

    #[test]
    fn aes_cbc_pads_a_full_block_when_aligned() {
        let key = [0u8; 32];
        let plain = [0xABu8; 16]; // already block-aligned -> a whole extra block
        let ct = aes256_cbc_encrypt(&key, &plain);
        assert_eq!(ct.len(), 32);
        let pt = aes256_cbc_decrypt_raw(&key, &ct).unwrap();
        assert_eq!(&pt[..16], &plain);
        assert!(pt[16..].iter().all(|&b| b == 16));
    }

    #[test]
    fn hex_upper_is_uppercase() {
        assert_eq!(hex_upper(&[0x0a, 0xff, 0x42]), "0AFF42");
    }
}
