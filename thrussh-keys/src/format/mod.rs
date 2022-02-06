use super::is_base64_char;
use crate::key;
use crate::Error;
#[cfg(not(feature = "openssl"))]
use data_encoding::BASE64_MIME;
#[cfg(feature = "openssl")]
use data_encoding::{BASE64_MIME, HEXLOWER_PERMISSIVE};

#[cfg(feature = "openssl")]
use openssl::rsa::Rsa;
use std::io::Write;

pub mod openssh;
pub use self::openssh::*;

#[cfg(feature = "openssl")]
pub mod pkcs5;
#[cfg(feature = "openssl")]
pub use self::pkcs5::*;

pub mod pkcs8;

const AES_128_CBC: &'static str = "DEK-Info: AES-128-CBC,";

#[derive(Clone, Copy, Debug)]
/// AES encryption key.
pub enum Encryption {
    /// Key for AES128
    Aes128Cbc([u8; 16]),
    /// Key for AES256
    Aes256Cbc([u8; 16]),
}

#[derive(Clone, Debug)]
enum Format {
    #[cfg(feature = "openssl")]
    Rsa,
    Openssh,
    #[cfg(feature = "openssl")]
    Pkcs5Encrypted(Encryption),
    Pkcs8Encrypted,
    Pkcs8,
}

/// Decode a secret key, possibly deciphering it with the supplied
/// password.
pub fn decode_secret_key(secret: &str, password: Option<&str>) -> Result<key::KeyPair, Error> {
    let mut format = None;
    let secret = {
        let mut started = false;
        let mut sec = String::new();
        for l in secret.lines() {
            if started == true {
                if l.starts_with("-----END ") {
                    break;
                }
                if l.chars().all(is_base64_char) {
                    sec.push_str(l)
                } else if l.starts_with(AES_128_CBC) {
                    #[cfg(feature = "openssl")]
                    {
                        let iv_: Vec<u8> = HEXLOWER_PERMISSIVE
                            .decode(l.split_at(AES_128_CBC.len()).1.as_bytes())?;
                        if iv_.len() != 16 {
                            return Err(Error::CouldNotReadKey.into());
                        }
                        let mut iv = [0; 16];
                        iv.clone_from_slice(&iv_);
                        format = Some(Format::Pkcs5Encrypted(Encryption::Aes128Cbc(iv)))
                    }
                }
            }
            if l == "-----BEGIN OPENSSH PRIVATE KEY-----" {
                started = true;
                format = Some(Format::Openssh);
            } else if l == "-----BEGIN RSA PRIVATE KEY-----" && cfg!(feature = "openssl") {
                #[cfg(feature = "openssl")]
                {
                    started = true;
                    format = Some(Format::Rsa);
                }
            } else if l == "-----BEGIN ENCRYPTED PRIVATE KEY-----" {
                started = true;
                format = Some(Format::Pkcs8Encrypted);
            } else if l == "-----BEGIN PRIVATE KEY-----" {
                started = true;
                format = Some(Format::Pkcs8);
            }
        }
        sec
    };

    let secret = BASE64_MIME.decode(secret.as_bytes())?;
    match format {
        Some(Format::Openssh) => decode_openssh(&secret, password),
        #[cfg(feature = "openssl")]
        Some(Format::Rsa) => decode_rsa(&secret),
        #[cfg(feature = "openssl")]
        Some(Format::Pkcs5Encrypted(enc)) => decode_pkcs5(&secret, password, enc),
        Some(Format::Pkcs8Encrypted) | Some(Format::Pkcs8) => {
            self::pkcs8::decode_pkcs8(&secret, password.map(|x| x.as_bytes()))
        }
        None => Err(Error::CouldNotReadKey.into()),
    }
}

pub fn encode_pkcs8_pem<W: Write>(key: &key::KeyPair, mut w: W) -> Result<(), Error> {
    let x = self::pkcs8::encode_pkcs8(key);
    w.write_all(b"-----BEGIN PRIVATE KEY-----\n")?;
    w.write_all(BASE64_MIME.encode(&x).as_bytes())?;
    w.write_all(b"\n-----END PRIVATE KEY-----\n")?;
    Ok(())
}

pub fn encode_pkcs8_pem_encrypted<W: Write>(
    key: &key::KeyPair,
    pass: &[u8],
    rounds: u32,
    mut w: W,
) -> Result<(), Error> {
    let x = self::pkcs8::encode_pkcs8_encrypted(pass, rounds, key)?;
    w.write_all(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n")?;
    w.write_all(BASE64_MIME.encode(&x).as_bytes())?;
    w.write_all(b"\n-----END ENCRYPTED PRIVATE KEY-----\n")?;
    Ok(())
}

#[cfg(feature = "openssl")]
fn decode_rsa(secret: &[u8]) -> Result<key::KeyPair, Error> {
    Ok(key::KeyPair::RSA {
        key: Rsa::private_key_from_der(secret)?,
        hash: key::SignatureHash::SHA2_256,
    })
}

fn pkcs_unpad(dec: &mut Vec<u8>) {
    let len = dec.len();
    if len > 0 {
        let padding_len = dec[len - 1];
        if dec[(len - padding_len as usize)..]
            .iter()
            .all(|&x| x == padding_len)
        {
            dec.truncate(len - padding_len as usize)
        }
    }
}
