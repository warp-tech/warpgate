use {Error, ErrorKind, KEYTYPE_ED25519, KEYTYPE_RSA, rsa_key_from_components};
use std;
use thrussh::encoding::Reader;
use thrussh::key;
use super::is_base64_char;
use hex::FromHex;
use base64::{decode_config, MIME};
use ring::signature;
use untrusted;
use yasna;
use ring;

use openssl::symm::{encrypt, decrypt, Cipher, Mode, Crypter};
use openssl::hash::{MessageDigest, Hasher};
use bcrypt_pbkdf;


const PBES2: &'static [u64] = &[1, 2, 840, 113549, 1, 5, 13];
const PBKDF2: &'static [u64] = &[1, 2, 840, 113549, 1, 5, 12];
const HMAC_SHA256: &'static [u64] = &[1, 2, 840, 113549, 2, 9];
const AES256CBC: &'static [u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 42];
const ED25519: &'static [u64] = &[1, 3, 101, 112];
const RSA: &'static [u64] = &[1, 2, 840, 113549, 1, 1, 1];

// https://tools.ietf.org/html/rfc5208
fn decode_pkcs8(
    secret: &[u8],
    password: Option<&[u8]>,
) -> Result<(key::Algorithm, super::KeyPairComponents), Error> {
    if let Some(pass) = password {
        // let mut sec = Vec::new();
        let secret = yasna::parse_der(&secret, |reader| {
            reader.read_sequence(|reader| {
                // Encryption parameters
                let parameters = reader.next().read_sequence(|reader| {
                    let oid = reader.next().read_oid()?;
                    debug!("oid = {:?} {:?}", oid, oid.components().as_slice() == PBES2);
                    if oid.components().as_slice() == PBES2 {
                        asn1_read_pbes2(reader)
                    } else {
                        Ok(Err(ErrorKind::UnknownAlgorithm(oid).into()))
                    }
                })?;
                // Ciphertext
                let ciphertext = reader.next().read_bytes()?;
                Ok(parameters.map(|p| p.decrypt(pass, &ciphertext)))
            })
        })???;
        debug!("secret {:?}", secret);

        let mut oid = None;
        yasna::parse_der(&secret, |reader| {
            reader.read_sequence(|reader| {
                let version = reader.next().read_u64()?;
                debug!("version = {:?}", version);
                reader.next().read_sequence(|reader| {
                    oid = Some(reader.next().read_oid()?);
                    Ok(())
                }).unwrap_or(());
                Ok(())
            })
        }).unwrap_or(());

        debug!("pkcs8 oid {:?}", oid);
        let oid = if let Some(oid) = oid {
            oid
        } else {
            return Err(ErrorKind::CouldNotReadKey.into())
        };
        if oid.components().as_slice() == ED25519 {
            let components = signature::primitive::Ed25519KeyPairComponents::from_pkcs8(
                untrusted::Input::from(&secret),
            )?;
            debug!("components!");
            let keypair = signature::Ed25519KeyPair::from_pkcs8(untrusted::Input::from(&secret))?;
            debug!("keypair!");
            Ok((key::Algorithm::Ed25519(keypair),
                super::KeyPairComponents::Ed25519(components)))

        } else if oid.components().as_slice() == RSA {
            let components = signature::primitive::RSAKeyPairComponents::from_pkcs8(
                untrusted::Input::from(&secret),
            )?;

            let keypair = signature::RSAKeyPair::from_pkcs8(untrusted::Input::from(&secret))?;
            Ok((
                key::Algorithm::RSA(
                    std::sync::Arc::new(keypair),
                    key::RSAPublicKey {
                        n: components.n.as_slice_less_safe().to_vec(),
                        e: components.e.as_slice_less_safe().to_vec(),
                        hash: key::SignatureHash::SHA2_512,
                    },
                ),
                super::KeyPairComponents::RSA(
                    super::RSAKeyPairComponents::from_components(&components),
                ),
            ))
        } else {
            Err(ErrorKind::CouldNotReadKey.into())
        }
    } else {
        Err(ErrorKind::KeyIsEncrypted.into())
    }
}

#[cfg(test)]
use env_logger;

#[test]
fn test_read_write_pkcs8() {
    env_logger::init().unwrap_or(());
    let r = ring::rand::SystemRandom::new();
    let key = ring::signature::Ed25519KeyPair::generate_pkcs8(&r).unwrap();
    let password = b"blabla";
    let ciphertext = encode_pkcs8(&r, &key, Some(password), 100).unwrap();
    let (_, comp) = decode_pkcs8(&ciphertext, Some(password)).unwrap();
    use super::KeyPairComponents;
    match comp {
        KeyPairComponents::Ed25519(_) => debug!("Ed25519"),
        KeyPairComponents::RSA(_) => debug!("RSA"),
    }
}


use yasna::models::ObjectIdentifier;
pub fn encode_pkcs8<R:ring::rand::SecureRandom>(
    rand: &R,
    plaintext: &[u8],
    password: Option<&[u8]>,
    rounds: u32
) -> Result<Vec<u8>, Error> {
    if let Some(pass) = password {

        let mut salt = [0; 64];
        rand.fill(&mut salt)?;
        let mut iv = [0; 16];
        rand.fill(&mut iv)?;
        let mut key = [0; 32]; // AES256-CBC
        ring::pbkdf2::derive(&ring::digest::SHA256, rounds, &salt, pass, &mut key[..]);
        debug!("key = {:?}", key);

        let mut plaintext = plaintext.to_vec();
        let padding_len = 32 - (plaintext.len() % 32);
        plaintext.extend(std::iter::repeat(padding_len as u8).take(padding_len));

        debug!("plaintext {:?}", plaintext);
        let ciphertext = encrypt(Cipher::aes_256_cbc(), &key, Some(&iv), &plaintext)?;

        let v = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                // Encryption parameters
                writer.next().write_sequence(|writer| {
                    writer.next().write_oid(&ObjectIdentifier::from_slice(PBES2));
                    asn1_write_pbes2(writer.next(), rounds as u64, &salt, &iv)
                });
                // Ciphertext
                writer.next().write_bytes(&ciphertext[..])
            })
        });
        Ok(v)
    } else {
        Err(ErrorKind::KeyIsEncrypted.into())
    }
}

fn asn1_write_pbes2(writer: yasna::DERWriter, rounds: u64, salt: &[u8], iv: &[u8]) {
    writer.write_sequence(|writer| {
        // 1. Key generation algorithm
        writer.next().write_sequence(|writer| {
            writer.next().write_oid(&ObjectIdentifier::from_slice(PBKDF2));
            asn1_write_pbkdf2(writer.next(), rounds, salt)
        });
        // 2. Encryption algorithm.
        writer.next().write_sequence(|writer| {
            writer.next().write_oid(&ObjectIdentifier::from_slice(AES256CBC));
            writer.next().write_bytes(iv)
        });
    })
}

fn asn1_write_pbkdf2(writer: yasna::DERWriter, rounds: u64, salt: &[u8]) {
    writer.write_sequence(|writer| {
        writer.next().write_bytes(salt);
        writer.next().write_u64(rounds);
        writer.next().write_sequence(|writer| {
            writer.next().write_oid(&ObjectIdentifier::from_slice(HMAC_SHA256));
            writer.next().write_null()
        })
    })
}

enum Algorithms {
    Pbes2(KeyDerivation, Encryption),
}

impl Algorithms {
    fn decrypt(&self, password: &[u8], cipher: &[u8]) -> Result<Vec<u8>, Error> {
        match *self {
            Algorithms::Pbes2(ref der, ref enc) => {
                let mut key = enc.key();
                der.derive(password, &mut key);
                let out = enc.decrypt(&key, cipher)?;
                Ok(out)
            }
        }
    }
}

impl KeyDerivation {
    fn derive(&self, password: &[u8], key: &mut [u8]) {
        match *self {
            KeyDerivation::Pbkdf2 {
                ref salt,
                rounds,
                digest,
            } => ring::pbkdf2::derive(digest, rounds as u32, salt, password, key),
        }
    }
}

enum Key {
    K128([u8; 16]),
    K256([u8; 32]),
}

impl std::ops::Deref for Key {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match *self {
            Key::K128(ref k) => k,
            Key::K256(ref k) => k,
        }
    }
}

impl std::ops::DerefMut for Key {
    fn deref_mut(&mut self) -> &mut [u8] {
        match *self {
            Key::K128(ref mut k) => k,
            Key::K256(ref mut k) => k,
        }
    }
}

impl Encryption {
    fn key(&self) -> Key {
        match *self {
            Encryption::Aes128Cbc(_) => Key::K128([0; 16]),
            Encryption::Aes256Cbc(_) => Key::K256([0; 32]),
        }
    }

    fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let (cipher, iv) = match *self {
            Encryption::Aes128Cbc(ref iv) => (Cipher::aes_128_cbc(), iv),
            Encryption::Aes256Cbc(ref iv) => (Cipher::aes_256_cbc(), iv),
        };
        let mut dec = decrypt(
            cipher,
            &key,
            Some(&iv[..]),
            ciphertext
        )?;
        pkcs_unpad(&mut dec);
        Ok(dec)
    }
}

enum KeyDerivation {
    Pbkdf2 {
        salt: Vec<u8>,
        rounds: u64,
        digest: &'static ring::digest::Algorithm,
    },
}

fn asn1_read_pbes2(
    reader: &mut yasna::BERReaderSeq,
) -> Result<Result<Algorithms, Error>, yasna::ASN1Error> {
    reader.next().read_sequence(|reader| {
        // PBES2 has two components.
        // 1. Key generation algorithm
        let keygen = reader.next().read_sequence(|reader| {
            let oid = reader.next().read_oid()?;
            if oid.components().as_slice() == PBKDF2 {
                asn1_read_pbkdf2(reader)
            } else {
                Ok(Err(ErrorKind::UnknownAlgorithm(oid).into()))
            }
        })?;
        // 2. Encryption algorithm.
        let algorithm = reader.next().read_sequence(|reader| {
            let oid = reader.next().read_oid()?;
            if oid.components().as_slice() == AES256CBC {
                asn1_read_aes256cbc(reader)
            } else {
                Ok(Err(ErrorKind::UnknownAlgorithm(oid).into()))
            }
        })?;
        Ok(keygen.and_then(|keygen| {
            algorithm.map(|algo| Algorithms::Pbes2(keygen, algo))
        }))
    })
}

fn asn1_read_pbkdf2(
    reader: &mut yasna::BERReaderSeq,
) -> Result<Result<KeyDerivation, Error>, yasna::ASN1Error> {
    reader.next().read_sequence(|reader| {
        let salt = reader.next().read_bytes()?;
        let rounds = reader.next().read_u64()?;
        let digest = reader.next().read_sequence(|reader| {
            let oid = reader.next().read_oid()?;
            if oid.components().as_slice() == HMAC_SHA256 {
                reader.next().read_null()?;
                Ok(Ok(&ring::digest::SHA256))
            } else {
                Ok(Err(ErrorKind::UnknownAlgorithm(oid).into()))
            }
        })?;
        Ok(digest.map(|digest| {
            KeyDerivation::Pbkdf2 {
                salt,
                rounds,
                digest,
            }
        }))
    })
}

fn asn1_read_aes256cbc(
    reader: &mut yasna::BERReaderSeq,
) -> Result<Result<Encryption, Error>, yasna::ASN1Error> {
    let iv = reader.next().read_bytes()?;
    let mut i = [0; 16];
    i.clone_from_slice(&iv);
    Ok(Ok(Encryption::Aes256Cbc(i)))

}
