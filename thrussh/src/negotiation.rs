// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
use crate::{cipher, kex, msg, Error};
use std::str::from_utf8;
use thrussh_keys::key;
// use super::mac; // unimplemented
use crate::compression::*;
use cryptovec::CryptoVec;
use thrussh_keys::encoding::{Encoding, Reader};
use thrussh_keys::key::{KeyPair, PublicKey};
use rand::RngCore;

#[derive(Debug)]
pub struct Names {
    pub kex: kex::Name,
    pub key: key::Name,
    pub cipher: cipher::Name,
    pub mac: Option<&'static str>,
    pub server_compression: Compression,
    pub client_compression: Compression,
    pub ignore_guessed: bool,
}

/// Lists of preferred algorithms. This is normally hard-coded into implementations.
#[derive(Debug)]
pub struct Preferred {
    /// Preferred key exchange algorithms.
    pub kex: &'static [kex::Name],
    /// Preferred public key algorithms.
    pub key: &'static [key::Name],
    /// Preferred symmetric ciphers.
    pub cipher: &'static [cipher::Name],
    /// Preferred MAC algorithms.
    pub mac: &'static [&'static str],
    /// Preferred compression algorithms.
    pub compression: &'static [&'static str],
}

impl Preferred {
    #[cfg(feature = "openssl")]
    pub const DEFAULT: Preferred = Preferred {
        kex: &[kex::CURVE25519],
        key: &[key::ED25519, key::RSA_SHA2_256, key::RSA_SHA2_512],
        cipher: &[cipher::chacha20poly1305::NAME, cipher::aes256gcm::NAME, cipher::aes256gcm::NAME_ALT],
        mac: &["none"],
        compression: &["none", "zlib", "zlib@openssh.com"],
    };

    #[cfg(not(feature = "openssl"))]
    pub const DEFAULT: Preferred = Preferred {
        kex: &[kex::CURVE25519],
        key: &[key::ED25519],
        cipher: &[cipher::chacha20poly1305::NAME, cipher::aes256gcm::NAME, cipher::aes256gcm::NAME_ALT],
        mac: &["none"],
        compression: &["none", "zlib", "zlib@openssh.com"],
    };

    pub const COMPRESSED: Preferred = Preferred {
        kex: &[kex::CURVE25519],
        key: &[key::ED25519, key::RSA_SHA2_256, key::RSA_SHA2_512],
        cipher: &[cipher::chacha20poly1305::NAME, cipher::aes256gcm::NAME, cipher::aes256gcm::NAME_ALT],
        mac: &["none"],
        compression: &["zlib", "zlib@openssh.com", "none"],
    };
}

impl Default for Preferred {
    fn default() -> Preferred {
        Preferred::DEFAULT
    }
}

/// Named algorithms.
pub trait Named {
    /// The name of this algorithm.
    fn name(&self) -> &'static str;
}

impl Named for () {
    fn name(&self) -> &'static str {
        ""
    }
}

#[cfg(feature = "openssl")]
use thrussh_keys::key::{ED25519, SSH_RSA};
#[cfg(not(feature = "openssl"))]
use thrussh_keys::key::{ED25519};

impl Named for PublicKey {
    fn name(&self) -> &'static str {
        match self {
            &PublicKey::Ed25519(_) => ED25519.0,
            #[cfg(feature = "openssl")]
            &PublicKey::RSA { .. } => SSH_RSA.0,
        }
    }
}

impl Named for KeyPair {
    fn name(&self) -> &'static str {
        match self {
            &KeyPair::Ed25519 { .. } => ED25519.0,
            #[cfg(feature = "openssl")]
            &KeyPair::RSA { ref hash, .. } => hash.name().0,
        }
    }
}

pub trait Select {
    fn select<S: AsRef<str> + Copy>(a: &[S], b: &[u8]) -> Option<(bool, S)>;

    fn read_kex(buffer: &[u8], pref: &Preferred) -> Result<Names, Error> {
        let mut r = buffer.reader(17);
        let kex_string = r.read_string()?;
        let (kex_both_first, kex_algorithm) = if let Some(x) = Self::select(pref.kex, kex_string) {
            x
        } else {
            debug!(
                "Could not find common kex algorithm, other side only supports {:?}, we only support {:?}",
                from_utf8(kex_string),
                pref.kex
            );
            return Err(Error::NoCommonKexAlgo.into());
        };

        let key_string = r.read_string()?;
        let (key_both_first, key_algorithm) = if let Some(x) = Self::select(pref.key, key_string) {
            x
        } else {
            debug!(
                "Could not find common key algorithm, other side only supports {:?}, we only support {:?}",
                from_utf8(key_string),
                pref.key
            );
            return Err(Error::NoCommonKeyAlgo.into());
        };

        let cipher_string = r.read_string()?;
        let cipher = Self::select(pref.cipher, cipher_string);
        if cipher.is_none() {
            debug!(
                "Could not find common cipher, other side only supports {:?}, we only support {:?}",
                from_utf8(cipher_string),
                pref.cipher
            );
            return Err(Error::NoCommonCipher.into());
        }
        r.read_string()?; // cipher server-to-client.
        debug!("kex {}", line!());
        let mac = Self::select(pref.mac, r.read_string()?);
        let mac = mac.and_then(|(_, x)| Some(x));
        r.read_string()?; // mac server-to-client.

        debug!("kex {}", line!());
        // client-to-server compression.
        let client_compression =
            if let Some((_, c)) = Self::select(pref.compression, r.read_string()?) {
                Compression::from_string(c)
            } else {
                return Err(Error::NoCommonCompression.into());
            };
        debug!("kex {}", line!());
        // server-to-client compression.
        let server_compression =
            if let Some((_, c)) = Self::select(pref.compression, r.read_string()?) {
                Compression::from_string(c)
            } else {
                return Err(Error::NoCommonCompression.into());
            };
        debug!("client_compression = {:?}", client_compression);
        r.read_string()?; // languages client-to-server
        r.read_string()?; // languages server-to-client

        let follows = r.read_byte()? != 0;
        match (cipher, mac, follows) {
            (Some((_, cipher)), mac, fol) => {
                Ok(Names {
                    kex: kex_algorithm,
                    key: key_algorithm,
                    cipher,
                    mac,
                    client_compression,
                    server_compression,
                    // Ignore the next packet if (1) it follows and (2) it's not the correct guess.
                    ignore_guessed: fol && !(kex_both_first && key_both_first),
                })
            }
            _ => Err(Error::KexInit.into()),
        }
    }
}

pub struct Server;
pub struct Client;

impl Select for Server {
    fn select<S: AsRef<str> + Copy>(server_list: &[S], client_list: &[u8]) -> Option<(bool, S)> {
        let mut both_first_choice = true;
        for c in client_list.split(|&x| x == b',') {
            for &s in server_list {
                if c == s.as_ref().as_bytes() {
                    return Some((both_first_choice, s));
                }
                both_first_choice = false
            }
        }
        None
    }
}

impl Select for Client {
    fn select<S: AsRef<str> + Copy>(client_list: &[S], server_list: &[u8]) -> Option<(bool, S)> {
        let mut both_first_choice = true;
        for &c in client_list {
            for s in server_list.split(|&x| x == b',') {
                if s == c.as_ref().as_bytes() {
                    return Some((both_first_choice, c));
                }
                both_first_choice = false
            }
        }
        None
    }
}

pub fn write_kex(prefs: &Preferred, buf: &mut CryptoVec) -> Result<(), Error> {
    // buf.clear();
    buf.push(msg::KEXINIT);

    let mut cookie = [0; 16];
    rand::thread_rng().fill_bytes(&mut cookie);

    buf.extend(&cookie); // cookie
    buf.extend_list(prefs.kex.iter()); // kex algo

    buf.extend_list(prefs.key.iter());

    buf.extend_list(prefs.cipher.iter()); // cipher client to server
    buf.extend_list(prefs.cipher.iter()); // cipher server to client

    buf.extend_list(prefs.mac.iter()); // mac client to server
    buf.extend_list(prefs.mac.iter()); // mac server to client
    buf.extend_list(prefs.compression.iter()); // compress client to server
    buf.extend_list(prefs.compression.iter()); // compress server to client

    buf.write_empty_list(); // languages client to server
    buf.write_empty_list(); // languagesserver to client

    buf.push(0); // doesn't follow
    buf.extend(&[0, 0, 0, 0]); // reserved
    Ok(())
}
