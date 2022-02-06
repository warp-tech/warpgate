#![deny(trivial_casts, unstable_features, unused_import_braces)]
//! This crate contains methods to deal with SSH keys, as defined in
//! crate Thrussh. This includes in particular various functions for
//! opening key files, deciphering encrypted keys, and dealing with
//! agents.
//!
//! The following example (which uses the `openssl` feature) shows how
//! to do all these in a single example: start and SSH agent server,
//! connect to it with a client, decipher an encrypted private key
//! (the password is `b"blabla"`), send it to the agent, and ask the
//! agent to sign a piece of data (`b"Please sign this", below).
//!
//!```
//! use thrussh_keys::*;
//! use futures::Future;
//!
//! #[derive(Clone)]
//! struct X{}
//! impl agent::server::Agent for X {
//!     fn confirm(self, _: std::sync::Arc<key::KeyPair>) -> Box<dyn Future<Output = (Self, bool)> + Send + Unpin> {
//!         Box::new(futures::future::ready((self, true)))
//!     }
//! }
//!
//! const PKCS8_ENCRYPTED: &'static str = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQITo1O0b8YrS0CAggA\nMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBBtLH4T1KOfo1GGr7salhR8BIIE\n0KN9ednYwcTGSX3hg7fROhTw7JAJ1D4IdT1fsoGeNu2BFuIgF3cthGHe6S5zceI2\nMpkfwvHbsOlDFWMUIAb/VY8/iYxhNmd5J6NStMYRC9NC0fVzOmrJqE1wITqxtORx\nIkzqkgFUbaaiFFQPepsh5CvQfAgGEWV329SsTOKIgyTj97RxfZIKA+TR5J5g2dJY\nj346SvHhSxJ4Jc0asccgMb0HGh9UUDzDSql0OIdbnZW5KzYJPOx+aDqnpbz7UzY/\nP8N0w/pEiGmkdkNyvGsdttcjFpOWlLnLDhtLx8dDwi/sbEYHtpMzsYC9jPn3hnds\nTcotqjoSZ31O6rJD4z18FOQb4iZs3MohwEdDd9XKblTfYKM62aQJWH6cVQcg+1C7\njX9l2wmyK26Tkkl5Qg/qSfzrCveke5muZgZkFwL0GCcgPJ8RixSB4GOdSMa/hAMU\nkvFAtoV2GluIgmSe1pG5cNMhurxM1dPPf4WnD+9hkFFSsMkTAuxDZIdDk3FA8zof\nYhv0ZTfvT6V+vgH3Hv7Tqcxomy5Qr3tj5vvAqqDU6k7fC4FvkxDh2mG5ovWvc4Nb\nXv8sed0LGpYitIOMldu6650LoZAqJVv5N4cAA2Edqldf7S2Iz1QnA/usXkQd4tLa\nZ80+sDNv9eCVkfaJ6kOVLk/ghLdXWJYRLenfQZtVUXrPkaPpNXgD0dlaTN8KuvML\nUw/UGa+4ybnPsdVflI0YkJKbxouhp4iB4S5ACAwqHVmsH5GRnujf10qLoS7RjDAl\no/wSHxdT9BECp7TT8ID65u2mlJvH13iJbktPczGXt07nBiBse6OxsClfBtHkRLzE\nQF6UMEXsJnIIMRfrZQnduC8FUOkfPOSXc8r9SeZ3GhfbV/DmWZvFPCpjzKYPsM5+\nN8Bw/iZ7NIH4xzNOgwdp5BzjH9hRtCt4sUKVVlWfEDtTnkHNOusQGKu7HkBF87YZ\nRN/Nd3gvHob668JOcGchcOzcsqsgzhGMD8+G9T9oZkFCYtwUXQU2XjMN0R4VtQgZ\nrAxWyQau9xXMGyDC67gQ5xSn+oqMK0HmoW8jh2LG/cUowHFAkUxdzGadnjGhMOI2\nzwNJPIjF93eDF/+zW5E1l0iGdiYyHkJbWSvcCuvTwma9FIDB45vOh5mSR+YjjSM5\nnq3THSWNi7Cxqz12Q1+i9pz92T2myYKBBtu1WDh+2KOn5DUkfEadY5SsIu/Rb7ub\n5FBihk2RN3y/iZk+36I69HgGg1OElYjps3D+A9AjVby10zxxLAz8U28YqJZm4wA/\nT0HLxBiVw+rsHmLP79KvsT2+b4Diqih+VTXouPWC/W+lELYKSlqnJCat77IxgM9e\nYIhzD47OgWl33GJ/R10+RDoDvY4koYE+V5NLglEhbwjloo9Ryv5ywBJNS7mfXMsK\n/uf+l2AscZTZ1mhtL38efTQCIRjyFHc3V31DI0UdETADi+/Omz+bXu0D5VvX+7c6\nb1iVZKpJw8KUjzeUV8yOZhvGu3LrQbhkTPVYL555iP1KN0Eya88ra+FUKMwLgjYr\nJkUx4iad4dTsGPodwEP/Y9oX/Qk3ZQr+REZ8lg6IBoKKqqrQeBJ9gkm1jfKE6Xkc\nCog3JMeTrb3LiPHgN6gU2P30MRp6L1j1J/MtlOAr5rux\n-----END ENCRYPTED PRIVATE KEY-----\n";
//!
//! fn main() {
//!    env_logger::try_init().unwrap_or(());
//!    let dir = tempdir::TempDir::new("thrussh").unwrap();
//!    let agent_path = dir.path().join("agent");
//!
//!    let mut core = tokio::runtime::Runtime::new().unwrap();
//!    let agent_path_ = agent_path.clone();
//!    // Starting a server
//!    core.spawn(async move {
//!        let mut listener = tokio::net::UnixListener::bind(&agent_path_)
//!            .unwrap();
//!        thrussh_keys::agent::server::serve(tokio_stream::wrappers::UnixListenerStream::new(listener), X {}).await
//!    });
//!    let key = decode_secret_key(PKCS8_ENCRYPTED, Some("blabla")).unwrap();
//!    let public = key.clone_public_key();
//!    core.block_on(async move {
//!        let stream = tokio::net::UnixStream::connect(&agent_path).await?;
//!        let mut client = agent::client::AgentClient::connect(stream);
//!        client.add_identity(&key, &[agent::Constraint::KeyLifetime { seconds: 60 }]).await?;
//!        client.request_identities().await?;
//!        let buf = b"signed message";
//!        let sig = client.sign_request(&public, cryptovec::CryptoVec::from_slice(&buf[..])).await.1.unwrap();
//!        // Here, `sig` is encoded in a format usable internally by the SSH protocol.
//!        Ok::<(), Error>(())
//!    }).unwrap()
//! }
//!```

#![recursion_limit = "128"]
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate thiserror;
#[macro_use]
extern crate log;

#[cfg(test)]
extern crate env_logger;

use byteorder::{BigEndian, WriteBytesExt};
use data_encoding::BASE64_MIME;
use std::borrow::Cow;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

pub mod encoding;
pub mod key;
pub mod signature;

mod format;
pub use format::*;

/// A module to write SSH agent.
pub mod agent;

#[derive(Debug, Error)]
pub enum Error {
    /// The key could not be read, for an unknown reason
    #[error("Could not read key")]
    CouldNotReadKey,
    /// The type of the key is unsupported
    #[error("Unsupported key type")]
    UnsupportedKeyType(Vec<u8>),
    /// The key is encrypted (should supply a password?)
    #[error("The key is encrypted")]
    KeyIsEncrypted,
    /// Home directory could not be found
    #[error("No home directory found")]
    NoHomeDir,
    /// The server key has changed
    #[error("The server key changed at line {}", line)]
    KeyChanged { line: usize },
    /// The key uses an unsupported algorithm
    #[error("Unknown key algorithm")]
    UnknownAlgorithm(yasna::models::ObjectIdentifier),
    /// Index out of bounds
    #[error("Index out of bounds")]
    IndexOutOfBounds,
    /// Unknown signature type
    #[error("Unknown signature type: {}", sig_type)]
    UnknownSignatureType { sig_type: String },
    /// Agent protocol error
    #[error("Agent protocol error")]
    AgentProtocolError,
    #[error("Agent failure")]
    AgentFailure,
    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[cfg(feature = "openssl")]
    #[error(transparent)]
    Openssl(#[from] openssl::error::ErrorStack),

    #[error(transparent)]
    BlockMode(#[from] block_modes::BlockModeError),

    #[error("Base64 decoding error: {0}")]
    Decode(#[from] data_encoding::DecodeError),
    #[error("ASN1 decoding error: {0}")]
    ASN1(yasna::ASN1Error),
    #[error("Environment variable `{0}` not found")]
    EnvVar(&'static str),
    #[error("Unable to connect to ssh-agent. The environment variable `SSH_AUTH_SOCK` \
    was set, but it points to a nonexistent file or directory.")]
    BadAuthSock,
}

impl From<yasna::ASN1Error> for Error {
    fn from(e: yasna::ASN1Error) -> Error {
        Error::ASN1(e)
    }
}

const KEYTYPE_ED25519: &'static [u8] = b"ssh-ed25519";
const KEYTYPE_RSA: &'static [u8] = b"ssh-rsa";

/// Load a public key from a file. Ed25519 and RSA keys are supported.
///
/// ```
/// thrussh_keys::load_public_key("/home/pe/.ssh/id_ed25519.pub").unwrap();
/// ```
pub fn load_public_key<P: AsRef<Path>>(path: P) -> Result<key::PublicKey, Error> {
    let mut pubkey = String::new();
    let mut file = File::open(path.as_ref())?;
    file.read_to_string(&mut pubkey)?;

    let mut split = pubkey.split_whitespace();
    match (split.next(), split.next()) {
        (Some(_), Some(key)) => parse_public_key_base64(key),
        (Some(key), None) => parse_public_key_base64(key),
        _ => Err(Error::CouldNotReadKey.into()),
    }
}

/// Reads a public key from the standard encoding. In some cases, the
/// encoding is prefixed with a key type identifier and a space (such
/// as `ssh-ed25519 AAAAC3N...`).
///
/// ```
/// thrussh_keys::parse_public_key_base64("AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ").is_ok();
/// ```
pub fn parse_public_key_base64(key: &str) -> Result<key::PublicKey, Error> {
    let base = BASE64_MIME.decode(key.as_bytes())?;
    Ok(key::parse_public_key(&base)?)
}

pub trait PublicKeyBase64 {
    /// Create the base64 part of the public key blob.
    fn public_key_bytes(&self) -> Vec<u8>;
    fn public_key_base64(&self) -> String {
        let mut s = BASE64_MIME.encode(&self.public_key_bytes());
        assert_eq!(s.pop(), Some('\n'));
        assert_eq!(s.pop(), Some('\r'));
        s
    }
}

impl PublicKeyBase64 for key::PublicKey {
    fn public_key_bytes(&self) -> Vec<u8> {
        let mut s = Vec::new();
        match *self {
            key::PublicKey::Ed25519(ref publickey) => {
                let name = b"ssh-ed25519";
                s.write_u32::<BigEndian>(name.len() as u32).unwrap();
                s.extend_from_slice(name);
                s.write_u32::<BigEndian>(publickey.key.len() as u32)
                    .unwrap();
                s.extend_from_slice(&publickey.key);
            }
            #[cfg(feature = "openssl")]
            key::PublicKey::RSA { ref key, .. } => {
                use encoding::Encoding;
                let name = b"ssh-rsa";
                s.write_u32::<BigEndian>(name.len() as u32).unwrap();
                s.extend_from_slice(name);
                s.extend_ssh_mpint(&key.0.rsa().unwrap().e().to_vec());
                s.extend_ssh_mpint(&key.0.rsa().unwrap().n().to_vec());
            }
        }
        s
    }
}

impl PublicKeyBase64 for key::KeyPair {
    fn public_key_bytes(&self) -> Vec<u8> {
        let name = self.name().as_bytes();
        let mut s = Vec::new();
        s.write_u32::<BigEndian>(name.len() as u32).unwrap();
        s.extend_from_slice(name);
        match *self {
            key::KeyPair::Ed25519(ref key) => {
                let public = &key.key[32..];
                s.write_u32::<BigEndian>(32).unwrap();
                s.extend_from_slice(&public);
            }
            #[cfg(feature = "openssl")]
            key::KeyPair::RSA { ref key, .. } => {
                use encoding::Encoding;
                s.extend_ssh_mpint(&key.e().to_vec());
                s.extend_ssh_mpint(&key.n().to_vec());
            }
        }
        s
    }
}

/// Write a public key onto the provided `Write`, encoded in base-64.
pub fn write_public_key_base64<W: Write>(
    mut w: W,
    publickey: &key::PublicKey,
) -> Result<(), Error> {
    let pk = publickey.public_key_base64();
    writeln!(w, "{} {}", publickey.name(), pk)?;
    Ok(())
}

/// Load a secret key, deciphering it with the supplied password if necessary.
pub fn load_secret_key<P: AsRef<Path>>(
    secret_: P,
    password: Option<&str>,
) -> Result<key::KeyPair, Error> {
    let mut secret_file = std::fs::File::open(secret_)?;
    let mut secret = String::new();
    secret_file.read_to_string(&mut secret)?;
    decode_secret_key(&secret, password)
}

fn is_base64_char(c: char) -> bool {
    (c >= 'a' && c <= 'z')
        || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9')
        || c == '/'
        || c == '+'
        || c == '='
}

/// Record a host's public key into a nonstandard location.
pub fn learn_known_hosts_path<P: AsRef<Path>>(
    host: &str,
    port: u16,
    pubkey: &key::PublicKey,
    path: P,
) -> Result<(), Error> {
    if let Some(parent) = path.as_ref().parent() {
        std::fs::create_dir_all(parent)?
    }
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(path)?;

    // Test whether the known_hosts file ends with a \n
    let mut buf = [0; 1];
    let mut ends_in_newline = false;
    if file.seek(SeekFrom::End(-1)).is_ok() {
        file.read_exact(&mut buf)?;
        ends_in_newline = buf[0] == b'\n';
    }

    // Write the key.
    file.seek(SeekFrom::End(0))?;
    let mut file = std::io::BufWriter::new(file);
    if !ends_in_newline {
        file.write(b"\n")?;
    }
    if port != 22 {
        write!(file, "[{}]:{} ", host, port)?
    } else {
        write!(file, "{} ", host)?
    }
    write_public_key_base64(&mut file, pubkey)?;
    file.write(b"\n")?;
    Ok(())
}

/// Check that a server key matches the one recorded in file `path`.
pub fn check_known_hosts_path<P: AsRef<Path>>(
    host: &str,
    port: u16,
    pubkey: &key::PublicKey,
    path: P,
) -> Result<bool, Error> {
    let mut f = if let Ok(f) = File::open(path) {
        BufReader::new(f)
    } else {
        return Ok(false);
    };
    let mut buffer = String::new();

    let host_port = if port == 22 {
        Cow::Borrowed(host)
    } else {
        Cow::Owned(format!("[{}]:{}", host, port))
    };
    debug!("host_port = {:?}", host_port);
    let mut line = 1;
    while f.read_line(&mut buffer).unwrap() > 0 {
        {
            if buffer.as_bytes()[0] == b'#' {
                buffer.clear();
                continue;
            }
            debug!("line = {:?}", buffer);
            let mut s = buffer.split(' ');
            let hosts = s.next();
            let _ = s.next();
            let key = s.next();
            match (hosts, key) {
                (Some(h), Some(k)) => {
                    debug!("{:?} {:?}", h, k);
                    let host_matches = h.split(',').any(|x| x == host_port);
                    if host_matches {
                        if &parse_public_key_base64(k)? == pubkey {
                            return Ok(true);
                        } else {
                            return Err((Error::KeyChanged { line }).into());
                        }
                    }
                }
                _ => {}
            }
        }
        buffer.clear();
        line += 1;
    }
    Ok(false)
}

/// Record a host's public key into the user's known_hosts file.
#[cfg(target_os = "windows")]
pub fn learn_known_hosts(host: &str, port: u16, pubkey: &key::PublicKey) -> Result<(), Error> {
    if let Some(mut known_host_file) = dirs::home_dir() {
        known_host_file.push("ssh");
        known_host_file.push("known_hosts");
        learn_known_hosts_path(host, port, pubkey, &known_host_file)
    } else {
        Err(Error::NoHomeDir)
    }
}

/// Record a host's public key into the user's known_hosts file.
#[cfg(not(target_os = "windows"))]
pub fn learn_known_hosts(host: &str, port: u16, pubkey: &key::PublicKey) -> Result<(), Error> {
    if let Some(mut known_host_file) = dirs::home_dir() {
        known_host_file.push(".ssh");
        known_host_file.push("known_hosts");
        learn_known_hosts_path(host, port, pubkey, &known_host_file)
    } else {
        Err(Error::NoHomeDir)
    }
}

/// Check whether the host is known, from its standard location.
#[cfg(target_os = "windows")]
pub fn check_known_hosts(host: &str, port: u16, pubkey: &key::PublicKey) -> Result<bool, Error> {
    if let Some(mut known_host_file) = dirs::home_dir() {
        known_host_file.push("ssh");
        known_host_file.push("known_hosts");
        check_known_hosts_path(host, port, pubkey, &known_host_file)
    } else {
        Err(Error::NoHomeDir.into())
    }
}

/// Check whether the host is known, from its standard location.
#[cfg(not(target_os = "windows"))]
pub fn check_known_hosts(host: &str, port: u16, pubkey: &key::PublicKey) -> Result<bool, Error> {
    if let Some(mut known_host_file) = dirs::home_dir() {
        known_host_file.push(".ssh");
        known_host_file.push("known_hosts");
        check_known_hosts_path(host, port, pubkey, &known_host_file)
    } else {
        Err(Error::NoHomeDir.into())
    }
}

#[cfg(test)]
mod test {
    extern crate tempdir;
    use super::*;
    #[cfg(feature = "openssl")]
    use futures::Future;
    use std::fs::File;
    use std::io::Write;

    const ED25519_KEY: &'static str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABDLGyfA39
J2FcJygtYqi5ISAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIN+Wjn4+4Fcvl2Jl
KpggT+wCRxpSvtqqpVrQrKN1/A22AAAAkOHDLnYZvYS6H9Q3S3Nk4ri3R2jAZlQlBbUos5
FkHpYgNw65KCWCTXtP7ye2czMC3zjn2r98pJLobsLYQgRiHIv/CUdAdsqbvMPECB+wl/UQ
e+JpiSq66Z6GIt0801skPh20jxOO3F52SoX1IeO5D5PXfZrfSZlw6S8c7bwyp2FHxDewRx
7/wNsnDM0T7nLv/Q==
-----END OPENSSH PRIVATE KEY-----";

    #[cfg(feature = "openssl")]
    const RSA_KEY: &'static str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAuSvQ9m76zhRB4m0BUKPf17lwccj7KQ1Qtse63AOqP/VYItqEH8un
rxPogXNBgrcCEm/ccLZZsyE3qgp3DRQkkqvJhZ6O8VBPsXxjZesRCqoFNCczy+Mf0R/Qmv
Rnpu5+4DDLz0p7vrsRZW9ji/c98KzxeUonWgkplQaCBYLN875WdeUYMGtb1MLfNCEj177j
gZl3CzttLRK3su6dckowXcXYv1gPTPZAwJb49J43o1QhV7+1zdwXvuFM6zuYHdu9ZHSKir
6k1dXOET3/U+LWG5ofAo8oxUWv/7vs6h7MeajwkUeIBOWYtD+wGYRvVpxvj7nyOoWtg+jm
0X6ndnsD+QAAA8irV+ZAq1fmQAAAAAdzc2gtcnNhAAABAQC5K9D2bvrOFEHibQFQo9/XuX
BxyPspDVC2x7rcA6o/9Vgi2oQfy6evE+iBc0GCtwISb9xwtlmzITeqCncNFCSSq8mFno7x
UE+xfGNl6xEKqgU0JzPL4x/RH9Ca9Gem7n7gMMvPSnu+uxFlb2OL9z3wrPF5SidaCSmVBo
IFgs3zvlZ15Rgwa1vUwt80ISPXvuOBmXcLO20tErey7p1ySjBdxdi/WA9M9kDAlvj0njej
VCFXv7XN3Be+4UzrO5gd271kdIqKvqTV1c4RPf9T4tYbmh8CjyjFRa//u+zqHsx5qPCRR4
gE5Zi0P7AZhG9WnG+PufI6ha2D6ObRfqd2ewP5AAAAAwEAAQAAAQAdELqhI/RsSpO45eFR
9hcZtnrm8WQzImrr9dfn1w9vMKSf++rHTuFIQvi48Q10ZiOGH1bbvlPAIVOqdjAPtnyzJR
HhzmyjhjasJlk30zj+kod0kz63HzSMT9EfsYNfmYoCyMYFCKz52EU3xc87Vhi74XmZz0D0
CgIj6TyZftmzC4YJCiwwU8K+29nxBhcbFRxpgwAksFL6PCSQsPl4y7yvXGcX+7lpZD8547
v58q3jIkH1g2tBOusIuaiphDDStVJhVdKA55Z0Kju2kvCqsRIlf1efrq43blRgJFFFCxNZ
8Cpolt4lOHhg+o3ucjILlCOgjDV8dB21YLxmgN5q+xFNAAAAgQC1P+eLUkHDFXnleCEVrW
xL/DFxEyneLQz3IawGdw7cyAb7vxsYrGUvbVUFkxeiv397pDHLZ5U+t5cOYDBZ7G43Mt2g
YfWBuRNvYhHA9Sdf38m5qPA6XCvm51f+FxInwd/kwRKH01RHJuRGsl/4Apu4DqVob8y00V
WTYyV6JBNDkQAAAIEA322lj7ZJXfK/oLhMM/RS+DvaMea1g/q43mdRJFQQso4XRCL6IIVn
oZXFeOxrMIRByVZBw+FSeB6OayWcZMySpJQBo70GdJOc3pJb3js0T+P2XA9+/jwXS58K9a
+IkgLkv9XkfxNGNKyPEEzXC8QQzvjs1LbmO59VLko8ypwHq/cAAACBANQqaULI0qdwa0vm
d3Ae1+k3YLZ0kapSQGVIMT2lkrhKV35tj7HIFpUPa4vitHzcUwtjYhqFezVF+JyPbJ/Fsp
XmEc0g1fFnQp5/SkUwoN2zm8Up52GBelkq2Jk57mOMzWO0QzzNuNV/feJk02b2aE8rrAqP
QR+u0AypRPmzHnOPAAAAEXJvb3RAMTQwOTExNTQ5NDBkAQ==
-----END OPENSSH PRIVATE KEY-----";

    #[test]
    fn test_decode_ed25519_secret_key() {
        extern crate env_logger;
        env_logger::try_init().unwrap_or(());
        decode_secret_key(ED25519_KEY, Some("blabla")).unwrap();
    }

    #[test]
    #[cfg(feature = "openssl")]
    fn test_decode_rsa_secret_key() {
        extern crate env_logger;
        env_logger::try_init().unwrap_or(());
        decode_secret_key(RSA_KEY, None).unwrap();
    }

    #[test]
    #[cfg(feature = "openssl")]
    fn test_fingerprint() {
        let key = parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAILagOJFgwaMNhBWQINinKOXmqS4Gh5NgxgriXwdOoINJ",
        )
        .unwrap();
        assert_eq!(
            key.fingerprint(),
            "ldyiXa1JQakitNU5tErauu8DvWQ1dZ7aXu+rm7KQuog"
        );
    }

    #[test]
    fn test_check_known_hosts() {
        env_logger::try_init().unwrap_or(());
        let dir = tempdir::TempDir::new("thrussh").unwrap();
        let path = dir.path().join("known_hosts");
        {
            let mut f = File::create(&path).unwrap();
            f.write(b"[localhost]:13265 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ\n#pijul.org,37.120.161.53 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G2sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X\npijul.org,37.120.161.53 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G1sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X\n").unwrap();
        }

        // Valid key, non-standard port.
        let host = "localhost";
        let port = 13265;
        let hostkey = parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ",
        )
        .unwrap();
        assert!(check_known_hosts_path(host, port, &hostkey, &path).unwrap());

        // Valid key, several hosts, port 22
        let host = "pijul.org";
        let port = 22;
        let hostkey = parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G1sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X",
        )
        .unwrap();
        assert!(check_known_hosts_path(host, port, &hostkey, &path).unwrap());

        // Now with the key in a comment above, check that it's not recognized
        let host = "pijul.org";
        let port = 22;
        let hostkey = parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G2sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X",
        )
        .unwrap();
        assert!(check_known_hosts_path(host, port, &hostkey, &path).is_err());
    }

    #[test]
    #[cfg(feature = "openssl")]
    fn test_srhb() {
        env_logger::try_init().unwrap_or(());
        let key = "AAAAB3NzaC1yc2EAAAADAQABAAACAQC0Xtz3tSNgbUQAXem4d+d6hMx7S8Nwm/DOO2AWyWCru+n/+jQ7wz2b5+3oG2+7GbWZNGj8HCc6wJSA3jUsgv1N6PImIWclD14qvoqY3Dea1J0CJgXnnM1xKzBz9C6pDHGvdtySg+yzEO41Xt4u7HFn4Zx5SGuI2NBsF5mtMLZXSi33jCIWVIkrJVd7sZaY8jiqeVZBB/UvkLPWewGVuSXZHT84pNw4+S0Rh6P6zdNutK+JbeuO+5Bav4h9iw4t2sdRkEiWg/AdMoSKmo97Gigq2mKdW12ivnXxz3VfxrCgYJj9WwaUUWSfnAju5SiNly0cTEAN4dJ7yB0mfLKope1kRhPsNaOuUmMUqlu/hBDM/luOCzNjyVJ+0LLB7SV5vOiV7xkVd4KbEGKou8eeCR3yjFazUe/D1pjYPssPL8cJhTSuMc+/UC9zD8yeEZhB9V+vW4NMUR+lh5+XeOzenl65lWYd/nBZXLBbpUMf1AOfbz65xluwCxr2D2lj46iApSIpvE63i3LzFkbGl9GdUiuZJLMFJzOWdhGGc97cB5OVyf8umZLqMHjaImxHEHrnPh1MOVpv87HYJtSBEsN4/omINCMZrk++CRYAIRKRpPKFWV7NQHcvw3m7XLR3KaTYe+0/MINIZwGdou9fLUU3zSd521vDjA/weasH0CyDHq7sZw==";

        parse_public_key_base64(key).unwrap();
    }

    #[test]
    #[cfg(feature = "openssl")]
    fn test_nikao() {
        env_logger::try_init().unwrap_or(());
        let key = "-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAw/FG8YLVoXhsUVZcWaY7iZekMxQ2TAfSVh0LTnRuzsumeLhb
0fh4scIt4C4MLwpGe/u3vj290C28jLkOtysqnIpB4iBUrFNRmEz2YuvjOzkFE8Ju
0l1VrTZ9APhpLZvzT2N7YmTXcLz1yWopCe4KqTHczEP4lfkothxEoACXMaxezt5o
wIYfagDaaH6jXJgJk1SQ5VYrROVpDjjX8/Zg01H1faFQUikYx0M8EwL1fY5B80Hd
6DYSok8kUZGfkZT8HQ54DBgocjSs449CVqkVoQC1aDB+LZpMWovY15q7hFgfQmYD
qulbZRWDxxogS6ui/zUR2IpX7wpQMKKkBS1qdQIDAQABAoIBAQCodpcCKfS2gSzP
uapowY1KvP/FkskkEU18EDiaWWyzi1AzVn5LRo+udT6wEacUAoebLU5K2BaMF+aW
Lr1CKnDWaeA/JIDoMDJk+TaU0i5pyppc5LwXTXvOEpzi6rCzL/O++88nR4AbQ7sm
Uom6KdksotwtGvttJe0ktaUi058qaoFZbels5Fwk5bM5GHDdV6De8uQjSfYV813P
tM/6A5rRVBjC5uY0ocBHxPXkqAdHfJuVk0uApjLrbm6k0M2dg1X5oyhDOf7ZIzAg
QGPgvtsVZkQlyrD1OoCMPwzgULPXTe8SktaP9EGvKdMf5kQOqUstqfyx+E4OZa0A
T82weLjBAoGBAOUChhaLQShL3Vsml/Nuhhw5LsxU7Li34QWM6P5AH0HMtsSncH8X
ULYcUKGbCmmMkVb7GtsrHa4ozy0fjq0Iq9cgufolytlvC0t1vKRsOY6poC2MQgaZ
bqRa05IKwhZdHTr9SUwB/ngtVNWRzzbFKLkn2W5oCpQGStAKqz3LbKstAoGBANsJ
EyrXPbWbG+QWzerCIi6shQl+vzOd3cxqWyWJVaZglCXtlyySV2eKWRW7TcVvaXQr
Nzm/99GNnux3pUCY6szy+9eevjFLLHbd+knzCZWKTZiWZWr503h/ztfFwrMzhoAh
z4nukD/OETugPvtG01c2sxZb/F8LH9KORznhlSlpAoGBAJnqg1J9j3JU4tZTbwcG
fo5ThHeCkINp2owPc70GPbvMqf4sBzjz46QyDaM//9SGzFwocplhNhaKiQvrzMnR
LSVucnCEm/xdXLr/y6S6tEiFCwnx3aJv1uQRw2bBYkcDmBTAjVXPdUcyOHU+BYXr
Jv6ioMlKlel8/SUsNoFWypeVAoGAXhr3Bjf1xlm+0O9PRyZjQ0RR4DN5eHbB/XpQ
cL8hclsaK3V5tuek79JL1f9kOYhVeVi74G7uzTSYbCY3dJp+ftGCjDAirNEMaIGU
cEMgAgSqs/0h06VESwg2WRQZQ57GkbR1E2DQzuj9FG4TwSe700OoC9o3gqon4PHJ
/j9CM8kCgYEAtPJf3xaeqtbiVVzpPAGcuPyajTzU0QHPrXEl8zr/+iSK4Thc1K+c
b9sblB+ssEUQD5IQkhTWcsXdslINQeL77WhIMZ2vBAH8Hcin4jgcLmwUZfpfnnFs
QaChXiDsryJZwsRnruvMRX9nedtqHrgnIsJLTXjppIhGhq5Kg4RQfOU=
-----END RSA PRIVATE KEY-----
";
        decode_secret_key(key, None).unwrap();
    }

    #[cfg(feature = "openssl")]
    pub const PKCS8_RSA: &'static str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwBGetHjW+3bDQpVktdemnk7JXgu1NBWUM+ysifYLDBvJ9ttX
GNZSyQKA4v/dNr0FhAJ8I9BuOTjYCy1YfKylhl5D/DiSSXFPsQzERMmGgAlYvU2U
+FTxpBC11EZg69CPVMKKevfoUD+PZA5zB7Hc1dXFfwqFc5249SdbAwD39VTbrOUI
WECvWZs6/ucQxHHXP2O9qxWqhzb/ddOnqsDHUNoeceiNiCf2anNymovrIMjAqq1R
t2UP3f06/Zt7Jx5AxKqS4seFkaDlMAK8JkEDuMDOdKI36raHkKanfx8CnGMSNjFQ
QtvnpD8VSGkDTJN3Qs14vj2wvS477BQXkBKN1QIDAQABAoIBABb6xLMw9f+2ENyJ
hTggagXsxTjkS7TElCu2OFp1PpMfTAWl7oDBO7xi+UqvdCcVbHCD35hlWpqsC2Ui
8sBP46n040ts9UumK/Ox5FWaiuYMuDpF6vnfJ94KRcb0+KmeFVf9wpW9zWS0hhJh
jC+yfwpyfiOZ/ad8imGCaOguGHyYiiwbRf381T/1FlaOGSae88h+O8SKTG1Oahq4
0HZ/KBQf9pij0mfVQhYBzsNu2JsHNx9+DwJkrXT7K9SHBpiBAKisTTCnQmS89GtE
6J2+bq96WgugiM7X6OPnmBmE/q1TgV18OhT+rlvvNi5/n8Z1ag5Xlg1Rtq/bxByP
CeIVHsECgYEA9dX+LQdv/Mg/VGIos2LbpJUhJDj0XWnTRq9Kk2tVzr+9aL5VikEb
09UPIEa2ToL6LjlkDOnyqIMd/WY1W0+9Zf1ttg43S/6Rvv1W8YQde0Nc7QTcuZ1K
9jSSP9hzsa3KZtx0fCtvVHm+ac9fP6u80tqumbiD2F0cnCZcSxOb4+UCgYEAyAKJ
70nNKegH4rTCStAqR7WGAsdPE3hBsC814jguplCpb4TwID+U78Xxu0DQF8WtVJ10
SJuR0R2q4L9uYWpo0MxdawSK5s9Am27MtJL0mkFQX0QiM7hSZ3oqimsdUdXwxCGg
oktxCUUHDIPJNVd4Xjg0JTh4UZT6WK9hl1zLQzECgYEAiZRCFGc2KCzVLF9m0cXA
kGIZUxFAyMqBv+w3+zq1oegyk1z5uE7pyOpS9cg9HME2TAo4UPXYpLAEZ5z8vWZp
45sp/BoGnlQQsudK8gzzBtnTNp5i/MnnetQ/CNYVIVnWjSxRUHBqdMdRZhv0/Uga
e5KA5myZ9MtfSJA7VJTbyHUCgYBCcS13M1IXaMAt3JRqm+pftfqVs7YeJqXTrGs/
AiDlGQigRk4quFR2rpAV/3rhWsawxDmb4So4iJ16Wb2GWP4G1sz1vyWRdSnmOJGC
LwtYrvfPHegqvEGLpHa7UsgDpol77hvZriwXwzmLO8A8mxkeW5dfAfpeR5o+mcxW
pvnTEQKBgQCKx6Ln0ku6jDyuDzA9xV2/PET5D75X61R2yhdxi8zurY/5Qon3OWzk
jn/nHT3AZghGngOnzyv9wPMKt9BTHyTB6DlB6bRVLDkmNqZh5Wi8U1/IjyNYI0t2
xV/JrzLAwPoKk3bkqys3bUmgo6DxVC/6RmMwPQ0rmpw78kOgEej90g==
-----END RSA PRIVATE KEY-----
";

    #[test]
    #[cfg(feature = "openssl")]
    fn test_loewenheim() {
        env_logger::try_init().unwrap_or(());
        let key = "-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,80E4FCAD049EE007CCE1C65D52CDB87A

ZKBKtex8+DA/d08TTPp4vY8RV+r+1nUC1La+r0dSiXsfunRNDPcYhHbyA/Fdr9kQ
+d1/E3cEb0k2nq7xYyMzy8hpNp/uHu7UfllGdaBusiPjHR+feg6AQfbM0FWpdGzo
9l/Vho5Ocw8abQq1Q9aPW5QQXBURC7HtCQXbpuYjUAQBeea1LzPCw6UIF80GUUkY
1AycXxVfx1AeURAKTZR4hsxC5pqI4yhAvVNXxP+tTTa9NE8lOP0yqVNurfIqyAnp
5ELMwNdHXZyUcT+EH5PsC69ocQgEZqLs0chvke62woMOjeSpsW5cIjGohW9lOD1f
nJkECVZ50kE0SDvcL4Y338tHwMt7wdwdj1dkAWSUjAJT4ShjqV/TzaLAiNAyRxLl
cm3mAccaFIIBZG/bPLGI0B5+mf9VExXGJrbGlvURhtE3nwmjLg1vT8lVfqbyL3a+
0tFvmDYn71L97t/3hcD2tVnKLv9g8+/OCsUAk3+/0eS7D6GpmlOMRHdLLUHc4SOm
bIDT/dE6MjsCSm7n/JkTb8P+Ta1Hp94dUnX4pfjzZ+O8V1H8wv7QW5KsuJhJ8cn4
eS3BEgNH1I4FCCjLsZdWve9ehV3/19WXh+BF4WXFq9b3plmfJgTiZslvjy4dgThm
OhEK44+fN1UhzguofxTR4Maz7lcehQxGAxp14hf1EnaAEt3LVjEPEShgK5dx1Ftu
LWFz9nR4vZcMsaiszElrevqMhPQHXY7cnWqBenkMfkdcQDoZjKvV86K98kBIDMu+
kf855vqRF8b2n/6HPdm3eqFh/F410nSB0bBSglUfyOZH1nS+cs79RQZEF9fNUmpH
EPQtQ/PALohicj9Vh7rRaMKpsORdC8/Ahh20s01xL6siZ334ka3BLYT94UG796/C
4K1S2kPdUP8POJ2HhaK2l6qaG8tcEX7HbwwZeKiEHVNvWuIGQO9TiDONLycp9x4y
kNM3sv2pI7vEhs7d2NapWgNha1RcTSv0CQ6Th/qhGo73LBpVmKwombVImHAyMGAE
aVF32OycVd9c9tDgW5KdhWedbeaxD6qkSs0no71083kYIS7c6iC1R3ZeufEkMhmx
dwrciWTJ+ZAk6rS975onKz6mo/4PytcCY7Df/6xUxHF3iJCnuK8hNpLdJcdOiqEK
zj/d5YGyw3J2r+NrlV1gs3FyvR3eMCWWH2gpIQISBpnEANY40PxA/ogH+nCUvI/O
n8m437ZeLTg6lnPqsE4nlk2hUEwRdy/SVaQURbn7YlcYIt0e81r5sBXb4MXkLrf0
XRWmpSggdcaaMuXi7nVSdkgCMjGP7epS7HsfP46OrTtJLHn5LxvdOEaW53nPOVQg
/PlVfDbwWl8adE3i3PDQOw9jhYXnYS3sv4R8M8y2GYEXbINrTJyUGrlNggKFS6oh
Hjgt0gsM2N/D8vBrQwnRtyymRnFd4dXFEYKAyt+vk0sa36eLfl0z6bWzIchkJbdu
raMODVc+NiJE0Qe6bwAi4HSpJ0qw2lKwVHYB8cdnNVv13acApod326/9itdbb3lt
KJaj7gc0n6gmKY6r0/Ddufy1JZ6eihBCSJ64RARBXeg2rZpyT+xxhMEZLK5meOeR
-----END RSA PRIVATE KEY-----
";
        let key = decode_secret_key(key, Some("passphrase")).unwrap();
        let public = key.clone_public_key();
        let buf = b"blabla";
        let sig = key.sign_detached(buf).unwrap();
        assert!(public.verify_detached(buf, sig.as_ref()));
    }

    #[test]
    #[cfg(feature = "openssl")]
    fn test_o01eg() {
        env_logger::try_init().unwrap_or(());

        let key = "-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,EA77308AAF46981303D8C44D548D097E

QR18hXmAgGehm1QMMYGF34PAtBpTj+8/ZPFx2zZxir7pzDpfYoNAIf/fzLsW1ruG
0xo/ZK/T3/TpMgjmLsCR6q+KU4jmCcCqWQIGWYJt9ljFI5y/CXr5uqP3DKcqtdxQ
fbBAfXJ8ITF+Tj0Cljm2S1KYHor+mkil5Lf/ZNiHxcLfoI3xRnpd+2cemN9Ly9eY
HNTbeWbLosfjwdfPJNWFNV5flm/j49klx/UhXhr5HNFNgp/MlTrvkH4rBt4wYPpE
cZBykt4Fo1KGl95pT22inGxQEXVHF1Cfzrf5doYWxjiRTmfhpPSz/Tt0ev3+jIb8
Htx6N8tNBoVxwCiQb7jj3XNim2OGohIp5vgW9sh6RDfIvr1jphVOgCTFKSo37xk0
156EoCVo3VcLf+p0/QitbUHR+RGW/PvUJV/wFR5ShYqjI+N2iPhkD24kftJ/MjPt
AAwCm/GYoYjGDhIzQMB+FETZKU5kz23MQtZFbYjzkcI/RE87c4fkToekNCdQrsoZ
wG0Ne2CxrwwEnipHCqT4qY+lZB9EbqQgbWOXJgxA7lfznBFjdSX7uDc/mnIt9Y6B
MZRXH3PTfotHlHMe+Ypt5lfPBi/nruOl5wLo3L4kY5pUyqR0cXKNycIJZb/pJAnE
ryIb59pZP7njvoHzRqnC9dycnTFW3geK5LU+4+JMUS32F636aorunRCl6IBmVQHL
uZ+ue714fn/Sn6H4dw6IH1HMDG1hr8ozP4sNUCiAQ05LsjDMGTdrUsr2iBBpkQhu
VhUDZy9g/5XF1EgiMbZahmqi5WaJ5K75ToINHb7RjOE7MEiuZ+RPpmYLE0HXyn9X
HTx0ZGr022dDI6nkvUm6OvEwLUUmmGKRHKe0y1EdICGNV+HWqnlhGDbLWeMyUcIY
M6Zh9Dw3WXD3kROf5MrJ6n9MDIXx9jy7nmBh7m6zKjBVIw94TE0dsRcWb0O1IoqS
zLQ6ihno+KsQHDyMVLEUz1TuE52rIpBmqexDm3PdDfCgsNdBKP6QSTcoqcfHKeex
K93FWgSlvFFQQAkJumJJ+B7ZWnK+2pdjdtWwTpflAKNqc8t//WmjWZzCtbhTHCXV
1dnMk7azWltBAuXnjW+OqmuAzyh3ayKgqfW66mzSuyQNa1KqFhqpJxOG7IHvxVfQ
kYeSpqODnL87Zd/dU8s0lOxz3/ymtjPMHlOZ/nHNqW90IIeUwWJKJ46Kv6zXqM1t
MeD1lvysBbU9rmcUdop0D3MOgGpKkinR5gy4pUsARBiz4WhIm8muZFIObWes/GDS
zmmkQRO1IcfXKAHbq/OdwbLBm4vM9nk8vPfszoEQCnfOSd7aWrLRjDR+q2RnzNzh
K+fodaJ864JFIfB/A+aVviVWvBSt0eEbEawhTmNPerMrAQ8tRRhmNxqlDP4gOczi
iKUmK5recsXk5us5Ik7peIR/f9GAghpoJkF0HrHio47SfABuK30pzcj62uNWGljS
3d9UQLCepT6RiPFhks/lgimbtSoiJHql1H9Q/3q4MuO2PuG7FXzlTnui3zGw/Vvy
br8gXU8KyiY9sZVbmplRPF+ar462zcI2kt0a18mr0vbrdqp2eMjb37QDbVBJ+rPE
-----END RSA PRIVATE KEY-----
";
        decode_secret_key(key, Some("12345")).unwrap();
    }
    #[test]
    #[cfg(feature = "openssl")]
    fn test_pkcs8() {
        env_logger::try_init().unwrap_or(());
        println!("test");
        decode_secret_key(PKCS8_RSA, Some("blabla")).unwrap();
    }

    #[cfg(feature = "openssl")]
    const PKCS8_ENCRYPTED: &'static str = "-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQITo1O0b8YrS0CAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBBtLH4T1KOfo1GGr7salhR8BIIE
0KN9ednYwcTGSX3hg7fROhTw7JAJ1D4IdT1fsoGeNu2BFuIgF3cthGHe6S5zceI2
MpkfwvHbsOlDFWMUIAb/VY8/iYxhNmd5J6NStMYRC9NC0fVzOmrJqE1wITqxtORx
IkzqkgFUbaaiFFQPepsh5CvQfAgGEWV329SsTOKIgyTj97RxfZIKA+TR5J5g2dJY
j346SvHhSxJ4Jc0asccgMb0HGh9UUDzDSql0OIdbnZW5KzYJPOx+aDqnpbz7UzY/
P8N0w/pEiGmkdkNyvGsdttcjFpOWlLnLDhtLx8dDwi/sbEYHtpMzsYC9jPn3hnds
TcotqjoSZ31O6rJD4z18FOQb4iZs3MohwEdDd9XKblTfYKM62aQJWH6cVQcg+1C7
jX9l2wmyK26Tkkl5Qg/qSfzrCveke5muZgZkFwL0GCcgPJ8RixSB4GOdSMa/hAMU
kvFAtoV2GluIgmSe1pG5cNMhurxM1dPPf4WnD+9hkFFSsMkTAuxDZIdDk3FA8zof
Yhv0ZTfvT6V+vgH3Hv7Tqcxomy5Qr3tj5vvAqqDU6k7fC4FvkxDh2mG5ovWvc4Nb
Xv8sed0LGpYitIOMldu6650LoZAqJVv5N4cAA2Edqldf7S2Iz1QnA/usXkQd4tLa
Z80+sDNv9eCVkfaJ6kOVLk/ghLdXWJYRLenfQZtVUXrPkaPpNXgD0dlaTN8KuvML
Uw/UGa+4ybnPsdVflI0YkJKbxouhp4iB4S5ACAwqHVmsH5GRnujf10qLoS7RjDAl
o/wSHxdT9BECp7TT8ID65u2mlJvH13iJbktPczGXt07nBiBse6OxsClfBtHkRLzE
QF6UMEXsJnIIMRfrZQnduC8FUOkfPOSXc8r9SeZ3GhfbV/DmWZvFPCpjzKYPsM5+
N8Bw/iZ7NIH4xzNOgwdp5BzjH9hRtCt4sUKVVlWfEDtTnkHNOusQGKu7HkBF87YZ
RN/Nd3gvHob668JOcGchcOzcsqsgzhGMD8+G9T9oZkFCYtwUXQU2XjMN0R4VtQgZ
rAxWyQau9xXMGyDC67gQ5xSn+oqMK0HmoW8jh2LG/cUowHFAkUxdzGadnjGhMOI2
zwNJPIjF93eDF/+zW5E1l0iGdiYyHkJbWSvcCuvTwma9FIDB45vOh5mSR+YjjSM5
nq3THSWNi7Cxqz12Q1+i9pz92T2myYKBBtu1WDh+2KOn5DUkfEadY5SsIu/Rb7ub
5FBihk2RN3y/iZk+36I69HgGg1OElYjps3D+A9AjVby10zxxLAz8U28YqJZm4wA/
T0HLxBiVw+rsHmLP79KvsT2+b4Diqih+VTXouPWC/W+lELYKSlqnJCat77IxgM9e
YIhzD47OgWl33GJ/R10+RDoDvY4koYE+V5NLglEhbwjloo9Ryv5ywBJNS7mfXMsK
/uf+l2AscZTZ1mhtL38efTQCIRjyFHc3V31DI0UdETADi+/Omz+bXu0D5VvX+7c6
b1iVZKpJw8KUjzeUV8yOZhvGu3LrQbhkTPVYL555iP1KN0Eya88ra+FUKMwLgjYr
JkUx4iad4dTsGPodwEP/Y9oX/Qk3ZQr+REZ8lg6IBoKKqqrQeBJ9gkm1jfKE6Xkc
Cog3JMeTrb3LiPHgN6gU2P30MRp6L1j1J/MtlOAr5rux
-----END ENCRYPTED PRIVATE KEY-----";

    #[test]
    #[cfg(feature = "openssl")]
    fn test_gpg() {
        env_logger::try_init().unwrap_or(());
        let algo = [115, 115, 104, 45, 114, 115, 97];
        let key = [
            0, 0, 0, 7, 115, 115, 104, 45, 114, 115, 97, 0, 0, 0, 3, 1, 0, 1, 0, 0, 1, 129, 0, 163,
            72, 59, 242, 4, 248, 139, 217, 57, 126, 18, 195, 170, 3, 94, 154, 9, 150, 89, 171, 236,
            192, 178, 185, 149, 73, 210, 121, 95, 126, 225, 209, 199, 208, 89, 130, 175, 229, 163,
            102, 176, 155, 69, 199, 155, 71, 214, 170, 61, 202, 2, 207, 66, 198, 147, 65, 10, 176,
            20, 105, 197, 133, 101, 126, 193, 252, 245, 254, 182, 14, 250, 118, 113, 18, 220, 38,
            220, 75, 247, 50, 163, 39, 2, 61, 62, 28, 79, 199, 238, 189, 33, 194, 190, 22, 87, 91,
            1, 215, 115, 99, 138, 124, 197, 127, 237, 228, 170, 42, 25, 117, 1, 106, 36, 54, 163,
            163, 207, 129, 133, 133, 28, 185, 170, 217, 12, 37, 113, 181, 182, 180, 178, 23, 198,
            233, 31, 214, 226, 114, 146, 74, 205, 177, 82, 232, 238, 165, 44, 5, 250, 150, 236, 45,
            30, 189, 254, 118, 55, 154, 21, 20, 184, 235, 223, 5, 20, 132, 249, 147, 179, 88, 146,
            6, 100, 229, 200, 221, 157, 135, 203, 57, 204, 43, 27, 58, 85, 54, 219, 138, 18, 37,
            80, 106, 182, 95, 124, 140, 90, 29, 48, 193, 112, 19, 53, 84, 201, 153, 52, 249, 15,
            41, 5, 11, 147, 18, 8, 27, 31, 114, 45, 224, 118, 111, 176, 86, 88, 23, 150, 184, 252,
            128, 52, 228, 90, 30, 34, 135, 234, 123, 28, 239, 90, 202, 239, 188, 175, 8, 141, 80,
            59, 194, 80, 43, 205, 34, 137, 45, 140, 244, 181, 182, 229, 247, 94, 216, 115, 173,
            107, 184, 170, 102, 78, 249, 4, 186, 234, 169, 148, 98, 128, 33, 115, 232, 126, 84, 76,
            222, 145, 90, 58, 1, 4, 163, 243, 93, 215, 154, 205, 152, 178, 109, 241, 197, 82, 148,
            222, 78, 44, 193, 248, 212, 157, 118, 217, 75, 211, 23, 229, 121, 28, 180, 208, 173,
            204, 14, 111, 226, 25, 163, 220, 95, 78, 175, 189, 168, 67, 159, 179, 176, 200, 150,
            202, 248, 174, 109, 25, 89, 176, 220, 226, 208, 187, 84, 169, 157, 14, 88, 217, 221,
            117, 254, 51, 45, 93, 184, 80, 225, 158, 29, 76, 38, 69, 72, 71, 76, 50, 191, 210, 95,
            152, 175, 26, 207, 91, 7,
        ];
        debug!("algo = {:?}", std::str::from_utf8(&algo));
        key::PublicKey::parse(&algo, &key).unwrap();
    }

    #[test]
    #[cfg(feature = "openssl")]
    fn test_pkcs8_encrypted() {
        env_logger::try_init().unwrap_or(());
        println!("test");
        decode_secret_key(PKCS8_ENCRYPTED, Some("blabla")).unwrap();
    }

    fn test_client_agent(key: key::KeyPair) {
        env_logger::try_init().unwrap_or(());
        use std::process::{Command, Stdio};
        let dir = tempdir::TempDir::new("thrussh").unwrap();
        let agent_path = dir.path().join("agent");
        let mut agent = Command::new("ssh-agent")
            .arg("-a")
            .arg(&agent_path)
            .arg("-D")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to execute process");
        std::thread::sleep(std::time::Duration::from_millis(10));
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let public = key.clone_public_key();
            let stream = tokio::net::UnixStream::connect(&agent_path).await?;
            let mut client = agent::client::AgentClient::connect(stream);
            client.add_identity(&key, &[]).await?;
            client.request_identities().await?;
            let buf = cryptovec::CryptoVec::from_slice(b"blabla");
            let len = buf.len();
            let (_, buf) = client.sign_request(&public, buf).await;
            let buf = buf?;
            let (a, b) = buf.split_at(len);
            match key {
                key::KeyPair::Ed25519 { .. } => {
                    let sig = &b[b.len() - 64..];
                    assert!(public.verify_detached(a, sig));
                }
                _ => {}
            }
            Ok::<(), Error>(())
        })
        .unwrap();
        agent.kill().unwrap();
        agent.wait().unwrap();
    }

    #[test]
    fn test_client_agent_ed25519() {
        let key = decode_secret_key(ED25519_KEY, Some("blabla")).unwrap();
        test_client_agent(key)
    }

    #[test]
    #[cfg(feature = "openssl")]
    fn test_client_agent_rsa() {
        let key = decode_secret_key(PKCS8_ENCRYPTED, Some("blabla")).unwrap();
        test_client_agent(key)
    }

    #[test]
    #[cfg(feature = "openssl")]
    fn test_client_agent_openssh_rsa() {
        let key = decode_secret_key(RSA_KEY, None).unwrap();
        test_client_agent(key)
    }

    #[test]
    #[cfg(feature = "openssl")]
    fn test_agent() {
        env_logger::try_init().unwrap_or(());
        let dir = tempdir::TempDir::new("thrussh").unwrap();
        let agent_path = dir.path().join("agent");

        let core = tokio::runtime::Runtime::new().unwrap();
        use agent;

        #[derive(Clone)]
        struct X {}
        impl agent::server::Agent for X {
            fn confirm(
                self,
                _: std::sync::Arc<key::KeyPair>,
            ) -> Box<dyn Future<Output = (Self, bool)> + Send + Unpin> {
                Box::new(futures::future::ready((self, true)))
            }
        }
        let agent_path_ = agent_path.clone();
        core.spawn(async move {
            let mut listener = tokio::net::UnixListener::bind(&agent_path_).unwrap();

            agent::server::serve(
                Incoming {
                    listener: &mut listener,
                },
                X {},
            )
            .await
        });
        let key = decode_secret_key(PKCS8_ENCRYPTED, Some("blabla")).unwrap();
        let public = key.clone_public_key();
        core.block_on(async move {
            let stream = tokio::net::UnixStream::connect(&agent_path).await?;
            let mut client = agent::client::AgentClient::connect(stream);
            client
                .add_identity(&key, &[agent::Constraint::KeyLifetime { seconds: 60 }])
                .await?;
            client.request_identities().await?;
            let buf = cryptovec::CryptoVec::from_slice(b"blabla");
            let len = buf.len();
            let (_, buf) = client.sign_request(&public, buf).await;
            let buf = buf?;
            let (a, b) = buf.split_at(len);
            match key {
                key::KeyPair::Ed25519 { .. } => {
                    let sig = &b[b.len() - 64..];
                    assert!(public.verify_detached(a, sig));
                }
                _ => {}
            }
            Ok::<(), Error>(())
        })
        .unwrap()
    }

    struct Incoming<'a> {
        listener: &'a mut tokio::net::UnixListener,
    }
    impl futures::stream::Stream for Incoming<'_> {
        type Item = Result<tokio::net::UnixStream, std::io::Error>;

        fn poll_next(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            let (sock, _addr) = futures::ready!(self.get_mut().listener.poll_accept(cx))?;
            std::task::Poll::Ready(Some(Ok(sock)))
        }
    }
}
