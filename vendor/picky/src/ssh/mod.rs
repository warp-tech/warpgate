pub mod certificate;
pub mod decode;
pub mod encode;
pub mod private_key;
pub mod public_key;

use crate::key::ec::NamedEcCurve;
use crate::key::ed::NamedEdAlgorithm;
use crate::key::{EcCurve, EdAlgorithm, KeyError};

use byteorder::ReadBytesExt;
use std::io::{self, Read};

pub use certificate::{SshCertKeyType, SshCertType, SshCertificate, SshCertificateBuilder};
pub use private_key::SshPrivateKey;
pub use public_key::SshPublicKey;

pub(crate) type Base64Writer<'a, T, E> = base64::write::EncoderWriter<'a, T, E>;
pub(crate) type Base64Reader<'a, T, E> = base64::read::DecoderReader<'a, T, E>;

const SSH_COMBO_ED25519_KEY_LENGTH: usize = ed25519_dalek::SECRET_KEY_LENGTH + ed25519_dalek::PUBLIC_KEY_LENGTH;

mod key_type {
    pub const RSA: &str = "ssh-rsa";
    pub const ECDSA_SHA2_NIST_P256: &str = "ecdsa-sha2-nistp256";
    pub const ECDSA_SHA2_NIST_P384: &str = "ecdsa-sha2-nistp384";
    pub const ECDSA_SHA2_NIST_P521: &str = "ecdsa-sha2-nistp521";
    pub const ED25519: &str = "ssh-ed25519";
    pub const SK_ECDSA_SHA2_NIST_P256: &str = "sk-ecdsa-sha2-nistp256@openssh.com";
    pub const SK_ED25519: &str = "sk-ssh-ed25519@openssh.com";
}

mod key_identifier {
    pub const ECDSA_SHA2_NIST_P256: &str = "nistp256";
    pub const ECDSA_SHA2_NIST_P384: &str = "nistp384";
    pub const ECDSA_SHA2_NIST_P521: &str = "nistp521";
}

trait EcCurveSshExt {
    fn to_ecdsa_ssh_key_type(&self) -> Result<&'static str, KeyError>;
    fn to_ecdsa_ssh_key_identifier(&self) -> Result<&'static str, KeyError>;
}

impl EcCurveSshExt for NamedEcCurve {
    fn to_ecdsa_ssh_key_type(&self) -> Result<&'static str, KeyError> {
        match self {
            NamedEcCurve::Known(EcCurve::NistP256) => Ok(key_type::ECDSA_SHA2_NIST_P256),
            NamedEcCurve::Known(EcCurve::NistP384) => Ok(key_type::ECDSA_SHA2_NIST_P384),
            NamedEcCurve::Known(EcCurve::NistP521) => Ok(key_type::ECDSA_SHA2_NIST_P521),
            NamedEcCurve::Unsupported(oid) => Err(KeyError::unsupported_curve(oid, "ssh key type serialization")),
        }
    }

    fn to_ecdsa_ssh_key_identifier(&self) -> Result<&'static str, KeyError> {
        match self {
            NamedEcCurve::Known(EcCurve::NistP256) => Ok(key_identifier::ECDSA_SHA2_NIST_P256),
            NamedEcCurve::Known(EcCurve::NistP384) => Ok(key_identifier::ECDSA_SHA2_NIST_P384),
            NamedEcCurve::Known(EcCurve::NistP521) => Ok(key_identifier::ECDSA_SHA2_NIST_P521),
            NamedEcCurve::Unsupported(oid) => Err(KeyError::unsupported_curve(oid, "ssh key identifier serialization")),
        }
    }
}

trait EdAlgorithmSshExt {
    fn to_ed_ssh_key_type(&self) -> Result<&'static str, KeyError>;
}

impl EdAlgorithmSshExt for NamedEdAlgorithm {
    fn to_ed_ssh_key_type(&self) -> Result<&'static str, KeyError> {
        match self {
            NamedEdAlgorithm::Known(EdAlgorithm::Ed25519) => Ok(key_type::ED25519),
            NamedEdAlgorithm::Known(EdAlgorithm::X25519) => Err(KeyError::UnsupportedAlgorithm {
                algorithm: "X25519 can't be use for SSH EdDSA keys",
            }),
            NamedEdAlgorithm::Unsupported(oid) => {
                Err(KeyError::unsupported_ed_algorithm(oid, "ssh key type serialization"))
            }
        }
    }
}

fn read_until_whitespace(stream: &mut dyn Read, buffer: &mut Vec<u8>) -> io::Result<()> {
    loop {
        match stream.read_u8() {
            Ok(symbol) => {
                if symbol as char == ' ' {
                    break;
                } else {
                    buffer.push(symbol);
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                break;
            }
            Err(e) => return Err(e),
        };
    }

    Ok(())
}

fn read_until_linebreak(stream: &mut dyn Read, buffer: &mut Vec<u8>) -> io::Result<()> {
    loop {
        match stream.read_u8() {
            Ok(b'\r') | Ok(b'\n') => break,
            Ok(c) => buffer.push(c),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                break;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(())
}
