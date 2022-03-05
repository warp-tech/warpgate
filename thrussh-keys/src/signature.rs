use crate::key::SignatureHash;
use crate::Error;
use byteorder::{BigEndian, WriteBytesExt};
use serde;
use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

pub struct SignatureBytes(pub [u8; 64]);

/// The type of a signature, depending on the algorithm used.
#[derive(Serialize, Deserialize, Clone)]
pub enum Signature {
    /// An Ed25519 signature
    Ed25519(SignatureBytes),
    /// An RSA signature
    RSA { hash: SignatureHash, bytes: Vec<u8> },
}

impl Signature {
    pub fn to_base64(&self) -> String {
        use crate::encoding::Encoding;
        let mut bytes_ = Vec::new();
        match self {
            Signature::Ed25519(ref bytes) => {
                let t = b"ssh-ed25519";
                bytes_
                    .write_u32::<BigEndian>((t.len() + bytes.0.len() + 8) as u32)
                    .unwrap();
                bytes_.extend_ssh_string(t);
                bytes_.extend_ssh_string(&bytes.0[..]);
            }
            Signature::RSA {
                ref hash,
                ref bytes,
            } => {
                let t = match hash {
                    SignatureHash::SHA2_256 => &b"rsa-sha2-256"[..],
                    SignatureHash::SHA2_512 => &b"rsa-sha2-512"[..],
                    SignatureHash::SHA1 => &b"ssh-rsa"[..],
                };
                bytes_
                    .write_u32::<BigEndian>((t.len() + bytes.len() + 8) as u32)
                    .unwrap();
                bytes_.extend_ssh_string(t);
                bytes_.extend_ssh_string(&bytes[..]);
            }
        }
        data_encoding::BASE64_NOPAD.encode(&bytes_[..])
    }

    pub fn from_base64(s: &[u8]) -> Result<Self, Error> {
        let bytes_ = data_encoding::BASE64_NOPAD.decode(s)?;
        use crate::encoding::Reader;
        let mut r = bytes_.reader(0);
        let sig = r.read_string()?;
        let mut r = sig.reader(0);
        let typ = r.read_string()?;
        let bytes = r.read_string()?;
        match typ {
            b"ssh-ed25519" => {
                let mut bytes_ = [0; 64];
                bytes_.clone_from_slice(bytes);
                Ok(Signature::Ed25519(SignatureBytes(bytes_)))
            }
            b"rsa-sha2-256" => Ok(Signature::RSA {
                hash: SignatureHash::SHA2_256,
                bytes: bytes.to_vec(),
            }),
            b"rsa-sha2-512" => Ok(Signature::RSA {
                hash: SignatureHash::SHA2_512,
                bytes: bytes.to_vec(),
            }),
            _ => Err(Error::UnknownSignatureType {
                sig_type: std::str::from_utf8(typ).unwrap_or("").to_string(),
            }),
        }
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        match *self {
            Signature::Ed25519(ref signature) => &signature.0,
            Signature::RSA { ref bytes, .. } => &bytes[..],
        }
    }
}

impl AsRef<[u8]> for SignatureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SignatureBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Vis;
        impl<'de> Visitor<'de> for Vis {
            type Value = SignatureBytes;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("64 bytes")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut result = [0; 64];
                for x in result.iter_mut() {
                    if let Some(y) = seq.next_element()? {
                        *x = y
                    } else {
                        return Err(serde::de::Error::invalid_length(64, &self));
                    }
                }
                Ok(SignatureBytes(result))
            }
        }
        deserializer.deserialize_tuple(64, Vis)
    }
}

impl Serialize for SignatureBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tup = serializer.serialize_tuple(64)?;
        for byte in self.0.iter() {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }
}

impl fmt::Debug for SignatureBytes {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{:?}", &self.0[..])
    }
}

impl Clone for SignatureBytes {
    fn clone(&self) -> Self {
        let mut result = SignatureBytes([0; 64]);
        result.0.clone_from_slice(&self.0);
        result
    }
}
