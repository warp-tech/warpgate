use crate::key::ec::{EcCurve, NamedEcCurve};
use crate::key::ed::NamedEdAlgorithm;
use crate::key::{EdAlgorithm, PrivateKey, PublicKey};
use crate::ssh::certificate::{
    SshCertKeyType, SshCertType, SshCertTypeError, SshCertificate, SshCertificateError, SshCriticalOption,
    SshCriticalOptionError, SshCriticalOptionType, SshExtension, SshExtensionError, SshExtensionType, SshSignature,
    SshSignatureError, SshSignatureFormat, Timestamp,
};
use crate::ssh::private_key::{KdfOption, SshBasePrivateKey, SshPrivateKeyError};
use crate::ssh::public_key::{SshBasePublicKey, SshPublicKey, SshPublicKeyError};
use crate::ssh::{Base64Reader, SSH_COMBO_ED25519_KEY_LENGTH, key_type, read_until_linebreak, read_until_whitespace};

use super::certificate::SshSignatureBlob;
use base64::engine::general_purpose;
use byteorder::{BigEndian, ReadBytesExt};
use crypto_bigint::BoxedUint;
use picky_asn1_x509::oid::ObjectIdentifier;
use picky_asn1_x509::oids;
use std::io::{self, Cursor, Read};

pub trait SshReadExt {
    type Error;

    fn read_ssh_string(&mut self) -> Result<String, Self::Error>;
    fn read_ssh_bytes(&mut self) -> Result<Vec<u8>, Self::Error>;
    fn read_ssh_mpint(&mut self) -> Result<BoxedUint, Self::Error>;
}

impl<T> SshReadExt for T
where
    T: Read,
{
    type Error = io::Error;

    fn read_ssh_string(&mut self) -> Result<String, Self::Error> {
        let size = self.read_u32::<BigEndian>()? as usize;
        let mut buffer = vec![0; size];
        self.read_exact(&mut buffer)?;

        Ok(String::from_utf8_lossy(&buffer).into_owned())
    }

    fn read_ssh_bytes(&mut self) -> Result<Vec<u8>, Self::Error> {
        let size = self.read_u32::<BigEndian>()? as usize;
        let mut buffer = vec![0; size];
        self.read_exact(&mut buffer)?;

        Ok(buffer)
    }

    fn read_ssh_mpint(&mut self) -> Result<BoxedUint, Self::Error> {
        let size = self.read_u32::<BigEndian>()? as usize;
        let mut buffer = vec![0; size];
        self.read_exact(&mut buffer)?;

        if buffer[0] == 0 {
            buffer.remove(0);
        }

        Ok(BoxedUint::from_be_slice_vartime(&buffer))
    }
}

pub trait SshComplexTypeDecode: Sized {
    type Error;

    fn decode(stream: impl Read) -> Result<Self, Self::Error>;
}

impl SshComplexTypeDecode for SshCertType {
    type Error = SshCertTypeError;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error> {
        SshCertType::try_from(stream.read_u32::<BigEndian>()?)
    }
}

impl SshComplexTypeDecode for SshCriticalOption {
    type Error = SshCriticalOptionError;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error> {
        let option_type: String = stream.read_ssh_string()?;
        let data: String = stream.read_ssh_string()?;
        Ok(SshCriticalOption {
            option_type: SshCriticalOptionType::try_from(option_type)?,
            data,
        })
    }
}

impl<T> SshComplexTypeDecode for Vec<T>
where
    T: SshComplexTypeDecode,
    T::Error: From<std::io::Error>,
{
    type Error = T::Error;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error> {
        let data = stream.read_ssh_bytes()?;
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let mut res = Vec::new();
        while cursor.position() < len {
            let elem: Result<T, Self::Error> = SshComplexTypeDecode::decode(&mut cursor);
            res.push(elem?);
        }
        Ok(res)
    }
}

impl SshComplexTypeDecode for SshExtension {
    type Error = SshExtensionError;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error> {
        let extension_type = stream.read_ssh_string()?;
        let data = stream.read_ssh_string()?;
        Ok(SshExtension {
            extension_type: SshExtensionType::try_from(extension_type)?,
            data,
        })
    }
}

impl SshComplexTypeDecode for Vec<String> {
    type Error = io::Error;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error> {
        let data = stream.read_ssh_bytes()?;
        let len = data.len();
        let mut cursor = Cursor::new(data);
        let mut res = Vec::new();
        while cursor.position() < len as u64 {
            res.push(cursor.read_ssh_string()?);
        }
        Ok(res)
    }
}

impl SshComplexTypeDecode for SshSignature {
    type Error = SshSignatureError;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error> {
        let _overall_size = stream.read_u32::<BigEndian>()?;

        let format = SshSignatureFormat::new(stream.read_ssh_string()?.as_str())?;
        let data = stream.read_ssh_bytes()?;

        match format {
            SshSignatureFormat::SkEd25519 | SshSignatureFormat::SkEcdsaSha2NistP256 => {
                let flags = stream.read_u8()?;
                let counter = stream.read_u32::<BigEndian>()?;

                Ok(SshSignature {
                    format,
                    blob: SshSignatureBlob::Sk { data, flags, counter },
                })
            }
            _ => Ok(SshSignature {
                format,
                blob: SshSignatureBlob::Standard(data),
            }),
        }
    }
}

impl SshComplexTypeDecode for KdfOption {
    type Error = io::Error;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error> {
        let data = stream.read_ssh_bytes()?;
        if data.is_empty() {
            return Ok(KdfOption::default());
        }
        let mut data = data.as_slice();
        let salt = data.read_ssh_bytes()?;
        let rounds = data.read_u32::<BigEndian>()?;
        Ok(KdfOption { salt, rounds })
    }
}

impl SshComplexTypeDecode for Timestamp {
    type Error = io::Error;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error> {
        let timestamp = stream.read_u64::<BigEndian>()?;
        let time = Timestamp::from(timestamp);
        Ok(time)
    }
}

impl SshComplexTypeDecode for SshBasePublicKey {
    type Error = SshPublicKeyError;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error> {
        let key_type = stream.read_ssh_string()?;
        match key_type.as_str() {
            key_type::RSA => {
                let e = stream.read_ssh_mpint()?;
                let n = stream.read_ssh_mpint()?;
                Ok(SshBasePublicKey::Rsa(PublicKey::from_rsa_components(&n, &e)))
            }
            key_type::ECDSA_SHA2_NIST_P256 | key_type::ECDSA_SHA2_NIST_P384 | key_type::ECDSA_SHA2_NIST_P521 => {
                let (curve, point) = decode_ec_public_key_body_impl(key_type.as_str(), &mut stream)?;
                Ok(SshBasePublicKey::Ec(PublicKey::from_ec_encoded_components(
                    &curve.into(),
                    &point,
                )))
            }
            key_type::ED25519 => {
                let (algorithm, public_key) = decode_ed25519_public_key_body_impl(key_type.as_str(), &mut stream)?;

                Ok(SshBasePublicKey::Ed(PublicKey::from_ed_encoded_components(
                    &algorithm.into(),
                    &public_key,
                )))
            }
            key_type::SK_ECDSA_SHA2_NIST_P256 => {
                let (curve, point) = decode_ec_public_key_body_impl(key_type.as_str(), &mut stream)?;
                let base_key = PublicKey::from_ec_encoded_components(&curve.into(), &point);
                let application = stream.read_ssh_string()?;

                Ok(SshBasePublicKey::SkEcdsaSha2NistP256 { base_key, application })
            }
            key_type::SK_ED25519 => {
                let (algorithm, public_key) = decode_ed25519_public_key_body_impl(key_type.as_str(), &mut stream)?;
                let base_key = PublicKey::from_ed_encoded_components(&algorithm.into(), &public_key);
                let application = stream.read_ssh_string()?;

                Ok(SshBasePublicKey::SkEd25519 { base_key, application })
            }
            _ => Err(SshPublicKeyError::UnknownKeyType),
        }
    }
}

fn decode_ed25519_public_key_body_impl(
    key_type: &str,
    stream: &mut impl Read,
) -> Result<(NamedEdAlgorithm, Vec<u8>), SshPublicKeyError> {
    let algorithm = match key_type {
        key_type::ED25519 => NamedEdAlgorithm::Known(EdAlgorithm::Ed25519),
        key_type::SK_ED25519 => NamedEdAlgorithm::Known(EdAlgorithm::Ed25519),
        _ => {
            return Err(SshPublicKeyError::UnknownKeyType);
        }
    };
    let public_key = stream.read_ssh_bytes()?;
    Ok((algorithm, public_key))
}

fn decode_ec_public_key_body_impl(
    key_type: &str,
    stream: &mut impl Read,
) -> Result<(NamedEcCurve, Vec<u8>), SshPublicKeyError> {
    let curve = match key_type {
        key_type::ECDSA_SHA2_NIST_P256 => NamedEcCurve::Known(EcCurve::NistP256),
        key_type::ECDSA_SHA2_NIST_P384 => NamedEcCurve::Known(EcCurve::NistP384),
        key_type::ECDSA_SHA2_NIST_P521 => NamedEcCurve::Unsupported(oids::secp521r1()),
        key_type::SK_ECDSA_SHA2_NIST_P256 => NamedEcCurve::Known(EcCurve::NistP256),
        _ => {
            return Err(SshPublicKeyError::UnknownKeyType);
        }
    };

    // Duplicated information about key type
    let _identifier = stream.read_ssh_string()?;

    // Public key encoded from an elliptic curve point into an
    // octet string as per [RFC](https://datatracker.ietf.org/doc/html/rfc5656#section-3.1).
    let point_data = stream.read_ssh_bytes()?;

    Ok((curve, point_data))
}

impl SshComplexTypeDecode for SshPublicKey {
    type Error = SshPublicKeyError;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error> {
        let mut buffer = Vec::with_capacity(1024);

        read_until_whitespace(&mut stream, &mut buffer)?;

        let header = String::from_utf8_lossy(&buffer).into_owned();
        buffer.clear();

        let inner_key = match header.as_str() {
            key_type::RSA
            | key_type::ECDSA_SHA2_NIST_P256
            | key_type::ECDSA_SHA2_NIST_P384
            | key_type::ECDSA_SHA2_NIST_P521
            | key_type::ED25519
            | key_type::SK_ECDSA_SHA2_NIST_P256
            | key_type::SK_ED25519 => {
                read_until_whitespace(&mut stream, &mut buffer)?;
                let mut slice = buffer.as_slice();
                let decoder = Base64Reader::new(&mut slice, &general_purpose::STANDARD);
                SshComplexTypeDecode::decode(decoder)?
            }
            _ => return Err(SshPublicKeyError::UnknownKeyType),
        };

        buffer.clear();
        read_until_linebreak(&mut stream, &mut buffer)?;
        let comment = core::str::from_utf8(&buffer)?.trim_end().to_owned();

        Ok(SshPublicKey { inner_key, comment })
    }
}

impl SshComplexTypeDecode for SshBasePrivateKey {
    type Error = SshPrivateKeyError;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error> {
        let key_type = stream.read_ssh_string()?;
        match key_type.as_str() {
            key_type::RSA => {
                let n_constant = stream.read_ssh_mpint()?;
                let e_constant = stream.read_ssh_mpint()?;
                let d_constant = stream.read_ssh_mpint()?;
                let _iqmp = stream.read_ssh_mpint()?;
                let p_constant = stream.read_ssh_mpint()?;
                let q_constant = stream.read_ssh_mpint()?;

                Ok(SshBasePrivateKey::Rsa(PrivateKey::from_rsa_components(
                    &n_constant,
                    &e_constant,
                    &d_constant,
                    &[p_constant, q_constant],
                )?))
            }
            key_type::ECDSA_SHA2_NIST_P256 | key_type::ECDSA_SHA2_NIST_P384 | key_type::ECDSA_SHA2_NIST_P521 => {
                let (curve, point) = decode_ec_public_key_body_impl(key_type.as_str(), &mut stream)?;

                let private_key_secret = stream.read_ssh_mpint()?.to_be_bytes_trimmed_vartime();

                Ok(SshBasePrivateKey::Ec(PrivateKey::from_ec_encoded_components(
                    curve.into(),
                    &private_key_secret,
                    Some(point.as_slice()),
                )))
            }
            key_type::ED25519 => {
                let (algorithm, public_key) = decode_ed25519_public_key_body_impl(key_type.as_str(), &mut stream)?;

                let private_key_secret = stream.read_ssh_mpint()?.to_be_bytes_trimmed_vartime();

                // OpenSSH is really strange in regards to private ed25519 keys. It stores them as
                // 64 byte-array, but actually only first 32 bytes are the private key, and the rest
                // is public key copy
                if private_key_secret.len() != SSH_COMBO_ED25519_KEY_LENGTH {
                    return Err(SshPrivateKeyError::InvalidKeyFormat);
                }

                let private_key_secret = &private_key_secret[..ed25519_dalek::SECRET_KEY_LENGTH];

                Ok(SshBasePrivateKey::Ed(PrivateKey::from_ed_encoded_components(
                    algorithm.into(),
                    private_key_secret,
                    Some(&public_key),
                )))
            }
            key_type::SK_ECDSA_SHA2_NIST_P256 => {
                let (_curve, point) = decode_ec_public_key_body_impl(key_type.as_str(), &mut stream)?;

                let application = stream.read_ssh_string()?;
                let flags = stream.read_u8()?;
                let handle = stream.read_ssh_bytes()?;
                let _reserved = stream.read_ssh_bytes()?;

                Ok(SshBasePrivateKey::SkEcdsaSha2NistP256 {
                    public_key: PublicKey::from_ec_encoded_components(
                        &ObjectIdentifier::from(NamedEcCurve::Known(EcCurve::NistP256)),
                        &point,
                    ),
                    application,
                    flags,
                    handle,
                })
            }
            key_type::SK_ED25519 => {
                let (_algorithm, public_key) = decode_ed25519_public_key_body_impl(key_type.as_str(), &mut stream)?;

                let application = stream.read_ssh_string()?;
                let flags = stream.read_u8()?;
                let handle = stream.read_ssh_bytes()?;
                let _reserved = stream.read_ssh_bytes()?;

                Ok(SshBasePrivateKey::SkEd25519 {
                    public_key: PublicKey::from_ed_encoded_components(
                        &ObjectIdentifier::from(EdAlgorithm::Ed25519),
                        &public_key,
                    ),
                    application,
                    flags,
                    handle,
                })
            }
            key_type => Err(SshPrivateKeyError::UnsupportedKeyType(key_type.to_owned())),
        }
    }
}

impl SshComplexTypeDecode for SshCertificate {
    type Error = SshCertificateError;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error> {
        let mut cert_type = Vec::new();
        read_until_whitespace(&mut stream, &mut cert_type)?;

        let _ = SshCertKeyType::try_from(String::from_utf8(cert_type)?)?;

        let mut cert_data = Vec::new();
        read_until_whitespace(&mut stream, &mut cert_data)?;

        let mut cert_data = cert_data.as_slice();
        let mut cert_data = Base64Reader::new(&mut cert_data, &general_purpose::STANDARD);

        let cert_key_type = cert_data.read_ssh_string()?;
        let cert_key_type = SshCertKeyType::try_from(cert_key_type)?;

        let nonce = cert_data.read_ssh_bytes()?;

        let inner_public_key = match &cert_key_type {
            SshCertKeyType::SshRsaV01 | SshCertKeyType::RsaSha2_256V01 | SshCertKeyType::RsaSha2_512v01 => {
                let e = cert_data.read_ssh_mpint()?;
                let n = cert_data.read_ssh_mpint()?;
                SshBasePublicKey::Rsa(PublicKey::from_rsa_components(&n, &e))
            }
            SshCertKeyType::EcdsaSha2Nistp256V01
            | SshCertKeyType::EcdsaSha2Nistp384V01
            | SshCertKeyType::EcdsaSha2Nistp521V01 => {
                let curve = match cert_key_type {
                    SshCertKeyType::EcdsaSha2Nistp256V01 => NamedEcCurve::Known(EcCurve::NistP256),
                    SshCertKeyType::EcdsaSha2Nistp384V01 => NamedEcCurve::Known(EcCurve::NistP384),
                    SshCertKeyType::EcdsaSha2Nistp521V01 => NamedEcCurve::Known(EcCurve::NistP521),
                    _ => unreachable!("Already validated in match above"),
                };

                let _curve_identifier = cert_data.read_ssh_string()?;

                let public_key_data = cert_data.read_ssh_bytes()?;
                SshBasePublicKey::Ec(PublicKey::from_ec_encoded_components(&curve.into(), &public_key_data))
            }
            SshCertKeyType::SshEd25519V01 => {
                let algorithm = NamedEdAlgorithm::Known(EdAlgorithm::Ed25519).into();

                let public_key_data = cert_data.read_ssh_bytes()?;
                SshBasePublicKey::Ed(PublicKey::from_ed_encoded_components(&algorithm, &public_key_data))
            }
            SshCertKeyType::SshDssV01 => {
                return Err(SshCertificateError::UnsupportedCertificateType(
                    cert_key_type.as_str().to_owned(),
                ));
            }
            SshCertKeyType::SkSshSha2Nistp256V01 => {
                let _curve_identifier = cert_data.read_ssh_string()?;
                let public_key_data = cert_data.read_ssh_bytes()?;
                let application = cert_data.read_ssh_string()?;

                SshBasePublicKey::SkEcdsaSha2NistP256 {
                    base_key: PublicKey::from_ec_encoded_components(
                        &NamedEcCurve::Known(EcCurve::NistP256).into(),
                        &public_key_data,
                    ),
                    application,
                }
            }
            SshCertKeyType::SkSshEd25519V01 => {
                let public_key_data = cert_data.read_ssh_bytes()?;
                let application = cert_data.read_ssh_string()?;

                SshBasePublicKey::SkEd25519 {
                    base_key: PublicKey::from_ed_encoded_components(
                        &NamedEdAlgorithm::Known(EdAlgorithm::Ed25519).into(),
                        &public_key_data,
                    ),
                    application,
                }
            }
        };

        let serial = cert_data.read_u64::<BigEndian>()?;
        let cert_type: SshCertType = SshComplexTypeDecode::decode(&mut cert_data)?;

        let key_id = cert_data.read_ssh_string()?;

        let valid_principals: Vec<String> = SshComplexTypeDecode::decode(&mut cert_data)?;

        let valid_after: Timestamp = SshComplexTypeDecode::decode(&mut cert_data)?;
        let valid_before: Timestamp = SshComplexTypeDecode::decode(&mut cert_data)?;

        let critical_options: Vec<SshCriticalOption> = SshComplexTypeDecode::decode(&mut cert_data)?;

        let extensions: Vec<SshExtension> = SshComplexTypeDecode::decode(&mut cert_data)?;

        let _ = cert_data.read_ssh_bytes()?; // reserved

        // here is public key
        let signature_key = cert_data.read_ssh_bytes()?;
        let signature_public_key: SshBasePublicKey = SshComplexTypeDecode::decode(signature_key.as_slice())?;

        let signature = SshSignature::decode(cert_data)?;

        let mut comment = Vec::new();
        read_until_linebreak(&mut stream, &mut comment)?;
        let comment = core::str::from_utf8(&comment)?.trim_end().to_owned();

        Ok(SshCertificate {
            cert_key_type,
            public_key: SshPublicKey {
                inner_key: inner_public_key,
                comment: String::new(),
            },
            nonce,
            serial,
            cert_type,
            key_id,
            valid_principals,
            valid_after,
            valid_before,
            critical_options,
            extensions,
            signature_key: SshPublicKey {
                inner_key: signature_public_key,
                comment: String::new(),
            },
            signature,
            comment,
        })
    }
}

#[cfg(test)]
mod test {
    use super::SshReadExt;
    use std::io::Cursor;

    #[test]
    fn ssh_string_decode() {
        let mut cursor = Cursor::new([0, 0, 0, 5, 112, 105, 99, 107, 121].to_vec());

        let ssh_string = cursor.read_ssh_string().unwrap();

        assert_eq!(5, ssh_string.len());
        assert_eq!("picky".to_owned(), ssh_string);
        assert_eq!(9, cursor.position());

        let mut cursor = Cursor::new([0, 0, 0, 0].to_vec());

        let ssh_string = cursor.read_ssh_string().unwrap();

        assert_eq!(0, ssh_string.len());
        assert_eq!("".to_owned(), ssh_string);
        assert_eq!(4, cursor.position());
    }

    #[test]
    fn byte_array_decode() {
        let mut cursor = Cursor::new([0, 0, 0, 5, 1, 2, 3, 4, 5].to_vec());

        let byte_array = cursor.read_ssh_bytes().unwrap();

        assert_eq!(5, byte_array.len());
        assert_eq!([1, 2, 3, 4, 5].to_vec(), byte_array);
        assert_eq!(9, cursor.position());

        let mut cursor = Cursor::new([0, 0, 0, 0].to_vec());

        let byte_array = cursor.read_ssh_bytes().unwrap();

        assert_eq!(0, byte_array.len());
        assert_eq!(Vec::<u8>::new(), byte_array);
        assert_eq!(4, cursor.position());
    }

    #[test]
    fn mpint_decoding() {
        let mut cursor = Cursor::new(vec![
            0x00, 0x00, 0x00, 0x08, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7,
        ]);
        let mpint = cursor.read_ssh_mpint().unwrap();
        assert_eq!(
            mpint.to_be_bytes_trimmed_vartime().as_ref(),
            &[0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]
        );

        let mut cursor = Cursor::new(vec![0x00, 0x00, 0x00, 0x02, 0x00, 0x80]);
        let mpint = cursor.read_ssh_mpint().unwrap();
        assert_eq!(mpint.to_be_bytes_trimmed_vartime().as_ref(), [0x80]);

        let mut cursor = Cursor::new(vec![0x00, 0x00, 0x00, 0x02, 0xed, 0xcc]);
        let mpint = cursor.read_ssh_mpint().unwrap();
        assert_eq!(mpint.to_be_bytes_trimmed_vartime().as_ref(), &[0xed, 0xcc]);
    }
}
