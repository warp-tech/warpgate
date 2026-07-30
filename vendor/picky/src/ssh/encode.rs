use crate::key::ec::{EcdsaKeypair, EcdsaPublicKey};
use crate::key::ed::{EdKeypair, EdPublicKey};
use crate::ssh::certificate::{
    SshCertType, SshCertTypeError, SshCertificate, SshCertificateError, SshCriticalOption, SshCriticalOptionError,
    SshExtension, SshExtensionError, SshSignature, SshSignatureError, Timestamp,
};
use crate::ssh::private_key::{
    AES256_CTR, AUTH_MAGIC, Aes256Ctr, BCRYPT, KdfOption, NONE, SshBasePrivateKey, SshPrivateKey, SshPrivateKeyError,
};
use crate::ssh::public_key::{SshBasePublicKey, SshPublicKey, SshPublicKeyError};
use crate::ssh::{Base64Writer, EcCurveSshExt as _, EdAlgorithmSshExt as _, SSH_COMBO_ED25519_KEY_LENGTH, key_type};

use super::certificate::SshSignatureBlob;
use super::key_identifier;
use aes::cipher::{KeyIvInit, StreamCipher};
use base64::engine::general_purpose;
use byteorder::{BigEndian, WriteBytesExt};
use crypto_bigint::NonZero;
use rsa::traits::{PrivateKeyParts as _, PublicKeyParts as _};
use rsa::{BoxedUint, RsaPrivateKey, RsaPublicKey};
use std::io::{self, Write};

pub trait SshWriteExt {
    type Error;

    fn write_ssh_string(&mut self, data: &str) -> Result<(), Self::Error>;
    fn write_ssh_bytes(&mut self, data: &[u8]) -> Result<(), Self::Error>;
    fn write_ssh_mpint(&mut self, data: &BoxedUint) -> Result<(), Self::Error>;
}

impl<T> SshWriteExt for T
where
    T: Write,
{
    type Error = io::Error;

    fn write_ssh_string(&mut self, data: &str) -> Result<(), Self::Error> {
        self.write_u32::<BigEndian>(data.len() as u32)?;
        self.write_all(data.as_bytes())
    }

    fn write_ssh_bytes(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.write_u32::<BigEndian>(data.len() as u32)?;
        self.write_all(data)
    }

    fn write_ssh_mpint(&mut self, data: &BoxedUint) -> Result<(), Self::Error> {
        let data = data.to_be_bytes_trimmed_vartime();
        let size = data.len() as u32;
        // If the most significant bit would be set for
        // a positive number, the number MUST be preceded by a zero byte.
        if size > 0 && data[0] & 0b10000000 != 0 {
            self.write_u32::<BigEndian>(size + 1)?;
            self.write_u8(0)?;
        } else {
            self.write_u32::<BigEndian>(size)?;
        }
        self.write_all(&data)
    }
}

pub trait SshComplexTypeEncode {
    type Error;

    fn encode(&self, stream: impl Write) -> Result<(), Self::Error>;
}

impl SshComplexTypeEncode for SshCertType {
    type Error = SshCertTypeError;

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        stream.write_u32::<BigEndian>((*self).into())?;
        Ok(())
    }
}

impl SshComplexTypeEncode for SshCriticalOption {
    type Error = SshCriticalOptionError;

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        stream.write_ssh_string(self.option_type.as_str())?;
        stream.write_ssh_string(self.data.as_str())?;
        Ok(())
    }
}

impl<T> SshComplexTypeEncode for Vec<T>
where
    T: SshComplexTypeEncode,
    T::Error: From<std::io::Error>,
{
    type Error = T::Error;

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        let mut data = Vec::new();
        for elem in self.iter() {
            elem.encode(&mut data)?;
        }
        stream.write_ssh_bytes(&data)?;
        Ok(())
    }
}

impl SshComplexTypeEncode for SshExtension {
    type Error = SshExtensionError;

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        stream.write_ssh_string(self.extension_type.as_str())?;
        stream.write_ssh_string(self.data.as_str())?;
        Ok(())
    }
}

impl SshComplexTypeEncode for Vec<String> {
    type Error = io::Error;

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        let mut data = Vec::new();
        for s in self.iter() {
            data.write_ssh_string(s)?;
        }
        stream.write_ssh_bytes(&data)?;
        Ok(())
    }
}

impl SshComplexTypeEncode for SshSignature {
    type Error = SshSignatureError;

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        let overall_size = self.format.as_str().len() + self.blob.size() + 8;
        stream.write_u32::<BigEndian>(overall_size as u32)?;
        stream.write_ssh_string(self.format.as_str())?;

        match &self.blob {
            SshSignatureBlob::Standard(data) => {
                stream.write_ssh_bytes(data)?;
            }
            SshSignatureBlob::Sk { data, flags, counter } => {
                stream.write_ssh_bytes(data)?;
                stream.write_u8(*flags)?;
                stream.write_u32::<BigEndian>(*counter)?;
            }
        };

        Ok(())
    }
}

impl SshComplexTypeEncode for KdfOption {
    type Error = io::Error;

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        if self.salt.is_empty() {
            stream.write_u32::<BigEndian>(0)?;
            return Ok(());
        }
        let mut data = Vec::new();
        data.write_ssh_bytes(&self.salt)?;
        data.write_u32::<BigEndian>(self.rounds)?;
        stream.write_ssh_bytes(&data)?;
        Ok(())
    }
}

impl SshComplexTypeEncode for Timestamp {
    type Error = io::Error;

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        stream.write_u64::<BigEndian>(self.0)?;
        Ok(())
    }
}

impl SshComplexTypeEncode for SshBasePublicKey {
    type Error = SshPublicKeyError;

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        match self {
            SshBasePublicKey::Rsa(rsa) => {
                let rsa = RsaPublicKey::try_from(rsa)?;
                stream.write_ssh_string(key_type::RSA)?;
                stream.write_ssh_mpint(rsa.e())?;
                stream.write_ssh_mpint(rsa.n())?;
                Ok(())
            }
            SshBasePublicKey::Ec(ec) => {
                let key = EcdsaPublicKey::try_from(ec)?;
                encode_ecdsa_public_key_body(&mut stream, &key)?;
                Ok(())
            }
            SshBasePublicKey::Ed(ed) => {
                let key = EdPublicKey::try_from(ed)?;
                encode_ed_public_key_body(&mut stream, &key)
            }
            SshBasePublicKey::SkEcdsaSha2NistP256 { base_key, application } => {
                let key = EcdsaPublicKey::try_from(base_key)?;

                stream.write_ssh_string(key_type::SK_ECDSA_SHA2_NIST_P256)?;
                stream.write_ssh_string(key_identifier::ECDSA_SHA2_NIST_P256)?;
                stream.write_ssh_bytes(key.encoded_point())?;

                stream.write_ssh_string(application.as_str())?;

                Ok(())
            }
            SshBasePublicKey::SkEd25519 { base_key, application } => {
                let key = EdPublicKey::try_from(base_key)?;

                stream.write_ssh_string(key_type::SK_ED25519)?;
                stream.write_ssh_bytes(key.data())?;

                stream.write_ssh_string(application.as_str())?;

                Ok(())
            }
        }
    }
}

impl SshComplexTypeEncode for SshPublicKey {
    type Error = SshPublicKeyError;

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        // Write key type
        match &self.inner_key {
            SshBasePublicKey::Rsa(_) => {
                stream.write_all(key_type::RSA.as_bytes())?;
            }
            SshBasePublicKey::Ec(key) => {
                let key = EcdsaPublicKey::try_from(key)?;
                stream.write_all(key.curve().to_ecdsa_ssh_key_type()?.as_bytes())?;
            }
            SshBasePublicKey::Ed(key) => {
                let key = EdPublicKey::try_from(key)?;
                stream.write_all(key.algorithm().to_ed_ssh_key_type()?.as_bytes())?;
            }
            SshBasePublicKey::SkEcdsaSha2NistP256 { .. } => {
                stream.write_all(key_type::SK_ECDSA_SHA2_NIST_P256.as_bytes())?;
            }
            SshBasePublicKey::SkEd25519 { .. } => {
                stream.write_all(key_type::SK_ED25519.as_bytes())?;
            }
        };

        stream.write_u8(b' ')?;

        {
            let mut base64_write = Base64Writer::new(&mut stream, &general_purpose::STANDARD);
            self.inner_key.encode(&mut base64_write)?;
            base64_write.finish()?;
        }

        stream.write_u8(b' ')?;
        stream.write_all(self.comment.as_bytes())?;
        stream.write_all("\r\n".as_bytes())?;

        Ok(())
    }
}

impl SshComplexTypeEncode for SshBasePrivateKey {
    type Error = SshPrivateKeyError;

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        match self {
            SshBasePrivateKey::Rsa(rsa) => {
                let rsa = RsaPrivateKey::try_from(rsa)?;
                stream.write_ssh_string(key_type::RSA)?;
                stream.write_ssh_mpint(rsa.n())?;
                stream.write_ssh_mpint(rsa.e())?;
                stream.write_ssh_mpint(rsa.d())?;

                let prime = NonZero::new(rsa.primes()[0].clone())
                    .into_option()
                    .ok_or(SshPrivateKeyError::RsaPrimeIsZero)?;
                let iqmp = rsa.primes()[1]
                    .invert_mod(&prime)
                    .into_option()
                    .ok_or(SshPrivateKeyError::RsaSecondPrimeInvertModFirstPrimeFailed)?;
                stream.write_ssh_mpint(&iqmp)?;

                for prime in rsa.primes().iter() {
                    stream.write_ssh_mpint(prime)?;
                }
            }
            SshBasePrivateKey::Ec(key) => {
                let keypair = EcdsaKeypair::try_from(key)?;

                let public_key = EcdsaPublicKey::try_from(&keypair)?;

                // Encode the public key part
                encode_ecdsa_public_key_body(&mut stream, &public_key)?;

                // Ecnode encoded secret
                let secret = BoxedUint::from_be_slice_vartime(keypair.secret());
                stream.write_ssh_mpint(&secret)?;
            }
            SshBasePrivateKey::Ed(key) => {
                let keypair = EdKeypair::try_from(key)?;
                let public_key = EdPublicKey::try_from(&keypair)?;
                encode_ed_public_key_body(&mut stream, &public_key)?;

                // SSH Ed25519 key private kye field contains secret in first 32 bytes and the
                // public key copy in the last 32 bytes.
                let mut secret = Vec::with_capacity(SSH_COMBO_ED25519_KEY_LENGTH);
                secret.extend_from_slice(keypair.secret());
                secret.extend_from_slice(public_key.data());

                stream.write_ssh_bytes(&secret)?;
            }
            SshBasePrivateKey::SkEcdsaSha2NistP256 {
                public_key,
                application,
                flags,
                handle,
            } => {
                let ec_key = EcdsaPublicKey::try_from(public_key)?;

                // Encode the public key part
                stream.write_ssh_string(key_type::SK_ECDSA_SHA2_NIST_P256)?;
                stream.write_ssh_string(key_identifier::ECDSA_SHA2_NIST_P256)?;
                stream.write_ssh_bytes(ec_key.encoded_point())?;

                stream.write_ssh_string(application.as_str())?;
                stream.write_u8(*flags)?;
                stream.write_ssh_bytes(handle)?;
                // Reserved
                stream.write_ssh_bytes(&[])?;
            }
            SshBasePrivateKey::SkEd25519 {
                public_key,
                application,
                flags,
                handle,
            } => {
                let ed_key = EdPublicKey::try_from(public_key)?;

                stream.write_ssh_string(key_type::SK_ED25519)?;
                stream.write_ssh_bytes(ed_key.data())?;

                stream.write_ssh_string(application.as_str())?;
                stream.write_u8(*flags)?;
                stream.write_ssh_bytes(handle)?;
                // Reserved
                stream.write_ssh_bytes(&[])?;
            }
        };

        Ok(())
    }
}

fn encode_ed_public_key_body(mut stream: impl Write, key: &EdPublicKey<'_>) -> Result<(), SshPublicKeyError> {
    stream.write_ssh_string(key.algorithm().to_ed_ssh_key_type()?)?;
    stream.write_ssh_bytes(key.data())?;
    Ok(())
}

fn encode_ecdsa_public_key_body(mut stream: impl Write, key: &EcdsaPublicKey<'_>) -> Result<(), SshPublicKeyError> {
    stream.write_ssh_string(key.curve().to_ecdsa_ssh_key_type()?)?;
    stream.write_ssh_string(key.curve().to_ecdsa_ssh_key_identifier()?)?;

    // So called "Q" value from RFC5656. In fact - standard SEC1 encoded public key representation
    stream.write_ssh_bytes(key.encoded_point())?;
    Ok(())
}

impl SshComplexTypeEncode for SshPrivateKey {
    type Error = SshPrivateKeyError;

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        const AES256_CTR_BLOCK_SIZE: usize = 16;
        const UNENCRYPTED_PADDING_SIZE: usize = 8;

        stream.write_all(AUTH_MAGIC.as_bytes())?;
        stream.write_u8(b'\0')?;

        if self.passphrase.is_some() {
            stream.write_ssh_string(AES256_CTR)?;
            stream.write_ssh_string(BCRYPT)?;

            let salt = &self.kdf.option.salt;
            let rounds = self.kdf.option.rounds;

            let mut kdf_options = Vec::new();
            kdf_options.write_ssh_bytes(salt)?;
            kdf_options.write_u32::<BigEndian>(rounds)?;

            stream.write_ssh_bytes(&kdf_options)?;
        } else {
            stream.write_ssh_string(NONE)?;
            stream.write_ssh_string(NONE)?;
            stream.write_ssh_string("")?;
        }

        stream.write_u32::<BigEndian>(1)?; // keys amount

        let mut public_key = Vec::new();
        self.public_key().inner_key.encode(&mut public_key)?;
        stream.write_ssh_bytes(&public_key)?;

        public_key.clear();
        let mut private_key = public_key;

        private_key.write_u32::<BigEndian>(self.check)?;
        private_key.write_u32::<BigEndian>(self.check)?;
        self.base_key.encode(&mut private_key)?;

        private_key.write_ssh_string(&self.comment)?;

        let padding_size = if self.passphrase.is_some() {
            AES256_CTR_BLOCK_SIZE
        } else {
            UNENCRYPTED_PADDING_SIZE
        };

        // add padding
        for i in 1..=(padding_size - (private_key.len() % padding_size)) {
            private_key.push(i as u8);
        }

        if let Some(passphrase) = &self.passphrase {
            // encrypt private_key
            let n = 48;
            let mut hash = [0; 48];

            let salt = &self.kdf.option.salt;
            let rounds = self.kdf.option.rounds;

            bcrypt_pbkdf::bcrypt_pbkdf(passphrase, salt, rounds, &mut hash)?;

            let (key, iv) = hash.split_at(n - 16);
            let mut cipher = Aes256Ctr::new_from_slices(key, iv).unwrap();

            let private_key_len = private_key.len();
            private_key.resize(private_key_len + 32, 0u8);
            cipher.apply_keystream(&mut private_key);
            private_key.truncate(private_key_len);
        }

        stream.write_ssh_bytes(&private_key)?;

        Ok(())
    }
}

impl SshComplexTypeEncode for SshCertificate {
    type Error = SshCertificateError;

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        stream.write_all(self.cert_key_type.as_str().as_bytes())?;
        stream.write_u8(b' ')?;

        let mut cert_data = Base64Writer::new(stream, &general_purpose::STANDARD);

        cert_data.write_ssh_string(self.cert_key_type.as_str())?;
        cert_data.write_ssh_bytes(&self.nonce)?;
        match &self.public_key.inner_key {
            SshBasePublicKey::Rsa(rsa) => {
                let rsa = RsaPublicKey::try_from(rsa)?;
                cert_data.write_ssh_mpint(rsa.e())?;
                cert_data.write_ssh_mpint(rsa.n())?;
            }
            SshBasePublicKey::Ec(ec) => {
                let ec = EcdsaPublicKey::try_from(ec)?;
                cert_data.write_ssh_string(ec.curve().to_ecdsa_ssh_key_identifier()?)?;
                cert_data.write_ssh_bytes(ec.encoded_point())?;
            }
            SshBasePublicKey::Ed(ed) => {
                let ed = EdPublicKey::try_from(ed)?;
                cert_data.write_ssh_bytes(ed.data())?;
            }
            SshBasePublicKey::SkEcdsaSha2NistP256 { base_key, application } => {
                let ec = EcdsaPublicKey::try_from(base_key)?;
                cert_data.write_ssh_string(key_identifier::ECDSA_SHA2_NIST_P256)?;
                cert_data.write_ssh_bytes(ec.encoded_point())?;
                cert_data.write_ssh_string(application.as_str())?;
            }
            SshBasePublicKey::SkEd25519 { base_key, application } => {
                let ed = EdPublicKey::try_from(base_key)?;
                cert_data.write_ssh_bytes(ed.data())?;
                cert_data.write_ssh_string(application.as_str())?;
            }
        };

        cert_data.write_u64::<BigEndian>(self.serial)?;

        self.cert_type.encode(&mut cert_data)?;

        cert_data.write_ssh_string(self.key_id.as_str())?;

        self.valid_principals.encode(&mut cert_data)?;
        self.valid_after.encode(&mut cert_data)?;
        self.valid_before.encode(&mut cert_data)?;
        self.critical_options.encode(&mut cert_data)?;
        self.extensions.encode(&mut cert_data)?;

        cert_data.write_ssh_bytes(&[])?; // reserved

        let mut rsa_key = Vec::new();
        self.signature_key.inner_key.encode(&mut rsa_key)?;

        cert_data.write_ssh_bytes(&rsa_key)?;
        self.signature.encode(&mut cert_data)?;

        // stream.write_all(cert_data.finish()?.as_slice())?;
        let mut stream = cert_data.finish().unwrap();
        stream.write_u8(b' ')?;

        stream.write_all(self.comment.as_bytes())?;
        stream.write_all("\r\n".as_bytes())?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::SshWriteExt;
    use rsa::BoxedUint;

    #[test]
    fn ssh_string_encode() {
        let mut res = Vec::new();
        let ssh_string = "picky";

        res.write_ssh_string(ssh_string).unwrap();

        assert_eq!(vec![0, 0, 0, 5, 112, 105, 99, 107, 121], res);

        res.clear();
        let ssh_string = "";

        res.write_ssh_string(ssh_string).unwrap();

        assert_eq!(vec![0, 0, 0, 0], res);
    }

    #[test]
    fn byte_array_encode() {
        let mut res = Vec::new();
        let byte_array = [1, 2, 3, 4, 5, 6];

        res.write_ssh_bytes(&byte_array).unwrap();

        assert_eq!(vec![0, 0, 0, 6, 1, 2, 3, 4, 5, 6], res);

        res.clear();
        let byte_array = [];

        res.write_ssh_bytes(&byte_array).unwrap();

        assert_eq!(vec![0, 0, 0, 0], res);
    }

    #[test]
    fn mpint_encoding() {
        let mpint = BoxedUint::from_be_slice_vartime(&[0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]);
        let mut res = Vec::new();
        res.write_ssh_mpint(&mpint).unwrap();

        assert_eq!(
            res,
            vec![0x00, 0x00, 0x00, 0x08, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7],
        );

        let mpint = BoxedUint::from_be_slice_vartime(&[0x80]);
        let mut res = Vec::new();
        res.write_ssh_mpint(&mpint).unwrap();

        assert_eq!(res, vec![0x00, 0x00, 0x00, 0x02, 0x00, 0x80]);
    }
}
