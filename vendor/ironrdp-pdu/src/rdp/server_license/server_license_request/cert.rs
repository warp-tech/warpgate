use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, cast_length, ensure_fixed_part_size,
    ensure_size, invalid_field_err, read_padding, write_padding,
};

use super::{BlobHeader, BlobType, KEY_EXCHANGE_ALGORITHM_RSA};

pub const SIGNATURE_ALGORITHM_RSA: u32 = 1;
pub const PROP_CERT_NO_BLOBS_SIZE: usize = 8;
pub const PROP_CERT_BLOBS_HEADERS_SIZE: usize = 8;
pub const X509_CERT_LENGTH_FIELD_SIZE: usize = 4;
pub const X509_CERT_COUNT: usize = 4;
pub const RSA_KEY_PADDING_LENGTH: u32 = 8;
pub const RSA_SENTINEL: u32 = 0x3141_5352;
pub const RSA_KEY_SIZE_WITHOUT_MODULUS: usize = 20;

const MIN_CERTIFICATE_AMOUNT: usize = 2;
const MAX_CERTIFICATE_AMOUNT: usize = 200;
const MAX_CERTIFICATE_LEN: usize = 4096;

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum CertificateType {
    Proprietary(ProprietaryCertificate),
    X509(X509CertificateChain),
}

/// [2.2.1.4.2] X.509 Certificate Chain (X509 _CERTIFICATE_CHAIN)
///
/// [2.2.1.4.2]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/bf2cc9cc-2b01-442e-a288-6ddfa3b80d59
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct X509CertificateChain {
    pub certificate_array: Vec<Vec<u8>>,
}

impl X509CertificateChain {
    const NAME: &'static str = "X509CertificateChain";
}

impl Encode for X509CertificateChain {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u32(cast_length!("certArrayLen", self.certificate_array.len())?);

        for certificate in &self.certificate_array {
            dst.write_u32(cast_length!("certLen", certificate.len())?);
            dst.write_slice(certificate);
        }

        let padding_len = 8 + 4 * self.certificate_array.len(); // MSDN: A byte array of the length 8 + 4*NumCertBlobs
        write_padding!(dst, padding_len);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        let certificates_length: usize = self
            .certificate_array
            .iter()
            .map(|certificate| certificate.len() + X509_CERT_LENGTH_FIELD_SIZE)
            .sum();
        let padding: usize = 8 + 4 * self.certificate_array.len();
        X509_CERT_COUNT + certificates_length + padding
    }
}

impl<'de> Decode<'de> for X509CertificateChain {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_size!(in: src, size: 4);
        let certificate_count = cast_length!("certArrayLen", src.read_u32())?;
        if !(MIN_CERTIFICATE_AMOUNT..MAX_CERTIFICATE_AMOUNT).contains(&certificate_count) {
            return Err(invalid_field_err!("certArrayLen", "invalid x509 certificate amount"));
        }

        let certificate_array: Vec<_> = core::iter::repeat_with(|| {
            ensure_size!(in: src, size: 4);
            let certificate_len = cast_length!("certLen", src.read_u32())?;
            if certificate_len > MAX_CERTIFICATE_LEN {
                return Err(invalid_field_err!("certLen", "invalid x509 certificate length"));
            }

            ensure_size!(in: src, size: certificate_len);
            let certificate = src.read_slice(certificate_len).into();

            Ok(certificate)
        })
        .take(certificate_count)
        .collect::<Result<_, _>>()?;

        let padding = 8 + 4 * certificate_count; // MSDN: A byte array of the length 8 + 4*NumCertBlobs
        ensure_size!(in: src, size: padding);
        read_padding!(src, padding);

        Ok(Self { certificate_array })
    }
}

/// [2.2.1.4.3.1.1] Server Proprietary Certificate (PROPRIETARYSERVERCERTIFICATE)
///
/// [2.2.1.4.3.1.1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/a37d449a-73ac-4f00-9b9d-56cefc954634
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ProprietaryCertificate {
    pub public_key: RsaPublicKey,
    pub signature: Vec<u8>,
}

impl ProprietaryCertificate {
    const NAME: &'static str = "ProprietaryCertificate";

    const FIXED_PART_SIZE: usize = PROP_CERT_BLOBS_HEADERS_SIZE + PROP_CERT_NO_BLOBS_SIZE;
}

impl Encode for ProprietaryCertificate {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u32(SIGNATURE_ALGORITHM_RSA);
        dst.write_u32(KEY_EXCHANGE_ALGORITHM_RSA);

        BlobHeader::new(BlobType::RSA_KEY, self.public_key.size()).encode(dst)?;
        self.public_key.encode(dst)?;

        BlobHeader::new(BlobType::RSA_SIGNATURE, self.signature.len()).encode(dst)?;
        dst.write_slice(&self.signature);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.public_key.size() + self.signature.len()
    }
}

impl<'de> Decode<'de> for ProprietaryCertificate {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_size!(in: src, size: PROP_CERT_NO_BLOBS_SIZE);

        let signature_algorithm_id = src.read_u32();
        if signature_algorithm_id != SIGNATURE_ALGORITHM_RSA {
            return Err(invalid_field_err!("sigAlgId", "invalid signature algorithm ID"));
        }

        let key_algorithm_id = src.read_u32();
        if key_algorithm_id != KEY_EXCHANGE_ALGORITHM_RSA {
            return Err(invalid_field_err!("keyAlgId", "invalid key algorithm ID"));
        }

        let key_blob_header = BlobHeader::decode(src)?;
        if key_blob_header.blob_type != BlobType::RSA_KEY {
            return Err(invalid_field_err!("blobType", "invalid blob type"));
        }
        let public_key = RsaPublicKey::decode(src)?;

        let sig_blob_header = BlobHeader::decode(src)?;
        if sig_blob_header.blob_type != BlobType::RSA_SIGNATURE {
            return Err(invalid_field_err!("blobType", "invalid blob type"));
        }
        ensure_size!(in: src, size: sig_blob_header.length);
        let signature = src.read_slice(sig_blob_header.length).into();

        Ok(Self { public_key, signature })
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct RsaPublicKey {
    pub public_exponent: u32,
    pub modulus: Vec<u8>,
}

impl RsaPublicKey {
    const NAME: &'static str = "RsaPublicKey";

    const FIXED_PART_SIZE: usize = RSA_KEY_SIZE_WITHOUT_MODULUS;
}

impl Encode for RsaPublicKey {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        let keylen = cast_length!("modulusLen", self.modulus.len())?;
        let bitlen = (keylen - RSA_KEY_PADDING_LENGTH) * 8;
        let datalen = bitlen / 8 - 1;

        dst.write_u32(RSA_SENTINEL); // magic
        dst.write_u32(keylen);
        dst.write_u32(bitlen);
        dst.write_u32(datalen);
        dst.write_u32(self.public_exponent);
        dst.write_slice(&self.modulus);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.modulus.len()
    }
}

impl<'de> Decode<'de> for RsaPublicKey {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let magic = src.read_u32();
        if magic != RSA_SENTINEL {
            return Err(invalid_field_err!("magic", "invalid RSA public key magic"));
        }

        let keylen = cast_length!("keyLen", src.read_u32())?;

        let bitlen: usize = cast_length!("bitlen", src.read_u32())?;
        if keylen != (bitlen / 8) + 8 {
            return Err(invalid_field_err!("bitlen", "invalid RSA public key length"));
        }

        if bitlen < 8 {
            return Err(invalid_field_err!("bitlen", "invalid RSA public key length"));
        }

        let datalen: usize = cast_length!("dataLen", src.read_u32())?;
        if datalen != (bitlen / 8) - 1 {
            return Err(invalid_field_err!("dataLen", "invalid RSA public key data length"));
        }

        let public_exponent = src.read_u32();

        ensure_size!(in: src, size: keylen);
        let modulus = src.read_slice(keylen).into();

        Ok(Self {
            public_exponent,
            modulus,
        })
    }
}
