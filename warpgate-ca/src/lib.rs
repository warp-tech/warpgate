use std::time::{Duration, SystemTime};

use aws_lc_rs::digest;
use aws_lc_rs::error::KeyRejected;
use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P384_SHA3_384_ASN1_SIGNING};
use data_encoding::BASE64;
use der::{Decode, DecodePem, Encode};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use uuid::Uuid;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use x509_cert::{Certificate, TbsCertificate, Version};
use x509_parser::pem::parse_x509_pem;

use hex;

mod error;
pub use error::CaError;

impl From<KeyRejected> for CaError {
    fn from(err: KeyRejected) -> Self {
        CaError::Other(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Key rejected: {:?}", err),
        )))
    }
}

/// A certificate and its associated private key
#[derive(Debug)]
pub struct CertifiedKey {
    /// The X.509 certificate
    pub certificate: Certificate,
    /// The private key in DER format
    pub private_key_der: Vec<u8>,
}

impl CertifiedKey {
    /// Get the certificate as PEM-encoded string
    pub fn certificate_pem(&self) -> Result<String, CaError> {
        let der = self.certificate.to_der()?;
        let pem_data = pem::Pem::new("CERTIFICATE", der);
        Ok(pem::encode(&pem_data))
    }

    /// Get the private key as PEM-encoded string
    pub fn private_key_pem(&self) -> String {
        let pem_data = pem::Pem::new("EC PRIVATE KEY", self.private_key_der.clone());
        pem::encode(&pem_data)
    }
}

pub fn generate_root_certificate_rcgen() -> Result<(String, String), CaError> {
    use rcgen::{CertificateParams, DistinguishedName, IsCa, KeyPair};

    // Create a new key pair
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)?;

    // Create certificate parameters
    let mut params = CertificateParams::new(vec![])?;

    // Set up distinguished name
    let mut dn = DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "Warpgate Instance CA");
    params.distinguished_name = dn;

    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.not_before = SystemTime::now().into();
    params.not_after = (SystemTime::now() + Duration::from_secs(99 * 365 * 24 * 60 * 60)).into();

    // Generate the certificate
    let cert = params.self_signed(&key_pair)?;

    Ok((cert.pem(), key_pair.serialize_pem()))
}

pub fn deserialize_certificate(pem: &str) -> Result<Certificate, CaError> {
    let (_, pem_cert) = parse_x509_pem(pem.as_bytes())?;

    Ok(Certificate::from_der(&pem_cert.contents)?)
}

pub fn serialize_certificate_serial(cert: &Certificate) -> String {
    BASE64.encode(cert.tbs_certificate.serial_number.as_bytes())
}

pub fn certificate_sha256_hex_fingerprint(cert: &Certificate) -> Result<String, CaError> {
    let der = cert.to_der()?;
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &der);
    Ok(hex::encode(digest.as_ref()))
}

/// Deserialize a CA certificate and private key from PEM format
pub fn deserialize_ca(
    certificate_pem: &str,
    private_key_pem: &str,
) -> Result<CertifiedKey, CaError> {
    let certificate = deserialize_certificate(certificate_pem)?;

    // Parse the private key PEM
    let key_pem = pem::parse(private_key_pem).map_err(|e| {
        CaError::Other(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to parse private key PEM: {:?}", e),
        )))
    })?;

    // Validate it's a private key by checking the tag
    let tag = key_pem.tag();
    dbg!(&tag);
    let ec_private_key_tag = "PRIVATE KEY";
    if tag != ec_private_key_tag {
        return Err(CaError::InvalidKeyFormat);
    }

    Ok(CertifiedKey {
        certificate,
        private_key_der: key_pem.contents().to_vec(),
    })
}

/// Issue a client certificate signed by the CA
pub fn issue_client_certificate(
    ca: &CertifiedKey,
    subject_name: &str,
    public_key_pem: &str,
    user_id: Uuid,
) -> Result<Certificate, CaError> {
    use const_oid::db::{rfc4519, rfc5280, rfc5912};
    use der::asn1::{OctetString, SetOfVec, Utf8StringRef};
    use x509_cert::attr::AttributeTypeAndValue;
    use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};
    use x509_cert::ext::Extension;
    use x509_cert::name::{RdnSequence, RelativeDistinguishedName};

    let ca_key_pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA3_384_ASN1_SIGNING, &ca.private_key_der)?;

    let validity = {
        let validity = Duration::from_secs(365 * 24 * 60 * 60);
        let now = SystemTime::now();
        Validity {
            not_before: now.try_into()?,
            not_after: (now + validity).try_into()?,
        }
    };

    let subject = {
        let mut name_attrs = Vec::new();
        name_attrs.push(AttributeTypeAndValue {
            oid: rfc4519::UID,
            value: Utf8StringRef::new(&user_id.to_string())?.into(),
        });

        #[allow(clippy::unwrap_used)] // infallible
        let rdn = RelativeDistinguishedName::try_from(SetOfVec::try_from(name_attrs)?).unwrap();
        RdnSequence::from(vec![rdn])
    };

    // Get the issuer name from the CA certificate
    let issuer = ca.certificate.tbs_certificate.issuer.clone();

    let serial_number = {
        // Generate a unique serial number
        let mut hasher = digest::Context::new(&digest::SHA256);
        hasher.update(subject_name.as_bytes());
        hasher.update(
            &SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .to_le_bytes(),
        );
        let hash = hasher.finish();
        let serial_bytes = &hash.as_ref()[..8]; // Use first 8 bytes
        SerialNumber::new(serial_bytes)?
    };

    let public_key = SubjectPublicKeyInfo::from_pem(public_key_pem)?;

    let tbs_cert = TbsCertificate {
        version: Version::V3,
        serial_number,
        signature: AlgorithmIdentifier {
            oid: rfc5912::ECDSA_WITH_SHA_384,
            parameters: None,
        },
        issuer,
        validity,
        subject,
        subject_public_key_info: public_key,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(vec![
            Extension {
                extn_id: rfc5280::ID_CE_BASIC_CONSTRAINTS,
                critical: true,
                extn_value: OctetString::new(
                    BasicConstraints {
                        ca: false,
                        path_len_constraint: None,
                    }
                    .to_der()?,
                )?,
            },
            Extension {
                extn_id: rfc5280::ID_CE_KEY_USAGE,
                critical: true,
                extn_value: OctetString::new({
                    (KeyUsage::from(
                        KeyUsages::DigitalSignature
                            | KeyUsages::KeyEncipherment
                            | KeyUsages::DataEncipherment,
                    ))
                    .to_der()?
                })?,
            },
        ]),
    };

    let signature = {
        // Sign the certificate
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let tbs_cert_der = tbs_cert.to_der()?;
        ca_key_pair.sign(&rng, &tbs_cert_der)?
    };

    let certificate = Certificate {
        tbs_certificate: tbs_cert,
        signature_algorithm: AlgorithmIdentifier {
            oid: rfc5912::ECDSA_WITH_SHA_384,
            parameters: None,
        },
        signature: der::asn1::BitString::from_bytes(signature.as_ref())?,
    };

    Ok(certificate)
}

/// Convert a certificate to PEM format
pub fn certificate_to_pem(certificate: &Certificate) -> Result<String, CaError> {
    let der = certificate.to_der()?;
    let pem_data = pem::Pem::new("CERTIFICATE", der);
    Ok(pem::encode(&pem_data))
}
