use std::time::{Duration, SystemTime};

use aws_lc_rs::digest;
use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use aws_lc_rs::error::KeyRejected;
use der::{Decode, Encode};
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};
use x509_cert::{Certificate, TbsCertificate, Version};
use x509_parser::parse_x509_certificate;
use x509_parser::pem::parse_x509_pem;
use spki::{SubjectPublicKeyInfo, AlgorithmIdentifier};

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
        let pem_data = pem::Pem::new("PRIVATE KEY", self.private_key_der.clone());
        pem::encode(&pem_data)
    }
}

/// Generate a new root CA certificate and private key
pub fn generate_root_certificate() -> Result<CertifiedKey, CaError> {
    // Generate a new ECDSA P-256 key pair
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)?;
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_bytes.as_ref())?;

    // Create validity period (1 year from now)
    let now = SystemTime::now();
    let not_before = Time::try_from(now)?;
    let not_after = Time::try_from(now + Duration::from_secs(365 * 24 * 60 * 60))?;
    let validity = Validity { not_before, not_after };

    // Create distinguished name for the CA
    let mut name_attrs = Vec::new();
    name_attrs.push(x509_cert::attr::AttributeTypeAndValue {
        oid: const_oid::db::rfc4519::CN, // Common Name
        value: der::Any::from(der::asn1::Utf8StringRef::new("Warpgate Root CA")?),
    });
    let rdn = x509_cert::name::RelativeDistinguishedName::try_from(
        der::asn1::SetOfVec::from(name_attrs)
    )?;
    let subject = x509_cert::name::RdnSequence::from(vec![rdn]);

    // For self-signed certificate, issuer = subject
    let issuer = subject.clone();

    // Create serial number
    let serial_number = SerialNumber::from(42u64);

    // Get the public key from the private key - we need to construct the SubjectPublicKeyInfo manually
    let public_key_bytes = key_pair.public_key().as_ref();
    
    // Create the algorithm identifier for ECDSA with secp256r1
    let algorithm = AlgorithmIdentifier {
        oid: const_oid::db::rfc5912::ID_EC_PUBLIC_KEY,
        parameters: Some(der::Any::from(const_oid::db::rfc5912::SECP_256_R_1)),
    };
    
    let public_key = SubjectPublicKeyInfo {
        algorithm,
        subject_public_key: der::asn1::BitString::from_bytes(public_key_bytes)?,
    };

    // Build the certificate manually
    let tbs_cert = TbsCertificate {
        version: Version::V3,
        serial_number,
        signature: AlgorithmIdentifier {
            oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
            parameters: None,
        },
        issuer,
        validity,
        subject,
        subject_public_key_info: public_key,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(vec![
            // Basic Constraints: CA=true
            x509_cert::ext::Extension {
                extn_id: const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS,
                critical: true,
                extn_value: der::asn1::OctetString::new(
                    x509_cert::ext::pkix::BasicConstraints { ca: true, path_len_constraint: None }.to_der()?
                )?,
            },
            // Key Usage: Certificate Sign, CRL Sign
            x509_cert::ext::Extension {
                extn_id: const_oid::db::rfc5280::ID_CE_KEY_USAGE,
                critical: true,
                extn_value: der::asn1::OctetString::new({
                    let key_usage = x509_cert::ext::pkix::KeyUsage(
                        der::asn1::BitString::from_bytes(&[0x06])? // keyCertSign and cRLSign
                    );
                    key_usage.to_der()?
                })?,
            },
        ]),
    };

    // Sign the certificate
    let tbs_cert_der = tbs_cert.to_der()?;
    let signature = key_pair.sign(&rng, &tbs_cert_der)?;

    let certificate = Certificate {
        tbs_certificate: tbs_cert,
        signature_algorithm: AlgorithmIdentifier {
            oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
            parameters: None,
        },
        signature: der::asn1::BitString::from_bytes(signature.as_ref())?,
    };

    Ok(CertifiedKey {
        certificate,
        private_key_der: pkcs8_bytes.as_ref().to_vec(),
    })
}

/// Deserialize a CA certificate and private key from PEM format
pub fn deserialize_ca(
    certificate_pem: &str,
    private_key_pem: &str,
) -> Result<CertifiedKey, CaError> {
    // Parse and validate the certificate PEM
    let (_, pem_cert) = parse_x509_pem(certificate_pem.as_bytes())
        .map_err(|e| CaError::Other(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to parse certificate PEM: {:?}", e),
        ))))?;

    // Parse the X.509 certificate to validate it
    let (_, _parsed_cert) = parse_x509_certificate(&pem_cert.contents)
        .map_err(|e| CaError::Other(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to parse certificate: {:?}", e),
        ))))?;

    // Parse the certificate with x509-cert
    let certificate = Certificate::from_der(&pem_cert.contents)?;

    // Parse the private key PEM
    let key_pem = pem::parse(private_key_pem)
        .map_err(|e| CaError::Other(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to parse private key PEM: {:?}", e),
        ))))?;

    // Validate it's a private key by checking the tag
    let tag = key_pem.tag();
    if tag != "PRIVATE KEY" && tag != "EC PRIVATE KEY" && tag != "RSA PRIVATE KEY" {
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
    public_key_der: &[u8],
) -> Result<Certificate, CaError> {
    // Parse the CA's private key for signing
    let ca_key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &ca.private_key_der)?;

    // Create validity period (1 year from now)
    let now = SystemTime::now();
    let not_before = Time::try_from(now)?;
    let not_after = Time::try_from(now + Duration::from_secs(365 * 24 * 60 * 60))?;
    let validity = Validity { not_before, not_after };

    // Create distinguished name for the client
    let mut name_attrs = Vec::new();
    name_attrs.push(x509_cert::attr::AttributeTypeAndValue {
        oid: const_oid::db::rfc4519::CN, // Common Name
        value: der::Any::from(der::asn1::Utf8StringRef::new(subject_name)?),
    });
    let rdn = x509_cert::name::RelativeDistinguishedName::try_from(
        der::asn1::SetOfVec::from(name_attrs)
    )?;
    let subject = x509_cert::name::RdnSequence::from(vec![rdn]);

    // Get the issuer name from the CA certificate
    let issuer = ca.certificate.tbs_certificate.issuer.clone();

    // Generate a unique serial number based on current time and subject
    let mut hasher = digest::Context::new(&digest::SHA256);
    hasher.update(subject_name.as_bytes());
    hasher.update(&SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default().as_nanos().to_le_bytes());
    let hash = hasher.finish();
    let serial_bytes = &hash.as_ref()[..8]; // Use first 8 bytes
    let serial_number = SerialNumber::new(serial_bytes)?;

    // Parse the public key
    let public_key = SubjectPublicKeyInfo::from_der(public_key_der)?;

    // Build the certificate
    let tbs_cert = TbsCertificate {
        version: Version::V3,
        serial_number,
        signature: AlgorithmIdentifier {
            oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
            parameters: None,
        },
        issuer,
        validity,
        subject,
        subject_public_key_info: public_key,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(vec![
            // Basic Constraints: CA=false
            x509_cert::ext::Extension {
                extn_id: const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS,
                critical: true,
                extn_value: der::asn1::OctetString::new(
                    x509_cert::ext::pkix::BasicConstraints { ca: false, path_len_constraint: None }.to_der()?
                )?,
            },
            // Key Usage: Digital Signature, Key Encipherment
            x509_cert::ext::Extension {
                extn_id: const_oid::db::rfc5280::ID_CE_KEY_USAGE,
                critical: true,
                extn_value: der::asn1::OctetString::new({
                    let key_usage = x509_cert::ext::pkix::KeyUsage(
                        der::asn1::BitString::from_bytes(&[0xC0])? // digitalSignature and keyEncipherment
                    );
                    key_usage.to_der()?
                })?,
            },
        ]),
    };

    // Sign the certificate
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let tbs_cert_der = tbs_cert.to_der()?;
    let signature = ca_key_pair.sign(&rng, &tbs_cert_der)?;

    let certificate = Certificate {
        tbs_certificate: tbs_cert,
        signature_algorithm: AlgorithmIdentifier {
            oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
            parameters: None,
        },
        signature: der::asn1::BitString::from_bytes(signature.as_ref())?,
    };

    Ok(certificate)
}", err),
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
        let pem_data = pem::Pem::new("PRIVATE KEY", self.private_key_der.clone());
        pem::encode(&pem_data)
    }
}

/// Generate a new root CA certificate and private key
pub fn generate_root_certificate() -> Result<CertifiedKey, CaError> {
    // Generate a new ECDSA P-256 key pair
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)?;
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_bytes.as_ref())?;

    // Create validity period (1 year from now)
    let now = SystemTime::now();
    let not_before = Time::try_from(now)?;
    let not_after = Time::try_from(now + Duration::from_secs(365 * 24 * 60 * 60))?;
    let validity = Validity { not_before, not_after };

    // Create distinguished name for the CA
    let mut name_attrs = Vec::new();
    name_attrs.push(x509_cert::attr::AttributeTypeAndValue {
        oid: const_oid::db::rfc4519::CN, // Common Name
        value: der::Any::from(der::asn1::Utf8StringRef::new("Warpgate Root CA")?),
    });
    let rdn = x509_cert::name::RelativeDistinguishedName::from(name_attrs);
    let subject = RdnSequence::from(vec![rdn]);

    // For self-signed certificate, issuer = subject
    let issuer = subject.clone();

    // Create serial number
    let serial_number = SerialNumber::from(42u64);

    // Get the public key from the private key
    let public_key_der = key_pair.public_key_bytes();
    
    // Parse the public key into the correct format
    let algorithm = SpkiAlgorithmIdentifier {
        oid: const_oid::db::rfc5912::ID_EC_PUBLIC_KEY,
        parameters: Some(der::Any::from(const_oid::db::rfc5912::SECP_256_R_1)), // secp256r1
    };
    let public_key = SubjectPublicKeyInfo {
        algorithm,
        subject_public_key: der::asn1::BitString::from_bytes(&public_key_der)?,
    };

    // Build the certificate
    let tbs_cert = x509_cert::TbsCertificate {
        version: x509_cert::Version::V3,
        serial_number,
        signature: AlgorithmIdentifier {
            oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
            parameters: None,
        },
        issuer,
        validity,
        subject,
        subject_public_key_info: public_key,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(vec![
            // Basic Constraints: CA=true
            x509_cert::ext::Extension {
                extn_id: const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS,
                critical: true,
                extn_value: der::asn1::OctetString::new(
                    x509_cert::ext::pkix::BasicConstraints { ca: true, path_len_constraint: None }.to_der()?
                )?,
            },
            // Key Usage: Certificate Sign, CRL Sign
            x509_cert::ext::Extension {
                extn_id: const_oid::db::rfc5280::ID_CE_KEY_USAGE,
                critical: true,
                extn_value: der::asn1::OctetString::new(
                    x509_cert::ext::pkix::KeyUsage::KeyCertSign.to_der()?
                )?,
            },
        ]),
    };

    // Sign the certificate
    let tbs_cert_der = tbs_cert.to_der()?;
    let signature = key_pair.sign(&rng, &tbs_cert_der)?;

    let certificate = Certificate {
        tbs_certificate: tbs_cert,
        signature_algorithm: AlgorithmIdentifier {
            oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
            parameters: None,
        },
        signature: der::asn1::BitString::from_bytes(signature.as_ref())?,
    };

    Ok(CertifiedKey {
        certificate,
        private_key_der: pkcs8_bytes.as_ref().to_vec(),
    })
}

/// Deserialize a CA certificate and private key from PEM format
pub fn deserialize_ca(
    certificate_pem: &str,
    private_key_pem: &str,
) -> Result<CertifiedKey, CaError> {
    // Parse and validate the certificate PEM
    let (_, pem_cert) = parse_x509_pem(certificate_pem.as_bytes())
        .map_err(|e| CaError::Other(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to parse certificate PEM: {:?}", e),
        ))))?;

    // Parse the X.509 certificate to validate it
    let (_, _parsed_cert) = parse_x509_certificate(&pem_cert.contents)
        .map_err(|e| CaError::Other(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to parse certificate: {:?}", e),
        ))))?;

    // Parse the certificate with x509-cert
    let certificate = Certificate::from_der(&pem_cert.contents)?;

    // Parse the private key PEM
    let key_pem = pem::parse(private_key_pem)
        .map_err(|e| CaError::Other(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to parse private key PEM: {:?}", e),
        ))))?;

    // Validate it's a private key by checking the tag
    let tag = key_pem.tag();
    if tag != "PRIVATE KEY" && tag != "EC PRIVATE KEY" && tag != "RSA PRIVATE KEY" {
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
    public_key_der: &[u8],
) -> Result<Certificate, CaError> {
    // Parse the CA's private key for signing
    let ca_key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &ca.private_key_der)?;

    // Create validity period (1 year from now)
    let now = SystemTime::now();
    let not_before = Time::try_from(now)?;
    let not_after = Time::try_from(now + Duration::from_secs(365 * 24 * 60 * 60))?;
    let validity = Validity { not_before, not_after };

    // Create distinguished name for the client
    let mut name_attrs = Vec::new();
    name_attrs.push(x509_cert::attr::AttributeTypeAndValue {
        oid: const_oid::db::rfc4519::CN, // Common Name
        value: der::Any::from(der::asn1::Utf8StringRef::new(subject_name)?),
    });
    let rdn = x509_cert::name::RelativeDistinguishedName::from(name_attrs);
    let subject = RdnSequence::from(vec![rdn]);

    // Get the issuer name from the CA certificate
    let issuer = ca.certificate.tbs_certificate.issuer.clone();

    // Generate a unique serial number based on current time and subject
    let mut hasher = digest::Context::new(&digest::SHA256);
    hasher.update(subject_name.as_bytes());
    hasher.update(&SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default().as_nanos().to_le_bytes());
    let hash = hasher.finish();
    let serial_bytes = &hash.as_ref()[..8]; // Use first 8 bytes
    let serial_number = SerialNumber::new(serial_bytes)?;

    // Parse the public key
    let public_key = SubjectPublicKeyInfo::from_der(public_key_der)?;

    // Build the certificate
    let tbs_cert = x509_cert::TbsCertificate {
        version: x509_cert::Version::V3,
        serial_number,
        signature: AlgorithmIdentifier {
            oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
            parameters: None,
        },
        issuer,
        validity,
        subject,
        subject_public_key_info: public_key,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(vec![
            // Basic Constraints: CA=false
            x509_cert::ext::Extension {
                extn_id: const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS,
                critical: true,
                extn_value: der::asn1::OctetString::new(
                    x509_cert::ext::pkix::BasicConstraints { ca: false, path_len_constraint: None }.to_der()?
                )?,
            },
            // Key Usage: Digital Signature, Key Encipherment
            x509_cert::ext::Extension {
                extn_id: const_oid::db::rfc5280::ID_CE_KEY_USAGE,
                critical: true,
                extn_value: der::asn1::OctetString::new(
                    (x509_cert::ext::pkix::KeyUsage::DigitalSignature | x509_cert::ext::pkix::KeyUsage::KeyEncipherment).to_der()?
                )?,
            },
        ]),
    };

    // Sign the certificate
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let tbs_cert_der = tbs_cert.to_der()?;
    let signature = ca_key_pair.sign(&rng, &tbs_cert_der)?;

    let certificate = Certificate {
        tbs_certificate: tbs_cert,
        signature_algorithm: AlgorithmIdentifier {
            oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
            parameters: None,
        },
        signature: der::asn1::BitString::from_bytes(signature.as_ref())?,
    };

    Ok(certificate)
}
