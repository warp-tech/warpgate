use std::path::{Path, PathBuf};
use std::sync::Arc;

use poem::listener::RustlsCertificate;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::{CertifiedKey, SigningKey};
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use x509_parser::prelude::{FromDer, GeneralName, ParsedExtension, X509Certificate};

use crate::{HttpConfig, RustlsSetupError, SniCertificateConfig, WarpgateConfig};

#[derive(Clone)]
pub struct TlsCertificateBundle {
    bytes: Vec<u8>,
    certificates: Vec<CertificateDer<'static>>,
}

#[derive(Clone)]
pub struct TlsPrivateKey {
    bytes: Vec<u8>,
    key: Arc<dyn SigningKey>,
}

#[derive(Clone)]
pub struct TlsCertificateAndPrivateKey {
    pub certificate: TlsCertificateBundle,
    pub private_key: TlsPrivateKey,
}

impl TlsCertificateBundle {
    pub async fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, RustlsSetupError> {
        let mut file = File::open(path).await?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).await?;
        Self::from_bytes(bytes)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, RustlsSetupError> {
        let certificates = rustls_pemfile::certs(&mut &bytes[..])
            .collect::<Result<Vec<CertificateDer<'static>>, _>>()?;

        if certificates.is_empty() {
            return Err(RustlsSetupError::NoCertificates);
        }
        Ok(Self {
            bytes,
            certificates,
        })
    }

    pub fn sni_names(&self) -> Result<Vec<String>, RustlsSetupError> {
        if self.certificates.is_empty() {
            return Ok(Vec::new());
        }

        // Parse leaf certificate
        let cert_der = &self.certificates[0];
        let (_, cert) =
            X509Certificate::from_der(cert_der).map_err(|e| RustlsSetupError::X509(e.into()))?;

        let mut names = Vec::new();

        if let Some(san_ext) = cert
            .extensions()
            .iter()
            .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
        {
            let san = san_ext.parsed_extension();
            if let ParsedExtension::SubjectAlternativeName(san) = san {
                for name in &san.general_names {
                    match name {
                        GeneralName::DNSName(dns_name) => {
                            names.push(dns_name.to_string());
                        }
                        GeneralName::IPAddress(ip_bytes) => {
                            // Convert IP bytes to string representation
                            if ip_bytes.len() == 4 {
                                // IPv4
                                names.push(format!(
                                    "{}.{}.{}.{}",
                                    ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
                                ));
                            } else if ip_bytes.len() == 16 {
                                // IPv6
                                let mut ipv6_parts = Vec::new();
                                for chunk in ip_bytes.chunks(2) {
                                    ipv6_parts.push(format!(
                                        "{:02x}{:02x}",
                                        chunk[0],
                                        chunk.get(1).unwrap_or(&0)
                                    ));
                                }
                                names.push(ipv6_parts.join(":"));
                            }
                        }
                        _ => {} // Ignore other types like email, URI, etc.
                    }
                }
            }
        }

        if let Some(subject) = cert.subject().iter_common_name().next() {
            if let Ok(cn) = subject.as_str() {
                names.push(cn.to_string());
            }
        }

        // Remove duplicates while preserving order
        let mut unique_names = Vec::new();
        for name in names {
            if !unique_names.contains(&name) {
                unique_names.push(name);
            }
        }

        Ok(unique_names)
    }
}

impl TlsPrivateKey {
    pub async fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, RustlsSetupError> {
        let mut file = File::open(path).await?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).await?;
        Self::from_bytes(bytes)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, RustlsSetupError> {
        let key = match rustls_pemfile::pkcs8_private_keys(&mut bytes.as_slice()).next() {
            Some(Ok(key)) => Some(PrivateKeyDer::from(key)),
            _ => None,
        }
        .or_else(
            || match rustls_pemfile::ec_private_keys(&mut bytes.as_slice()).next() {
                Some(Ok(key)) => Some(PrivateKeyDer::from(key)),
                _ => None,
            },
        )
        .or_else(
            || match rustls_pemfile::rsa_private_keys(&mut bytes.as_slice()).next() {
                Some(Ok(key)) => Some(PrivateKeyDer::from(key)),
                _ => None,
            },
        );

        let key = key.ok_or(RustlsSetupError::NoKeys)?;
        let key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)?;

        Ok(Self { bytes, key })
    }
}

impl From<TlsCertificateBundle> for Vec<u8> {
    fn from(val: TlsCertificateBundle) -> Self {
        val.bytes
    }
}

impl From<TlsPrivateKey> for Vec<u8> {
    fn from(val: TlsPrivateKey) -> Self {
        val.bytes
    }
}

impl From<TlsCertificateAndPrivateKey> for RustlsCertificate {
    fn from(val: TlsCertificateAndPrivateKey) -> Self {
        RustlsCertificate::new()
            .cert(val.certificate)
            .key(val.private_key)
    }
}

impl From<TlsCertificateAndPrivateKey> for CertifiedKey {
    fn from(val: TlsCertificateAndPrivateKey) -> Self {
        let cert = val.certificate;
        let key = val.private_key;
        CertifiedKey {
            cert: cert.certificates,
            key: key.key,
            ocsp: None,
        }
    }
}

pub trait IntoTlsCertificateRelativePaths {
    fn certificate_path(&self) -> PathBuf;
    fn key_path(&self) -> PathBuf;
}

impl IntoTlsCertificateRelativePaths for HttpConfig {
    fn certificate_path(&self) -> PathBuf {
        self.certificate.as_str().into()
    }

    fn key_path(&self) -> PathBuf {
        self.key.as_str().into()
    }
}

impl IntoTlsCertificateRelativePaths for SniCertificateConfig {
    fn certificate_path(&self) -> PathBuf {
        self.certificate.as_str().into()
    }

    fn key_path(&self) -> PathBuf {
        self.key.as_str().into()
    }
}

pub async fn load_certificate_and_key<R: IntoTlsCertificateRelativePaths>(
    from: &R,
    config: &WarpgateConfig,
) -> Result<TlsCertificateAndPrivateKey, RustlsSetupError> {
    Ok(TlsCertificateAndPrivateKey {
        certificate: TlsCertificateBundle::from_file(
            config.paths_relative_to.join(&from.certificate_path()),
        )
        .await?,
        private_key: TlsPrivateKey::from_file(config.paths_relative_to.join(&from.key_path()))
            .await?,
    })
}
