use std::path::Path;
use std::sync::Arc;

use poem::listener::RustlsCertificate;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ResolvesServerCert;
use rustls::sign::{CertifiedKey, SigningKey};
use tokio::fs::File;
use tokio::io::AsyncReadExt;

use crate::RustlsSetupError;

#[derive(Debug, Clone)]
pub struct TlsCertificateBundle {
    bytes: Vec<u8>,
    certificates: Vec<CertificateDer<'static>>,
}

#[derive(Debug, Clone)]
pub struct TlsPrivateKey {
    bytes: Vec<u8>,
    key: Arc<dyn SigningKey>,
}

impl TlsPrivateKey {
    pub fn key(&self) -> &Arc<dyn SigningKey> {
        &self.key
    }
}

#[derive(Debug, Clone)]
pub struct TlsCertificateAndPrivateKey {
    pub certificate: TlsCertificateBundle,
    pub private_key: TlsPrivateKey,
}

impl TlsCertificateBundle {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn certificates(&self) -> &[CertificateDer<'static>] {
        &self.certificates
    }

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

#[derive(Debug, Clone)]
pub struct SingleCertResolver(Arc<CertifiedKey>);

impl SingleCertResolver {
    pub fn new(inner: TlsCertificateAndPrivateKey) -> Self {
        Self(Arc::new(inner.into()))
    }
}

impl ResolvesServerCert for SingleCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}
