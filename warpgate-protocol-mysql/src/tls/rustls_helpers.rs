use std::sync::Arc;

use rustls::server::{ClientHello, NoClientAuth, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{Certificate, PrivateKey, ServerConfig};

#[derive(thiserror::Error, Debug)]
pub enum RustlsSetupError {
    #[error("rustls")]
    Rustls(#[from] rustls::Error),
    #[error("sign")]
    Sign(#[from] rustls::sign::SignError),
    #[error("no private keys in key file")]
    NoKeys,
    #[error("I/O")]
    Io(#[from] std::io::Error),
}

pub trait FromCertificateAndKey<E>
where
    Self: Sized,
{
    fn try_from_certificate_and_key(cert: Vec<u8>, key: Vec<u8>) -> Result<Self, E>;
}

impl FromCertificateAndKey<RustlsSetupError> for rustls::ServerConfig {
    fn try_from_certificate_and_key(
        cert: Vec<u8>,
        key_bytes: Vec<u8>,
    ) -> Result<Self, RustlsSetupError> {
        let certificates = rustls_pemfile::certs(&mut &cert[..]).map(|mut certs| {
            certs
                .drain(..)
                .map(Certificate)
                .collect::<Vec<Certificate>>()
        })?;

        let mut key = rustls_pemfile::pkcs8_private_keys(&mut key_bytes.as_slice())?
            .drain(..)
            .next()
            .map(PrivateKey);

        if key.is_none() {
            key = rustls_pemfile::rsa_private_keys(&mut key_bytes.as_slice())?
                .drain(..)
                .next()
                .map(PrivateKey);
        }

        let key = key.ok_or(RustlsSetupError::NoKeys)?;
        let key = rustls::sign::any_supported_type(&key)?;

        let cert_key = Arc::new(CertifiedKey {
            cert: certificates,
            key,
            ocsp: None,
            sct_list: None,
        });

        Ok(ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(NoClientAuth::new())
            .with_cert_resolver(Arc::new(ResolveServerCert(cert_key))))
    }
}

struct ResolveServerCert(Arc<CertifiedKey>);

impl ResolvesServerCert for ResolveServerCert {
    fn resolve(&self, _: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}
