use std::io::Cursor;
use std::sync::Arc;
use std::time::SystemTime;

use rustls::client::{ServerCertVerified, ServerCertVerifier, WebPkiVerifier};
use rustls::server::{ClientHello, NoClientAuth, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{Certificate, ClientConfig, Error as TlsError, PrivateKey, ServerConfig, ServerName};

use super::ROOT_CERT_STORE;

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
    #[error("PKI")]
    Pki(#[from] webpki::Error),
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

pub async fn configure_tls_connector(
    accept_invalid_certs: bool,
    accept_invalid_hostnames: bool,
    root_cert: Option<&[u8]>,
) -> Result<ClientConfig, RustlsSetupError> {
    let config = ClientConfig::builder().with_safe_defaults();

    let config = if accept_invalid_certs {
        config
            .with_custom_certificate_verifier(Arc::new(DummyTlsVerifier))
            .with_no_client_auth()
    } else {
        let mut cert_store = ROOT_CERT_STORE.clone();

        if let Some(data) = root_cert {
            let mut cursor = Cursor::new(data);

            for cert in rustls_pemfile::certs(&mut cursor)? {
                cert_store.add(&rustls::Certificate(cert))?;
            }
        }

        if accept_invalid_hostnames {
            let verifier = WebPkiVerifier::new(cert_store, None);

            config
                .with_custom_certificate_verifier(Arc::new(NoHostnameTlsVerifier { verifier }))
                .with_no_client_auth()
        } else {
            config
                .with_root_certificates(cert_store)
                .with_no_client_auth()
        }
    };

    Ok(config)
}

struct DummyTlsVerifier;

impl ServerCertVerifier for DummyTlsVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }
}

pub struct NoHostnameTlsVerifier {
    verifier: WebPkiVerifier,
}

impl ServerCertVerifier for NoHostnameTlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::Certificate,
        intermediates: &[rustls::Certificate],
        server_name: &ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        now: SystemTime,
    ) -> Result<ServerCertVerified, TlsError> {
        match self.verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            scts,
            ocsp_response,
            now,
        ) {
            Err(TlsError::InvalidCertificateData(reason))
                if reason.contains("CertNotValidForName") =>
            {
                Ok(ServerCertVerified::assertion())
            }
            res => res,
        }
    }
}
