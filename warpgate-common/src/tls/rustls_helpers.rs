use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
pub use rustls::pki_types::CertificateDer;
use rustls::pki_types::{ServerName, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{CertificateError, ClientConfig, Error as TlsError, SignatureScheme};

use super::{RustlsSetupError, ROOT_CERT_STORE};
use crate::{Target, TargetOptions, Tls};

#[derive(Debug)]
pub struct ResolveServerCert(pub Arc<CertifiedKey>);

impl ResolvesServerCert for ResolveServerCert {
    fn resolve(&self, _: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

pub async fn configure_tls_connector(
    options: WarpgateVerifierOptions,
) -> Result<ClientConfig, RustlsSetupError> {
    let config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?;

    let verifier = WarpgateVerifier::new(options)?;

    let config = config
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    Ok(config)
}

pub struct WarpgateVerifierOptions {
    pub accept_invalid_certs: bool,
    pub accept_invalid_hostnames: bool,
    pub additional_trusted_certificates: Vec<CertificateDer<'static>>,
}

impl WarpgateVerifierOptions {
    pub fn from_target(target: &Target) -> Self {
        match &target.options {
            TargetOptions::Http(options) => {
                Self::from_tls_and_cert(&options.tls, &target.trusted_tls_certificate)
            }
            TargetOptions::MySql(options) => {
                Self::from_tls_and_cert(&options.tls, &target.trusted_tls_certificate)
            }
            TargetOptions::Postgres(options) => {
                Self::from_tls_and_cert(&options.tls, &target.trusted_tls_certificate)
            }

            TargetOptions::Ssh(_) | TargetOptions::WebAdmin(_) => {
                Self::from_tls_and_cert(&Tls::default(), &None)
            }
        }
    }

    fn from_tls_and_cert(tls: &Tls, cert: &Option<CertificateDer<'static>>) -> Self {
        Self {
            accept_invalid_certs: !tls.verify,
            accept_invalid_hostnames: false,
            additional_trusted_certificates: cert
                .as_ref()
                .map(|c| vec![c.clone()])
                .unwrap_or_default(),
        }
    }
}

#[derive(Debug)]
pub struct WarpgateVerifier {
    inner: Option<Arc<WebPkiServerVerifier>>,
    accept_invalid_hostnames: bool,
}

impl WarpgateVerifier {
    pub fn new(options: WarpgateVerifierOptions) -> Result<Self, RustlsSetupError> {
        if options.accept_invalid_certs {
            Ok(Self {
                inner: None,
                accept_invalid_hostnames: options.accept_invalid_hostnames,
            })
        } else {
            let mut cert_store = ROOT_CERT_STORE.clone();

            for cert in options.additional_trusted_certificates {
                cert_store.add(cert)?;
            }

            Ok(Self {
                inner: Some(WebPkiServerVerifier::builder(Arc::new(cert_store)).build()?),
                accept_invalid_hostnames: options.accept_invalid_hostnames,
            })
        }
    }
}

impl ServerCertVerifier for WarpgateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let Some(inner) = &self.inner else {
            return Ok(ServerCertVerified::assertion());
        };
        match inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now) {
            Err(TlsError::InvalidCertificate(CertificateError::NotValidForName))
                if self.accept_invalid_hostnames =>
            {
                Ok(ServerCertVerified::assertion())
            }
            res => res,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        let Some(inner) = &self.inner else {
            return Ok(HandshakeSignatureValid::assertion());
        };
        inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        let Some(inner) = &self.inner else {
            return Ok(HandshakeSignatureValid::assertion());
        };
        inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        let Some(inner) = &self.inner else {
            return vec![
                SignatureScheme::RSA_PKCS1_SHA1,
                SignatureScheme::ECDSA_SHA1_Legacy,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
            ];
        };
        inner.supported_verify_schemes()
    }
}
