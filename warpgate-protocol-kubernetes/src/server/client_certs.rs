use std::sync::Arc;

use base64::{self, Engine};
use poem::listener::Acceptor;
use poem::web::{LocalAddr, RemoteAddr};
use poem::Addr;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, ServerConfig, SignatureScheme};
use tokio_rustls::server::TlsStream;
use tracing::{debug, warn};

/// Custom client certificate verifier that accepts any client certificate
#[derive(Debug)]
pub struct AcceptAnyClientCert;

impl ClientCertVerifier for AcceptAnyClientCert {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // Accept any client certificate - we'll extract and validate it later
        debug!("Client certificate received, accepting for later validation");
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
}

/// Custom TLS acceptor that captures client certificates and embeds them in remote_addr
pub struct CertificateCapturingAcceptor<T> {
    inner: T,
    tls_acceptor: tokio_rustls::TlsAcceptor,
}

impl<T> CertificateCapturingAcceptor<T> {
    pub fn new(inner: T, server_config: ServerConfig) -> Self {
        Self {
            inner,
            tls_acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(server_config)),
        }
    }
}

impl<T> Acceptor for CertificateCapturingAcceptor<T>
where
    T: Acceptor,
{
    type Io = TlsStream<T::Io>;

    fn local_addr(&self) -> Vec<LocalAddr> {
        self.inner.local_addr()
    }

    async fn accept(
        &mut self,
    ) -> std::io::Result<(Self::Io, LocalAddr, RemoteAddr, http::uri::Scheme)> {
        let (stream, local_addr, remote_addr, _) = self.inner.accept().await?;

        // Perform TLS handshake
        let tls_stream = self.tls_acceptor.accept(stream).await?;

        // Extract client certificate from the TLS connection
        let enhanced_remote_addr = if let Some(cert_der) = extract_peer_certificates(&tls_stream) {
            // Serialize certificate as base64 and embed in remote_addr
            let cert_b64 = base64::engine::general_purpose::STANDARD.encode(&cert_der);
            let original_remote_addr_str = match &remote_addr.0 {
                Addr::SocketAddr(addr) => addr.to_string(),
                Addr::Unix(_) => remote_addr.to_string(),
                Addr::Custom(_, _) => "".into(),
            };
            RemoteAddr(Addr::Custom(
                "captured-cert",
                format!("{original_remote_addr_str}|cert:{cert_b64}").into(),
            ))
        } else {
            remote_addr
        };

        Ok((
            tls_stream,
            local_addr,
            enhanced_remote_addr,
            http::uri::Scheme::HTTPS,
        ))
    }
}

/// Extract peer certificates from the TLS stream
fn extract_peer_certificates<T>(tls_stream: &TlsStream<T>) -> Option<Vec<u8>> {
    // Get the TLS connection info
    let (_, tls_conn) = tls_stream.get_ref();

    // Extract peer certificates - this gives us the certificate chain
    if let Some(peer_certs) = tls_conn.peer_certificates() {
        if let Some(end_entity_cert) = peer_certs.first() {
            debug!("Extracted client certificate from TLS stream");
            return Some(end_entity_cert.as_ref().to_vec());
        }
    }

    debug!("No client certificate found in TLS stream");
    None
}

/// Certificate data extracted from client TLS connection
#[derive(Debug, Clone)]
pub struct ClientCertificate {
    pub der_bytes: Vec<u8>,
}

/// Middleware that extracts client certificates from enhanced remote_addr and stores them in request extensions
pub struct CertificateExtractorMiddleware;

impl<E> poem::Middleware<E> for CertificateExtractorMiddleware
where
    E: poem::Endpoint,
{
    type Output = CertificateExtractorEndpoint<E>;

    fn transform(&self, ep: E) -> Self::Output {
        CertificateExtractorEndpoint { inner: ep }
    }
}

// Extracts client certificates stored in the request by [CertificateCapturingAcceptor]
pub struct CertificateExtractorEndpoint<E> {
    inner: E,
}

impl<E> poem::Endpoint for CertificateExtractorEndpoint<E>
where
    E: poem::Endpoint,
{
    type Output = E::Output;
    async fn call(&self, mut req: poem::Request) -> poem::Result<Self::Output> {
        // Extract certificate from enhanced remote_addr if present
        if let RemoteAddr(Addr::Custom("captured-cert", value)) = req.remote_addr() {
            if let Some(cert_part) = value.split("|cert:").nth(1) {
                // Decode the base64 certificate
                match base64::engine::general_purpose::STANDARD.decode(cert_part) {
                    Ok(cert_der) => {
                        debug!(
                        "Middleware: Successfully extracted client certificate from remote_addr"
                    );

                        let client_cert = ClientCertificate {
                            der_bytes: cert_der,
                        };

                        // Store certificate in request extensions for later access
                        req.extensions_mut().insert(client_cert);
                        debug!("Middleware: Client certificate stored in request extensions");
                    }
                    Err(e) => {
                        warn!(
                            "Middleware: Failed to decode client certificate from remote_addr: {}",
                            e
                        );
                    }
                }
            }
        } else {
            debug!("Middleware: No client certificate found in remote_addr");
        }

        // Continue with the request
        self.inner.call(req).await
    }
}

/// Helper trait to easily extract client certificate from request
pub trait RequestCertificateExt {
    /// Get the client certificate from request extensions, if present
    fn client_certificate(&self) -> Option<&ClientCertificate>;
}

impl RequestCertificateExt for poem::Request {
    fn client_certificate(&self) -> Option<&ClientCertificate> {
        self.extensions().get::<ClientCertificate>()
    }
}
