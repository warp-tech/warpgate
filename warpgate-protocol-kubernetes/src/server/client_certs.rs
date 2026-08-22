use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use base64::{self, Engine};
use poem::Addr;
use poem::listener::Acceptor;
use poem::web::RemoteAddr;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, ServerConfig, SignatureScheme};
use tokio::time::timeout;
use tokio_rustls::server::TlsStream;
use tracing::{debug, warn};
use warpgate_common::helpers::concurrent_acceptor::ConcurrentAcceptor;

/// Client certificate verifier that proves the peer holds the presented
/// certificate's private key (by verifying the handshake signature) but does
/// **not** validate the certificate chain against a trust anchor. The
/// certificate's identity is matched against Warpgate's credential database
/// afterwards in [`crate::server::auth::validate_client_certificate`].
#[derive(Debug)]
pub struct AcceptAnyClientCert {
    provider: Arc<CryptoProvider>,
}

impl AcceptAnyClientCert {
    pub const fn new(provider: Arc<CryptoProvider>) -> Self {
        Self { provider }
    }
}

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
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
}

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Custom TLS acceptor that captures client certificates and embeds them in remote_addr
pub fn certificate_capturing_acceptor<A>(
    inner: A,
    server_config: ServerConfig,
) -> ConcurrentAcceptor<TlsStream<A::Io>>
where
    A: Acceptor + 'static,
{
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    ConcurrentAcceptor::new(inner, move |(stream, local_addr, remote_addr, _)| {
        let tls_acceptor = tls_acceptor.clone();
        async move {
            let tls_stream = timeout(HANDSHAKE_TIMEOUT, tls_acceptor.accept(stream))
                .await
                .context("TLS handshake timed out")?
                .context("TLS handshake failed")?;
            let remote_addr = embed_client_certificate(&tls_stream, remote_addr);
            Ok((
                tls_stream,
                local_addr,
                remote_addr,
                http::uri::Scheme::HTTPS,
            ))
        }
    })
}

/// Smuggle the peer certificate in the RemoteAddr
fn embed_client_certificate<T>(tls_stream: &TlsStream<T>, remote_addr: RemoteAddr) -> RemoteAddr {
    let Some(cert_der) = extract_peer_certificates(tls_stream) else {
        return remote_addr;
    };
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
}

/// Extract peer certificates from the TLS stream
fn extract_peer_certificates<T>(tls_stream: &TlsStream<T>) -> Option<Vec<u8>> {
    // Get the TLS connection info
    let (_, tls_conn) = tls_stream.get_ref();

    // Extract peer certificates - this gives us the certificate chain
    if let Some(peer_certs) = tls_conn.peer_certificates()
        && let Some(end_entity_cert) = peer_certs.first()
    {
        debug!("Extracted client certificate from TLS stream");
        return Some(end_entity_cert.as_ref().to_vec());
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use base64::Engine;
    use poem::Addr;
    use poem::listener::{Acceptor, Listener, TcpListener};
    use poem::web::RemoteAddr;
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use tokio::net::TcpStream;
    use tokio::time::timeout;
    use tokio_rustls::TlsConnector;

    use super::{AcceptAnyClientCert, certificate_capturing_acceptor};

    #[tokio::test]
    async fn stalled_tls_handshake_does_not_block_later_connections() {
        let certificate =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let certificate_der = CertificateDer::from(certificate.cert.der().to_vec());
        let private_key = PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der());
        let client_certificate =
            rcgen::generate_simple_self_signed(vec!["kubectl-client".to_string()]).unwrap();
        let client_certificate_der = CertificateDer::from(client_certificate.cert.der().to_vec());
        let client_private_key =
            PrivatePkcs8KeyDer::from(client_certificate.signing_key.serialize_der());

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let server_config = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(Arc::new(AcceptAnyClientCert::new(provider.clone())))
            .with_single_cert(vec![certificate_der.clone()], private_key.into())
            .unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(certificate_der).unwrap();
        let client_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                vec![client_certificate_der.clone()],
                client_private_key.into(),
            )
            .unwrap();

        let tcp_acceptor = TcpListener::bind("127.0.0.1:0")
            .into_acceptor()
            .await
            .unwrap();
        let address = tcp_acceptor
            .local_addr()
            .into_iter()
            .find_map(|address| address.0.as_socket_addr().copied())
            .unwrap();

        // Queue a connection that will never send a TLS ClientHello before the
        // acceptor starts polling, ensuring it is accepted first.
        let stalled_connection = TcpStream::connect(address).await.unwrap();
        let mut acceptor = certificate_capturing_acceptor(tcp_acceptor, server_config);

        // A later, valid TLS handshake must still complete.
        let second_connection = TcpStream::connect(address).await.unwrap();
        let connector = TlsConnector::from(Arc::new(client_config));
        let server_name = ServerName::try_from("localhost").unwrap().to_owned();
        let ((_, _, remote_addr, _), second_tls) = timeout(Duration::from_secs(1), async {
            tokio::try_join!(
                acceptor.accept(),
                connector.connect(server_name, second_connection),
            )
        })
        .await
        .expect("a stalled TLS handshake blocked the next connection")
        .expect("the second TLS handshake failed");
        let RemoteAddr(Addr::Custom("captured-cert", value)) = remote_addr else {
            panic!("client certificate was not captured")
        };
        let captured_certificate = base64::engine::general_purpose::STANDARD
            .decode(value.split("|cert:").nth(1).unwrap())
            .unwrap();
        assert_eq!(captured_certificate, client_certificate_der.as_ref());

        drop(second_tls);
        drop(stalled_connection);
    }
}
