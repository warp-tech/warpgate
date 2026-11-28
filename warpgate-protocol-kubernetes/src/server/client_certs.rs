use std::sync::Arc;

use base64::{self, Engine};
use poem::listener::Acceptor;
use poem::web::RemoteAddr;
use rustls::ServerConfig;
use warpgate_common::helpers::concurrent_acceptor::ConcurrentAcceptor;
use warpgate_common_http::mtls_acceptor::{
    RemoteAddrExtension, Verified, annotate_remote_addr, extracting_mtls_acceptor,
    remote_addr_annotation,
};
use warpgate_tls::ServerTlsStream;

const CAPTURED_CERT_SCHEME: &str = "captured-cert";

/// Custom TLS acceptor that captures client certificates and embeds them in remote_addr
pub fn certificate_capturing_acceptor<A>(
    inner: A,
    proxy_protocol: bool,
    server_config: ServerConfig,
) -> ConcurrentAcceptor<ServerTlsStream<A::Io>>
where
    A: Acceptor + 'static,
{
    let server_config = Arc::new(server_config);
    extracting_mtls_acceptor(
        inner,
        proxy_protocol,
        move |_| server_config.clone(),
        |certificate, remote_addr| async move {
            Ok(Verified::Ordinary(match certificate {
                Some(certificate) => annotate_remote_addr(
                    &remote_addr,
                    CAPTURED_CERT_SCHEME,
                    &format!(
                        "cert:{}",
                        base64::engine::general_purpose::STANDARD.encode(certificate)
                    ),
                ),
                None => remote_addr,
            }))
        },
    )
}

/// Certificate data extracted from client TLS connection
#[derive(Debug, Clone)]
pub struct ClientCertificate {
    pub der_bytes: Vec<u8>,
}

fn client_certificate_from_remote_addr(remote_addr: &RemoteAddr) -> Option<ClientCertificate> {
    let encoded =
        remote_addr_annotation(remote_addr, CAPTURED_CERT_SCHEME)?.strip_prefix("cert:")?;
    let der_bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    Some(ClientCertificate { der_bytes })
}

pub fn client_certificate_extension()
-> RemoteAddrExtension<fn(&RemoteAddr) -> Option<ClientCertificate>> {
    RemoteAddrExtension::new(client_certificate_from_remote_addr)
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
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use poem::listener::{Acceptor, Listener, TcpAcceptor, TcpListener};
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::timeout;
    use tokio_rustls::TlsConnector;
    use warpgate_tls::PossessionOnlyClientCertVerifier;

    use super::{certificate_capturing_acceptor, client_certificate_from_remote_addr};

    struct Rig {
        tcp_acceptor: TcpAcceptor,
        address: SocketAddr,
        server_config: ServerConfig,
        connector: TlsConnector,
        client_certificate_der: CertificateDer<'static>,
    }

    async fn rig() -> Rig {
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
            .with_client_cert_verifier(Arc::new(PossessionOnlyClientCertVerifier::optional(
                provider.clone(),
            )))
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

        Rig {
            tcp_acceptor,
            address,
            server_config,
            connector: TlsConnector::from(Arc::new(client_config)),
            client_certificate_der,
        }
    }

    fn server_name() -> ServerName<'static> {
        ServerName::try_from("localhost").unwrap()
    }

    const PROXY_HEADER: &[u8] = b"PROXY TCP4 203.0.113.10 10.0.0.2 42300 443\r\n";

    #[tokio::test]
    async fn stalled_tls_handshake_does_not_block_later_connections() {
        assert_stalled_connection_does_not_block(false, b"").await;
    }

    #[tokio::test]
    async fn stalled_proxy_header_does_not_block_later_connections() {
        assert_stalled_connection_does_not_block(true, PROXY_HEADER).await;
    }

    async fn assert_stalled_connection_does_not_block(proxy_protocol: bool, preamble: &[u8]) {
        let rig = rig().await;

        // Queue a connection that will never send anything before the
        // acceptor starts polling, ensuring it is accepted first.
        let stalled_connection = TcpStream::connect(rig.address).await.unwrap();
        let mut acceptor =
            certificate_capturing_acceptor(rig.tcp_acceptor, proxy_protocol, rig.server_config);

        // A later, valid TLS handshake must still complete.
        let mut second_connection = TcpStream::connect(rig.address).await.unwrap();
        second_connection.write_all(preamble).await.unwrap();
        let ((_, _, remote_addr, _), second_tls) = timeout(Duration::from_secs(1), async {
            tokio::try_join!(
                acceptor.accept(),
                rig.connector.connect(server_name(), second_connection),
            )
        })
        .await
        .expect("a stalled connection blocked the next one")
        .expect("the second TLS handshake failed");
        let captured = client_certificate_from_remote_addr(&remote_addr)
            .expect("client certificate was not captured");
        assert_eq!(captured.der_bytes, rig.client_certificate_der.as_ref());

        drop(second_tls);
        drop(stalled_connection);
    }

    #[tokio::test]
    async fn proxy_protocol_listener_takes_the_address_from_the_header() {
        let rig = rig().await;
        let mut acceptor =
            certificate_capturing_acceptor(rig.tcp_acceptor, true, rig.server_config);

        let mut connection = TcpStream::connect(rig.address).await.unwrap();
        connection.write_all(PROXY_HEADER).await.unwrap();
        let ((_, _, remote_addr, _), _tls) = timeout(Duration::from_secs(1), async {
            tokio::try_join!(
                acceptor.accept(),
                rig.connector.connect(server_name(), connection),
            )
        })
        .await
        .unwrap()
        .unwrap();
        assert!(client_certificate_from_remote_addr(&remote_addr).is_some());
        assert!(remote_addr.to_string().contains("203.0.113.10:42300"));
    }

    #[tokio::test]
    async fn proxy_protocol_listener_drops_a_client_without_a_header() {
        let rig = rig().await;
        let mut acceptor =
            certificate_capturing_acceptor(rig.tcp_acceptor, true, rig.server_config);

        let connection = TcpStream::connect(rig.address).await.unwrap();
        let (accepted, tls) = tokio::join!(
            timeout(Duration::from_millis(500), acceptor.accept()),
            rig.connector.connect(server_name(), connection),
        );
        assert!(
            accepted.is_err(),
            "a client without a PROXY header was kept"
        );
        // The server decides after the handshake, so the client sees a failed
        // handshake or EOF on its first read
        if let Ok(mut tls) = tls {
            let read = timeout(Duration::from_secs(1), tls.read(&mut [0u8; 1]))
                .await
                .expect("the connection was left open");
            assert!(matches!(read, Ok(0) | Err(_)));
        }
    }
}
