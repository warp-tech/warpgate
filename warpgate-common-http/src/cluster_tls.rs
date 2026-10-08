//! Inbound half of cluster peer authentication.
//!
//! Peers connect to the ordinary HTTPS listener with the SNI name
//! [`CLUSTER_TLS_SNI_NAME`]. Only for that name does the listener demand a
//! client certificate; the certificate's key must be the one a live `nodes`
//! row has pinned. Browsers and other clients, which send a real host name,
//! never see a certificate request.
//!
//! The acceptor marks an authenticated peer connection in its `RemoteAddr`
//! (see [`crate::tls_acceptor`]), and [`cluster_peer_extension`] turns that
//! into a [`ClusterPeer`] request extension that the auth code reads through
//! [`cluster_peer`].

use std::sync::Arc;

use anyhow::Context;
use poem::Request;
use poem::listener::Acceptor;
use poem::web::RemoteAddr;
use rustls::ServerConfig;
use tokio_rustls::server::TlsStream;
use tracing::warn;
use uuid::Uuid;
use warpgate_ca::{CLUSTER_TLS_SNI_NAME, ClusterTlsIdentity, certificate_der_spki_sha256_hex};
use warpgate_common::NodeId;
use warpgate_common::helpers::concurrent_acceptor::ConcurrentAcceptor;
use warpgate_core::cluster::Cluster;
use warpgate_tls::{
    PossessionOnlyClientCertVerifier, RustlsSetupError, SniCertResolver,
    TlsCertificateAndPrivateKey, cluster_identity_certified_key,
};

use crate::mtls_acceptor::{
    RemoteAddrExtension, annotate_remote_addr, extracting_mtls_acceptor, remote_addr_annotation,
};

/// A request from another cluster node, authenticated by its pinned TLS
/// client certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClusterPeer {
    pub node_id: NodeId,
}

const CLUSTER_PEER_ADDR_SCHEME: &str = "cluster-peer";
const CLUSTER_PEER_PAYLOAD_PREFIX: &str = "node-uuid:";

/// Resolves a connecting peer's TLS pin to a cluster node.
pub trait PeerRegistry: Send + Sync + 'static {
    fn node_for_pin(&self, spki_sha256_hex: String) -> impl Future<Output = Option<NodeId>> + Send;
}

impl PeerRegistry for Cluster {
    async fn node_for_pin(&self, spki_sha256_hex: String) -> Option<NodeId> {
        match self.lookup_by_mtls_fingerprint(&spki_sha256_hex).await {
            Ok(node) => node,
            // A registry we can't read is a peer we can't vouch for.
            Err(error) => {
                warn!(%error, "Failed to look up a cluster peer's TLS pin");
                None
            }
        }
    }
}

/// The two server configurations the listener switches between by SNI.
#[derive(Clone)]
pub struct ClusterTlsConfigs {
    public: Arc<ServerConfig>,
    cluster: Arc<ServerConfig>,
}

impl ClusterTlsConfigs {
    pub fn new(
        certificates: Vec<TlsCertificateAndPrivateKey>,
        identity: &ClusterTlsIdentity,
    ) -> Result<Self, RustlsSetupError> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let public = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SniCertResolver::new(certificates.into_iter())?));
        let (certs, key) = cluster_identity_certified_key(identity)?;
        let cluster = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(Arc::new(PossessionOnlyClientCertVerifier::mandatory(
                provider,
            )))
            .with_single_cert(certs, key)?;
        Ok(Self {
            public: Arc::new(public),
            cluster: Arc::new(cluster),
        })
    }
}

/// TLS acceptor for the HTTPS listener: serves public certificates by SNI and,
/// for the cluster SNI name, requires a client certificate pinned by a live
/// node. A peer that proves a key nobody has pinned is dropped before poem
/// ever sees a request from it.
pub fn cluster_aware_tls_acceptor<A, R>(
    inner: A,
    configs: ClusterTlsConfigs,
    registry: Arc<R>,
) -> ConcurrentAcceptor<TlsStream<A::Io>>
where
    A: Acceptor + 'static,
    R: PeerRegistry,
{
    extracting_mtls_acceptor(
        inner,
        move |client_hello| {
            if client_hello.server_name() == Some(CLUSTER_TLS_SNI_NAME) {
                configs.cluster.clone()
            } else {
                configs.public.clone()
            }
        },
        move |certificate, remote_addr| {
            // certificate present = configs.cluster was used
            let registry = registry.clone();
            async move {
                let Some(certificate) = certificate else {
                    return Ok(remote_addr);
                };
                let spki = certificate_der_spki_sha256_hex(certificate.as_ref())?;
                let node_id = registry
                    .node_for_pin(spki)
                    .await
                    .context("unknown cluster peer certificate")?;
                Ok(annotate_remote_addr(
                    &remote_addr,
                    CLUSTER_PEER_ADDR_SCHEME,
                    &format!("{CLUSTER_PEER_PAYLOAD_PREFIX}{node_id}"),
                ))
            }
        },
    )
}

fn peer_from_remote_addr(remote_addr: &RemoteAddr) -> Option<ClusterPeer> {
    let node_id = remote_addr_annotation(remote_addr, CLUSTER_PEER_ADDR_SCHEME)?
        .strip_prefix(CLUSTER_PEER_PAYLOAD_PREFIX)?
        .parse::<Uuid>()
        .ok()?;
    Some(ClusterPeer {
        node_id: NodeId(node_id),
    })
}

/// The authenticated cluster peer this request arrived from, if any.
pub fn cluster_peer(req: &Request) -> Option<&ClusterPeer> {
    req.extensions().get::<ClusterPeer>()
}

/// True if the request was forwarded by another node over a connection that
/// proved the node's pinned TLS identity. Gates every `x-warpgate-cluster-*`
/// header.
pub fn is_cluster_peer_request(req: &Request) -> bool {
    cluster_peer(req).is_some()
}

/// Middleware copying the acceptor's peer marker into a [`ClusterPeer`]
/// request extension.
pub fn cluster_peer_extension() -> RemoteAddrExtension<fn(&RemoteAddr) -> Option<ClusterPeer>> {
    RemoteAddrExtension::new(peer_from_remote_addr)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    use poem::listener::{Acceptor, Listener, TcpListener};
    use rustls::ClientConfig;
    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::timeout;
    use tokio_rustls::TlsConnector;
    use warpgate_ca::{CLUSTER_TLS_SNI_NAME, ClusterTlsIdentity};
    use warpgate_common::NodeId;
    use warpgate_tls::{
        DummyTlsVerifier, TlsCertificateAndPrivateKey, TlsCertificateBundle, TlsPrivateKey,
        cluster_identity_certified_key,
    };

    use super::*;

    impl PeerRegistry for HashMap<String, NodeId> {
        async fn node_for_pin(&self, spki_sha256_hex: String) -> Option<NodeId> {
            self.get(&spki_sha256_hex).copied()
        }
    }

    struct Rig {
        address: std::net::SocketAddr,
        acceptor: ConcurrentAcceptor<TlsStream<TcpStream>>,
        ca_cert: String,
        ca_key: String,
        peer: ClusterTlsIdentity,
        peer_node: NodeId,
        public_cert: rustls::pki_types::CertificateDer<'static>,
    }

    async fn rig() -> Rig {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (ca_cert, ca_key) = warpgate_ca::issue_ca_root_certificate().unwrap();
        let own = ClusterTlsIdentity::issue(&ca_cert, &ca_key).unwrap();
        let peer = ClusterTlsIdentity::issue(&ca_cert, &ca_key).unwrap();
        let peer_node = NodeId(Uuid::new_v4());
        let registry = Arc::new(HashMap::from([(peer.spki_sha256_hex.clone(), peer_node)]));

        let public = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let public_cert = rustls::pki_types::CertificateDer::from(public.cert.der().to_vec());
        let public_pair = TlsCertificateAndPrivateKey {
            certificate: TlsCertificateBundle::from_bytes(public.cert.pem().into_bytes()).unwrap(),
            private_key: TlsPrivateKey::from_bytes(public.signing_key.serialize_pem().into_bytes())
                .unwrap(),
        };
        let configs = ClusterTlsConfigs::new(vec![public_pair], &own).unwrap();

        let tcp = TcpListener::bind("127.0.0.1:0".to_string())
            .into_acceptor()
            .await
            .unwrap();
        let address = tcp
            .local_addr()
            .into_iter()
            .find_map(|a| a.0.as_socket_addr().copied())
            .unwrap();
        Rig {
            address,
            acceptor: cluster_aware_tls_acceptor(tcp, configs, registry),
            ca_cert,
            ca_key,
            peer,
            peer_node,
            public_cert,
        }
    }

    fn client_config(identity: Option<&ClusterTlsIdentity>) -> ClientConfig {
        let builder = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DummyTlsVerifier));
        match identity {
            Some(identity) => {
                let (certs, key) = cluster_identity_certified_key(identity).unwrap();
                builder.with_client_auth_cert(certs, key).unwrap()
            }
            None => builder.with_no_client_auth(),
        }
    }

    /// Connects with `sni` and the given client identity while the acceptor
    /// accepts; returns what the acceptor produced (if it kept the connection)
    /// and the client's handshake result.
    async fn connect(
        rig: &mut Rig,
        sni: &'static str,
        identity: Option<&ClusterTlsIdentity>,
    ) -> (
        Option<(TlsStream<TcpStream>, RemoteAddr)>,
        Result<tokio_rustls::client::TlsStream<TcpStream>, std::io::Error>,
    ) {
        let connector = TlsConnector::from(Arc::new(client_config(identity)));
        let tcp = TcpStream::connect(rig.address).await.unwrap();
        let server_name = ServerName::try_from(sni).unwrap();
        let client = async move {
            let mut stream = connector.connect(server_name, tcp).await?;
            // The server only learns whether it keeps the connection after the
            // handshake, so a dropped connection shows up on the first read.
            stream.write_all(b"x").await?;
            let mut buf = [0u8; 1];
            match timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
                Ok(Ok(0)) => Err(std::io::Error::other("connection closed by server")),
                Ok(Err(e)) => Err(e),
                _ => Ok(stream),
            }
        };
        // The accepted stream is handed back (not dropped here) so the client
        // probe above only sees EOF when the acceptor itself dropped the peer.
        let server = async {
            timeout(Duration::from_secs(1), rig.acceptor.accept())
                .await
                .ok()
                .and_then(Result::ok)
                .map(|(io, _, remote_addr, _)| (io, remote_addr))
        };
        tokio::join!(server, client)
    }

    #[tokio::test]
    async fn pinned_peer_is_marked_on_the_cluster_sni() {
        let mut rig = rig().await;
        let peer = rig.peer.clone();
        let (accepted, client) = connect(&mut rig, CLUSTER_TLS_SNI_NAME, Some(&peer)).await;
        client.expect("pinned peer handshake");
        let (_io, remote_addr) = accepted.expect("connection kept");
        let marker = peer_from_remote_addr(&remote_addr).unwrap();
        assert_eq!(marker.node_id, rig.peer_node);
    }

    #[tokio::test]
    async fn unpinned_certificate_from_the_same_ca_is_dropped() {
        let mut rig = rig().await;
        let rogue = ClusterTlsIdentity::issue(&rig.ca_cert, &rig.ca_key).unwrap();
        let (accepted, client) = connect(&mut rig, CLUSTER_TLS_SNI_NAME, Some(&rogue)).await;
        assert!(accepted.is_none(), "an unpinned peer must not reach poem");
        assert!(client.is_err());
    }

    #[tokio::test]
    async fn cluster_sni_without_a_certificate_fails_the_handshake() {
        let mut rig = rig().await;
        let (accepted, client) = connect(&mut rig, CLUSTER_TLS_SNI_NAME, None).await;
        assert!(accepted.is_none());
        assert!(client.is_err());
    }

    #[tokio::test]
    async fn public_sni_never_asks_for_a_certificate() {
        let mut rig = rig().await;
        // A client holding an identity would present it if asked; the public
        // path must not ask, and must serve the public certificate.
        let peer = rig.peer.clone();
        let (accepted, client) = connect(&mut rig, "localhost", Some(&peer)).await;
        let client = client.expect("public handshake");
        let (_, connection) = client.get_ref();
        assert_eq!(
            connection.peer_certificates().unwrap().first().unwrap(),
            &rig.public_cert
        );
        let (_io, remote_addr) = accepted.expect("connection kept");
        assert!(peer_from_remote_addr(&remote_addr).is_none());
        assert!(remote_addr.0.as_socket_addr().is_some());
    }

    #[test]
    fn marker_round_trip() {
        let node_id = NodeId(Uuid::new_v4());
        let plain = RemoteAddr(poem::Addr::SocketAddr("127.0.0.1:4000".parse().unwrap()));
        let addr =
            annotate_remote_addr(&plain, CLUSTER_PEER_ADDR_SCHEME, &format!("node:{node_id}"));
        assert_eq!(peer_from_remote_addr(&addr), Some(ClusterPeer { node_id }));
        assert_eq!(peer_from_remote_addr(&plain), None);
        let other = annotate_remote_addr(&plain, "captured-cert", "cert:AAAA");
        assert_eq!(peer_from_remote_addr(&other), None);
    }
}
