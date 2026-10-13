use std::collections::HashMap;
use std::io::Cursor;
use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme,
};
use rustls_pki_types::pem::PemObject;
use warpgate_ca::ClusterTlsIdentity;

use super::{ROOT_CERT_STORE, RustlsSetupError, TlsCertificateAndPrivateKey};

#[derive(Debug)]
pub struct ResolveServerCert(pub Arc<CertifiedKey>);

impl ResolvesServerCert for ResolveServerCert {
    fn resolve(&self, _: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// Picks the certificate whose SAN matches the requested SNI name, falling back
/// to the first certificate for clients that send no SNI or an unknown name.
#[derive(Debug)]
pub struct SniCertResolver {
    fallback: Arc<CertifiedKey>,
    by_name: HashMap<String, Arc<CertifiedKey>>,
}

impl SniCertResolver {
    /// The first certificate is the fallback; every certificate (including the
    /// first) is also registered under each of its SAN names.
    pub fn new(
        mut certificates: impl Iterator<Item = TlsCertificateAndPrivateKey>,
    ) -> Result<Self, RustlsSetupError> {
        let primary = certificates
            .next()
            .ok_or(RustlsSetupError::NoCertificates)?;
        let fallback = Arc::new(CertifiedKey::from(primary.clone()));
        let mut by_name = HashMap::new();
        for cert in std::iter::once(primary).chain(certificates) {
            let names = cert.certificate.sni_names()?;
            let key = Arc::new(CertifiedKey::from(cert));
            for name in names {
                by_name.insert(name, key.clone());
            }
        }
        Ok(Self { fallback, by_name })
    }
}

impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(
            client_hello
                .server_name()
                .and_then(|name| self.by_name.get(name))
                .unwrap_or(&self.fallback)
                .clone(),
        )
    }
}

/// Client certificate verifier that proves the peer holds the presented
/// certificate's private key (by verifying the handshake signature) but does
/// **not** validate the certificate chain against a trust anchor. Who the
/// certificate belongs to is decided after the handshake: by Warpgate's
/// credential database for Kubernetes clients, by the `nodes` SPKI pins for
/// cluster peers.
#[derive(Debug)]
pub struct PossessionOnlyClientCertVerifier {
    provider: Arc<CryptoProvider>,
    mandatory: bool,
}

impl PossessionOnlyClientCertVerifier {
    /// A client may connect without a certificate.
    pub const fn optional(provider: Arc<CryptoProvider>) -> Self {
        Self {
            provider,
            mandatory: false,
        }
    }

    /// The handshake fails unless the client presents a certificate.
    pub const fn mandatory(provider: Arc<CryptoProvider>) -> Self {
        Self {
            provider,
            mandatory: true,
        }
    }
}

impl ClientCertVerifier for PossessionOnlyClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
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
    ) -> Result<HandshakeSignatureValid, TlsError> {
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

/// The identity's certificate chain and key in rustls form.
pub fn cluster_identity_certified_key(
    identity: &ClusterTlsIdentity,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), RustlsSetupError> {
    let certs = CertificateDer::pem_slice_iter(identity.certificate_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(identity.private_key_pem.as_bytes())?;
    Ok((certs, key))
}

pub async fn configure_tls_connector(
    accept_invalid_certs: bool,
    accept_invalid_hostnames: bool,
    root_cert: Option<&[u8]>,
) -> Result<ClientConfig, RustlsSetupError> {
    let config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?;

    let config = if accept_invalid_certs {
        config
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(DummyTlsVerifier))
            .with_no_client_auth()
    } else {
        let mut cert_store = ROOT_CERT_STORE.clone();

        if let Some(data) = root_cert {
            let mut cursor = Cursor::new(data);

            for cert in CertificateDer::pem_reader_iter(&mut cursor) {
                cert_store.add(cert?)?;
            }
        }

        if accept_invalid_hostnames {
            let verifier = WebPkiServerVerifier::builder(Arc::new(cert_store)).build()?;

            config
                .dangerous()
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

#[derive(Debug)]
pub struct DummyTlsVerifier;

impl ServerCertVerifier for DummyTlsVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
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
        ]
    }
}

#[derive(Debug)]
pub struct NoHostnameTlsVerifier {
    verifier: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for NoHostnameTlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self.verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Err(TlsError::InvalidCertificate(CertificateError::NotValidForName)) => {
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
        self.verifier.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.verifier.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }
}

/// TLS verifier used for cluster peer to peer connections
/// Verifies that a cert is issued by the own warpgate-ca
/// and SPKI matches the pinned value
#[derive(Debug)]
pub struct ClusterPeerVerifier {
    verifier: Arc<WebPkiServerVerifier>,
    expected_spki_sha256_hex: String,
}

impl ClusterPeerVerifier {
    pub fn new(
        ca_certificate_pem: &[u8],
        expected_spki_sha256_hex: String,
    ) -> Result<Self, RustlsSetupError> {
        let mut cert_store = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_reader_iter(&mut Cursor::new(ca_certificate_pem)) {
            cert_store.add(cert?)?;
        }
        Ok(Self {
            verifier: WebPkiServerVerifier::builder(Arc::new(cert_store)).build()?,
            expected_spki_sha256_hex,
        })
    }
}

/// A TLS client config trusting only the cluster peer with the pinned
/// certificate, and presenting this node's own identity so the peer can pin
/// us in turn.
pub fn configure_cluster_tls_connector(
    ca_certificate_pem: &[u8],
    expected_spki_sha256_hex: String,
    identity: &ClusterTlsIdentity,
) -> Result<ClientConfig, RustlsSetupError> {
    let (certs, key) = cluster_identity_certified_key(identity)?;
    Ok(
        ClientConfig::builder_with_provider(
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ClusterPeerVerifier::new(
            ca_certificate_pem,
            expected_spki_sha256_hex,
        )?))
        .with_client_auth_cert(certs, key)?,
    )
}

impl ServerCertVerifier for ClusterPeerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // Verify the certificate against CA
        let verified = self.verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;

        // Verify the SPKI against pin
        let spki = warpgate_ca::certificate_der_spki_sha256_hex(end_entity.as_ref())
            .map_err(|e| TlsError::General(e.to_string()))?;
        if spki != self.expected_spki_sha256_hex {
            return Err(TlsError::General(
                "peer certificate key does not match the node's registered pin".into(),
            ));
        }
        Ok(verified)
    }

    // Delegate the rest
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.verifier.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.verifier.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use rustls::{ClientConnection, ServerConnection};

    use super::*;

    fn install_crypto_provider() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    fn handshake(
        client: &mut ClientConnection,
        server: &mut ServerConnection,
    ) -> Result<(), TlsError> {
        while client.is_handshaking() || server.is_handshaking() {
            let mut buf = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut buf).unwrap();
            }
            let mut slice = &buf[..];
            while !slice.is_empty() {
                server.read_tls(&mut slice).unwrap();
            }
            server.process_new_packets()?;

            let mut buf = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut buf).unwrap();
            }
            let mut slice = &buf[..];
            while !slice.is_empty() {
                client.read_tls(&mut slice).unwrap();
            }
            client.process_new_packets()?;
        }
        Ok(())
    }

    /// The server's identity, the client's identity (same CA) and a client
    /// connection expecting the given pin (empty = the server's real pin).
    fn connections(
        expected_pin: String,
    ) -> (ClusterTlsIdentity, ClusterTlsIdentity, ClientConnection) {
        let (ca_cert, ca_key) = warpgate_ca::issue_ca_root_certificate().unwrap();
        let server_identity = ClusterTlsIdentity::issue(&ca_cert, &ca_key).unwrap();
        let client_identity = ClusterTlsIdentity::issue(&ca_cert, &ca_key).unwrap();

        let pin = if expected_pin.is_empty() {
            server_identity.spki_sha256_hex.clone()
        } else {
            expected_pin
        };
        let client_config =
            configure_cluster_tls_connector(ca_cert.as_bytes(), pin, &client_identity).unwrap();
        let client = ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from(warpgate_ca::CLUSTER_TLS_SNI_NAME).unwrap(),
        )
        .unwrap();
        (server_identity, client_identity, client)
    }

    fn server(identity: &ClusterTlsIdentity) -> ServerConnection {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let (certs, key) = cluster_identity_certified_key(identity).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(Arc::new(PossessionOnlyClientCertVerifier::mandatory(
                provider,
            )))
            .with_single_cert(certs, key)
            .unwrap();
        ServerConnection::new(Arc::new(config)).unwrap()
    }

    #[test]
    fn cluster_handshake_succeeds_and_exposes_the_client_certificate() {
        install_crypto_provider();
        let (server_identity, client_identity, mut client) = connections(String::new());
        let mut srv = server(&server_identity);
        handshake(&mut client, &mut srv).unwrap();
        let peer = srv.peer_certificates().unwrap().first().unwrap();
        assert_eq!(
            warpgate_ca::certificate_der_spki_sha256_hex(peer.as_ref()).unwrap(),
            client_identity.spki_sha256_hex,
        );
    }

    #[test]
    fn cluster_handshake_rejects_wrong_pin() {
        install_crypto_provider();
        let (server_identity, _, mut client) = connections("00".repeat(32));
        let mut srv = server(&server_identity);
        assert!(handshake(&mut client, &mut srv).is_err());
    }

    #[test]
    fn mandatory_verifier_rejects_a_client_without_a_certificate() {
        install_crypto_provider();
        let (ca_cert, ca_key) = warpgate_ca::issue_ca_root_certificate().unwrap();
        let identity = ClusterTlsIdentity::issue(&ca_cert, &ca_key).unwrap();
        let client_config = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DummyTlsVerifier))
        .with_no_client_auth();
        let mut client = ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from(warpgate_ca::CLUSTER_TLS_SNI_NAME).unwrap(),
        )
        .unwrap();
        let mut srv = server(&identity);
        assert!(handshake(&mut client, &mut srv).is_err());
    }
}
