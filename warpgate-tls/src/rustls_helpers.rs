use std::io::Cursor;
use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{CertificateError, ClientConfig, Error as TlsError, SignatureScheme};
use rustls_pki_types::pem::PemObject;

use super::{ROOT_CERT_STORE, RustlsSetupError};

#[derive(Debug)]
pub struct ResolveServerCert(pub Arc<CertifiedKey>);

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

/// A TLS client config trusting only the cluster peer with
/// specific pinned certificate
pub fn configure_cluster_tls_connector(
    ca_certificate_pem: &[u8],
    expected_spki_sha256_hex: String,
) -> Result<ClientConfig, RustlsSetupError> {
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
        .with_no_client_auth(),
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
    use rustls::pki_types::PrivateKeyDer;
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

    fn connections(expected_pin: String) -> (warpgate_ca::ClusterTlsIdentity, ClientConnection) {
        let (ca_cert, ca_key) = warpgate_ca::issue_ca_root_certificate().unwrap();
        let identity = warpgate_ca::ClusterTlsIdentity::issue(&ca_cert, &ca_key).unwrap();

        let pin = if expected_pin.is_empty() {
            identity.spki_sha256_hex.clone()
        } else {
            expected_pin
        };
        let client_config = configure_cluster_tls_connector(ca_cert.as_bytes(), pin).unwrap();
        let client = ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from(warpgate_ca::CLUSTER_TLS_SNI_NAME).unwrap(),
        )
        .unwrap();
        (identity, client)
    }

    fn server(identity: &warpgate_ca::ClusterTlsIdentity) -> ServerConnection {
        let certs = CertificateDer::pem_slice_iter(identity.certificate_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_slice(identity.private_key_pem.as_bytes()).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        ServerConnection::new(Arc::new(config)).unwrap()
    }

    #[test]
    fn cluster_handshake_succeeds() {
        install_crypto_provider();
        let (identity, mut client) = connections(String::new());
        let mut srv = server(&identity);
        handshake(&mut client, &mut srv).unwrap();
    }

    #[test]
    fn cluster_handshake_rejects_wrong_pin() {
        install_crypto_provider();
        let (identity, mut client) = connections("00".repeat(32));
        let mut srv = server(&identity);
        assert!(handshake(&mut client, &mut srv).is_err());
    }
}
