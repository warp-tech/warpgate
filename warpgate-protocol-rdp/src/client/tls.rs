//! TLS setup for the target-facing RDP connection.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use anyhow::{Context, Result};
use ironrdp_server::tokio_rustls::TlsConnector;
use ironrdp_server::tokio_rustls::client::TlsStream as RustlsTlsStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use warpgate_common::RdpTlsSecurity;

#[cfg(feature = "openssl-tls")]
const OPENSSL_WINDOWS_2012_CIPHER_LIST: &str = concat!(
    "ECDHE-RSA-AES256-SHA384:",
    "ECDHE-RSA-AES128-SHA256:",
    "ECDHE-RSA-AES256-SHA:",
    "ECDHE-RSA-AES128-SHA:",
    "AES256-GCM-SHA384:",
    "AES128-GCM-SHA256:",
    "AES256-SHA256:",
    "AES128-SHA256:",
    "AES256-SHA:",
    "AES128-SHA:",
    "!aNULL:!eNULL:!EXPORT:!DES:!3DES:!RC4:!MD5:@SECLEVEL=0"
);
#[cfg(feature = "openssl-tls")]
const OPENSSL_WINDOWS_2008_CIPHER_LIST: &str = "ALL:@SECLEVEL=0";

pub enum TargetTlsStream {
    Rustls(RustlsTlsStream<TcpStream>),
    #[cfg(feature = "openssl-tls")]
    OpenSsl(tokio_openssl::SslStream<TcpStream>),
}

impl AsyncRead for TargetTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Rustls(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(feature = "openssl-tls")]
            Self::OpenSsl(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TargetTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Rustls(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(feature = "openssl-tls")]
            Self::OpenSsl(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Rustls(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "openssl-tls")]
            Self::OpenSsl(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Rustls(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(feature = "openssl-tls")]
            Self::OpenSsl(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// Wrap `stream` in TLS and return it alongside the server's public key, which CredSSP
/// channel-binds to.
pub async fn upgrade(
    stream: TcpStream,
    server_name: String,
    verify: bool,
    tls_security: RdpTlsSecurity,
) -> Result<(TargetTlsStream, Vec<u8>)> {
    match tls_security {
        RdpTlsSecurity::Windows2016 => upgrade_rustls(stream, server_name, verify).await,
        RdpTlsSecurity::Windows2012 => {
            #[cfg(feature = "openssl-tls")]
            {
                upgrade_openssl_windows_2012(stream, server_name, verify).await
            }

            #[cfg(not(feature = "openssl-tls"))]
            {
                let _ = (stream, server_name, verify);
                anyhow::bail!(
                    "RDP TLS security profile `{tls_security:?}` requires building Warpgate with the `rdp-openssl-tls` feature"
                )
            }
        }
        RdpTlsSecurity::Windows2008 => {
            #[cfg(feature = "openssl-tls")]
            {
                upgrade_openssl_windows_2008(stream, server_name, verify).await
            }

            #[cfg(not(feature = "openssl-tls"))]
            {
                let _ = (stream, server_name, verify);
                anyhow::bail!(
                    "RDP TLS security profile `{tls_security:?}` requires building Warpgate with the `rdp-openssl-tls` feature"
                )
            }
        }
    }
}

async fn upgrade_rustls(
    stream: TcpStream,
    server_name: String,
    verify: bool,
) -> Result<(TargetTlsStream, Vec<u8>)> {
    let config = build_rustls_config(verify)?;
    upgrade_rustls_with_config(stream, server_name, config).await
}

fn build_rustls_config(verify: bool) -> Result<rustls::client::ClientConfig> {
    let config = if verify {
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            roots.add(cert).ok();
        }
        rustls::client::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else {
        // RDP servers commonly use self-signed certs, so verification is off by default;
        // CredSSP/NLA still channel-binds to the server's public key.
        rustls::client::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(danger::NoCertificateVerification))
            .with_no_client_auth()
    };

    Ok(config)
}

async fn upgrade_rustls_with_config(
    stream: TcpStream,
    server_name: String,
    mut config: rustls::client::ClientConfig,
) -> Result<(TargetTlsStream, Vec<u8>)> {
    config.resumption = rustls::client::Resumption::disabled();

    let connector = TlsConnector::from(Arc::new(config));
    let server_name = server_name.try_into().context("invalid server name")?;
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .context("TLS handshake")?;

    let cert = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .context("missing peer certificate")?;
    let server_public_key = extract_server_public_key(cert)?;

    Ok((TargetTlsStream::Rustls(tls_stream), server_public_key))
}

#[cfg(feature = "openssl-tls")]
async fn upgrade_openssl_windows_2012(
    stream: TcpStream,
    server_name: String,
    verify: bool,
) -> Result<(TargetTlsStream, Vec<u8>)> {
    use openssl::ssl::{SslConnector, SslMethod, SslVersion};

    let mut builder =
        SslConnector::builder(SslMethod::tls_client()).context("OpenSSL connector")?;
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .context("setting OpenSSL minimum TLS version")?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_2))
        .context("setting OpenSSL maximum TLS version")?;
    builder
        .set_cipher_list(OPENSSL_WINDOWS_2012_CIPHER_LIST)
        .context("setting OpenSSL cipher list")?;

    upgrade_openssl(stream, server_name, verify, builder).await
}

#[cfg(feature = "openssl-tls")]
async fn upgrade_openssl_windows_2008(
    stream: TcpStream,
    server_name: String,
    verify: bool,
) -> Result<(TargetTlsStream, Vec<u8>)> {
    use openssl::ssl::{SslConnector, SslMethod, SslVersion};

    let mut builder =
        SslConnector::builder(SslMethod::tls_client()).context("OpenSSL connector")?;
    builder
        .set_min_proto_version(Some(SslVersion::TLS1))
        .context("setting OpenSSL minimum TLS version")?;
    builder
        .set_cipher_list(OPENSSL_WINDOWS_2008_CIPHER_LIST)
        .context("setting OpenSSL cipher list")?;

    upgrade_openssl(stream, server_name, verify, builder).await
}

#[cfg(feature = "openssl-tls")]
async fn upgrade_openssl(
    stream: TcpStream,
    server_name: String,
    verify: bool,
    mut builder: openssl::ssl::SslConnectorBuilder,
) -> Result<(TargetTlsStream, Vec<u8>)> {
    use openssl::ssl::SslVerifyMode;

    if !verify {
        builder.set_verify(SslVerifyMode::NONE);
    }

    let connector = builder.build();
    let mut config = connector.configure().context("OpenSSL connect config")?;
    if !verify {
        config.set_verify_hostname(false);
    }

    let ssl = config
        .into_ssl(&server_name)
        .context("OpenSSL server name setup")?;
    let mut tls_stream =
        tokio_openssl::SslStream::new(ssl, stream).context("OpenSSL TLS stream")?;
    Pin::new(&mut tls_stream)
        .connect()
        .await
        .context("OpenSSL TLS handshake")?;

    let cert = tls_stream
        .ssl()
        .peer_certificate()
        .context("missing peer certificate")?;
    let cert = cert.to_der().context("serializing peer certificate")?;
    let server_public_key = extract_server_public_key(&cert)?;

    Ok((TargetTlsStream::OpenSsl(tls_stream), server_public_key))
}

fn extract_server_public_key(cert: &[u8]) -> Result<Vec<u8>> {
    use x509_cert::der::Decode as _;
    let cert = x509_cert::Certificate::from_der(cert).context("parsing certificate")?;
    let key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .context("public key not byte-aligned")?
        .to_owned();
    Ok(key)
}

mod danger {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    pub struct NoCertificateVerification;

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
            ]
        }
    }
}
