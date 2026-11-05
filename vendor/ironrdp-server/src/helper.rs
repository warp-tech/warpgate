use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio_rustls::rustls::pki_types::pem::PemObject as _;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::{TlsAcceptor, rustls};

use crate::error::{ServerError, ServerErrorExt as _, ServerResult};

pub struct TlsIdentityCtx {
    pub certs: Vec<CertificateDer<'static>>,
    pub priv_key: PrivateKeyDer<'static>,
    pub pub_key: Vec<u8>,
}

impl TlsIdentityCtx {
    /// A constructor to create a `TlsIdentityCtx` from the given certificate and key paths.
    ///
    /// The file format can be either PEM (if the file extension ends with .pem) or DER.
    pub fn init_from_paths(cert_path: &Path, key_path: &Path) -> ServerResult<Self> {
        let certs = if cert_path.extension().is_some_and(|ext| ext == "pem") {
            CertificateDer::pem_file_iter(cert_path)
                .map_err(|e| ServerError::custom("reading server cert", e))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| ServerError::custom("collecting server cert", e))?
        } else {
            certs(&mut BufReader::new(
                File::open(cert_path).map_err(|e| ServerError::io("opening server cert", e))?,
            ))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| ServerError::io("collecting server cert", e))?
        };

        let priv_key = if key_path.extension().is_some_and(|ext| ext == "pem") {
            PrivateKeyDer::from_pem_file(key_path).map_err(|e| ServerError::custom("reading server key", e))?
        } else {
            pkcs8_private_keys(&mut BufReader::new(
                File::open(key_path).map_err(|e| ServerError::io("opening server key", e))?,
            ))
            .next()
            .ok_or_else(|| ServerError::reason("server key", "no private key"))?
            .map(PrivateKeyDer::from)
            .map_err(|e| ServerError::io("reading server key", e))?
        };

        let pub_key = {
            use x509_cert::der::Decode as _;

            let cert = certs
                .first()
                .ok_or_else(|| ServerError::reason("server cert", "invalid cert"))?;
            let cert =
                x509_cert::Certificate::from_der(cert).map_err(|e| ServerError::custom("parsing server cert", e))?;
            cert.tbs_certificate()
                .subject_public_key_info()
                .subject_public_key
                .as_bytes()
                .ok_or_else(|| ServerError::reason("server cert", "subject public key BIT STRING is not aligned"))?
                .to_owned()
        };

        Ok(Self {
            certs,
            priv_key,
            pub_key,
        })
    }

    pub fn make_acceptor(&self) -> ServerResult<TlsAcceptor> {
        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(self.certs.clone(), self.priv_key.clone_key())
            .map_err(|e| ServerError::custom("bad certificate/key", e))?;

        // This adds support for the SSLKEYLOGFILE env variable (https://wiki.wireshark.org/TLS#using-the-pre-master-secret)
        server_config.key_log = Arc::new(rustls::KeyLogFile::new());

        Ok(TlsAcceptor::from(Arc::new(server_config)))
    }
}
