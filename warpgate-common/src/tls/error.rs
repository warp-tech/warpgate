use rustls::server::VerifierBuilderError;
use x509_parser::error::X509Error;

#[derive(thiserror::Error, Debug)]
pub enum RustlsSetupError {
    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("rustls: {0}")]
    RustlsPem(#[from] rustls_pki_types::pem::Error),
    #[error("verifier setup: {0}")]
    VerifierBuilder(#[from] VerifierBuilderError),
    #[error("no certificates found in certificate file")]
    NoCertificates,
    #[error("no private keys found in key file")]
    NoKeys,
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("PKI: {0}")]
    Pki(webpki::Error),
    #[error("parsing certificate: {0}")]
    X509(#[from] X509Error),
}
