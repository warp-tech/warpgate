#[derive(thiserror::Error, Debug)]
pub enum RustlsSetupError {
    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("sign: {0}")]
    Sign(#[from] rustls::sign::SignError),
    #[error("no certificates found in certificate file")]
    NoCertificates,
    #[error("no private keys found in key file")]
    NoKeys,
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("PKI: {0}")]
    Pki(#[from] webpki::Error),
}
