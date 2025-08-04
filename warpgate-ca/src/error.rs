use std::error::Error;

use x509_parser::error::X509Error;

#[derive(thiserror::Error, Debug)]
pub enum CaError {
    #[error("x509-cert: {0}")]
    X509Cert(#[from] x509_cert::builder::Error),
    #[error("aws-lc-rs: {0}")]
    AwsLcRs(#[from] aws_lc_rs::error::Unspecified),
    #[error("DER: {0}")]
    Der(#[from] der::Error),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("PEM: {0}")]
    Pem(#[from] x509_parser::asn1_rs::Err<X509Error>),
    #[error("Invalid key format")]
    InvalidKeyFormat,
    #[error("Invalid certificate format")]
    InvalidCertificateFormat,
    #[error(transparent)]
    Other(Box<dyn Error + Send + Sync>),
}
