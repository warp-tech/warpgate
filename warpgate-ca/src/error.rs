use std::error::Error;

use x509_parser::error::{PEMError, X509Error};

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
    #[error("ASN.1 X509 {0}")]
    Asn1X509(#[from] x509_parser::asn1_rs::Err<X509Error>),
    #[error("ASN.1 PEM: {0}")]
    Asn1Pem(#[from] x509_parser::asn1_rs::Err<PEMError>),
    #[error("rcgen: {0}")]
    RcGen(#[from] rcgen::Error),
    #[error("Invalid key format")]
    InvalidKeyFormat,
    #[error("Invalid certificate format")]
    InvalidCertificateFormat,
    #[error(transparent)]
    Other(Box<dyn Error + Send + Sync>),
}
