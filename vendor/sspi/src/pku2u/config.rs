use std::fmt;
use std::sync::Arc;

use picky::hash::HashAlgorithm;
use picky::key::PrivateKey;
use picky::signature::SignatureAlgorithm;
use picky_asn1_x509::Certificate;

use crate::negotiate::{NegotiatedProtocol, ProtocolConfig};
use crate::secret::SecretPrivateKey;
use crate::{Error, ErrorKind, Pku2u, Result};

type SignFn = dyn Fn(&[u8]) -> Result<Vec<u8>> + Send + Sync;

#[derive(Clone)]
pub struct Pku2uPrivateKey(Arc<SignFn>);

impl Pku2uPrivateKey {
    pub fn new(private_key: PrivateKey) -> Self {
        let private_key = SecretPrivateKey::new(private_key);
        Self::from_signer(move |data| {
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA1)
                .sign(data, private_key.as_ref())
                .map_err(|error| Error::new(ErrorKind::InternalError, format!("PKU2U signing failed: {error}")))
        })
    }

    pub(crate) fn from_signer(signer: impl Fn(&[u8]) -> Result<Vec<u8>> + Send + Sync + 'static) -> Self {
        Self(Arc::new(signer))
    }

    pub(crate) fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        (self.0)(data)
    }
}

impl fmt::Debug for Pku2uPrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Pku2uPrivateKey")
    }
}

impl From<PrivateKey> for Pku2uPrivateKey {
    fn from(private_key: PrivateKey) -> Self {
        Self::new(private_key)
    }
}

#[derive(Debug, Clone)]
pub struct Pku2uCredential {
    pub certificate: Certificate,
    pub private_key: Pku2uPrivateKey,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Pku2uConfig {
    pub p2p_certificate: Certificate,
    pub private_key: Pku2uPrivateKey,
    pub client_hostname: String,
    pub additional_credentials: Vec<Pku2uCredential>,
    pub trusted_client_certificates: Vec<Certificate>,
    pub trusted_server_certificates: Vec<Certificate>,
}

impl Pku2uConfig {
    pub fn new(p2p_certificate: Certificate, private_key: PrivateKey, client_hostname: String) -> Self {
        let trusted_client_certificates = vec![p2p_certificate.clone()];
        Self {
            p2p_certificate,
            private_key: private_key.into(),
            client_hostname,
            additional_credentials: Vec::new(),
            trusted_client_certificates,
            trusted_server_certificates: Vec::new(),
        }
    }

    pub fn with_additional_credential(mut self, certificate: Certificate, private_key: PrivateKey) -> Self {
        self.additional_credentials.push(Pku2uCredential {
            certificate,
            private_key: private_key.into(),
        });
        self
    }

    pub fn with_trusted_client_certificate(mut self, certificate: Certificate) -> Self {
        if !self.trusted_client_certificates.contains(&certificate) {
            self.trusted_client_certificates.push(certificate);
        }
        self
    }

    pub fn with_trusted_server_certificate(mut self, certificate: Certificate) -> Self {
        if !self.trusted_server_certificates.contains(&certificate) {
            self.trusted_server_certificates.push(certificate);
        }
        self
    }

    #[cfg(target_os = "windows")]
    pub fn default_client_config(client_hostname: String) -> Result<Self> {
        use super::cert_utils::extraction::extract_client_p2p_cert_and_key;

        let (p2p_certificate, private_key) = extract_client_p2p_cert_and_key()?;
        let trusted_client_certificates = vec![p2p_certificate.clone()];

        Ok(Self {
            p2p_certificate,
            private_key,
            client_hostname,
            additional_credentials: Vec::new(),
            trusted_client_certificates,
            trusted_server_certificates: Vec::new(),
        })
    }
}

impl ProtocolConfig for Pku2uConfig {
    fn new_instance(&self) -> Result<NegotiatedProtocol> {
        Ok(NegotiatedProtocol::Pku2u(Pku2u::new_client_from_config(Clone::clone(
            self,
        ))?))
    }

    fn new_server_instance(&self) -> Result<NegotiatedProtocol> {
        Ok(NegotiatedProtocol::Pku2u(Pku2u::new_server_from_config(Clone::clone(
            self,
        ))?))
    }

    fn box_clone(&self) -> Box<dyn ProtocolConfig> {
        Box::new(Clone::clone(self))
    }
}
