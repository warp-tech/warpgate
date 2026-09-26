use crypto_bigint::BoxedUint;
use picky::key::PublicKey as RsaPublicKey;
use picky_asn1_x509::signed_data::{CertificateChoices, SignedData};
use picky_asn1_x509::{Certificate, PublicKey};

use crate::{Error, ErrorKind, Result};

/// validates server's p2p certificate.
/// If certificate is valid then return its public key.
#[instrument(level = "trace", ret)]
pub fn validate_server_p2p_certificate(signed_data: &SignedData) -> Result<RsaPublicKey> {
    let certificates = &signed_data.certificates.0.0;

    if let Some(certificate) = certificates.iter().next() {
        let cert: Certificate = match certificate {
            CertificateChoices::Certificate(cert) => picky_asn1_der::from_bytes(&cert.0)?,
            cert => {
                error!(?cert, "Server sent unsupported certificate format");

                return Err(Error::new(
                    ErrorKind::Pku2uCertFailure,
                    "Received unknown certificate format",
                ));
            }
        };

        let public_key = match cert.tbs_certificate.subject_public_key_info.subject_public_key {
            PublicKey::Rsa(rsa) => rsa,
            public_key => {
                error!(
                    ?public_key,
                    "Server sent unsupported public key type. Only RSA keys supported",
                );

                return Err(Error::new(
                    ErrorKind::Pku2uCertFailure,
                    "Received certificate has unsupported public key type. Only RSA is supported",
                ));
            }
        }
        .0;

        return Ok(RsaPublicKey::from_rsa_components(
            &BoxedUint::from_be_slice_vartime(&public_key.modulus.0),
            &BoxedUint::from_be_slice_vartime(&public_key.public_exponent.0),
        ));
    }

    Err(Error::new(
        ErrorKind::Pku2uCertFailure,
        "Received invalid server certificates",
    ))
}
