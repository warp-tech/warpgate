use picky::hash::HashAlgorithm;
use picky::key::PublicKey as RsaPublicKey;
use picky::signature::SignatureAlgorithm;
use picky_asn1::wrapper::Asn1SetOf;
use picky_asn1_x509::pkcs7::content_info::ContentValue;
use picky_asn1_x509::pkcs7::signer_info::SignerIdentifier;
use picky_asn1_x509::signed_data::{CertificateChoices, SignedData};
use picky_asn1_x509::{AttributeValues, Certificate, oids};

use crate::{Error, ErrorKind, Result};

pub fn validate_signed_data(signed_data: &SignedData, rsa_public_key: &RsaPublicKey) -> Result<()> {
    let signer_info = signed_data
        .signers_infos
        .0
        .0
        .first()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Missing signers_infos in signed data"))?;

    if !signer_info.digest_algorithm.0.is_a(oids::sha1()) {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "PKU2U SignedData uses an unsupported digest algorithm",
        ));
    }

    let certificate = match signed_data.certificates.0.0.first().ok_or_else(|| {
        Error::new(
            ErrorKind::Pku2uCertFailure,
            "PKU2U SignedData has no signing certificate",
        )
    })? {
        CertificateChoices::Certificate(certificate) => picky_asn1_der::from_bytes::<Certificate>(&certificate.0)?,
        _ => {
            return Err(Error::new(
                ErrorKind::Pku2uCertFailure,
                "PKU2U SignedData contains an unsupported signing certificate",
            ));
        }
    };

    match &signer_info.sid {
        SignerIdentifier::IssuerAndSerialNumber(signer)
            if signer.issuer == certificate.tbs_certificate.issuer
                && signer.serial_number.0 == certificate.tbs_certificate.serial_number => {}
        _ => {
            return Err(Error::new(
                ErrorKind::Pku2uCertFailure,
                "PKU2U signer identifier does not match the signing certificate",
            ));
        }
    }

    let content = match &signed_data
        .content_info
        .content
        .as_ref()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "PKU2U SignedData has no encapsulated content"))?
        .0
    {
        ContentValue::OctetString(content) => &content.0,
        _ => {
            return Err(Error::new(
                ErrorKind::InvalidToken,
                "PKU2U SignedData encapsulated content is not an octet string",
            ));
        }
    };

    let mut message_digests = signer_info.signed_attrs.0.0.0.iter().filter_map(|attribute| {
        if attribute.ty.0 == oids::message_digest() {
            if let AttributeValues::MessageDigest(values) = &attribute.value {
                values.0.first().map(|value| value.0.as_slice())
            } else {
                None
            }
        } else {
            None
        }
    });
    let message_digest = message_digests.next().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidToken,
            "PKU2U SignedData has no messageDigest attribute",
        )
    })?;
    if message_digests.next().is_some() || message_digest != HashAlgorithm::SHA1.digest(content) {
        return Err(Error::new(
            ErrorKind::MessageAltered,
            "PKU2U SignedData messageDigest does not match its encapsulated content",
        ));
    }

    let signed_attributes = Asn1SetOf::from(signer_info.signed_attrs.0.0.0.clone());
    let encoded_signed_attributes = picky_asn1_der::to_vec(&signed_attributes)?;

    SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA1)
        .verify(rsa_public_key, &encoded_signed_attributes, &signer_info.signature.0.0)
        .map_err(|_| Error::new(ErrorKind::InvalidToken, "Invalid signed data signature"))
}
