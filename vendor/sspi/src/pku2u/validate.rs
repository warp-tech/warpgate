use picky::hash::HashAlgorithm;
use picky::key::PublicKey as RsaPublicKey;
use picky::signature::SignatureAlgorithm;
use picky_asn1::wrapper::Asn1SetOf;
use picky_asn1_x509::signed_data::SignedData;

use crate::{Error, ErrorKind, Result};

pub fn validate_signed_data(signed_data: &SignedData, rsa_public_key: &RsaPublicKey) -> Result<()> {
    let signer_info = signed_data
        .signers_infos
        .0
        .0
        .first()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Missing signers_infos in signed data"))?;

    let signed_attributes = Asn1SetOf::from(signer_info.signed_attrs.0.0.0.clone());
    let encoded_signed_attributes = picky_asn1_der::to_vec(&signed_attributes)?;

    SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA1)
        .verify(rsa_public_key, &encoded_signed_attributes, &signer_info.signature.0.0)
        .map_err(|_| Error::new(ErrorKind::InvalidToken, "Invalid signed data signature"))
}
