use oid::ObjectIdentifier;
use picky_asn1::bit_string::BitString;
use picky_asn1::date::GeneralizedTime;
use picky_asn1::wrapper::{
    Asn1SequenceOf, Asn1SetOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2,
    ExplicitContextTag3, ImplicitContextTag0, IntegerAsn1, ObjectIdentifierAsn1, OctetStringAsn1, Optional,
};
use picky_asn1_der::Asn1RawDer;
use picky_asn1_x509::cmsversion::CmsVersion;
use picky_asn1_x509::content_info::{ContentValue, EncapsulatedContentInfo};
use picky_asn1_x509::oids::PKINIT_DH_KEY_DATA;
use picky_asn1_x509::signed_data::{
    CertificateChoices, CertificateSet, DigestAlgorithmIdentifiers, SignedData, SignersInfos,
};
use picky_asn1_x509::signer_info::{
    Attributes, CertificateSerialNumber, DigestAlgorithmIdentifier, IssuerAndSerialNumber,
    SignatureAlgorithmIdentifier, SignatureValue, SignerIdentifier, SignerInfo, UnsignedAttributes,
};
use picky_asn1_x509::{AlgorithmIdentifier, Attribute, AttributeValues, Certificate, ShaVariant, oids};
use picky_krb::constants::types::{PA_PAC_REQUEST_TYPE, PA_PK_AS_REQ};
use picky_krb::crypto::diffie_hellman::compute_public_key;
use picky_krb::data_types::{KerbPaPacRequest, KerberosTime, PaData};
use picky_krb::messages::KdcReqBody;
use picky_krb::pkinit::{
    AuthPack, DhDomainParameters, DhReqInfo, DhReqKeyInfo, KdcDhKeyInfo, PaPkAsReq, PkAuthenticator,
};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use time::OffsetDateTime;

use crate::kerberos::client::generators::MAX_MICROSECONDS;
use crate::{Error, ErrorKind, Result};

/// [Generation of Client Request](https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.1)
/// 9. This nonce string MUST be as long as the longest key length of the symmetric key types that the client supports.
/// Key length of Aes256 is equal to 32
pub(crate) const DH_NONCE_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct DhParameters {
    // g
    pub base: Vec<u8>,
    // p
    pub modulus: Vec<u8>,
    //
    pub q: Vec<u8>,
    // generated private key
    pub private_key: Vec<u8>,
    // received public key
    pub other_public_key: Option<Vec<u8>>,
    pub client_nonce: Option<[u8; DH_NONCE_LEN]>,
    pub server_nonce: Option<[u8; DH_NONCE_LEN]>,
}

// PA_DATAs in the Kerberos smart card logon is packed into a wrapper with OID.
// It's very similar to the `EncapsulatedContentInfo` structure, but the content field has another type.
#[derive(Serialize, Deserialize)]
pub(crate) struct Wrapper<T> {
    pub content_info: ObjectIdentifierAsn1,
    pub content: ExplicitContextTag0<T>,
}

pub(crate) type SignDataFn = Box<dyn FnMut(&[u8]) -> Result<Vec<u8>> + Send>;

pub(crate) struct GenerateAsPaDataOptions<'a> {
    pub p2p_cert: Certificate,
    pub kdc_req_body: &'a KdcReqBody,
    pub dh_parameters: DhParameters,
    pub sign_data: SignDataFn,
    pub with_pre_auth: bool,
    pub authenticator_nonce: [u8; 4],
}

#[instrument(level = "trace", skip_all, ret)]
pub(crate) fn generate_pa_datas_for_as_req(options: &mut GenerateAsPaDataOptions<'_>) -> Result<Vec<PaData>> {
    let GenerateAsPaDataOptions {
        p2p_cert,
        kdc_req_body,
        dh_parameters,
        sign_data,
        with_pre_auth,
        authenticator_nonce,
    } = options;

    if !*with_pre_auth {
        return Ok(vec![
            PaData {
                padata_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![0x00, 0x96])),
                padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(Vec::new())),
            },
            PaData {
                padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_PAC_REQUEST_TYPE.to_vec())),
                padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(picky_asn1_der::to_vec(
                    &KerbPaPacRequest {
                        include_pac: ExplicitContextTag0::from(true),
                    },
                )?)),
            },
        ]);
    }

    let current_date = OffsetDateTime::now_utc();
    let mut microseconds = current_date.microsecond();
    if microseconds > MAX_MICROSECONDS {
        microseconds = MAX_MICROSECONDS;
    }

    // [Generation of Client Request](https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.1)
    // paChecksum: Contains the SHA1 checksum, performed over KDC-REQ-BODY.
    let encoded_kdc_req_body = picky_asn1_der::to_vec(&kdc_req_body)?;
    trace!(?kdc_req_body, "Encoded KdcReqBody");

    let mut sha1 = Sha1::new();
    sha1.update(&encoded_kdc_req_body);

    let kdc_req_body_sha1_hash = sha1.finalize().to_vec();

    let public_value = compute_public_key(&dh_parameters.private_key, &dh_parameters.modulus, &dh_parameters.base)?;

    let auth_pack = AuthPack {
        pk_authenticator: ExplicitContextTag0::from(PkAuthenticator {
            cusec: ExplicitContextTag0::from(IntegerAsn1::from(microseconds.to_be_bytes().to_vec())),
            ctime: ExplicitContextTag1::from(KerberosTime::from(GeneralizedTime::from(current_date))),
            nonce: ExplicitContextTag2::from(IntegerAsn1::from(authenticator_nonce.to_vec())),
            pa_checksum: Optional::from(Some(ExplicitContextTag3::from(OctetStringAsn1::from(
                kdc_req_body_sha1_hash,
            )))),
        }),
        client_public_value: Optional::from(Some(ExplicitContextTag1::from(DhReqInfo {
            key_info: DhReqKeyInfo {
                identifier: ObjectIdentifierAsn1::from(oids::diffie_hellman()),
                key_info: DhDomainParameters {
                    p: IntegerAsn1::from(dh_parameters.modulus.clone()),
                    g: IntegerAsn1::from(dh_parameters.base.clone()),
                    q: IntegerAsn1::from(dh_parameters.q.clone()),
                    j: Optional::from(None),
                    validation_params: Optional::from(None),
                },
            },
            key_value: BitStringAsn1::from(BitString::with_bytes(picky_asn1_der::to_vec(&IntegerAsn1::from(
                public_value,
            ))?)),
        }))),
        supported_cms_types: Optional::from(Some(ExplicitContextTag2::from(Asn1SequenceOf::from(Vec::new())))),
        client_dh_nonce: Optional::from(
            dh_parameters
                .client_nonce
                .as_ref()
                .map(|nonce| ExplicitContextTag3::from(OctetStringAsn1::from(nonce.to_vec()))),
        ),
    };

    let encoded_auth_pack = picky_asn1_der::to_vec(&auth_pack)?;
    trace!(?encoded_auth_pack, "Encoded auth pack");

    let mut sha1 = Sha1::new();
    sha1.update(&encoded_auth_pack);

    let digest = sha1.finalize().to_vec();

    let signed_data = SignedData {
        version: CmsVersion::V3,
        digest_algorithms: DigestAlgorithmIdentifiers(Asn1SetOf::from(vec![AlgorithmIdentifier::new_sha1()])),
        content_info: EncapsulatedContentInfo::new(oids::pkinit_auth_data(), Some(encoded_auth_pack)),
        certificates: Optional::from(CertificateSet(vec![CertificateChoices::Certificate(Asn1RawDer(
            picky_asn1_der::to_vec(p2p_cert)?,
        ))])),
        crls: None,
        signers_infos: SignersInfos(Asn1SetOf::from(vec![generate_signer_info(
            p2p_cert, digest, sign_data,
        )?])),
    };

    let e = Wrapper {
        content_info: ObjectIdentifierAsn1::from(oids::signed_data()),
        content: ExplicitContextTag0::from(signed_data),
    };

    let pa_pk_as_req = PaPkAsReq {
        signed_auth_pack: ImplicitContextTag0::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&e)?)),
        trusted_certifiers: Optional::from(None),
        kdc_pk_id: Optional::from(None),
    };

    Ok(vec![
        PaData {
            padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_PK_AS_REQ.to_vec())),
            padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&pa_pk_as_req)?)),
        },
        PaData {
            padata_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![0x12])),
            padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(Vec::new())),
        },
        PaData {
            padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_PAC_REQUEST_TYPE.to_vec())),
            padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&KerbPaPacRequest {
                include_pac: ExplicitContextTag0::from(true),
            })?)),
        },
    ])
}

pub(crate) fn generate_signer_info(
    p2p_cert: &Certificate,
    digest: Vec<u8>,
    sign_data: &mut dyn FnMut(&[u8]) -> Result<Vec<u8>>,
) -> Result<SignerInfo> {
    let signed_attributes = Asn1SetOf::from(vec![
        Attribute {
            ty: ObjectIdentifierAsn1::from(oids::content_type()),
            value: AttributeValues::ContentType(Asn1SetOf::from(vec![ObjectIdentifierAsn1::from(
                oids::pkinit_auth_data(),
            )])),
        },
        Attribute {
            ty: ObjectIdentifierAsn1::from(oids::message_digest()),
            value: AttributeValues::MessageDigest(Asn1SetOf::from(vec![OctetStringAsn1::from(digest)])),
        },
    ]);

    let encoded_signed_attributes = picky_asn1_der::to_vec(&signed_attributes)?;

    let signature = sign_data(&encoded_signed_attributes)?;

    trace!(?encoded_signed_attributes, ?signature, "Signed attributes",);

    Ok(SignerInfo {
        version: CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: p2p_cert.tbs_certificate.issuer.clone(),
            serial_number: CertificateSerialNumber(p2p_cert.tbs_certificate.serial_number.clone()),
        }),
        digest_algorithm: DigestAlgorithmIdentifier(AlgorithmIdentifier::new_sha(ShaVariant::SHA1)),
        signed_attrs: Optional::from(Attributes(Asn1SequenceOf::from(signed_attributes.0))),
        signature_algorithm: SignatureAlgorithmIdentifier(AlgorithmIdentifier::new_rsa_encryption()),
        signature: SignatureValue(OctetStringAsn1::from(signature)),
        unsigned_attrs: Optional::from(UnsignedAttributes(Vec::new())),
    })
}

#[instrument(level = "trace", ret)]
pub(crate) fn extract_server_dh_public_key(signed_data: &SignedData) -> Result<Vec<u8>> {
    let pkinit_dh_key_data = ObjectIdentifier::try_from(PKINIT_DH_KEY_DATA).unwrap();
    if signed_data.content_info.content_type.0 != pkinit_dh_key_data {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            format!(
                "Invalid content info identifier: {:?}. Expected: {:?}",
                signed_data.content_info.content_type.0, pkinit_dh_key_data
            ),
        ));
    }

    let dh_key_info_data = match &signed_data
        .content_info
        .content
        .as_ref()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "content info is not present"))?
        .0
    {
        ContentValue::OctetString(data) => &data.0,
        content_value => {
            error!(
                ?content_value,
                "The server has sent KDC DH key info in unsupported format. Only ContentValue::OctetString is supported",
            );

            return Err(Error::new(ErrorKind::InvalidToken, "unexpected content info"));
        }
    };

    let dh_key_info: KdcDhKeyInfo = picky_asn1_der::from_bytes(dh_key_info_data)?;

    let key: IntegerAsn1 = picky_asn1_der::from_bytes(dh_key_info.subject_public_key.0.payload_view())?;

    Ok(key.as_unsigned_bytes_be().to_vec())
}

#[cfg(test)]
mod tests {
    use picky_asn1::wrapper::{Asn1SetOf, ObjectIdentifierAsn1, OctetStringAsn1};
    use picky_asn1_x509::{Attribute, AttributeValues, oids};

    #[test]
    fn signing() {
        let digest = vec![
            22, 144, 59, 22, 68, 47, 213, 64, 69, 126, 237, 38, 151, 109, 213, 92, 122, 198, 202, 21,
        ];
        let signed_attributes = Asn1SetOf::from(vec![
            Attribute {
                ty: ObjectIdentifierAsn1::from(oids::content_type()),
                value: AttributeValues::ContentType(Asn1SetOf::from(vec![ObjectIdentifierAsn1::from(
                    oids::pkinit_auth_data(),
                )])),
            },
            Attribute {
                ty: ObjectIdentifierAsn1::from(oids::message_digest()),
                value: AttributeValues::MessageDigest(Asn1SetOf::from(vec![OctetStringAsn1::from(digest)])),
            },
        ]);
        let encoded_signed_attributes = picky_asn1_der::to_vec(&signed_attributes).unwrap();
        println!("{encoded_signed_attributes:?}");
    }
}
