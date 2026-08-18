use std::fmt::Debug;
use std::str::FromStr;

use picky_asn1::date::GeneralizedTime;
use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
    ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6, ExplicitContextTag7, ExplicitContextTag8,
    ImplicitContextTag0, IntegerAsn1, ObjectIdentifierAsn1, OctetStringAsn1, Optional,
};
use picky_asn1_der::Asn1RawDer;
use picky_asn1_der::application_tag::ApplicationTag;
use picky_asn1_x509::{AttributeTypeAndValueParameters, Certificate, oids};
use picky_krb::constants::gss_api::{ACCEPT_INCOMPLETE, AUTHENTICATOR_CHECKSUM_TYPE};
use picky_krb::constants::key_usages::KEY_USAGE_FINISHED;
use picky_krb::constants::types::NT_SRV_INST;
use picky_krb::crypto::ChecksumSuite;
use picky_krb::crypto::diffie_hellman::generate_private_key;
use picky_krb::data_types::{
    Authenticator, AuthenticatorInner, AuthorizationData, AuthorizationDataInner, Checksum, EncryptionKey,
    KerbAdRestrictionEntry, KerberosStringAsn1, KerberosTime, LsapTokenInfoIntegrity, PrincipalName, Realm,
};
use picky_krb::gss_api::{
    ApplicationTag0, GssApiNegInit, KrbMessage, MechType, MechTypeList, NegTokenInit, NegTokenTarg,
};
use picky_krb::negoex::RANDOM_ARRAY_SIZE;
use picky_krb::pkinit::{KrbFinished, Pku2uNegoBody, Pku2uNegoReq, Pku2uNegoReqMetadata};
use rand::rngs::StdRng;
use rand_core::Rng as _;
use time::OffsetDateTime;

use super::Pku2uConfig;
use crate::crypto::compute_md5_channel_bindings_hash;
use crate::kerberos::client::generators::{
    AuthenticatorChecksumExtension, ChecksumOptions, EncKey, GenerateAuthenticatorOptions, MAX_MICROSECONDS,
};
use crate::pk_init::DhParameters;
use crate::{Error, ErrorKind, KERBEROS_VERSION, Result};

/// [The PKU2U Realm Name](https://datatracker.ietf.org/doc/html/draft-zhu-pku2u-09#section-3)
/// The PKU2U realm name is defined as a reserved Kerberos realm name, and it has the value of "WELLKNOWN:PKU2U".
pub(super) const WELLKNOWN_REALM: &str = "WELLKNOWN:PKU2U";

/// [The GSS-API Binding for PKU2U](https://datatracker.ietf.org/doc/html/draft-zhu-pku2u-04#section-6)
/// The type for the checksum extension.
/// GSS_EXTS_FINISHED 2
const GSS_EXTS_FINISHED: u32 = 2;

/// [2.2.5 LSAP_TOKEN_INFO_INTEGRITY](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-KILE/%5bMS-KILE%5d.pdf)
/// indicating the token information type
/// 0x00000001 = User Account Control (UAC) restricted token
const LSAP_TOKEN_INFO_INTEGRITY_FLAG: u32 = 1;
/// [2.2.5 LSAP_TOKEN_INFO_INTEGRITY](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-KILE/%5bMS-KILE%5d.pdf)
/// indicating the integrity level of the calling process
/// 0x00002000 = Medium.
const LSAP_TOKEN_INFO_INTEGRITY_TOKEN_IL: u32 = 0x00002000;
/// [3.1.1.4 Machine ID](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-KILE/%5bMS-KILE%5d.pdf)
/// KILE implements a 32-byte binary random string machine ID.
const MACHINE_ID: [u8; 32] = [
    92, 95, 64, 72, 191, 160, 228, 23, 98, 35, 78, 151, 207, 227, 96, 126, 97, 180, 15, 98, 127, 211, 90, 177, 119,
    132, 45, 113, 206, 90, 169, 124,
];

// returns supported authentication types
pub(super) fn get_mech_list() -> MechTypeList {
    MechTypeList::from(vec![MechType::from(oids::negoex()), MechType::from(oids::ntlm_ssp())])
}

#[instrument(level = "debug", ret)]
pub(super) fn generate_pku2u_nego_req(service_names: &[&str], config: &Pku2uConfig) -> Result<Pku2uNegoReq> {
    let mut snames = Vec::with_capacity(service_names.len());
    for sname in service_names {
        snames.push(KerberosStringAsn1::from(IA5String::from_str(sname)?));
    }

    Ok(Pku2uNegoReq {
        metadata: ExplicitContextTag0::from(Asn1SequenceOf::from(vec![Pku2uNegoReqMetadata {
            inner: ImplicitContextTag0::from(OctetStringAsn1::from(picky_asn1_der::to_vec(
                &config.p2p_certificate.tbs_certificate.issuer,
            )?)),
        }])),
        body: ExplicitContextTag1::from(Pku2uNegoBody {
            realm: ExplicitContextTag0::from(Realm::from(IA5String::from_str(WELLKNOWN_REALM)?)),
            sname: ExplicitContextTag1::from(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(snames)),
            }),
        }),
    })
}

#[instrument(level = "trace", ret)]
pub(super) fn generate_neg_token_init(mech_token: Vec<u8>) -> Result<ApplicationTag0<GssApiNegInit>> {
    Ok(ApplicationTag0(GssApiNegInit {
        oid: ObjectIdentifierAsn1::from(oids::spnego()),
        neg_token_init: ExplicitContextTag0::from(NegTokenInit {
            mech_types: Optional::from(Some(ExplicitContextTag0::from(get_mech_list()))),
            req_flags: Optional::from(None),
            mech_token: Optional::from(Some(ExplicitContextTag2::from(OctetStringAsn1::from(mech_token)))),
            mech_list_mic: Optional::from(None),
        }),
    }))
}

#[instrument(level = "trace", ret)]
pub(super) fn generate_neg_token_targ(token: Vec<u8>) -> Result<ExplicitContextTag1<NegTokenTarg>> {
    Ok(ExplicitContextTag1::from(NegTokenTarg {
        neg_result: Optional::from(Some(ExplicitContextTag0::from(Asn1RawDer(ACCEPT_INCOMPLETE.to_vec())))),
        supported_mech: Optional::from(None),
        response_token: Optional::from(Some(ExplicitContextTag2::from(OctetStringAsn1::from(token)))),
        mech_list_mic: Optional::from(None),
    }))
}

/// returns (p, g, q)
pub(super) fn get_default_parameters() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    (
        vec![
            255, 255, 255, 255, 255, 255, 255, 255, 201, 15, 218, 162, 33, 104, 194, 52, 196, 198, 98, 139, 128, 220,
            28, 209, 41, 2, 78, 8, 138, 103, 204, 116, 2, 11, 190, 166, 59, 19, 155, 34, 81, 74, 8, 121, 142, 52, 4,
            221, 239, 149, 25, 179, 205, 58, 67, 27, 48, 43, 10, 109, 242, 95, 20, 55, 79, 225, 53, 109, 109, 81, 194,
            69, 228, 133, 181, 118, 98, 94, 126, 198, 244, 76, 66, 233, 166, 55, 237, 107, 11, 255, 92, 182, 244, 6,
            183, 237, 238, 56, 107, 251, 90, 137, 159, 165, 174, 159, 36, 17, 124, 75, 31, 230, 73, 40, 102, 81, 236,
            228, 91, 61, 194, 0, 124, 184, 161, 99, 191, 5, 152, 218, 72, 54, 28, 85, 211, 154, 105, 22, 63, 168, 253,
            36, 207, 95, 131, 101, 93, 35, 220, 163, 173, 150, 28, 98, 243, 86, 32, 133, 82, 187, 158, 213, 41, 7, 112,
            150, 150, 109, 103, 12, 53, 78, 74, 188, 152, 4, 241, 116, 108, 8, 202, 24, 33, 124, 50, 144, 94, 70, 46,
            54, 206, 59, 227, 158, 119, 44, 24, 14, 134, 3, 155, 39, 131, 162, 236, 7, 162, 143, 181, 197, 93, 240,
            111, 76, 82, 201, 222, 43, 203, 246, 149, 88, 23, 24, 57, 149, 73, 124, 234, 149, 106, 229, 21, 210, 38,
            24, 152, 250, 5, 16, 21, 114, 142, 90, 138, 172, 170, 104, 255, 255, 255, 255, 255, 255, 255, 255,
        ],
        vec![2],
        vec![
            127, 255, 255, 255, 255, 255, 255, 255, 228, 135, 237, 81, 16, 180, 97, 26, 98, 99, 49, 69, 192, 110, 14,
            104, 148, 129, 39, 4, 69, 51, 230, 58, 1, 5, 223, 83, 29, 137, 205, 145, 40, 165, 4, 60, 199, 26, 2, 110,
            247, 202, 140, 217, 230, 157, 33, 141, 152, 21, 133, 54, 249, 47, 138, 27, 167, 240, 154, 182, 182, 168,
            225, 34, 242, 66, 218, 187, 49, 47, 63, 99, 122, 38, 33, 116, 211, 27, 246, 181, 133, 255, 174, 91, 122, 3,
            91, 246, 247, 28, 53, 253, 173, 68, 207, 210, 215, 79, 146, 8, 190, 37, 143, 243, 36, 148, 51, 40, 246,
            114, 45, 158, 225, 0, 62, 92, 80, 177, 223, 130, 204, 109, 36, 27, 14, 42, 233, 205, 52, 139, 31, 212, 126,
            146, 103, 175, 193, 178, 174, 145, 238, 81, 214, 203, 14, 49, 121, 171, 16, 66, 169, 93, 207, 106, 148,
            131, 184, 75, 75, 54, 179, 134, 26, 167, 37, 94, 76, 2, 120, 186, 54, 4, 101, 12, 16, 190, 25, 72, 47, 35,
            23, 27, 103, 29, 241, 207, 59, 150, 12, 7, 67, 1, 205, 147, 193, 209, 118, 3, 209, 71, 218, 226, 174, 248,
            55, 166, 41, 100, 239, 21, 229, 251, 74, 172, 11, 140, 28, 202, 164, 190, 117, 74, 181, 114, 138, 233, 19,
            12, 76, 125, 2, 136, 10, 185, 71, 45, 69, 86, 85, 52, 127, 255, 255, 255, 255, 255, 255, 255,
        ],
    )
}

pub(super) fn generate_server_dh_parameters(rng: &mut StdRng) -> Result<DhParameters> {
    let mut server_nonce = [0; RANDOM_ARRAY_SIZE];
    rng.fill_bytes(&mut server_nonce);
    Ok(DhParameters {
        base: Vec::new(),
        modulus: Vec::new(),
        q: Vec::new(),
        private_key: Vec::new(),
        other_public_key: None,
        server_nonce: Some(server_nonce),
        client_nonce: None,
    })
}

pub fn generate_client_dh_parameters(rng: &mut StdRng) -> DhParameters {
    let (p, g, q) = get_default_parameters();

    let private_key = generate_private_key(&q, rng).expect("infallible");

    let mut client_nonce = [0; RANDOM_ARRAY_SIZE];
    rng.fill_bytes(&mut client_nonce);

    DhParameters {
        base: g,
        modulus: p,
        q,
        private_key,
        other_public_key: None,
        client_nonce: Some(client_nonce),
        server_nonce: None,
    }
}

pub(super) fn generate_neg<T: Debug + PartialEq + Clone>(
    krb_msg: T,
    krb5_token_id: [u8; 2],
) -> ApplicationTag<KrbMessage<T>, 0> {
    ApplicationTag::from(KrbMessage {
        krb5_oid: ObjectIdentifierAsn1::from(oids::gss_pku2u()),
        krb5_token_id,
        krb_msg,
    })
}

pub fn generate_authenticator_extension(key: &[u8], payload: &[u8]) -> Result<AuthenticatorChecksumExtension> {
    let hasher = ChecksumSuite::HmacSha196Aes256.hasher();

    let krb_finished = KrbFinished {
        gss_mic: ExplicitContextTag1::from(Checksum {
            cksumtype: ExplicitContextTag0::from(IntegerAsn1::from(vec![ChecksumSuite::HmacSha196Aes256.into()])),
            checksum: ExplicitContextTag1::from(OctetStringAsn1::from(hasher.checksum(
                key,
                KEY_USAGE_FINISHED,
                payload,
            )?)),
        }),
    };

    Ok(AuthenticatorChecksumExtension {
        extension_type: GSS_EXTS_FINISHED,
        extension_value: picky_asn1_der::to_vec(&krb_finished)?,
    })
}

#[instrument(level = "trace", ret)]
pub fn generate_authenticator(options: GenerateAuthenticatorOptions<'_>) -> Result<Authenticator> {
    let GenerateAuthenticatorOptions {
        kdc_rep,
        seq_num,
        sub_key,
        checksum,
        channel_bindings,
        extensions,
    } = options;

    let current_date = OffsetDateTime::now_utc();
    let mut microseconds = current_date.microsecond();
    if microseconds > MAX_MICROSECONDS {
        microseconds = MAX_MICROSECONDS;
    }

    let lsap_token = LsapTokenInfoIntegrity {
        flags: LSAP_TOKEN_INFO_INTEGRITY_FLAG,
        token_il: LSAP_TOKEN_INFO_INTEGRITY_TOKEN_IL,
        machine_id: MACHINE_ID,
    };

    let mut encoded_lsap_token = Vec::with_capacity(40);
    lsap_token.encode(&mut encoded_lsap_token)?;

    let restriction_entry = KerbAdRestrictionEntry {
        restriction_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![0])),
        restriction: ExplicitContextTag1::from(OctetStringAsn1::from(encoded_lsap_token)),
    };

    let authorization_data = Optional::from(Some(ExplicitContextTag8::from(AuthorizationData::from(vec![
        AuthorizationDataInner {
            ad_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![0x01])),
            ad_data: ExplicitContextTag1::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&Asn1SequenceOf::from(
                vec![AuthorizationDataInner {
                    ad_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![0x00, 0x8d])),
                    ad_data: ExplicitContextTag1::from(OctetStringAsn1::from(picky_asn1_der::to_vec(
                        &Asn1SequenceOf::from(vec![restriction_entry]),
                    )?)),
                }],
            ))?)),
        },
    ]))));

    let cksum = if let Some(ChecksumOptions {
        checksum_type,
        checksum_value,
    }) = checksum
    {
        let mut checksum_value = checksum_value.into_inner();
        if checksum_type == AUTHENTICATOR_CHECKSUM_TYPE
            && let Some(channel_bindings) = channel_bindings
        {
            if checksum_value.len() < 20 {
                return Err(Error::new(
                    ErrorKind::InvalidParameter,
                    format!(
                        "Invalid authenticator checksum length: expected >= 20 but got {}. ",
                        checksum_value.len()
                    ),
                ));
            }
            // [Authenticator Checksum](https://datatracker.ietf.org/doc/html/rfc4121#section-4.1.1)
            // 4..19 - Channel binding information (19 inclusive).
            checksum_value[4..20].copy_from_slice(&compute_md5_channel_bindings_hash(channel_bindings));
        }

        for extension in extensions {
            checksum_value.extend_from_slice(&extension.extension_type.to_be_bytes());
            checksum_value.extend_from_slice(&(extension.extension_value.len() as u32).to_be_bytes());
            checksum_value.extend_from_slice(&extension.extension_value);
        }

        Optional::from(Some(ExplicitContextTag3::from(Checksum {
            cksumtype: ExplicitContextTag0::from(IntegerAsn1::from(checksum_type)),
            checksum: ExplicitContextTag1::from(OctetStringAsn1::from(checksum_value)),
        })))
    } else {
        Optional::from(None)
    };

    Ok(Authenticator::from(AuthenticatorInner {
        authenticator_vno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        crealm: ExplicitContextTag1::from(kdc_rep.crealm.0.clone()),
        cname: ExplicitContextTag2::from(kdc_rep.cname.0.clone()),
        cksum,
        cusec: ExplicitContextTag4::from(IntegerAsn1::from(microseconds.to_be_bytes().to_vec())),
        ctime: ExplicitContextTag5::from(KerberosTime::from(GeneralizedTime::from(current_date))),
        subkey: Optional::from(sub_key.map(|EncKey { key_type, key_value }| {
            ExplicitContextTag6::from(EncryptionKey {
                key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![key_type.into()])),
                key_value: ExplicitContextTag1::from(OctetStringAsn1::from(key_value)),
            })
        })),
        seq_number: Optional::from(seq_num.map(|seq_num| {
            ExplicitContextTag7::from(IntegerAsn1::from_bytes_be_unsigned(seq_num.to_be_bytes().to_vec()))
        })),
        authorization_data,
    }))
}

pub(super) fn generate_as_req_username_from_certificate(certificate: &Certificate) -> Result<String> {
    let mut username = "AzureAD\\".to_owned();

    let mut issuer = false;
    for attr_type_and_value in certificate.tbs_certificate.issuer.0.0.iter() {
        for v in attr_type_and_value.0.iter() {
            if v.ty.0 == oids::at_common_name()
                && let AttributeTypeAndValueParameters::CommonName(name) = &v.value
            {
                issuer = true;
                username.push_str(&name.to_utf8_lossy());
            }
        }
    }

    if !issuer {
        return Err(Error::new(
            ErrorKind::Pku2uCertFailure,
            "Bad client certificate: cannot find common name of the issuer",
        ));
    }

    username.push('\\');

    let mut subject = false;
    for attr_type_and_value in certificate.tbs_certificate.subject.0.0.iter() {
        for v in attr_type_and_value.0.iter() {
            if v.ty.0 == oids::at_common_name()
                && let AttributeTypeAndValueParameters::CommonName(name) = &v.value
            {
                subject = true;
                username.push_str(&name.to_utf8_lossy());
            }
        }
    }

    if !subject {
        return Err(Error::new(
            ErrorKind::Pku2uCertFailure,
            "Bad client certificate: cannot find appropriate common name of the subject",
        ));
    }

    Ok(username)
}
