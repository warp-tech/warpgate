use std::fmt::Debug;
use std::str::FromStr;
use std::sync::{LazyLock, Mutex};

use picky_asn1::date::GeneralizedTime;
use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
    ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6, ExplicitContextTag7, ExplicitContextTag8,
    ImplicitContextTag0, IntegerAsn1, ObjectIdentifierAsn1, OctetStringAsn1, Optional,
};
use picky_asn1_der::Asn1RawDer;
use picky_asn1_x509::{AttributeTypeAndValueParameters, Certificate, oids};
use picky_krb::constants::gss_api::{ACCEPT_COMPLETE, ACCEPT_INCOMPLETE, AUTHENTICATOR_CHECKSUM_TYPE};
use picky_krb::constants::key_usages::{AP_REP_ENC, KEY_USAGE_FINISHED};
use picky_krb::constants::types::{AP_REP_MSG_TYPE, NT_SRV_INST};
use picky_krb::crypto::diffie_hellman::generate_private_key;
use picky_krb::crypto::{ChecksumSuite, CipherSuite};
use picky_krb::data_types::{
    Authenticator, AuthenticatorInner, AuthorizationData, AuthorizationDataInner, Checksum, EncApRepPart,
    EncApRepPartInner, EncryptedData, EncryptionKey, KerbAdRestrictionEntry, KerberosStringAsn1, KerberosTime,
    LsapTokenInfoIntegrity, Microseconds, PrincipalName, Realm,
};
use picky_krb::gss_api::{
    ApplicationTag0, GssApiNegInit, KrbMessage, MechType, MechTypeList, NegTokenInit, NegTokenTarg,
};
use picky_krb::messages::{ApRep, ApRepInner};
use picky_krb::negoex::RANDOM_ARRAY_SIZE;
use picky_krb::pkinit::{KrbFinished, Pku2uNegoBody, Pku2uNegoRep, Pku2uNegoReq, Pku2uNegoReqMetadata};
use rand::rngs::{StdRng, SysRng};
use rand_core::{Rng as _, SeedableRng as _};
use time::OffsetDateTime;

use super::Pku2uConfig;
use crate::crypto::compute_md5_channel_bindings_hash;
use crate::kerberos::client::generators::{
    AuthenticatorChecksumExtension, ChecksumOptions, EncKey, GenerateAuthenticatorOptions, MAX_MICROSECONDS,
};
use crate::pk_init::DhParameters;
use crate::{Error, ErrorKind, KERBEROS_VERSION, Result, Secret};

/// [The PKU2U Realm Name](https://datatracker.ietf.org/doc/html/draft-zhu-pku2u-09#section-3)
/// The PKU2U realm name is defined as a reserved Kerberos realm name, and it has the value of "WELLKNOWN:PKU2U".
pub(super) const WELLKNOWN_REALM: &str = "WELLKNOWN:PKU2U";

/// [The GSS-API Binding for PKU2U](https://datatracker.ietf.org/doc/html/draft-zhu-pku2u-04#section-6)
/// The type for the checksum extension.
/// GSS_EXTS_FINISHED 2
pub(super) const GSS_EXTS_FINISHED: u32 = 2;

/// [2.2.5 LSAP_TOKEN_INFO_INTEGRITY](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-KILE/%5bMS-KILE%5d.pdf)
/// indicating the token information type
/// 0x00000001 = User Account Control (UAC) restricted token
const LSAP_TOKEN_INFO_INTEGRITY_FLAG: u32 = 1;
/// [2.2.5 LSAP_TOKEN_INFO_INTEGRITY](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-KILE/%5bMS-KILE%5d.pdf)
/// indicating the integrity level of the calling process
/// 0x00002000 = Medium.
const LSAP_TOKEN_INFO_INTEGRITY_TOKEN_IL: u32 = 0x00002000;
static PER_BOOT_MACHINE_ID: LazyLock<Mutex<Option<[u8; 32]>>> = LazyLock::new(|| Mutex::new(None));

fn per_boot_machine_id() -> Result<[u8; 32]> {
    let mut stored = PER_BOOT_MACHINE_ID
        .lock()
        .map_err(|_| Error::new(ErrorKind::InternalError, "PKU2U machine identifier lock is poisoned"))?;
    if let Some(machine_id) = *stored {
        return Ok(machine_id);
    }

    let mut machine_id = [0; 32];
    StdRng::try_from_rng(&mut SysRng)?.fill_bytes(&mut machine_id);
    *stored = Some(machine_id);
    Ok(machine_id)
}

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

/// Builds the acceptor's `AcceptorMetaData` payload (`Pku2uNegoRep`).
///
/// Its `metadata` field lists the client-certificate issuers trusted by this acceptor. The initiator
/// uses this list to select one of its candidate credentials.
#[instrument(level = "debug", ret)]
pub(super) fn generate_pku2u_nego_rep(config: &Pku2uConfig) -> Result<Pku2uNegoRep> {
    let mut metadata = Vec::with_capacity(config.trusted_client_certificates.len());
    for certificate in &config.trusted_client_certificates {
        metadata.push(Pku2uNegoReqMetadata {
            inner: ImplicitContextTag0::from(OctetStringAsn1::from(picky_asn1_der::to_vec(
                &certificate.tbs_certificate.issuer,
            )?)),
        });
    }

    Ok(Pku2uNegoRep {
        metadata: ExplicitContextTag0::from(Asn1SequenceOf::from(metadata)),
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

/// Wraps `token` into a `NegTokenTarg`. `complete` selects the SPNEGO `negResult`: pass `false`
/// (`accept-incomplete`) for every leg that expects a further token from the peer, and `true`
/// (`accept-complete`) only for the final leg of a successful negotiation. This crate's own PKU2U
/// initiator does not currently inspect `negResult`, but a spec-compliant peer does.
#[instrument(level = "trace", ret)]
pub(super) fn generate_neg_token_targ(token: Vec<u8>, complete: bool) -> Result<ExplicitContextTag1<NegTokenTarg>> {
    generate_neg_token_targ_inner(token, complete, false)
}

pub(super) fn generate_initial_neg_token_targ(token: Vec<u8>) -> Result<ExplicitContextTag1<NegTokenTarg>> {
    generate_neg_token_targ_inner(token, false, true)
}

fn generate_neg_token_targ_inner(
    token: Vec<u8>,
    complete: bool,
    include_supported_mech: bool,
) -> Result<ExplicitContextTag1<NegTokenTarg>> {
    let neg_result = if complete { ACCEPT_COMPLETE } else { ACCEPT_INCOMPLETE };
    Ok(ExplicitContextTag1::from(NegTokenTarg {
        neg_result: Optional::from(Some(ExplicitContextTag0::from(Asn1RawDer(neg_result.to_vec())))),
        supported_mech: Optional::from(
            include_supported_mech.then(|| ExplicitContextTag1::from(MechType::from(oids::negoex()))),
        ),
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

/// Wraps a Kerberos message into a GSS-API [InitialContextToken](https://datatracker.ietf.org/doc/html/rfc2743#section-3.1):
/// `[APPLICATION 0] IMPLICIT SEQUENCE { thisMech MechType, innerContextToken ANY DEFINED BY thisMech }`.
///
/// **Important**: we must use [ApplicationTag0] (which overwrites the inner value's leading tag byte to
/// implement RFC 2743's `IMPLICIT` tagging) and not the generic `ApplicationTag` from `picky_asn1_der`
/// (which wraps the inner value in an *additional* explicit tag). Using the generic wrapper here
/// previously produced a doubly-nested, non-conformant token that neither this crate's own
/// [extract_krb_rep](super::extractors::extract_krb_rep)/[extract_krb_result](super::extractors::extract_krb_result)
/// nor a real PKU2U peer can parse.
pub(super) fn generate_neg<T: Debug + PartialEq + Clone>(
    krb_msg: T,
    krb5_token_id: [u8; 2],
) -> ApplicationTag0<KrbMessage<T>> {
    ApplicationTag0(KrbMessage {
        krb5_oid: ObjectIdentifierAsn1::from(oids::gss_pku2u()),
        krb5_token_id,
        krb_msg,
    })
}

pub fn generate_authenticator_extension(
    key: &[u8],
    payload: &[u8],
    checksum_suite: &ChecksumSuite,
) -> Result<AuthenticatorChecksumExtension> {
    let hasher = checksum_suite.hasher();

    let krb_finished = KrbFinished {
        gss_mic: ExplicitContextTag1::from(Checksum {
            cksumtype: ExplicitContextTag0::from(IntegerAsn1::from(vec![checksum_suite.into()])),
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
        machine_id: per_boot_machine_id()?,
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
            let Some(channel_binding_buf) = checksum_value.get_mut(4..20) else {
                return Err(Error::new(
                    ErrorKind::InvalidParameter,
                    format!(
                        "Invalid authenticator checksum length: expected >= 20 but got {}. ",
                        checksum_value.len()
                    ),
                ));
            };
            // [Authenticator Checksum](https://datatracker.ietf.org/doc/html/rfc4121#section-4.1.1)
            // 4..19 - Channel binding information (19 inclusive).
            channel_binding_buf.copy_from_slice(&compute_md5_channel_bindings_hash(channel_bindings)?);
        }

        for extension in extensions {
            checksum_value.extend_from_slice(&extension.extension_type.to_be_bytes());
            checksum_value.extend_from_slice(&u32::try_from(extension.extension_value.len())?.to_be_bytes());
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

/// Generates an acceptor's `AP-REP`, echoing the initiator's `Authenticator` `ctime`/`cusec` (per
/// [RFC 4120 §3.2.4](https://www.rfc-editor.org/rfc/rfc4120#section-3.2.4)) and embedding `seq_number`
/// as the acceptor's starting GSS sequence number and `subkey` as the negotiated acceptor sub-session key.
#[instrument(level = "trace", skip(session_key, subkey), ret)]
pub(super) fn generate_ap_rep(
    session_key: &Secret<Vec<u8>>,
    ctime: KerberosTime,
    cusec: Microseconds,
    seq_number: u32,
    subkey: &Secret<Vec<u8>>,
    encryption_type: &CipherSuite,
) -> Result<ApRep> {
    let enc_ap_rep_part = EncApRepPart::from(EncApRepPartInner {
        ctime: ExplicitContextTag0::from(ctime),
        cusec: ExplicitContextTag1::from(cusec),
        subkey: Optional::from(Some(ExplicitContextTag2::from(EncryptionKey {
            key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![encryption_type.into()])),
            key_value: ExplicitContextTag1::from(OctetStringAsn1::from(subkey.as_ref().clone())),
        }))),
        // Older clients' `extract_seq_number_from_ap_rep` required exactly 4 bytes (`u32::from_be_bytes`),
        // so this stays the full-width, non-minimized encoding — not `from_bytes_be_unsigned`,
        // which would strip it down to as little as one byte for small sequence numbers.
        seq_number: Optional::from(Some(ExplicitContextTag3::from(IntegerAsn1::from(
            seq_number.to_be_bytes().to_vec(),
        )))),
    });

    let cipher = encryption_type.cipher();
    let encoded_enc_ap_rep_part = picky_asn1_der::to_vec(&enc_ap_rep_part)?;
    let encrypted_enc_ap_rep_part = cipher.encrypt(session_key.as_ref(), AP_REP_ENC, &encoded_enc_ap_rep_part)?;

    Ok(ApRep::from(ApRepInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![AP_REP_MSG_TYPE])),
        enc_part: ExplicitContextTag2::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![encryption_type.into()])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted_enc_ap_rep_part)),
        }),
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

#[cfg(test)]
mod tests {
    use picky_krb::constants::key_usages::KEY_USAGE_FINISHED;
    use picky_krb::crypto::ChecksumSuite;
    use picky_krb::pkinit::KrbFinished;

    use super::{generate_authenticator_extension, generate_initial_neg_token_targ, per_boot_machine_id};

    #[test]
    fn authenticator_extension_uses_negotiated_checksum_suite() {
        for (suite, key) in [
            (ChecksumSuite::HmacSha196Aes128, vec![0x11; 16]),
            (ChecksumSuite::HmacSha196Aes256, vec![0x22; 32]),
        ] {
            let payload = b"PKU2U GSS transcript";
            let extension = generate_authenticator_extension(&key, payload, &suite).unwrap();
            let finished: KrbFinished = picky_asn1_der::from_bytes(&extension.extension_value).unwrap();

            assert_eq!(finished.gss_mic.0.cksumtype.0.0, vec![u8::from(&suite)]);
            assert_eq!(
                finished.gss_mic.0.checksum.0.0,
                suite.hasher().checksum(&key, KEY_USAGE_FINISHED, payload).unwrap()
            );
        }
    }

    #[test]
    fn initial_acceptor_token_selects_negoex() {
        let token = generate_initial_neg_token_targ(Vec::new()).unwrap();

        assert_eq!(
            token.0.supported_mech.0.unwrap().0,
            picky_asn1::wrapper::ObjectIdentifierAsn1::from(picky_asn1_x509::oids::negoex())
        );
    }

    #[test]
    fn machine_identifier_is_stable_for_the_process_lifetime() {
        assert_eq!(per_boot_machine_id().unwrap(), per_boot_machine_id().unwrap());
    }
}
