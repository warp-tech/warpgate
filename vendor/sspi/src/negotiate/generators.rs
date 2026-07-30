use oid::ObjectIdentifier;
use picky::oids;
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
    ObjectIdentifierAsn1, OctetStringAsn1, Optional,
};
use picky_asn1_der::Asn1RawDer;
use picky_krb::constants::gss_api::ACCEPT_INCOMPLETE;
use picky_krb::gss_api::{
    ApplicationTag0, GssApiNegInit, MechType, MechTypeList, NegTokenInit, NegTokenTarg, NegTokenTarg1,
};

use crate::{Error, ErrorKind, Result};

/// Generates supported mechanism type list.
pub(super) fn generate_mech_type_list(kerberos: bool, ntlm: bool) -> Result<MechTypeList> {
    if !ntlm && !kerberos {
        return Err(Error::new(
            ErrorKind::InvalidParameter,
            "NTLM and Kerberos are not enabled. no security packages available",
        ));
    }

    let mut mech_types = Vec::new();

    if kerberos {
        mech_types.push(MechType::from(oids::ms_krb5()));
        mech_types.push(MechType::from(oids::krb5()));
        // NEGOEX is not supported.
        // mech_types.push(MechType::from(oids::negoex()));
    }

    if ntlm {
        mech_types.push(MechType::from(oids::ntlm_ssp()));
    }

    Ok(MechTypeList::from(Asn1SequenceOf::from(mech_types)))
}

/// Generates the initial SPNEGO token.
///
/// The `sname` parameter is optional. If it is present, then the Kerberos U2U is in use, and `TgtReq` will be generated
/// for the input `sname` and placed in the `mech_token` field.
pub(super) fn generate_neg_token_init(
    mech_list: MechTypeList,
    mech_token: Option<Vec<u8>>,
) -> Result<ApplicationTag0<GssApiNegInit>> {
    let mech_token = mech_token.map(|token| ExplicitContextTag2::from(OctetStringAsn1::from(token)));

    Ok(ApplicationTag0(GssApiNegInit {
        oid: ObjectIdentifierAsn1::from(oids::spnego()),
        neg_token_init: ExplicitContextTag0::from(NegTokenInit {
            mech_types: Optional::from(Some(ExplicitContextTag0::from(mech_list))),
            req_flags: Optional::from(None),
            mech_token: Optional::from(mech_token),
            mech_list_mic: Optional::from(None),
        }),
    }))
}

pub(super) fn generate_neg_token_targ_1(response_token: Option<Vec<u8>>) -> NegTokenTarg1 {
    NegTokenTarg1::from(NegTokenTarg {
        neg_result: Optional::from(Some(ExplicitContextTag0::from(Asn1RawDer(ACCEPT_INCOMPLETE.to_vec())))),
        supported_mech: Optional::from(None),
        response_token: Optional::from(
            response_token.map(|token| ExplicitContextTag2::from(OctetStringAsn1::from(token))),
        ),
        mech_list_mic: Optional::from(None),
    })
}

pub(super) fn generate_final_neg_token_targ(
    neg_result: Vec<u8>,
    response_token: Option<Vec<u8>>,
    mech_list_mic: Option<Vec<u8>>,
) -> NegTokenTarg1 {
    NegTokenTarg1::from(NegTokenTarg {
        neg_result: Optional::from(Some(ExplicitContextTag0::from(Asn1RawDer(neg_result)))),
        supported_mech: Optional::from(None),
        response_token: Optional::from(
            response_token.map(|token| ExplicitContextTag2::from(OctetStringAsn1::from(token))),
        ),
        mech_list_mic: Optional::from(mech_list_mic.map(|v| ExplicitContextTag3::from(OctetStringAsn1::from(v)))),
    })
}

pub(super) fn generate_neg_token_targ(
    neg_result: Vec<u8>,
    mech_type: ObjectIdentifier,
    response_token: Option<Vec<u8>>,
) -> Result<NegTokenTarg1> {
    let response_token =
        response_token.map(|response_token| ExplicitContextTag2::from(OctetStringAsn1::from(response_token)));

    Ok(NegTokenTarg1::from(NegTokenTarg {
        neg_result: Optional::from(Some(ExplicitContextTag0::from(Asn1RawDer(neg_result)))),
        supported_mech: Optional::from(Some(ExplicitContextTag1::from(MechType::from(mech_type)))),
        response_token: Optional::from(response_token),
        mech_list_mic: Optional::from(None),
    }))
}
