use picky_asn1::wrapper::{
    ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3, IntegerAsn1, OctetStringAsn1,
    Optional,
};
use picky_krb::constants::key_usages::AP_REP_ENC;
use picky_krb::constants::types::{AP_REP_MSG_TYPE, TGT_REP_MSG_TYPE};
use picky_krb::data_types::{
    EncApRepPart, EncApRepPartInner, EncryptedData, EncryptionKey, KerberosTime, Microseconds, Ticket,
};
use picky_krb::messages::{ApRep, ApRepInner, TgtRep};

use crate::kerberos::{DEFAULT_ENCRYPTION_TYPE, EncryptionParams};
use crate::{KERBEROS_VERSION, Result, Secret};

pub(super) fn generate_ap_rep(
    session_key: &Secret<Vec<u8>>,
    ctime: KerberosTime,
    cusec: Microseconds,
    seq_number: Vec<u8>,
    enc_params: &EncryptionParams,
) -> Result<ApRep> {
    let encryption_type = enc_params.encryption_type.as_ref().unwrap_or(&DEFAULT_ENCRYPTION_TYPE);

    let enc_part = EncApRepPart::from(EncApRepPartInner {
        ctime: ExplicitContextTag0::from(ctime),
        cusec: ExplicitContextTag1::from(cusec),
        subkey: Optional::from(enc_params.sub_session_key.as_ref().map(|sub_key| {
            ExplicitContextTag2::from(EncryptionKey {
                key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![encryption_type.into()])),
                key_value: ExplicitContextTag1::from(OctetStringAsn1::from(sub_key.as_ref().to_vec())),
            })
        })),
        seq_number: Optional::from(Some(ExplicitContextTag3::from(IntegerAsn1::from(seq_number)))),
    });

    let cipher = encryption_type.cipher();
    let enc_data = cipher.encrypt(session_key.as_ref(), AP_REP_ENC, &picky_asn1_der::to_vec(&enc_part)?)?;

    Ok(ApRep::from(ApRepInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![AP_REP_MSG_TYPE])),
        enc_part: ExplicitContextTag2::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![encryption_type.into()])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(enc_data)),
        }),
    }))
}

pub(super) fn generate_tgt_rep(ticket: Ticket) -> TgtRep {
    TgtRep {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![TGT_REP_MSG_TYPE])),
        ticket: ExplicitContextTag2::from(ticket),
    }
}
