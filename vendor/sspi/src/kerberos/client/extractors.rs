use std::io::Read;

use picky_asn1::wrapper::{Asn1SequenceOf, ObjectIdentifierAsn1};
use picky_asn1_der::Asn1RawDer;
use picky_asn1_der::application_tag::ApplicationTag;
use picky_krb::constants::key_usages::{AP_REP_ENC, AS_REP_ENC, KRB_PRIV_ENC_PART, TGS_REP_ENC_SESSION_KEY};
use picky_krb::constants::types::PA_ETYPE_INFO2_TYPE;
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{EncApRepPart, EncKrbPrivPart, EtypeInfo2, PaData, Ticket};
use picky_krb::messages::{ApRep, AsRep, EncAsRepPart, EncTgsRepPart, KrbError, KrbPriv, TgsRep, TgtRep};

use crate::kerberos::{DEFAULT_ENCRYPTION_TYPE, EncryptionParams};
use crate::{Error, ErrorKind, Result, Secret};

/// Extracts password salt from the KRB error.
///
/// We need a salt to derive the correct encryption key from user's password. Usually, the salt is domain+username, but the custom salt
/// value can be set in KDC database. So, we always extract the correct salt from the [KrbError] message. More info in [RFC 4120 PA-ETYPE-INFO2](https://www.rfc-editor.org/rfc/rfc4120#section-5.2.7.5):
///
/// > The ETYPE-INFO2 pre-authentication type is sent by the KDC in a KRB-ERROR indicating a requirement for additional pre-authentication.
/// > It is usually used to notify a client of which key to use for the encryption of an encrypted timestamp for the purposes of sending a
/// > PA-ENC-TIMESTAMP pre-authentication value.
pub fn extract_salt_from_krb_error(error: &KrbError) -> Result<Option<String>> {
    trace!(?error, "KRB_ERROR");

    if let Some(e_data) = error.0.e_data.0.as_ref() {
        let pa_datas: Asn1SequenceOf<PaData> = picky_asn1_der::from_bytes(&e_data.0.0)?;

        if let Some(pa_etype_info_2) = pa_datas
            .0
            .into_iter()
            .find(|pa_data| pa_data.padata_type.0.0 == PA_ETYPE_INFO2_TYPE)
        {
            let etype_info_2: EtypeInfo2 = picky_asn1_der::from_bytes(&pa_etype_info_2.padata_data.0.0)?;
            if let Some(params) = etype_info_2.0.first() {
                return Ok(params.salt.0.as_ref().map(|salt| salt.0.to_string()));
            }
        }
    }

    Ok(None)
}

/// Decrypts the AS-REP enc-part with an already-derived long-term `key` and
/// returns the embedded session key.
fn decode_as_rep_session_key(as_rep: &AsRep, key: &[u8], enc_params: &EncryptionParams) -> Result<Secret<Vec<u8>>> {
    let cipher = enc_params
        .encryption_type
        .as_ref()
        .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
        .cipher();

    let enc_data = cipher.decrypt(key, AS_REP_ENC, &as_rep.0.enc_part.0.cipher.0.0)?;

    // This function extracts the session key from an AS-REP, so the enc-part is
    // expected to be tagged EncASRepPart (APPLICATION 25). We do not accept
    // EncTGSRepPart here: that tag belongs to the TGS exchange.
    let as_rep_enc_part = picky_asn1_der::from_bytes::<EncAsRepPart>(&enc_data)?;

    Ok(as_rep_enc_part.0.key.0.key_value.0.to_vec().into())
}

/// Extracts a session from the [AsRep].
#[instrument(level = "trace", ret, skip(password))]
pub fn extract_session_key_from_as_rep(
    as_rep: &AsRep,
    salt: &str,
    password: &str,
    enc_params: &EncryptionParams,
) -> Result<Secret<Vec<u8>>> {
    let cipher = enc_params
        .encryption_type
        .as_ref()
        .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
        .cipher();

    let key = cipher.generate_key_from_password(password.as_bytes(), salt.as_bytes())?;

    decode_as_rep_session_key(as_rep, &key, enc_params)
}

/// Extracts a session key from the [AsRep] using a pre-derived long-term key
/// (keytab-based client authentication).
#[instrument(level = "trace", ret, skip(key))]
pub fn extract_session_key_from_as_rep_with_key(
    as_rep: &AsRep,
    key: &[u8],
    enc_params: &EncryptionParams,
) -> Result<Secret<Vec<u8>>> {
    decode_as_rep_session_key(as_rep, key, enc_params)
}

/// Extracts a session from the [TgsRep].
#[instrument(level = "trace", ret)]
pub fn extract_session_key_from_tgs_rep(
    tgs_rep: &TgsRep,
    session_key: &Secret<Vec<u8>>,
    enc_params: &EncryptionParams,
) -> Result<Secret<Vec<u8>>> {
    let cipher = enc_params
        .encryption_type
        .as_ref()
        .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
        .cipher();

    let enc_data = cipher
        .decrypt(
            session_key.as_ref(),
            TGS_REP_ENC_SESSION_KEY,
            &tgs_rep.0.enc_part.0.cipher.0.0,
        )
        .map_err(|e| Error::new(ErrorKind::DecryptFailure, format!("{e:?}")))?;

    trace!(?enc_data, "Plain TgsRep::EncData");

    let enc_as_rep_part: EncTgsRepPart = picky_asn1_der::from_bytes(&enc_data)?;

    Ok(enc_as_rep_part.0.key.0.key_value.0.to_vec().into())
}

/// Extracts encryption type and salt from [AsRep].
///
/// More info in [RFC 4120 Receipt of KRB_AS_REP Message](https://www.rfc-editor.org/rfc/rfc4120#section-3.1.5):
///
/// > If any padata fields are present, they may be used to derive the proper secret key to decrypt the message.
#[instrument(level = "trace", ret)]
pub fn extract_encryption_params_from_as_rep(as_rep: &AsRep) -> Result<(u8, String)> {
    match as_rep
        .0
        .padata
        .0
        .as_ref()
        .map(|v| {
            v.0.0
                .iter()
                .find(|e| e.padata_type.0.0 == PA_ETYPE_INFO2_TYPE)
                .map(|pa_data| pa_data.padata_data.0.0.clone())
        })
        .unwrap_or_default()
    {
        Some(data) => {
            let pa_etype_info2: EtypeInfo2 = picky_asn1_der::from_bytes(&data)?;
            let pa_etype_info2 = pa_etype_info2
                .0
                .first()
                .ok_or_else(|| Error::new(ErrorKind::InvalidParameter, "Missing EtypeInto2Entry in EtypeInfo2"))?;

            Ok((
                pa_etype_info2.etype.0.0.first().copied().unwrap(),
                pa_etype_info2
                    .salt
                    .0
                    .as_ref()
                    .map(|salt| salt.0.to_string())
                    .ok_or_else(|| Error::new(ErrorKind::InvalidParameter, "Missing salt in EtypeInto2Entry"))?,
            ))
        }
        None => Ok((*as_rep.0.enc_part.0.etype.0.0.first().unwrap(), Default::default())),
    }
}

/// Extract a status code from the [KrbPriv] message.
pub fn extract_status_code_from_krb_priv_response(
    krb_priv: &KrbPriv,
    auth_key: &[u8],
    encryption_params: &EncryptionParams,
) -> Result<u16> {
    let encryption_type = encryption_params
        .encryption_type
        .clone()
        .unwrap_or(CipherSuite::try_from(
            *krb_priv
                .0
                .enc_part
                .0
                .etype
                .0
                .0
                .first()
                .unwrap_or(&((&DEFAULT_ENCRYPTION_TYPE).into())) as usize,
        )?);

    let cipher = encryption_type.cipher();

    let enc_part: EncKrbPrivPart =
        picky_asn1_der::from_bytes(&cipher.decrypt(auth_key, KRB_PRIV_ENC_PART, &krb_priv.0.enc_part.0.cipher.0.0)?)?;
    let user_data = enc_part.0.user_data.0.0;

    if user_data.len() < 2 {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "Invalid KRB_PRIV message: user-data first is too short (expected at least 2 bytes)",
        ));
    }

    Ok(u16::from_be_bytes(user_data[0..2].try_into().unwrap()))
}

/// Extracts the sequence number from the [ApRep].
#[instrument(level = "trace", ret)]
pub fn extract_seq_number_from_ap_rep(
    ap_rep: &ApRep,
    session_key: &Secret<Vec<u8>>,
    enc_params: &EncryptionParams,
) -> Result<Vec<u8>> {
    let cipher = enc_params
        .encryption_type
        .as_ref()
        .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
        .cipher();

    let res = cipher
        .decrypt(session_key.as_ref(), AP_REP_ENC, &ap_rep.0.enc_part.cipher.0.0)
        .map_err(|err| {
            Error::new(
                ErrorKind::DecryptFailure,
                format!("cannot decrypt ap_rep.enc_part: {err:?}"),
            )
        })?;

    let ap_rep_enc_part: EncApRepPart = picky_asn1_der::from_bytes(&res)?;

    Ok(ap_rep_enc_part
        .0
        .seq_number
        .0
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "missing sequence number in ap_rep"))?
        .0
        .0)
}

/// Extracts a sub-session key from the [ApRep].
#[instrument(level = "trace", ret)]
pub fn extract_sub_session_key_from_ap_rep(
    ap_rep: &ApRep,
    session_key: &Secret<Vec<u8>>,
    enc_params: &EncryptionParams,
) -> Result<Secret<Vec<u8>>> {
    let cipher = enc_params
        .encryption_type
        .as_ref()
        .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
        .cipher();

    let res = cipher
        .decrypt(session_key.as_ref(), AP_REP_ENC, &ap_rep.0.enc_part.cipher.0.0)
        .map_err(|err| {
            Error::new(
                ErrorKind::DecryptFailure,
                format!("cannot decrypt ap_rep.enc_part: {err:?}"),
            )
        })?;

    let ap_rep_enc_part: EncApRepPart = picky_asn1_der::from_bytes(&res)?;

    Ok(ap_rep_enc_part
        .0
        .subkey
        .0
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "missing sub-key in ap_req"))?
        .0
        .key_value
        .0
        .0
        .into())
}

/// Extracts TGT Ticket from encoded [NegTokenTarg1].
///
/// Returned OID means the selected authentication mechanism by the target server. More info:
/// * [3.2.1. Syntax](https://datatracker.ietf.org/doc/html/rfc2478#section-3.2.1): `responseToken` field;
///
/// We use this oid to choose between the regular Kerberos 5 and Kerberos 5 User-to-User authentication.
#[instrument(level = "trace", ret)]
pub fn extract_tgt_ticket_with_oid(mut resp_token: &[u8]) -> Result<Option<(Ticket, ObjectIdentifierAsn1)>> {
    if resp_token.is_empty() {
        return Ok(None);
    }

    let oid: ApplicationTag<Asn1RawDer, 0> = picky_asn1_der::from_reader(&mut resp_token)?;
    let oid: ObjectIdentifierAsn1 = picky_asn1_der::from_bytes(&oid.0.0)?;

    let mut t = [0, 0];

    resp_token.read_exact(&mut t)?;

    let tgt_rep: TgtRep = picky_asn1_der::from_reader(&mut resp_token)?;

    Ok(Some((tgt_rep.ticket.0, oid)))
}
