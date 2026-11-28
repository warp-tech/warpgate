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
        .unwrap_or(CipherSuite::try_from(usize::from(
            *krb_priv
                .0
                .enc_part
                .0
                .etype
                .0
                .0
                .first()
                .unwrap_or(&((&DEFAULT_ENCRYPTION_TYPE).into())),
        ))?);

    let cipher = encryption_type.cipher();

    let enc_part: EncKrbPrivPart =
        picky_asn1_der::from_bytes(&cipher.decrypt(auth_key, KRB_PRIV_ENC_PART, &krb_priv.0.enc_part.0.cipher.0.0)?)?;
    let user_data = enc_part.0.user_data.0.0;

    let Some((status_code, _)) = user_data.split_first_chunk::<2>() else {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "Invalid KRB_PRIV message: user-data first is too short (expected at least 2 bytes)",
        ));
    };

    Ok(u16::from_be_bytes(*status_code))
}

/// Decrypt and decodes the encrypted part of the encoded [ApRep] message.
#[instrument(level = "trace", ret)]
pub fn decrypt_ap_rep(
    ap_rep: &ApRep,
    session_key: &Secret<Vec<u8>>,
    enc_params: &EncryptionParams,
) -> Result<EncApRepPart> {
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

    Ok(picky_asn1_der::from_bytes(&res)?)
}

/// Extracts a sub-session key from the [EncApRepPart].
#[instrument(level = "trace", ret)]
pub fn extract_sub_session_key_from_ap_rep(ap_rep_enc_part: &EncApRepPart) -> Result<Secret<Vec<u8>>> {
    Ok(ap_rep_enc_part
        .0
        .subkey
        .0
        .clone()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "missing sub-key in ap_req"))?
        .0
        .key_value
        .0
        .0
        .into())
}

/// Extracts a sequence number from the [EncApRepPart].
#[instrument(level = "trace", ret)]
pub fn extract_seq_number_from_ap_rep(ap_rep_enc_part: &EncApRepPart) -> Result<u32> {
    let seq_number_bytes = ap_rep_enc_part
        .0
        .seq_number
        .0
        .clone()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "missing seq-number in ap_rep"))?
        .0
        .0;

    seq_number_from_integer_bytes(&seq_number_bytes).ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidToken,
            format!("invalid ApRep sequence number: {:?}", seq_number_bytes),
        )
    })
}

/// Converts the content octets of a DER INTEGER holding a 32-bit sequence number into a [u32].
///
/// DER uses the minimal number of octets, so a peer encodes a small sequence number in fewer than
/// 4 octets (the Windows acceptor sends 3 octets for values below `0x800000`, about 1 in 256 AP-REPs).
/// A value encoded as unsigned (RFC 4120 `UInt32`) can take a fifth leading `00` octet, and a value
/// encoded as signed (Windows `Int32`) can be a short negative number, which is sign-extended here.
fn seq_number_from_integer_bytes(bytes: &[u8]) -> Option<u32> {
    match bytes {
        [0x00, rest @ ..] if rest.len() == 4 => rest.try_into().ok().map(u32::from_be_bytes),
        [first, ..] if bytes.len() <= 4 => {
            let mut buf = if first & 0x80 != 0 { [0xff; 4] } else { [0x00; 4] };
            buf[4 - bytes.len()..].copy_from_slice(bytes);
            Some(u32::from_be_bytes(buf))
        }
        _ => None,
    }
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

#[cfg(test)]
mod tests {
    use picky_asn1::date::GeneralizedTime;
    use picky_asn1::wrapper::{ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag3, IntegerAsn1, Optional};
    use picky_krb::data_types::{EncApRepPartInner, KerberosTime};
    use time::OffsetDateTime;

    use super::*;

    #[test]
    fn seq_number_accepts_any_der_length() {
        for (bytes, expected) in [
            // Minimal DER from the Windows acceptor, previously rejected.
            (&[0x05, 0x84, 0xbc][..], 0x0005_84bc),
            (&[0x00], 0),
            (&[0x7f], 0x7f),
            (&[0x00, 0x80], 0x80),
            (&[0x12, 0x34, 0x56, 0x78], 0x1234_5678),
            // Full width, as sent by older sspi-rs acceptors.
            (&[0x9a, 0xbc, 0xde, 0xf0], 0x9abc_def0),
            // Unsigned encoding with a leading zero octet.
            (&[0x00, 0x9a, 0xbc, 0xde, 0xf0], 0x9abc_def0),
            // Short negative values from a signed Int32 encoder.
            (&[0xff], u32::MAX),
            (&[0x80, 0x00, 0x00], 0xff80_0000),
        ] {
            assert_eq!(seq_number_from_integer_bytes(bytes), Some(expected), "{bytes:02x?}");
        }
    }

    #[test]
    fn seq_number_rejects_out_of_range() {
        for bytes in [
            &[][..],
            &[0x01, 0x00, 0x00, 0x00, 0x00],
            &[0xff, 0x80, 0x00, 0x00, 0x00],
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
        ] {
            assert_eq!(seq_number_from_integer_bytes(bytes), None, "{bytes:02x?}");
        }
    }

    #[test]
    fn ap_rep_with_short_seq_number() {
        let enc_ap_rep_part = EncApRepPart::from(EncApRepPartInner {
            ctime: ExplicitContextTag0::from(KerberosTime::from(GeneralizedTime::from(OffsetDateTime::now_utc()))),
            cusec: ExplicitContextTag1::from(IntegerAsn1::from(vec![0x00])),
            subkey: Optional::from(None),
            seq_number: Optional::from(Some(ExplicitContextTag3::from(IntegerAsn1::from(vec![
                0x1a, 0xad, 0x10,
            ])))),
        });

        assert_eq!(extract_seq_number_from_ap_rep(&enc_ap_rep_part).unwrap(), 0x001a_ad10);
    }
}
