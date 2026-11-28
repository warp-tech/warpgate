use std::convert::TryInto;
use std::mem::size_of;

use picky_asn1_der::Asn1RawDer;
use picky_asn1_der::application_tag::ApplicationTag;
use picky_krb::constants::key_usages::AS_REP_ENC;
use picky_krb::constants::types::PA_PK_AS_REP;
use picky_krb::data_types::{KrbResult, ResultExt};
use picky_krb::messages::{AsRep, EncAsRepPart};
use picky_krb::pkinit::{DhRepInfo, PaPkAsRep};
use serde::Deserialize;

use crate::kerberos::{DEFAULT_ENCRYPTION_TYPE, EncryptionParams};
use crate::pk_init::DH_NONCE_LEN;
use crate::{Error, ErrorKind, Result, Secret};

pub(super) fn extract_krb_rep<'a, T: Deserialize<'a>>(mut data: &'a [u8]) -> Result<(T, &'a [u8])> {
    let _oid: ApplicationTag<Asn1RawDer, 0> = picky_asn1_der::from_reader(&mut data)?;

    Ok((picky_asn1_der::from_bytes(data)?, data))
}

pub(super) fn extract_krb_result<'a, T: Deserialize<'a>>(mut data: &'a [u8]) -> Result<(KrbResult<T>, &'a [u8])> {
    let _oid: ApplicationTag<Asn1RawDer, 0> = picky_asn1_der::from_reader(&mut data)?;
    let mut deserializer = picky_asn1_der::Deserializer::new_from_bytes(data);

    Ok((
        <KrbResult<T> as ResultExt<'a, T>>::deserialize(&mut deserializer)?,
        data,
    ))
}

#[instrument(level = "trace", ret)]
pub fn extract_pa_pk_as_rep(as_rep: &AsRep) -> Result<PaPkAsRep> {
    Ok(picky_asn1_der::from_bytes(
        &as_rep
            .0
            .padata
            .0
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "pa-datas is not present in as-rep"))?
            .iter()
            .find(|pa_data| pa_data.padata_type.0.0 == PA_PK_AS_REP)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidToken,
                    "PA_PK_AS_REP is not present in pa-datas of the as-rep",
                )
            })?
            .padata_data
            .0
            .0,
    )?)
}

#[instrument(level = "trace", ret)]
pub fn extract_server_nonce(dh_rep_info: &DhRepInfo) -> Result<[u8; DH_NONCE_LEN]> {
    let nonce = dh_rep_info
        .server_dh_nonce
        .0
        .as_ref()
        .map(|nonce| nonce.0.0.clone())
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "DH server nonce is not present"))?;

    if nonce.len() != DH_NONCE_LEN {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            format!(
                "invalid server dh nonce length: {}. Expected: {}",
                nonce.len(),
                DH_NONCE_LEN
            ),
        ));
    }

    Ok(nonce.try_into().unwrap())
}

#[instrument(level = "trace", ret)]
pub fn extract_session_key_from_as_rep(
    as_rep: &AsRep,
    key: &[u8],
    enc_params: &EncryptionParams,
) -> Result<Secret<Vec<u8>>> {
    Ok(decrypt_as_rep(as_rep, key, enc_params)?
        .0
        .key
        .0
        .key_value
        .0
        .to_vec()
        .into())
}

pub(super) fn extract_session_key_and_nonce_from_as_rep(
    as_rep: &AsRep,
    key: &[u8],
    enc_params: &EncryptionParams,
) -> Result<(Secret<Vec<u8>>, u32)> {
    let enc_as_rep_part = decrypt_as_rep(as_rep, key, enc_params)?;
    let nonce_bytes = enc_as_rep_part.0.nonce.0.as_unsigned_bytes_be();
    if nonce_bytes.len() > size_of::<u32>() {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "AS-REP nonce does not fit into a u32",
        ));
    }
    let mut nonce = [0; size_of::<u32>()];
    nonce[size_of::<u32>() - nonce_bytes.len()..].copy_from_slice(nonce_bytes);

    Ok((
        enc_as_rep_part.0.key.0.key_value.0.to_vec().into(),
        u32::from_be_bytes(nonce),
    ))
}

fn decrypt_as_rep(as_rep: &AsRep, key: &[u8], enc_params: &EncryptionParams) -> Result<EncAsRepPart> {
    let cipher = enc_params
        .encryption_type
        .as_ref()
        .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
        .cipher();

    let enc_data = cipher.decrypt(key, AS_REP_ENC, &as_rep.0.enc_part.0.cipher.0.0)?;
    trace!(?enc_data, "Plain AsRep::EncData");

    Ok(picky_asn1_der::from_bytes(&enc_data)?)
}

#[cfg(test)]
mod tests {
    use picky_krb::constants::gss_api::{AP_REQ_TOKEN_ID, AS_REQ_TOKEN_ID};

    use super::extract_krb_rep;
    use crate::ClientRequestFlags;
    use crate::kerberos::client::generators::{GenerateAsReqOptions, generate_as_req, generate_as_req_kdc_body};
    use crate::pku2u::generators::generate_neg;

    /// Regression test for a framing bug in [`generate_neg`]: it used to wrap the [KrbMessage](picky_krb::gss_api::KrbMessage)
    /// using the generic (`EXPLICIT`-style) `ApplicationTag` from `picky_asn1_der`, producing a doubly-nested,
    /// non-conformant token that [`extract_krb_rep`]/[`extract_krb_result`](super::extract_krb_result) (and any
    /// spec-compliant PKU2U peer) could not parse back. `generate_neg` must keep using [ApplicationTag0](picky_krb::gss_api::ApplicationTag0)
    /// (RFC 2743 `IMPLICIT` tagging) so that everything this module encodes round-trips through what it decodes.
    #[test]
    fn generate_neg_round_trips_through_extract_krb_rep() {
        let kdc_req_body = generate_as_req_kdc_body(&GenerateAsReqOptions {
            realm: "WELLKNOWN:PKU2U",
            username: "AzureAD\\issuer\\subject",
            cname_type: 0x80,
            snames: &["host"],
            nonce: 0x0102_0304,
            hostname: "hostname",
            context_requirements: ClientRequestFlags::empty(),
        })
        .unwrap();
        let as_req = generate_as_req(Vec::new(), kdc_req_body);

        let encoded = picky_asn1_der::to_vec(&generate_neg(as_req.clone(), AS_REQ_TOKEN_ID)).unwrap();
        let (decoded, _): (picky_krb::messages::AsReq, _) = extract_krb_rep(&encoded).unwrap();
        assert_eq!(decoded, as_req);

        // Any token id round-trips the same way (e.g. AP-REQ/AP-REP use a different one than AS-REQ/AS-REP).
        let encoded = picky_asn1_der::to_vec(&generate_neg(as_req.clone(), AP_REQ_TOKEN_ID)).unwrap();
        let (decoded, _): (picky_krb::messages::AsReq, _) = extract_krb_rep(&encoded).unwrap();
        assert_eq!(decoded, as_req);
    }

    #[test]
    fn bare_application_tagged_value_decodes_as_krb_result_ok() {
        use picky_krb::constants::gss_api::AS_REP_TOKEN_ID;
        use picky_krb::data_types::KrbResult;

        use super::extract_krb_result;

        let kdc_req_body = generate_as_req_kdc_body(&GenerateAsReqOptions {
            realm: "WELLKNOWN:PKU2U",
            username: "AzureAD\\issuer\\subject",
            cname_type: 0x80,
            snames: &["host"],
            nonce: 0x0102_0304,
            hostname: "hostname",
            context_requirements: ClientRequestFlags::empty(),
        })
        .unwrap();
        // AsReq is unused as the choice discriminant here; we just need *some* Application-tagged
        // value with a distinct tag number from KrbError (30) to stand in for AsRep (11) in this test.
        let as_req = generate_as_req(Vec::new(), kdc_req_body);

        // `KrbResult<T>` cannot be serialized directly (`Result<T, E>`'s blanket serde impl isn't
        // supported by picky_asn1_der's Serializer). But since `KrbResult<T> = Result<T, KrbError>`
        // is a *natural* choice between two distinctly Application-tagged alternatives (no extra
        // wrapper tag), a bare, directly-encoded `T` must already parse back as `KrbResult::Ok`.
        let encoded = picky_asn1_der::to_vec(&generate_neg(as_req.clone(), AS_REP_TOKEN_ID)).unwrap();
        let (decoded, _): (KrbResult<picky_krb::messages::AsReq>, _) = extract_krb_result(&encoded).unwrap();
        assert_eq!(decoded.unwrap(), as_req);
    }
}
