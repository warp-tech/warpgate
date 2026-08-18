use picky_krb::data_types::{KrbResult, ResultExt};
use picky_krb::messages::{AsRep, KdcReqBody};

use crate::generator::YieldPointLocal;
use crate::kerberos::client::extractors::extract_salt_from_krb_error;
use crate::kerberos::client::generators::generate_as_req;
use crate::kerberos::pa_datas::AsReqPaDataOptions;
use crate::kerberos::utils::serialize_message;
use crate::{Error, ErrorKind, Kerberos, Result};

/// Performs AS exchange as specified in [RFC 4210: The Authentication Service Exchange](https://www.rfc-editor.org/rfc/rfc4120#section-3.1).
pub(crate) async fn as_exchange(
    client: &mut Kerberos,
    yield_point: &mut YieldPointLocal,
    kdc_req_body: &KdcReqBody,
    mut pa_data_options: AsReqPaDataOptions<'_>,
) -> Result<AsRep> {
    pa_data_options.with_pre_auth(false);
    let pa_datas = pa_data_options.generate()?;
    let as_req = generate_as_req(pa_datas, kdc_req_body.clone());

    let response = client.send(yield_point, &serialize_message(&as_req)?).await?;

    // first 4 bytes are message len. skipping them
    {
        if response.len() < 4 {
            return Err(Error::new(
                ErrorKind::InternalError,
                "the KDC reply message is too small: expected at least 4 bytes",
            ));
        }

        let mut d = picky_asn1_der::Deserializer::new_from_bytes(&response[4..]);
        let as_rep: KrbResult<AsRep> = KrbResult::deserialize(&mut d)?;

        if as_rep.is_ok() {
            error!("KDC replied with AS_REP to the AS_REQ without the encrypted timestamp. The KRB_ERROR expected.");

            return Err(Error::new(
                ErrorKind::InvalidToken,
                "KDC server should not process AS_REQ without the pa-pac data",
            ));
        }

        if let Some(correct_salt) = extract_salt_from_krb_error(&as_rep.unwrap_err())? {
            debug!("salt extracted successfully from the KRB_ERROR");

            pa_data_options.with_salt(correct_salt.into_bytes());
        }
    }

    pa_data_options.with_pre_auth(true);
    let pa_datas = pa_data_options.generate()?;

    let as_req = generate_as_req(pa_datas, kdc_req_body.clone());

    let response = client.send(yield_point, &serialize_message(&as_req)?).await?;

    if response.len() < 4 {
        return Err(Error::new(
            ErrorKind::InternalError,
            "the KDC reply message is too small: expected at least 4 bytes",
        ));
    }

    // first 4 bytes are message len. skipping them
    let mut d = picky_asn1_der::Deserializer::new_from_bytes(&response[4..]);

    Ok(KrbResult::<AsRep>::deserialize(&mut d)?.inspect_err(|err| error!(?err, "AS exchange error"))?)
}
