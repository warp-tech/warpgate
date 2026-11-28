use picky_krb::constants::error_codes::KRB_AP_ERR_SKEW;
use picky_krb::data_types::{KrbResult, ResultExt};
use picky_krb::messages::{AsRep, KdcReqBody, KrbError};
use time::{Duration, OffsetDateTime};

use crate::generator::YieldPointLocal;
use crate::kerberos::client::extractors::extract_salt_from_krb_error;
use crate::kerberos::client::generators::generate_as_req;
use crate::kerberos::pa_datas::AsReqPaDataOptions;
use crate::kerberos::utils::serialize_message;
use crate::{Error, ErrorKind, Kerberos, Result};

fn clock_offset_from_error(error: &KrbError, received_at: OffsetDateTime) -> Result<Duration> {
    let seconds = OffsetDateTime::try_from(error.0.stime.0.0.clone())
        .map_err(|_| Error::new(ErrorKind::InvalidToken, "KDC skew error has invalid server time"))?;
    let usec = error.0.susec.0.0.as_slice();
    if usec.len() > 4 {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "KDC skew error has invalid microseconds",
        ));
    }
    let microseconds = usec.iter().fold(0_u32, |value, byte| (value << 8) | u32::from(*byte));
    if microseconds > 999_999 {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "KDC skew error has invalid microseconds",
        ));
    }
    let server_time = seconds
        .checked_add(Duration::microseconds(i64::from(microseconds)))
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "KDC skew error has invalid server time"))?;
    Ok(server_time - received_at)
}

/// Performs the AS exchange as specified in [RFC 4120, section 3.1](https://www.rfc-editor.org/rfc/rfc4120#section-3.1).
///
/// On a KDC clock-skew error, retries pre-authentication once using the server
/// time in the error. The offset is kept on the client context for subsequent
/// TGS and AP authenticators; other errors are returned without retrying.
pub(crate) async fn as_exchange(
    client: &mut Kerberos,
    yield_point: &mut YieldPointLocal,
    kdc_req_body: &KdcReqBody,
    mut pa_data_options: AsReqPaDataOptions<'_>,
) -> Result<AsRep> {
    pa_data_options.with_pre_auth(false);
    let pa_datas = pa_data_options.generate(client.current_kdc_time()?)?;
    let as_req = generate_as_req(pa_datas, kdc_req_body.clone());

    let response = client.send(yield_point, &serialize_message(&as_req)?).await?;

    // first 4 bytes are message len. skipping them
    {
        let Some(response) = response.get(4..) else {
            return Err(Error::new(
                ErrorKind::InternalError,
                "the KDC reply message is too small: expected at least 4 bytes",
            ));
        };

        let mut d = picky_asn1_der::Deserializer::new_from_bytes(response);
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
    let mut retried_skew = false;
    loop {
        let pa_datas = pa_data_options.generate(client.current_kdc_time()?)?;
        let as_req = generate_as_req(pa_datas, kdc_req_body.clone());
        let response = client.send(yield_point, &serialize_message(&as_req)?).await?;
        let received_at = OffsetDateTime::now_utc();

        // first 4 bytes are message len. skipping them
        let Some(response) = response.get(4..) else {
            return Err(Error::new(
                ErrorKind::InternalError,
                "the KDC reply message is too small: expected at least 4 bytes",
            ));
        };

        let mut d = picky_asn1_der::Deserializer::new_from_bytes(response);
        let as_rep: KrbResult<AsRep> = KrbResult::deserialize(&mut d)?;
        match as_rep {
            Ok(as_rep) => return Ok(as_rep),
            Err(err) if !retried_skew && err.0.error_code.0 == KRB_AP_ERR_SKEW => {
                client.clock_offset = clock_offset_from_error(&err, received_at)?;
                retried_skew = true;
                debug!(offset = ?client.clock_offset, "Retrying AS exchange with KDC clock offset");
            }
            Err(err) => {
                error!(?err, "AS exchange error");
                return Err(err.into());
            }
        }
    }
}
