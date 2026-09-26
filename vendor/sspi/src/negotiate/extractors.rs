use oid::ObjectIdentifier;
use picky::oids;
use picky_krb::gss_api::{ApplicationTag0, GssApiNegInit, MechTypeList, NegTokenInit};

use crate::ntlm::NtlmConfig;
use crate::{Error, ErrorKind, Negotiate, NegotiatedProtocol, Ntlm};

/// Extract TGT request and mech types from the first token returned by the Kerberos client.
#[instrument(ret, level = "trace")]
pub(super) fn decode_initial_neg_init(data: &[u8]) -> crate::Result<(Option<Vec<u8>>, MechTypeList)> {
    let token: ApplicationTag0<GssApiNegInit> = picky_asn1_der::from_bytes(data)?;
    let NegTokenInit {
        mech_types,
        req_flags: _,
        mech_token,
        mech_list_mic: _,
    } = token.0.neg_token_init.0;

    let mech_types = mech_types
        .0
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidToken,
                "mech_types is missing in GssApiNegInit message",
            )
        })?
        .0;

    let token = mech_token.0.map(|token| token.0.0);

    Ok((token, mech_types))
}

/// Selects the preferred authentication protocol OID based on the provided protocols list, allowed protocols,
/// and available protocols.
///
/// The Kerberos protocol will be selected only if it is allowed in the package list, its OID is present in the mech types,
/// and the internal protocol is configured to Kerberos. We cannot _just_ configure it from env vars as we do it for
/// the client-side Kerberos because the server-side Kerberos requires many configuration fields.
///
/// 1.2.840.48018.1.2.2 (MS KRB5 - Microsoft Kerberos 5) is preferred over 1.2.840.113554.1.2.2 (KRB5 - Kerberos 5).
pub(super) fn negotiate_mech_type(
    mech_list: &MechTypeList,
    negotiate: &mut Negotiate,
) -> crate::Result<(ObjectIdentifier, usize)> {
    let ms_krb5 = oids::ms_krb5();
    if let Some(mech_index) = mech_list.0.iter().position(|mech_type| mech_type.0 == ms_krb5)
        && negotiate.package_list.kerberos
        && negotiate.protocol.is_kerberos()
    {
        return Ok((ms_krb5, mech_index));
    }

    let krb5 = oids::krb5();
    if let Some(mech_index) = mech_list.0.iter().position(|mech_type| mech_type.0 == krb5)
        && negotiate.package_list.kerberos
        && negotiate.protocol.is_kerberos()
    {
        return Ok((krb5, mech_index));
    }

    let ntlm_oid = oids::ntlm_ssp();
    if let Some(mech_index) = mech_list.0.iter().position(|mech_type| mech_type.0 == ntlm_oid)
        && negotiate.package_list.ntlm
    {
        if let NegotiatedProtocol::Kerberos(kerberos) = &mut negotiate.protocol {
            // Negotiate is configured to use Kerberos, but only NTLM is possible (fallback to NTLM).
            negotiate.protocol = NegotiatedProtocol::Ntlm(Ntlm::with_config(NtlmConfig {
                client_computer_name: Some(kerberos.config.client_computer_name.clone()),
            }));
        }

        return Ok((ntlm_oid, mech_index));
    }

    Err(Error::new(
        ErrorKind::InvalidToken,
        "no supported authentication protocols found in mech list",
    ))
}
