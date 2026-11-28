use crypto_bigint::BoxedUint;
use picky::key::PublicKey as RsaPublicKey;
use picky_asn1_x509::signed_data::{CertificateChoices, SignedData};
use picky_asn1_x509::validity::Time;
use picky_asn1_x509::{Certificate, ExtensionView, PublicKey, oids};
use time::{Date, Month, OffsetDateTime};

use crate::{Error, ErrorKind, Result};

/// validates server's p2p certificate.
/// If certificate is valid then return its public key.
#[instrument(level = "trace", ret)]
pub fn validate_server_p2p_certificate(signed_data: &SignedData) -> Result<RsaPublicKey> {
    let cert = extract_signing_certificate(signed_data)?;
    let public_key = match cert.tbs_certificate.subject_public_key_info.subject_public_key {
        PublicKey::Rsa(rsa) => rsa,
        public_key => {
            error!(
                ?public_key,
                "Server sent unsupported public key type. Only RSA keys supported",
            );

            return Err(Error::new(
                ErrorKind::Pku2uCertFailure,
                "Received certificate has unsupported public key type. Only RSA is supported",
            ));
        }
    }
    .0;

    Ok(RsaPublicKey::from_rsa_components(
        &BoxedUint::from_be_slice_vartime(&public_key.modulus.0),
        &BoxedUint::from_be_slice_vartime(&public_key.public_exponent.0),
    ))
}

pub(crate) fn validate_peer_p2p_certificate(certificate: &Certificate, now: OffsetDateTime) -> Result<()> {
    let not_before = certificate_time(&certificate.tbs_certificate.validity.not_before)?;
    let not_after = certificate_time(&certificate.tbs_certificate.validity.not_after)?;
    if now < not_before || now > not_after {
        return Err(Error::new(
            ErrorKind::Pku2uCertFailure,
            format!("PKU2U peer certificate is not valid at {now}"),
        ));
    }

    let mut allows_digital_signature = false;
    let mut allows_peer_authentication = false;
    for extension in certificate.extensions() {
        match extension.extn_value() {
            ExtensionView::KeyUsage(key_usage) => {
                allows_digital_signature = key_usage.digital_signature();
            }
            ExtensionView::ExtendedKeyUsage(extended_key_usage) => {
                allows_peer_authentication = extended_key_usage.contains(oids::kp_client_auth())
                    || extended_key_usage
                        .iter()
                        .any(|purpose| Into::<String>::into(&purpose.0) == "1.3.6.1.5.2.3.4");
            }
            _ => {}
        }
    }
    if !allows_digital_signature {
        return Err(Error::new(
            ErrorKind::Pku2uCertFailure,
            "PKU2U peer certificate does not allow digital signatures",
        ));
    }
    if !allows_peer_authentication {
        return Err(Error::new(
            ErrorKind::Pku2uCertFailure,
            "PKU2U peer certificate does not allow PKINIT or client authentication",
        ));
    }

    Ok(())
}

fn certificate_time(time: &Time) -> Result<OffsetDateTime> {
    let (year, month, day, hour, minute, second) = match time {
        Time::Utc(time) => (
            time.0.year(),
            time.0.month(),
            time.0.day(),
            time.0.hour(),
            time.0.minute(),
            time.0.second(),
        ),
        Time::Generalized(time) => (
            time.0.year(),
            time.0.month(),
            time.0.day(),
            time.0.hour(),
            time.0.minute(),
            time.0.second(),
        ),
    };
    let month = Month::try_from(month).map_err(|error| {
        Error::new(
            ErrorKind::Pku2uCertFailure,
            format!("invalid certificate month: {error}"),
        )
    })?;
    let calendar_date = Date::from_calendar_date(i32::from(year), month, day).map_err(|error| {
        Error::new(
            ErrorKind::Pku2uCertFailure,
            format!("invalid certificate date: {error}"),
        )
    })?;
    Ok(calendar_date
        .with_hms(hour, minute, second)
        .map_err(|error| {
            Error::new(
                ErrorKind::Pku2uCertFailure,
                format!("invalid certificate time: {error}"),
            )
        })?
        .assume_utc())
}

pub(crate) fn extract_signing_certificate(signed_data: &SignedData) -> Result<Certificate> {
    match signed_data.certificates.0.0.first() {
        Some(CertificateChoices::Certificate(cert)) => Ok(picky_asn1_der::from_bytes(&cert.0)?),
        Some(cert) => {
            error!(?cert, "Server sent unsupported certificate format");
            Err(Error::new(
                ErrorKind::Pku2uCertFailure,
                "Received unknown certificate format",
            ))
        }
        None => Err(Error::new(
            ErrorKind::Pku2uCertFailure,
            "Received invalid server certificates",
        )),
    }
}
