use picky_krb::crypto::CipherSuite;
use picky_krb::messages::KrbPrivMessage;
use rand::rngs::{StdRng, SysRng};
use rand_core::{Rng as _, SeedableRng as _};

use crate::builders::ChangePassword;
use crate::generator::YieldPointLocal;
use crate::kerberos::client::extractors::{
    extract_encryption_params_from_as_rep, extract_session_key_from_as_rep, extract_status_code_from_krb_priv_response,
};
use crate::kerberos::client::generators::{
    EncKey, GenerateAsPaDataOptions, GenerateAsReqOptions, GenerateAuthenticatorOptions, generate_as_req_kdc_body,
    generate_authenticator, generate_krb_priv_request,
};
use crate::kerberos::client::principal::{get_client_principal_name_type, get_client_principal_realm};
use crate::kerberos::pa_datas::AsReqPaDataOptions;
use crate::kerberos::utils::serialize_message;
use crate::kerberos::{CHANGE_PASSWORD_SERVICE_NAME, DEFAULT_ENCRYPTION_TYPE, KADMIN, client};
use crate::utils::generate_random_symmetric_key;
use crate::{ClientRequestFlags, Error, ErrorKind, Kerberos, Result};

/// [Kerberos Change Password and Set Password Protocols](https://datatracker.ietf.org/doc/html/rfc3244#section-2)
/// "The service accepts requests on UDP port 464 and TCP port 464 as well."
const KPASSWD_PORT: u16 = 464;

#[instrument(level = "debug", ret, fields(state = ?client.state), skip(client, change_password))]
pub async fn change_password<'a>(
    client: &'a mut Kerberos,
    yield_point: &mut YieldPointLocal,
    change_password: ChangePassword<'a>,
) -> Result<()> {
    let username = &change_password.account_name;
    let domain = &change_password.domain_name;
    let password = &change_password.old_password;

    let salt = format!("{domain}{username}");

    let cname_type = get_client_principal_name_type(username, domain);
    let realm = &get_client_principal_realm(username, domain);

    let mut rand = StdRng::try_from_rng(&mut SysRng)?;
    let nonce = &rand.next_u32().to_ne_bytes();

    let options = GenerateAsReqOptions {
        realm,
        username,
        cname_type,
        snames: &[KADMIN, CHANGE_PASSWORD_SERVICE_NAME],
        // 4 = size of u32
        nonce,
        hostname: &client.config.client_computer_name,
        context_requirements: ClientRequestFlags::empty(),
    };
    let kdc_req_body = generate_as_req_kdc_body(&options)?;

    let pa_data_options = AsReqPaDataOptions::AuthIdentity(GenerateAsPaDataOptions {
        password: password.as_ref(),
        salt: salt.into_bytes(),
        enc_params: client.encryption_params.clone(),
        with_pre_auth: false,
    });

    let as_rep = client::as_exchange(client, yield_point, &kdc_req_body, pa_data_options).await?;

    debug!("AS exchange finished successfully.");

    client.realm = Some(as_rep.0.crealm.0.to_string());

    let (encryption_type, salt) = extract_encryption_params_from_as_rep(&as_rep)?;
    debug!(?encryption_type, "Negotiated encryption type");

    client.encryption_params.encryption_type = Some(CipherSuite::try_from(usize::from(encryption_type))?);

    let session_key = extract_session_key_from_as_rep(&as_rep, &salt, password.as_ref(), &client.encryption_params)?;

    let seq_num = client.next_seq_number();

    let enc_type = client
        .encryption_params
        .encryption_type
        .as_ref()
        .unwrap_or(&DEFAULT_ENCRYPTION_TYPE);
    let authenticator_seb_key = generate_random_symmetric_key(enc_type, &mut rand);

    let authenticator = generate_authenticator(GenerateAuthenticatorOptions {
        kdc_rep: &as_rep.0,
        seq_num: Some(seq_num),
        sub_key: Some(EncKey {
            key_type: enc_type.clone(),
            key_value: authenticator_seb_key,
        }),
        checksum: None,
        channel_bindings: client.channel_bindings.as_ref(),
        extensions: Vec::new(),
    })?;

    let krb_priv = generate_krb_priv_request(
        as_rep.0.ticket.0,
        &session_key,
        change_password.new_password.as_ref().as_bytes(),
        &authenticator,
        &client.encryption_params,
        seq_num,
        &client.config.client_computer_name,
    )?;

    if let Some((_realm, mut kdc_url)) = client.get_kdc() {
        kdc_url
            .set_port(Some(KPASSWD_PORT))
            .map_err(|_| Error::new(ErrorKind::InvalidParameter, "Cannot set port for KDC URL"))?;

        let response = client.send(yield_point, &serialize_message(&krb_priv)?).await?;
        trace!(?response, "Change password raw response");

        if response.len() < 4 {
            return Err(Error::new(
                ErrorKind::InternalError,
                "the KDC reply message is too small: expected at least 4 bytes",
            ));
        }

        let krb_priv_response = KrbPrivMessage::deserialize(&response[4..]).map_err(|err| {
            Error::new(
                ErrorKind::InvalidToken,
                format!("cannot deserialize krb_priv_response: {err:?}"),
            )
        })?;

        let result_status = extract_status_code_from_krb_priv_response(
            &krb_priv_response.krb_priv,
            &authenticator.0.subkey.0.as_ref().unwrap().0.key_value.0.0,
            &client.encryption_params,
        )?;

        if result_status != 0 {
            return Err(Error::new(
                ErrorKind::WrongCredentialHandle,
                format!("unsuccessful krb result code: {result_status}. expected 0"),
            ));
        }
    } else {
        return Err(Error::new(
            ErrorKind::NoAuthenticatingAuthority,
            "no KDC server found".to_owned(),
        ));
    }

    Ok(())
}
