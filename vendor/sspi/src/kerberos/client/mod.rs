mod as_exchange;
mod change_password;
pub mod extractors;
pub mod generators;
pub mod principal;

use std::io::Write;

pub(crate) use as_exchange::as_exchange;
pub use change_password::change_password;
use picky_asn1_x509::oids;
use picky_krb::constants::gss_api::{AP_REP_TOKEN_ID, AP_REQ_TOKEN_ID, AUTHENTICATOR_CHECKSUM_TYPE, TGT_REQ_TOKEN_ID};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{KrbResult, PrincipalName, ResultExt};
use picky_krb::messages::{ApRep, TgsRep};
use rand::rngs::{StdRng, SysRng};
use rand_core::{Rng as _, SeedableRng as _};

use self::extractors::{
    extract_encryption_params_from_as_rep, extract_seq_number_from_ap_rep, extract_session_key_from_tgs_rep,
    extract_sub_session_key_from_ap_rep, extract_tgt_ticket_with_oid,
};
use self::generators::{
    ChecksumOptions, ChecksumValues, EncKey, GenerateAsPaDataOptions, GenerateAsReqOptions,
    GenerateAuthenticatorOptions, GenerateKeytabPaDataOptions, GenerateTgsReqOptions, GssFlags, generate_ap_rep,
    generate_ap_req, generate_as_req_kdc_body, generate_authenticator, generate_tgs_req,
};
use self::principal::{
    ClientPrincipalName, get_client_principal_name, get_client_principal_name_type, get_client_principal_realm,
};
use crate::channel_bindings::ChannelBindings;
use crate::generator::YieldPointLocal;
use crate::kerberos::client::generators::generate_tgt_req;
use crate::kerberos::messages::{decode_krb_message, generate_krb_message};
use crate::kerberos::pa_datas::{AsRepSessionKeyExtractor, AsReqPaDataOptions};
use crate::kerberos::utils::serialize_message;
use crate::kerberos::{DEFAULT_ENCRYPTION_TYPE, EC, TGT_SERVICE_NAME};
use crate::utils::{generate_random_symmetric_key, parse_target_name};
use crate::{
    BufferType, ClientRequestFlags, ClientResponseFlags, CredentialsBuffers, Error, ErrorKind,
    InitializeSecurityContextResult, Kerberos, KerberosState, Result, SecurityBuffer, SecurityStatus, SspiImpl,
};

/// Inspects the `sname` of a ticket returned in a TGS-REP to decide whether it is a cross-realm
/// referral TGT rather than the requested service ticket.
///
/// A referral TGT has an `sname` of the form `krbtgt/<NEXT_REALM>` (RFC 4120 §3.3.3.2). In that
/// case this returns `Some(next_realm)` and the caller must re-issue the TGS-REQ to `<NEXT_REALM>`.
/// For an actual service ticket (e.g. `TERMSRV/host`) it returns `None`.
fn referral_target_realm(sname: &PrincipalName) -> Option<String> {
    let names = &sname.name_string.0.0;

    match names.as_slice() {
        [service, realm] if service.to_string().eq_ignore_ascii_case(TGT_SERVICE_NAME) => Some(realm.to_string()),
        _ => None,
    }
}

/// Performs one authentication step.
///
/// The user should call this function until it returns `SecurityStatus::Ok`.
pub async fn initialize_security_context<'a>(
    client: &'a mut Kerberos,
    yield_point: &mut YieldPointLocal,
    builder: &'a mut crate::builders::FilledInitializeSecurityContext<
        '_,
        '_,
        <Kerberos as SspiImpl>::CredentialsHandle,
    >,
) -> Result<InitializeSecurityContextResult> {
    trace!(?builder);

    if let KerberosState::TgtExchange = client.state {
        if builder
            .context_requirements
            .contains(ClientRequestFlags::USE_SESSION_KEY)
        {
            client.krb5_user_to_user = true;

            let (service_name, service_principal_name) = parse_target_name(builder.target_name.ok_or_else(|| {
                Error::new(
                    ErrorKind::NoCredentials,
                    "Service target name (service principal name) is not provided",
                )
            })?)?;

            let tgt_req = generate_tgt_req(&[service_name, service_principal_name])?;

            let encoded_neg_tgt_req = if !builder.context_requirements.contains(ClientRequestFlags::USE_DCE_STYLE) {
                generate_krb_message(oids::krb5_user_to_user(), TGT_REQ_TOKEN_ID, tgt_req)?
            } else {
                // Do not wrap if the `USE_DCE_STYLE` flag is set.
                // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/190ab8de-dc42-49cf-bf1b-ea5705b7a087
                picky_asn1_der::to_vec(&tgt_req)?
            };

            let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
            output_token.buffer = encoded_neg_tgt_req;

            client.state = KerberosState::Preauthentication;

            trace!(output_buffers = ?builder.output);

            return Ok(InitializeSecurityContextResult {
                status: SecurityStatus::ContinueNeeded,
                flags: ClientResponseFlags::empty(),
                expiry: None,
            });
        } else {
            client.state = KerberosState::Preauthentication;
        }
    }

    let status = match client.state {
        KerberosState::Preauthentication => {
            let input = builder
                .input
                .as_ref()
                .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "input buffers must be specified"))?;

            if let Ok(sec_buffer) =
                SecurityBuffer::find_buffer(builder.input.as_ref().unwrap(), BufferType::ChannelBindings)
            {
                client.channel_bindings = Some(ChannelBindings::from_bytes(&sec_buffer.buffer)?);
            }

            let input_token = SecurityBuffer::find_buffer(input, BufferType::Token)
                .map(|security_buffer| security_buffer.buffer.as_slice())
                .unwrap_or_default();

            let (tgt_ticket, mech_id) = if let Some((tbt_ticket, mech_oid)) = extract_tgt_ticket_with_oid(input_token)?
            {
                (Some(tbt_ticket), mech_oid.0)
            } else {
                (None, oids::krb5())
            };
            client.krb5_user_to_user = mech_id == oids::krb5_user_to_user();

            let credentials = builder
                .credentials_handle
                .as_ref()
                .unwrap()
                .as_ref()
                .ok_or_else(|| Error::new(ErrorKind::WrongCredentialHandle, "No credentials provided"))?;

            let (username, password, realm, cname_type) = match credentials {
                CredentialsBuffers::AuthIdentity(auth_identity) => {
                    let username = auth_identity.user.to_string();
                    let domain = auth_identity.domain.to_string();
                    let password = auth_identity.password.as_ref().as_ref().to_string();

                    let realm = get_client_principal_realm(&username, &domain);
                    let cname_type = get_client_principal_name_type(&username, &domain);

                    (username, password, realm, cname_type)
                }
                #[cfg(feature = "scard")]
                CredentialsBuffers::SmartCard(smart_card) => {
                    let username = smart_card.username.to_string();
                    let password = smart_card.pin.as_ref().as_ref().to_string();

                    let realm = get_client_principal_realm(&username, "");
                    let cname_type = get_client_principal_name_type(&username, "");

                    (username, password, realm.to_uppercase(), cname_type)
                }
                CredentialsBuffers::Keytab(keytab) => {
                    // The name type is read off the principal's user name format explicitly.
                    let ClientPrincipalName {
                        name,
                        realm_domain,
                        name_type,
                    } = get_client_principal_name(&keytab.principal);

                    let realm = get_client_principal_realm(name, realm_domain);

                    // No password: the keytab key is used directly for pre-auth.
                    (name.to_owned(), String::new(), realm, name_type)
                }
            };
            client.realm = Some(realm.clone());

            let mut rand = StdRng::try_from_rng(&mut SysRng)?;
            let options = GenerateAsReqOptions {
                realm: &realm,
                username: &username,
                cname_type,
                snames: &[TGT_SERVICE_NAME, &realm],
                // 4 = size of u32
                nonce: &rand.next_u32().to_be_bytes(),
                hostname: &client.config.client_computer_name,
                context_requirements: builder.context_requirements,
            };
            let kdc_req_body = generate_as_req_kdc_body(&options)?;

            let pa_data_options = match credentials {
                CredentialsBuffers::AuthIdentity(auth_identity) => {
                    let domain = auth_identity.domain.to_string();
                    let salt = format!("{domain}{username}").into_bytes();

                    AsReqPaDataOptions::AuthIdentity(GenerateAsPaDataOptions {
                        password: &password,
                        salt,
                        enc_params: client.encryption_params.clone(),
                        with_pre_auth: false,
                    })
                }
                CredentialsBuffers::Keytab(keytab) => AsReqPaDataOptions::Keytab(GenerateKeytabPaDataOptions {
                    key: keytab.key.clone(),
                    key_enctype: keytab.key_enctype.clone(),
                    with_pre_auth: false,
                }),
                #[cfg(feature = "scard")]
                CredentialsBuffers::SmartCard(scard_identity_buffer) => {
                    use sha1::{Digest, Sha1};

                    use crate::pku2u::generate_client_dh_parameters;
                    use crate::smartcard::SmartCard;
                    use crate::{SmartCardIdentity, pk_init};

                    let scard_identity = SmartCardIdentity::try_from(scard_identity_buffer)?;

                    let mut smart_card = SmartCard::from_credentials(&scard_identity)?;
                    let p2p_cert = scard_identity.certificate;

                    client.dh_parameters = Some(generate_client_dh_parameters(&mut rand));

                    AsReqPaDataOptions::SmartCard(Box::new(pk_init::GenerateAsPaDataOptions {
                        p2p_cert,
                        kdc_req_body: &kdc_req_body,
                        dh_parameters: client.dh_parameters.clone().unwrap(),
                        sign_data: Box::new(move |data_to_sign| {
                            let mut sha1 = Sha1::new();
                            sha1.update(data_to_sign);
                            let digest = sha1.finalize().to_vec();

                            smart_card.sign(digest)
                        }),
                        with_pre_auth: false,
                        authenticator_nonce: rand.next_u32().to_be_bytes(),
                    }))
                }
            };

            let as_rep = as_exchange(client, yield_point, &kdc_req_body, pa_data_options).await?;

            debug!("AS exchange finished successfully.");

            client.realm = Some(as_rep.0.crealm.0.to_string());

            let (encryption_type, salt) = extract_encryption_params_from_as_rep(&as_rep)?;

            let encryption_type = CipherSuite::try_from(encryption_type as usize)?;

            client.encryption_params.encryption_type = Some(encryption_type);

            let mut session_key_extractor = match credentials {
                CredentialsBuffers::AuthIdentity(_) => AsRepSessionKeyExtractor::AuthIdentity {
                    salt: &salt,
                    password: &password,
                    enc_params: &mut client.encryption_params,
                },
                CredentialsBuffers::Keytab(keytab) => AsRepSessionKeyExtractor::Keytab {
                    key: keytab.key.as_ref(),
                    enc_params: &client.encryption_params,
                },
                #[cfg(feature = "scard")]
                CredentialsBuffers::SmartCard(_) => AsRepSessionKeyExtractor::SmartCard {
                    dh_parameters: client.dh_parameters.as_mut().unwrap(),
                    enc_params: &mut client.encryption_params,
                },
            };
            let session_key_1 = session_key_extractor.session_key(&as_rep)?;

            let service_principal = builder.target_name.ok_or_else(|| {
                Error::new(
                    ErrorKind::NoCredentials,
                    "Service target name (service principal name) is not provided",
                )
            })?;

            let mut context_requirements = builder.context_requirements;

            if client.krb5_user_to_user && !context_requirements.contains(ClientRequestFlags::USE_SESSION_KEY) {
                warn!(
                    "KRB5 U2U has been negotiated (selected by the server) but the USE_SESSION_KEY flag is not set. Forcibly turning it on..."
                );
                context_requirements.set(ClientRequestFlags::USE_SESSION_KEY, true);
            }

            // Cross-realm referral chasing (RFC 4120 §3.3.3.2 / MS-KILE).
            //
            // * [Cross-Realm Operation](https://www.rfc-editor.org/rfc/rfc4120.html#section-1.2)
            // * [Server Referrals](https://www.rfc-editor.org/rfc/rfc6806.html#section-8)
            //
            // A KDC can only issue tickets for principals in its own realm. When the requested
            // service lives in another realm (e.g. a user in `RJM.LOCAL` targeting a host in the
            // child realm `DEV.RJM.LOCAL`), the KDC does not return the service ticket. Instead it
            // returns a referral TGT whose `sname` is `krbtgt/<NEXT_REALM>`, and the client must
            // re-issue the TGS-REQ for the same service to `<NEXT_REALM>`'s KDC using that referral
            // TGT. We loop until the returned ticket's `sname` matches the requested service (i.e.
            // it is no longer a `krbtgt/...` referral).
            //
            // The referral hop is routed via `send_for_realm`, which resolves the target realm's
            // KDC through `SSPI_KDC_URL_<REALM>` (env) / krb5.conf / DNS SRV rather than the pinned
            // home-realm KDC, which cannot decrypt a `krbtgt/<NEXT_REALM>` referral ticket.
            const MAX_REFERRAL_HOPS: usize = 10;

            let mut realm = as_rep.0.crealm.0.to_string();
            let mut ticket = as_rep.0.ticket.0.clone();
            let mut tgt_session_key = session_key_1;
            // KDC-REP that the AP_REQ authenticator (cname/crealm) for the next hop is built from.
            let mut auth_rep = as_rep.0.clone();
            // Only meaningful for U2U; carried on the first hop and dropped afterwards.
            let mut additional_tickets = tgt_ticket.map(|ticket| vec![ticket]);
            let mut hops = 0;

            let (tgs_rep, session_key_2) = loop {
                let mut authenticator = generate_authenticator(GenerateAuthenticatorOptions {
                    kdc_rep: &auth_rep,
                    seq_num: Some(rand.next_u32()),
                    sub_key: None,
                    checksum: None,
                    channel_bindings: client.channel_bindings.as_ref(),
                    extensions: Vec::new(),
                })?;

                let tgs_req = generate_tgs_req(GenerateTgsReqOptions {
                    realm: &realm,
                    service_principal,
                    session_key: &tgt_session_key,
                    ticket,
                    authenticator: &mut authenticator,
                    additional_tickets: additional_tickets.take(),
                    enc_params: &client.encryption_params,
                    context_requirements,
                })?;

                let response = client
                    .send_for_realm(yield_point, &realm, &serialize_message(&tgs_req)?)
                    .await?;

                if response.len() < 4 {
                    return Err(Error::new(
                        ErrorKind::InternalError,
                        "the KDC reply message is too small: expected at least 4 bytes",
                    ));
                }

                // first 4 bytes are message len. skipping them
                let mut d = picky_asn1_der::Deserializer::new_from_bytes(&response[4..]);
                let tgs_rep: KrbResult<TgsRep> = KrbResult::deserialize(&mut d)?;
                let tgs_rep = tgs_rep?;

                let session_key =
                    extract_session_key_from_tgs_rep(&tgs_rep, &tgt_session_key, &client.encryption_params)?;

                // A referral TGT is identified by an `sname` of the form `krbtgt/<NEXT_REALM>`.
                let Some(next_realm) = referral_target_realm(&tgs_rep.0.ticket.0.0.sname.0) else {
                    debug!("TGS exchange finished successfully");
                    break (tgs_rep, session_key);
                };
                debug!(%realm, %next_realm, "Received cross-realm referral TGT; chasing referral");

                hops += 1;
                if hops >= MAX_REFERRAL_HOPS {
                    return Err(Error::new(
                        ErrorKind::NoAuthenticatingAuthority,
                        format!(
                            "exceeded maximum Kerberos referral hops ({MAX_REFERRAL_HOPS}) resolving {service_principal}"
                        ),
                    ));
                }
                if next_realm.eq_ignore_ascii_case(&realm) {
                    return Err(Error::new(
                        ErrorKind::NoAuthenticatingAuthority,
                        format!("Kerberos referral did not progress past realm `{realm}`"),
                    ));
                }

                ticket = tgs_rep.0.ticket.0.clone();
                tgt_session_key = session_key;
                auth_rep = tgs_rep.0;
                realm = next_realm;
            };

            client.encryption_params.session_key = Some(session_key_2);

            let enc_type = client
                .encryption_params
                .encryption_type
                .as_ref()
                .unwrap_or(&DEFAULT_ENCRYPTION_TYPE);
            let authenticator_sub_key = generate_random_symmetric_key(enc_type, &mut rand);

            // the original flag is
            // GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG
            // we want to be able to turn of sign and seal, so we leave confidentiality and integrity flags out
            let mut flags: GssFlags = builder.context_requirements.into();
            if flags.contains(GssFlags::GSS_C_DELEG_FLAG) {
                // Below are reasons why we turn off the GSS_C_DELEG_FLAG flag.
                //
                // RFC4121: The Kerberos Version 5 GSS-API. Section 4.1.1:  Authenticator Checksum
                // https://datatracker.ietf.org/doc/html/rfc4121#section-4.1.1.1
                //
                // "The length of the checksum field MUST be at least 24 octets when GSS_C_DELEG_FLAG is not set,
                // and at least 28 octets plus Dlgth octets when GSS_C_DELEG_FLAG is set."
                // Out implementation _always_ uses the 24 octets checksum and do not support Kerberos credentials delegation.
                //
                // "When delegation is used, a ticket-granting ticket will be transferred in a KRB_CRED message."
                // We do not support KRB_CRED messages. So, the GSS_C_DELEG_FLAG flags should be turned off.
                warn!("Kerberos ApReq Authenticator checksum GSS_C_DELEG_FLAG is not supported. Turning it off...");
                flags.remove(GssFlags::GSS_C_DELEG_FLAG);
            }
            debug!(?flags, "ApReq Authenticator checksum flags");

            let mut checksum_value = ChecksumValues::default();
            checksum_value.set_flags(flags);

            let authenticator_options = GenerateAuthenticatorOptions {
                kdc_rep: &tgs_rep.0,
                // The AP_REQ Authenticator sequence number should be the same as `seq_num` in the first Kerberos Wrap/MIC token generated
                // by the `encrypt_message`/`generate_mic_token` method. So, we set the next sequence number but do not increment the counter,
                // which will be incremented on each `encrypt_message`/`generate_mic_token` method call.
                seq_num: Some(client.seq_number + 1),
                sub_key: Some(EncKey {
                    key_type: enc_type.clone(),
                    key_value: authenticator_sub_key,
                }),

                checksum: Some(ChecksumOptions {
                    checksum_type: AUTHENTICATOR_CHECKSUM_TYPE.to_vec(),
                    checksum_value,
                }),
                channel_bindings: client.channel_bindings.as_ref(),
                extensions: Vec::new(),
            };

            let authenticator = generate_authenticator(authenticator_options)?;

            let ap_req = generate_ap_req(
                tgs_rep.0.ticket.0,
                client
                    .encryption_params
                    .session_key
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorKind::InternalError, "session key is not set"))?,
                &authenticator,
                &client.encryption_params,
                context_requirements.into(),
            )?;

            let encoded_neg_ap_req = if !builder.context_requirements.contains(ClientRequestFlags::USE_DCE_STYLE) {
                generate_krb_message(mech_id, AP_REQ_TOKEN_ID, ap_req)?
            } else {
                // Do not wrap if the `USE_DCE_STYLE` flag is set.
                // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/190ab8de-dc42-49cf-bf1b-ea5705b7a087
                picky_asn1_der::to_vec(&ap_req)?
            };

            let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
            output_token.buffer = encoded_neg_ap_req;

            client.state = KerberosState::ApExchange;

            SecurityStatus::ContinueNeeded
        }
        KerberosState::ApExchange => {
            let input = builder
                .input
                .as_ref()
                .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Input buffers must be specified"))?;
            let input_token = SecurityBuffer::find_buffer(input, BufferType::Token)?;

            if builder.context_requirements.contains(ClientRequestFlags::USE_DCE_STYLE) {
                // The `EC` field depends on the authentication type. For example, during RDP auth
                // it is equal to 0, but during RPC auth it is equal to EC.
                client.encryption_params.ec = EC;

                use picky_krb::messages::ApRep;

                let ap_rep: ApRep = picky_asn1_der::from_bytes(&input_token.buffer)?;

                let session_key = client
                    .encryption_params
                    .session_key
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorKind::InternalError, "session key is not set"))?;
                let sub_session_key =
                    extract_sub_session_key_from_ap_rep(&ap_rep, session_key, &client.encryption_params)?;
                let seq_number = extract_seq_number_from_ap_rep(&ap_rep, session_key, &client.encryption_params)?;

                trace!(?sub_session_key, "DCE AP_REP sub-session key");

                client.encryption_params.sub_session_key = Some(sub_session_key);

                let ap_rep = generate_ap_rep(session_key, seq_number, &client.encryption_params)?;
                let ap_rep = picky_asn1_der::to_vec(&ap_rep)?;

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
                output_token.buffer.write_all(&ap_rep)?;
            } else {
                let ap_rep = decode_krb_message::<ApRep>(&input_token.buffer, AP_REP_TOKEN_ID)?;

                let session_key = client
                    .encryption_params
                    .session_key
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorKind::InternalError, "session key is not set"))?;
                let sub_session_key =
                    extract_sub_session_key_from_ap_rep(&ap_rep, session_key, &client.encryption_params)?;

                client.encryption_params.sub_session_key = Some(sub_session_key);

                client.next_seq_number();
            }

            client.state = KerberosState::Final;
            SecurityStatus::Ok
        }
        KerberosState::Final | KerberosState::TgtExchange => {
            return Err(Error::new(
                ErrorKind::OutOfSequence,
                format!("got wrong Kerberos state: {:?}", client.state),
            ));
        }
    };

    trace!(output_buffers = ?builder.output);

    Ok(InitializeSecurityContextResult {
        status,
        flags: ClientResponseFlags::empty(),
        expiry: None,
    })
}

#[cfg(test)]
mod tests {
    use picky_asn1::restricted_string::IA5String;
    use picky_asn1::wrapper::{Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, IntegerAsn1};
    use picky_krb::constants::types::{NT_PRINCIPAL, NT_SRV_INST};
    use picky_krb::data_types::{KerberosStringAsn1, PrincipalName};

    use super::referral_target_realm;

    fn principal_name(name_type: u8, names: &[&str]) -> PrincipalName {
        PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![name_type])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(
                names
                    .iter()
                    .map(|n| KerberosStringAsn1::from(IA5String::from_string((*n).to_owned()).unwrap()))
                    .collect::<Vec<_>>(),
            )),
        }
    }

    #[test]
    fn referral_target_realm_detects_cross_realm_tgt() {
        // krbtgt/<NEXT_REALM> => chase into NEXT_REALM.
        let sname = principal_name(NT_SRV_INST, &["krbtgt", "DEV.RJM.LOCAL"]);
        assert_eq!(referral_target_realm(&sname), Some("DEV.RJM.LOCAL".to_owned()));
    }

    #[test]
    fn referral_target_realm_is_case_insensitive_on_service() {
        // The service component comparison must ignore case ("krbtgt" vs "KRBTGT").
        let sname = principal_name(NT_SRV_INST, &["KrbTgt", "CORP.EXAMPLE.COM"]);
        assert_eq!(referral_target_realm(&sname), Some("CORP.EXAMPLE.COM".to_owned()));
    }

    #[test]
    fn referral_target_realm_ignores_actual_service_ticket() {
        // A real service ticket (TERMSRV/host) is not a referral.
        let sname = principal_name(NT_SRV_INST, &["TERMSRV", "WIN-UE7FOENEK0D.dev.rjm.local"]);
        assert_eq!(referral_target_realm(&sname), None);
    }

    #[test]
    fn referral_target_realm_ignores_non_two_component_names() {
        // A lone "krbtgt" (one component) or a 3-component name is not a referral.
        assert_eq!(referral_target_realm(&principal_name(NT_PRINCIPAL, &["krbtgt"])), None);
        assert_eq!(
            referral_target_realm(&principal_name(NT_SRV_INST, &["krbtgt", "A.COM", "B.COM"])),
            None
        );
        assert_eq!(referral_target_realm(&principal_name(NT_SRV_INST, &[])), None);
    }

    #[test]
    fn referral_target_realm_ignores_non_krbtgt_two_component_service() {
        // Two components but not krbtgt (e.g. host-based service with an instance) is not a referral.
        let sname = principal_name(NT_SRV_INST, &["cifs", "fileserver.dev.rjm.local"]);
        assert_eq!(referral_target_realm(&sname), None);
    }
}
