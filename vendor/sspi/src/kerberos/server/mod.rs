pub(crate) mod as_exchange;
mod cache;
mod extractors;
mod generators;

use std::time::Duration;

use cache::AuthenticatorCacheRecord;
use picky::oids;
use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::{Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, IntegerAsn1};
use picky_krb::constants::gss_api::{AP_REP_TOKEN_ID, AP_REQ_TOKEN_ID, TGT_REP_TOKEN_ID, TGT_REQ_TOKEN_ID};
use picky_krb::constants::types::NT_SRV_INST;
use picky_krb::data_types::{AuthenticatorInner, KerberosStringAsn1, PrincipalName};
use picky_krb::gss_api::MechTypeList;
use picky_krb::messages::{ApRep, ApReq, TgtReq};
use rand::rngs::{StdRng, SysRng};
use rand_core::{Rng as _, SeedableRng as _};
use time::OffsetDateTime;

use self::cache::AuthenticatorsCache;
use self::extractors::{decrypt_ap_req_authenticator, decrypt_ap_req_ticket};
use self::generators::generate_ap_rep;
use crate::builders::FilledAcceptSecurityContext;
use crate::generator::YieldPointLocal;
use crate::kerberos::DEFAULT_ENCRYPTION_TYPE;
use crate::kerberos::client::extractors::extract_seq_number_from_ap_rep;
use crate::kerberos::flags::ApOptions;
use crate::kerberos::messages::{decode_krb_message, generate_krb_message};
use crate::kerberos::server::as_exchange::request_tgt;
use crate::kerberos::server::extractors::client_upn;
use crate::kerberos::server::generators::generate_tgt_rep;
use crate::{
    AcceptSecurityContextResult, BufferType, CredentialsBuffers, Error, ErrorKind, Kerberos, KerberosState, Result,
    Secret, SecurityBuffer, SecurityStatus, ServerRequestFlags, ServerResponseFlags, SspiImpl, Username,
};

/// Additional properties that are needed only for server-side Kerberos.
#[derive(Debug, Clone)]
pub struct ServerProperties {
    /// Supported mech types sent by the client in the first incoming message.
    /// We user them for checksum calculation during MIC token generation.
    pub mech_types: MechTypeList,
    /// Maximum allowed time difference between client and server clocks.
    /// It is recommended to set this value not greater then a few minutes.
    pub max_time_skew: Duration,
    /// Key that is used for TGS tickets decryption.
    /// It should be provided by the user during regular Kerberos auth. Or
    /// it will be established during AS exchange in the case of Kerberos U2U auth.
    pub ticket_decryption_key: Option<Secret<Vec<u8>>>,
    /// Name of the Kerberos service.
    pub service_name: PrincipalName,
    /// Additional service principals this acceptor will honor, each paired
    /// with its own ticket-decryption key. A single keytab routinely holds
    /// keys for several host SPNs (e.g. `kafka/localhost` and
    /// `kafka/host.docker.internal`); the acceptor must validate an incoming
    /// AP-REQ against whichever SPN the client's ticket actually names — not
    /// just one pinned name — matching the behavior of MIT/Heimdal GSSAPI
    /// acceptors that key off the whole keytab.
    pub additional_service_keys: Vec<(PrincipalName, Secret<Vec<u8>>)>,
    /// User credentials on whose behalf the TGT ticket will be requested.
    pub user: Option<CredentialsBuffers>,
    /// Username of the authenticated client.
    ///
    /// This field should be set by the Kerberos implementation after successful log on.
    pub client: Option<Username>,
    /// Authenticators cache.
    ///
    /// [Receipt of KRB_AP_REQ Message](https://www.rfc-editor.org/rfc/rfc4120#section-3.2.3):
    ///
    /// > The server MUST utilize a replay cache to remember any authenticator presented within the allowable clock skew.
    /// > The replay cache will store at least the server name, along with the client name, time,
    /// > and microsecond fields from the recently-seen authenticators, and if a matching tuple is found,
    /// > the error is returned.
    pub authenticators_cache: AuthenticatorsCache,
}

impl ServerProperties {
    /// Creates a new instance of [ServerProperties].
    pub fn new(
        sname: &[&str],
        user: Option<CredentialsBuffers>,
        max_time_skew: Duration,
        ticket_decryption_key: Option<Secret<Vec<u8>>>,
    ) -> Result<Self> {
        let service_names = sname
            .iter()
            .map(|sname| Ok(KerberosStringAsn1::from(IA5String::from_string((*sname).to_owned())?)))
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            mech_types: MechTypeList::from(Vec::new()),
            max_time_skew,
            ticket_decryption_key,
            service_name: PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(service_names)),
            },
            additional_service_keys: Vec::new(),
            user,
            client: None,
            authenticators_cache: AuthenticatorsCache::new(),
        })
    }

    /// Register an additional service principal (by name components, without
    /// realm) and its ticket-decryption key. The acceptor will accept an
    /// AP-REQ whose ticket names this principal in addition to the primary
    /// [`service_name`](Self::service_name).
    pub fn add_service_key(&mut self, sname: &[&str], key: Secret<Vec<u8>>) -> Result<()> {
        let service_names = sname
            .iter()
            .map(|sname| Ok(KerberosStringAsn1::from(IA5String::from_string((*sname).to_owned())?)))
            .collect::<Result<Vec<_>>>()?;
        let principal = PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(service_names)),
        };
        self.additional_service_keys.push((principal, key));
        Ok(())
    }

    /// Resolve the ticket-decryption key for an incoming AP-REQ whose ticket
    /// names `ticket_sname`. Matches the requested service principal against
    /// the primary [`service_name`](Self::service_name) and any
    /// [`additional_service_keys`](Self::additional_service_keys), comparing
    /// name components only (ignoring the PrincipalName `name-type`, per
    /// RFC 4120 §6.2). Returns the matching key, or `None` if no configured
    /// service principal matches.
    pub fn ticket_decryption_key_for(&self, ticket_sname: &PrincipalName) -> Option<&Secret<Vec<u8>>> {
        if self.service_name.name_string.0 == ticket_sname.name_string.0
            && let Some(key) = self.ticket_decryption_key.as_ref()
        {
            return Some(key);
        }
        self.additional_service_keys
            .iter()
            .find(|(spn, _)| spn.name_string.0 == ticket_sname.name_string.0)
            .map(|(_, key)| key)
    }
}

/// Performs one authentication step.
///
/// The user should call this function until it returns `SecurityStatus::Ok`.
pub async fn accept_security_context(
    server: &mut Kerberos,
    yield_point: &mut YieldPointLocal,
    builder: FilledAcceptSecurityContext<'_, <Kerberos as SspiImpl>::CredentialsHandle>,
) -> Result<AcceptSecurityContextResult> {
    let input = builder
        .input
        .as_ref()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "input buffers must be specified"))?;
    let input_token = SecurityBuffer::find_buffer(input, BufferType::Token)?;

    if server.state == KerberosState::TgtExchange {
        if let Ok(tgt_req) = if builder.context_requirements.contains(ServerRequestFlags::USE_DCE_STYLE) {
            picky_asn1_der::from_bytes::<TgtReq>(&input_token.buffer).map_err(Error::from)
        } else {
            decode_krb_message::<TgtReq>(&input_token.buffer, TGT_REQ_TOKEN_ID)
        } {
            // The first token is TGT_REQ. It means that the client wants to perform Kerberos U2U.

            if !builder
                .context_requirements
                .contains(ServerRequestFlags::USE_SESSION_KEY)
            {
                warn!(
                    "KRB5 U2U has been negotiated (requested by the client) but the USE_SESSION_KEY flag is not set."
                );
            }

            server.krb5_user_to_user = true;

            let credentials = server
                .server
                .as_ref()
                .ok_or_else(|| Error::new(ErrorKind::IncompleteCredentials, "Kerberos server configuration not present"))?
                .user
                .as_ref()
                .ok_or_else(|| Error::new(ErrorKind::IncompleteCredentials, "KRB5 U2U has been negotiated (requested by the client) but the user credentials are not preset in Kerberos server configuration"))?
                .clone();

            let tgt_rep = generate_tgt_rep(request_tgt(server, &credentials, &tgt_req, yield_point).await?);

            let mech_id = if server.krb5_user_to_user {
                oids::krb5_user_to_user()
            } else {
                oids::krb5()
            };

            let encoded_tgt_rep = if builder.context_requirements.contains(ServerRequestFlags::USE_DCE_STYLE) {
                picky_asn1_der::to_vec(&tgt_rep)?
            } else {
                generate_krb_message(mech_id, TGT_REP_TOKEN_ID, tgt_rep)?
            };

            let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
            output_token.buffer = encoded_tgt_rep;

            server.state = KerberosState::Preauthentication;

            return Ok(AcceptSecurityContextResult {
                status: SecurityStatus::ContinueNeeded,
                flags: ServerResponseFlags::empty(),
                expiry: None,
            });
        } else if let Ok(_ap_req) = if builder.context_requirements.contains(ServerRequestFlags::USE_DCE_STYLE) {
            picky_asn1_der::from_bytes::<ApReq>(&input_token.buffer).map_err(Error::from)
        } else {
            decode_krb_message::<ApReq>(&input_token.buffer, AP_REQ_TOKEN_ID)
        } {
            // The client may send ApReq instead of TgtReq in the first message.
            // It means that the client wants to perform regular Kerberos without U2U.
            // In that case, we just move Kerberos state to the next one and process further.
            server.state = KerberosState::Preauthentication;
        } else {
            return Err(Error::new(
                ErrorKind::InvalidToken,
                "invalid Kerberos token: expected TgtReq or ApReq",
            ));
        }
    }

    let status =
        match server.state {
            KerberosState::Preauthentication => {
                let ap_req = if builder.context_requirements.contains(ServerRequestFlags::USE_DCE_STYLE) {
                    picky_asn1_der::from_bytes::<ApReq>(&input_token.buffer)?
                } else {
                    decode_krb_message::<ApReq>(&input_token.buffer, AP_REQ_TOKEN_ID)?
                };

                let server_data = server.server.as_ref().ok_or_else(|| {
                    Error::new(
                        ErrorKind::InvalidHandle,
                        "Kerberos server properties are not initialized",
                    )
                })?;

                let ticket_service_name = &ap_req.0.ticket.0.0.sname.0;
                // Match the service principal by its name components only, ignoring
                // the PrincipalName `name-type`. RFC 4120 §6.2 treats the name-type
                // as a hint about how to interpret the components, not as part of
                // the principal's identity, and acceptors (MIT, Heimdal) key off
                // the components. Stock Kafka GSSAPI clients build the server
                // principal as NT-UNKNOWN/NT-PRINCIPAL while a `kafka/host` keytab
                // entry is NT-SRV-INST, so a name-type-sensitive comparison would
                // spuriously reject otherwise-valid tickets.
                //
                // A keytab may carry keys for several host SPNs; accept whichever
                // one the ticket actually names and decrypt with its key.
                let ticket_decryption_key = server_data.ticket_decryption_key_for(ticket_service_name).ok_or_else(
                    || {
                        Error::new(
                            ErrorKind::InvalidToken,
                            format!(
                                "invalid ticket service name ({:?}): no matching service key configured (primary {:?})",
                                ticket_service_name, server_data.service_name
                            ),
                        )
                    },
                )?;

                let ticket_enc_part = decrypt_ap_req_ticket(ticket_decryption_key, &ap_req)?;
                let session_key = Secret::new(ticket_enc_part.0.key.0.key_value.0.0.clone());

                let AuthenticatorInner {
                    authenticator_vno: _,
                    crealm,
                    cname,
                    cksum: _,
                    cusec,
                    ctime,
                    subkey,
                    seq_number,
                    authorization_data: _,
                } = decrypt_ap_req_authenticator(&session_key, &ap_req)?.0;

                // RFC 4121 §4.2: if the initiator places a subkey in its
                // Authenticator and the acceptor returns no subkey of its own
                // (i.e. no mutual-auth AP-REP), that initiator subkey — not the
                // ticket session key — becomes the key for per-message (wrap/MIC)
                // tokens. Stock Java/Kafka GSSAPI clients always send an
                // Authenticator subkey, so dropping it makes the security-layer
                // wrap fail the client's checksum. Capture it here; the non-mutual
                // branch below installs it as the sub-session key.
                let authenticator_subkey: Option<Secret<Vec<u8>>> =
                    subkey.0.as_ref().map(|key| Secret::new(key.0.key_value.0.0.clone()));

                // The initiator's Authenticator sequence number. Without a mutual-
                // auth AP-REP to carry an acceptor sequence number, GSS initiators
                // (e.g. Java) initialise the *expected* acceptor sequence to their
                // own initiator value, so the acceptor's per-message tokens must be
                // numbered from it or the initiator rejects them as "gap" tokens.
                let authenticator_seq_number: Option<u32> = seq_number.0.as_ref().map(|seq| {
                    let seq_number_bytes = &seq.0.0;
                    // IntegerAsn1 is big-endian and may carry a leading 0x00 sign
                    // byte; take the low 4 octets.
                    let mut buf = [0u8; 4];
                    let start = seq_number_bytes.len().saturating_sub(4);
                    let slice = &seq_number_bytes[start..];
                    buf[4 - slice.len()..].copy_from_slice(slice);
                    u32::from_be_bytes(buf)
                });

                // [3.2.3.  Receipt of KRB_AP_REQ Message](https://www.rfc-editor.org/rfc/rfc4120#section-3.2.3)
                // The name and realm of the client from the ticket are compared against the same fields in the authenticator.
                if ticket_enc_part.0.crealm.0 != crealm.0 || ticket_enc_part.0.cname != cname.0 {
                    return Err(Error::new(
                        ErrorKind::InvalidToken,
                        "the name and realm of the client in ticket and authenticator do not match",
                    ));
                }

                let now = OffsetDateTime::now_utc();
                let client_time = OffsetDateTime::try_from(ctime.0.0.clone())
                    .map_err(|err| Error::new(ErrorKind::InvalidToken, format!("client time is not valid: {err:?}")))?;
                let max_time_skew = server_data.max_time_skew;

                if (now - client_time).abs() > max_time_skew {
                    return Err(Error::new(
                        ErrorKind::TimeSkew,
                        "invalid authenticator ctime: time skew is too big",
                    ));
                }

                let ticket_start_time = ticket_enc_part
                    .0
                    .starttime
                    .0
                    .map(|start_time| start_time.0)
                    // [5.3.  Tickets](https://www.rfc-editor.org/rfc/rfc4120#section-5.3)
                    // If the starttime field is absent from the ticket, then the authtime field SHOULD be used in its place to determine
                    // the life of the ticket.
                    .unwrap_or_else(|| ticket_enc_part.0.auth_time.0)
                    .0;
                let ticket_start_time = OffsetDateTime::try_from(ticket_start_time).map_err(|err| {
                    Error::new(
                        ErrorKind::InvalidToken,
                        format!("ticket end time is not valid: {err:?}"),
                    )
                })?;
                if ticket_start_time > now + max_time_skew {
                    return Err(Error::new(
                        ErrorKind::InvalidToken,
                        "ticket not yet valid: ticket start time is greater than current time + max time skew",
                    ));
                }

                let ticket_end_time = OffsetDateTime::try_from(ticket_enc_part.0.endtime.0.0).map_err(|err| {
                    Error::new(
                        ErrorKind::InvalidToken,
                        format!("ticket end time is not valid: {err:?}"),
                    )
                })?;
                if now > ticket_end_time + max_time_skew {
                    return Err(Error::new(
                        ErrorKind::InvalidToken,
                        "ticket is expired: current time is greater than ticket end time + max time skew",
                    ));
                }

                let server_data = server.server.as_mut().ok_or_else(|| {
                    Error::new(
                        ErrorKind::InvalidHandle,
                        "Kerberos server properties are not initialized",
                    )
                })?;

                let cache_record = AuthenticatorCacheRecord {
                    cname: cname.0.clone(),
                    sname: ticket_service_name.clone(),
                    ctime: ctime.0.clone(),
                    microseconds: cusec.0.clone(),
                };
                if !server_data.authenticators_cache.contains(&cache_record) {
                    server_data.authenticators_cache.insert(cache_record);
                } else {
                    return Err(Error::new(
                        ErrorKind::InvalidToken,
                        "ApReq Authenticator replay detected",
                    ));
                }

                debug!("ApReq Ticket and Authenticator are valid!");

                server_data.client = Some(client_upn(&cname.0, &crealm.0)?);

                let ap_options_bytes = ap_req.0.ap_options.0.0.as_bytes();
                // [5.5.1.  KRB_AP_REQ Definition](https://www.rfc-editor.org/rfc/rfc4120#section-5.5.1)
                // The `ap-options` field has 32 bits or 4 bytes long. But it is encoded as BitStringAsn1, so the first byte
                // indicates the number of bits used. Thus, the overall number of expected bytes is 1 + 4 = 5.
                if ap_options_bytes.len() != 1 + 4 {
                    return Err(Error::new(
                        ErrorKind::InvalidToken,
                        format!(
                            "invalid ApReq ap-options: invalid data length: expected 5 bytes but got {}",
                            ap_options_bytes.len()
                        ),
                    ));
                }
                let ap_options = u32::from_be_bytes(ap_options_bytes[1..].try_into().map_err(|err| {
                    Error::new(ErrorKind::InvalidToken, format!("invalid ApReq ap-options: {err:?}"))
                })?);
                let ap_options = ApOptions::from_bits(ap_options)
                    .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "invalid ApReq ap-options"))?;

                // [3.2.4.  Generation of a KRB_AP_REP Message](https://www.rfc-editor.org/rfc/rfc4120#section-3.2.3)
                // ...the server need not explicitly reply to the KRB_AP_REQ. However, if mutual authentication is being performed,
                // the KRB_AP_REQ message will have MUTUAL-REQUIRED set in its ap-options field, and a KRB_AP_REP message
                // is required in response.
                let status = if ap_options.contains(ApOptions::MUTUAL_REQUIRED) {
                    let key_size = server
                        .encryption_params
                        .encryption_type
                        .as_ref()
                        .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
                        .cipher()
                        .key_size();
                    let mut sub_session_key = vec![0; key_size];

                    let mut rand = StdRng::try_from_rng(&mut SysRng)?;
                    rand.fill_bytes(&mut sub_session_key);
                    server.encryption_params.sub_session_key = Some(sub_session_key.into());

                    // [3.2.4.  Generation of a KRB_AP_REP Message](https://www.rfc-editor.org/rfc/rfc4120#section-3.2.3)
                    // A subkey MAY be included if the server desires to negotiate a different subkey.
                    // The KRB_AP_REP message is encrypted in the session key extracted from the ticket.
                    let ap_rep = generate_ap_rep(
                        &session_key,
                        ctime.0,
                        cusec.0,
                        (server.seq_number + 1).to_be_bytes().to_vec(),
                        &server.encryption_params,
                    )?;

                    let mech_id = if server.krb5_user_to_user {
                        oids::krb5_user_to_user()
                    } else {
                        oids::krb5()
                    };

                    let (status, encoded_ap_rep) =
                        if builder.context_requirements.contains(ServerRequestFlags::USE_DCE_STYLE) {
                            let encoded_ap_rep = picky_asn1_der::to_vec(&ap_rep)?;
                            server.state = KerberosState::ApExchange;

                            (SecurityStatus::ContinueNeeded, encoded_ap_rep)
                        } else {
                            let encoded_ap_rep = generate_krb_message(mech_id, AP_REP_TOKEN_ID, ap_rep)?;
                            server.state = KerberosState::Final;

                            (SecurityStatus::Ok, encoded_ap_rep)
                        };

                    let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
                    output_token.buffer = encoded_ap_rep;

                    status
                } else {
                    // No mutual auth requested: the server emits no AP-REP, but the
                    // GSS context is nonetheless established from a valid AP-REQ
                    // (RFC 4120 §3.2.4 — MUTUAL-REQUIRED only governs whether an
                    // AP-REP is returned, not whether the context is usable). Move
                    // to Final so subsequent wrap/unwrap (e.g. the SASL GSSAPI
                    // security-layer negotiation) succeed instead of erroring with
                    // "context is not established".
                    //
                    // Since we return no acceptor subkey, per-message tokens use the
                    // initiator's Authenticator subkey if it provided one (RFC 4121
                    // §4.2), falling back to the ticket session key otherwise.
                    if let Some(subkey) = authenticator_subkey {
                        server.encryption_params.sub_session_key = Some(subkey);
                    }

                    // Number our outgoing per-message tokens from the initiator's
                    // Authenticator sequence number. With no AP-REP to carry an
                    // acceptor sequence, GSS initiators set their *expected*
                    // acceptor sequence equal to their own initiator value, so the
                    // first acceptor wrap token must use that number or the
                    // initiator rejects it as a "gap" token. `next_seq_number()`
                    // pre-increments, so seed one below.
                    if let Some(seq) = authenticator_seq_number {
                        server.seq_number = seq.wrapping_sub(1);
                    }
                    server.state = KerberosState::Final;

                    SecurityStatus::Ok
                };

                server.encryption_params.session_key = Some(session_key);

                status
            }
            KerberosState::ApExchange => {
                if !builder.context_requirements.contains(ServerRequestFlags::USE_DCE_STYLE) {
                    return Err(Error::new(
                        ErrorKind::OutOfSequence,
                        "USE_DCE_STYLE flag must be set in context requirements",
                    ));
                }

                let ap_rep = picky_asn1_der::from_bytes::<ApRep>(&input_token.buffer)?;

                let session_key = server
                    .encryption_params
                    .session_key
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorKind::InternalError, "session key is not set"))?;
                let seq_number = extract_seq_number_from_ap_rep(&ap_rep, session_key, &server.encryption_params)?;
                let seq_number = u32::from_be_bytes(seq_number.try_into().map_err(|err| {
                    Error::new(
                        ErrorKind::InvalidToken,
                        format!("invalid ApRep sequence number: {:?}", err),
                    )
                })?);

                let expected_seq_number = server.seq_number + 1;
                if seq_number != expected_seq_number {
                    return Err(Error::new(
                        ErrorKind::InvalidToken,
                        format!(
                            "invalid client ApRep sequence number: expected {expected_seq_number} but got {seq_number}",
                        ),
                    ));
                }

                server.state = KerberosState::Final;

                SecurityStatus::Ok
            }
            KerberosState::Final | KerberosState::TgtExchange => {
                return Err(Error::new(
                    ErrorKind::OutOfSequence,
                    format!("got wrong Kerberos state: {:?}", server.state),
                ));
            }
        };

    Ok(AcceptSecurityContextResult {
        status,
        flags: ServerResponseFlags::empty(),
        expiry: None,
    })
}
