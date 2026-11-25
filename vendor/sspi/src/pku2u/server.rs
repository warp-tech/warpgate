//! PKU2U acceptor (server) state machine.
//!
//! Unlike regular Kerberos, a PKU2U acceptor is not a client of a real KDC: it *is* the KDC for the
//! single peer it is negotiating with. It self-issues the AS-REP/Ticket pair using a
//! Diffie-Hellman-negotiated transport key ([PKINIT](https://www.rfc-editor.org/rfc/rfc4556.html)) and
//! its own configured certificate, and later validates the initiator's AP-REQ against that very same
//! self-issued Ticket. See [`Pku2u::initialize_security_context_impl`](super::Pku2u) for the mirrored
//! initiator flow this acceptor must stay wire-compatible with.

use std::collections::VecDeque;
use std::io::Write as _;
use std::sync::{LazyLock, Mutex};

use picky_asn1::bit_string::BitString;
use picky_asn1::date::GeneralizedTime;
use picky_asn1::wrapper::{
    Asn1SequenceOf, Asn1SetOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2,
    ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6, ExplicitContextTag7,
    ExplicitContextTag9, ExplicitContextTag10, ImplicitContextTag0, IntegerAsn1, OctetStringAsn1, Optional,
};
use picky_asn1_der::Asn1RawDer;
use picky_asn1_x509::cmsversion::CmsVersion;
use picky_asn1_x509::content_info::{ContentValue, EncapsulatedContentInfo};
use picky_asn1_x509::signed_data::{
    CertificateChoices, CertificateSet, DigestAlgorithmIdentifiers, SignedData, SignersInfos,
};
use picky_asn1_x509::{AlgorithmIdentifier, oids};
use picky_krb::constants::gss_api::{AP_REP_TOKEN_ID, AS_REP_TOKEN_ID, AUTHENTICATOR_CHECKSUM_TYPE};
use picky_krb::constants::key_usages::{
    ACCEPTOR_SIGN, AP_REQ_AUTHENTICATOR, AS_REP_ENC, INITIATOR_SIGN, KEY_USAGE_FINISHED, TICKET_REP,
};
use picky_krb::constants::types::{AS_REP_MSG_TYPE, PA_PK_AS_REP, PA_PK_AS_REQ};
use picky_krb::crypto::diffie_hellman::{DhNonce, compute_public_key, generate_key, generate_private_key};
use picky_krb::crypto::{ChecksumSuite, CipherSuite};
use picky_krb::data_types::{
    Authenticator, AuthenticatorInner, EncTicketPart, EncTicketPartInner, EncryptedData, EncryptionKey, KerberosFlags,
    KerberosTime, LastReqInner, Microseconds, PaData, Ticket, TicketInner, TransitedEncoding,
};
use picky_krb::gss_api::{ApplicationTag0, GssApiNegInit, NegTokenTarg1};
use picky_krb::messages::{ApReq, AsRep, AsReq, EncAsRepPart, EncKdcRepPart, KdcRep};
use picky_krb::negoex::NegoexMessage;
use picky_krb::negoex::data_types::MessageType;
use picky_krb::negoex::messages::{Exchange, Nego, Verify};
use picky_krb::pkinit::{AuthPack, DhRepInfo, KdcDhKeyInfo, KrbFinished, PaPkAsRep, PaPkAsReq, Pku2uNegoReq};
use rand::rngs::{StdRng, SysRng};
use rand_core::SeedableRng as _;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use time::{Duration, OffsetDateTime};

use super::extractors::extract_krb_rep;
use super::generators::{
    GSS_EXTS_FINISHED, WELLKNOWN_REALM, generate_ap_rep, generate_as_req_username_from_certificate,
    generate_initial_neg_token_targ, generate_neg, generate_neg_token_targ, generate_pku2u_nego_rep,
    get_default_parameters,
};
use super::validate::validate_signed_data;
use super::{
    Pku2u, Pku2uState, decode_exchange_message, decode_nego_message, decode_verify_message, ensure_no_negoex_tail,
};
use crate::builders::FilledAcceptSecurityContext;
use crate::crypto::compute_md5_channel_bindings_hash;
use crate::generator::YieldPointLocal;
use crate::pk_init::{DH_NONCE_LEN, Wrapper, generate_signer_info};
use crate::pku2u::cert_utils::validation::{
    extract_signing_certificate, validate_peer_p2p_certificate, validate_server_p2p_certificate,
};
use crate::utils::generate_random_symmetric_key;
use crate::{
    AcceptSecurityContextResult, BufferType, Error, ErrorKind, KERBEROS_VERSION, Result, Secret, SecurityBuffer,
    SecurityStatus, ServerResponseFlags, SspiImpl, Username,
};

/// Maximum tolerated clock skew for PKINIT/Kerberos timestamp freshness checks. There is no
/// per-acceptor configuration for this in PKU2U (unlike `kerberos::server::ServerProperties`), so a
/// single, generous-but-bounded constant is used for both the AS-REQ `PKAuthenticator` and the AP-REQ
/// `Authenticator`/Ticket validity window.
const MAX_TIME_SKEW: Duration = Duration::minutes(5);
const MAX_AUTHENTICATOR_CACHE_ENTRIES: usize = 4096;

type AuthenticatorCache = Mutex<VecDeque<([u8; 32], i64)>>;

static AUTHENTICATOR_CACHE: LazyLock<AuthenticatorCache> = LazyLock::new(|| Mutex::new(VecDeque::new()));

/// [Ticket Flags](https://www.rfc-editor.org/rfc/rfc4120#section-5.2.8): `initial` (bit 9) — this
/// ticket was issued directly from an AS exchange, not a TGS exchange.
const TICKET_FLAG_INITIAL: u32 = 0x0040_0000;
/// [Ticket Flags](https://www.rfc-editor.org/rfc/rfc4120#section-5.2.8): `pre-authent` (bit 10) — the
/// client used pre-authentication (PKINIT, in this case) to obtain the ticket.
const TICKET_FLAG_PRE_AUTHENT: u32 = 0x0020_0000;

/// Performs one PKU2U acceptor authentication step. The caller invokes this repeatedly (feeding back
/// each output token as the next input) until the returned status is [`SecurityStatus::Ok`].
pub(crate) async fn accept_security_context(
    server: &mut Pku2u,
    _yield_point: &mut YieldPointLocal,
    builder: FilledAcceptSecurityContext<'_, <Pku2u as SspiImpl>::CredentialsHandle>,
) -> Result<AcceptSecurityContextResult> {
    server.read_channel_bindings(builder.input.as_deref())?;

    let input = builder
        .input
        .as_ref()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Input buffers must be specified"))?;
    let input_token = SecurityBuffer::find_buffer(input, BufferType::Token)?;

    let status = match server.state {
        Pku2uState::Preauthentication => {
            // The very first message of the whole conversation: a SPNEGO NegTokenInit whose mechToken
            // is `Nego(InitiatorNego) || Exchange(InitiatorMetaData)`. The acceptor does not yet know
            // the conversation id or auth scheme — both are established here, from the initiator.
            let neg_token_init: ApplicationTag0<GssApiNegInit> = picky_asn1_der::from_bytes(&input_token.buffer)?;
            let mech_token = neg_token_init
                .0
                .neg_token_init
                .0
                .mech_token
                .0
                .as_ref()
                .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Missing mech_token in NegTokenInit"))?
                .0
                .0
                .clone();

            let (initiator_nego, initiator_metadata_data) =
                decode_nego_message(&mech_token, MessageType::InitiatorNego)?;
            trace!(?initiator_nego, "NEGOEX INITIATOR NEGOTIATE");

            // These are, by protocol definition, always the first two messages of the conversation.
            check_sequence_number!(initiator_nego.header.sequence_num, 0);
            server.conversation_id = initiator_nego.header.conversation_id;

            let expected_auth_scheme = check_if_empty!(server.auth_scheme, "auth scheme is not set");
            if !initiator_nego.auth_schemes.contains(&expected_auth_scheme) {
                return Err(Error::new(
                    ErrorKind::InvalidToken,
                    format!(
                        "initiator did not offer our supported auth scheme {expected_auth_scheme:?}: {:?}",
                        initiator_nego.auth_schemes
                    ),
                ));
            }

            let (initiator_metadata, tail) =
                decode_exchange_message(initiator_metadata_data, MessageType::InitiatorMetaData)?;
            ensure_no_negoex_tail(tail)?;
            trace!(?initiator_metadata, "NEGOEX INITIATOR META DATA");

            check_conversation_id!(initiator_metadata.header.conversation_id, server.conversation_id);
            check_sequence_number!(initiator_metadata.header.sequence_num, 1);
            check_auth_scheme!(initiator_metadata.auth_scheme, server.auth_scheme);

            let nego_req: Pku2uNegoReq = picky_asn1_der::from_bytes(&initiator_metadata.exchange)?;
            let expected_realm = WELLKNOWN_REALM;
            if nego_req.body.0.realm.0.to_string() != expected_realm {
                return Err(Error::new(
                    ErrorKind::InvalidToken,
                    format!(
                        "unexpected PKU2U realm in InitiatorMetaData: expected {expected_realm}, got {}",
                        *nego_req.body.0.realm.0
                    ),
                ));
            }
            server.negoex_messages.extend_from_slice(&mech_token);

            let mut mech_token_out = Vec::new();
            let acceptor_nego = Nego::new(
                MessageType::AcceptorNego,
                server.conversation_id,
                server.next_seq_number(),
                server.negoex_random,
                vec![expected_auth_scheme],
                Vec::new(),
            );
            acceptor_nego.encode(&mut mech_token_out)?;

            let acceptor_metadata = Exchange::new(
                MessageType::AcceptorMetaData,
                server.conversation_id,
                server.next_seq_number(),
                expected_auth_scheme,
                picky_asn1_der::to_vec(&generate_pku2u_nego_rep(&server.config)?)?,
            );
            acceptor_metadata.encode(&mut mech_token_out)?;

            server.negoex_messages.extend_from_slice(&mech_token_out);

            let encoded_neg_token_targ = picky_asn1_der::to_vec(&generate_initial_neg_token_targ(mech_token_out)?)?;
            let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
            output_token.buffer.write_all(&encoded_neg_token_targ)?;

            server.state = Pku2uState::AsExchange;

            SecurityStatus::ContinueNeeded
        }
        Pku2uState::AsExchange => {
            let neg_token_targ: NegTokenTarg1 = picky_asn1_der::from_bytes(&input_token.buffer)?;
            let mech_token = neg_token_targ
                .0
                .response_token
                .0
                .as_ref()
                .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Missing response_token in NegTokenTarg"))?
                .0
                .0
                .clone();

            let (as_req_exchange, tail) = decode_exchange_message(&mech_token, MessageType::ApRequest)?;
            ensure_no_negoex_tail(tail)?;
            trace!(?as_req_exchange, "NEGOEX AS-REQ EXCHANGE");

            check_conversation_id!(as_req_exchange.header.conversation_id, server.conversation_id);
            check_sequence_number!(as_req_exchange.header.sequence_num, server.next_seq_number());
            check_auth_scheme!(as_req_exchange.auth_scheme, server.auth_scheme);

            server.negoex_messages.extend_from_slice(&mech_token);
            server.gss_api_messages.extend_from_slice(&as_req_exchange.exchange);

            let (as_req, _): (AsReq, _) = extract_krb_rep(&as_req_exchange.exchange)?;
            let as_rep = build_as_rep(server, &as_req)?;

            let exchange_data = picky_asn1_der::to_vec(&generate_neg(as_rep, AS_REP_TOKEN_ID))?;
            server.gss_api_messages.extend_from_slice(&exchange_data);

            let mut mech_token_out = Vec::new();
            let as_rep_exchange = Exchange::new(
                MessageType::ApRequest,
                server.conversation_id,
                server.next_seq_number(),
                check_if_empty!(server.auth_scheme, "auth scheme is not set"),
                exchange_data,
            );
            as_rep_exchange.encode(&mut mech_token_out)?;
            server.negoex_messages.extend_from_slice(&mech_token_out);

            let encoded_neg_token_targ = picky_asn1_der::to_vec(&generate_neg_token_targ(mech_token_out, false)?)?;
            let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
            output_token.buffer.write_all(&encoded_neg_token_targ)?;

            server.state = Pku2uState::ApExchange;

            SecurityStatus::ContinueNeeded
        }
        Pku2uState::ApExchange => {
            let neg_token_targ: NegTokenTarg1 = picky_asn1_der::from_bytes(&input_token.buffer)?;
            let mech_token = neg_token_targ
                .0
                .response_token
                .0
                .as_ref()
                .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Missing response_token in NegTokenTarg"))?
                .0
                .0
                .clone();

            let (ap_req_exchange, initiator_verify_data) =
                decode_exchange_message(&mech_token, MessageType::ApRequest)?;
            trace!(?ap_req_exchange, "NEGOEX AP-REQ EXCHANGE");

            check_conversation_id!(ap_req_exchange.header.conversation_id, server.conversation_id);
            check_sequence_number!(ap_req_exchange.header.sequence_num, server.next_seq_number());
            check_auth_scheme!(ap_req_exchange.auth_scheme, server.auth_scheme);

            let exchange_message_len = mech_token.len() - initiator_verify_data.len();
            server
                .negoex_messages
                .extend_from_slice(&mech_token[..exchange_message_len]);

            let (initiator_verify, tail) = decode_verify_message(initiator_verify_data)?;
            ensure_no_negoex_tail(tail)?;
            trace!(?initiator_verify, "NEGOEX INITIATOR VERIFY");

            check_conversation_id!(initiator_verify.header.conversation_id, server.conversation_id);
            check_sequence_number!(initiator_verify.header.sequence_num, server.next_seq_number());
            check_auth_scheme!(initiator_verify.auth_scheme, server.auth_scheme);

            let (ap_req, _): (ApReq, _) = extract_krb_rep(&ap_req_exchange.exchange)?;
            let validated = validate_ap_req(server, &ap_req)?;

            // Validate the initiator's transcript signature (NEGOEX `Verify`, RFC-4121-style GSS
            // checksum over every NEGOEX message exchanged so far, keyed with the Authenticator's
            // subkey and INITIATOR_SIGN key usage) *before* trusting anything derived from the AP-REQ.
            let checksum_type: usize = initiator_verify.checksum.checksum_type.try_into().map_err(|_| {
                Error::new(
                    ErrorKind::InvalidToken,
                    "NEGOEX checksum type is too big to fit into usize",
                )
            })?;
            let checksum_suite = ChecksumSuite::try_from(checksum_type)?;
            let expected_checksum_suite = check_if_empty!(
                server.encryption_params.encryption_type.as_ref(),
                "encryption type is not set"
            )
            .cipher()
            .checksum_type();
            if checksum_suite != expected_checksum_suite {
                return Err(Error::new(
                    ErrorKind::InvalidToken,
                    format!(
                        "invalid NEGOEX checksum type: expected {expected_checksum_suite:?}, got {checksum_suite:?}"
                    ),
                ));
            }
            let expected_initiator_checksum = checksum_suite.hasher().checksum(
                validated.authenticator_subkey.as_ref(),
                INITIATOR_SIGN,
                &server.negoex_messages,
            )?;
            if initiator_verify.checksum.checksum_value != expected_initiator_checksum {
                return Err(Error::new(
                    ErrorKind::MessageAltered,
                    "bad verify message signature from initiator",
                ));
            }

            record_authenticator(&ap_req, validated.client_time)?;
            server.remote_gss_seq_number = validated.remote_seq_number;
            server.peer_name = Some(validated.peer_name);
            server.negoex_messages.extend_from_slice(initiator_verify_data);

            // Generate a fresh acceptor sub-session key for this AP-REP. Per RFC 4121 §4.2, the
            // acceptor's own subkey (carried in the *last* message of context establishment)
            // supersedes the initiator's for all further per-message (Wrap/MIC) tokens.
            let encryption_type = check_if_empty!(
                server.encryption_params.encryption_type.as_ref(),
                "encryption type is not set"
            )
            .clone();
            let mut rng = StdRng::try_from_rng(&mut SysRng)?;
            let acceptor_subkey: Secret<Vec<u8>> = generate_random_symmetric_key(&encryption_type, &mut rng).into();
            server.encryption_params.sub_session_key = Some(acceptor_subkey.clone());

            let exchange_seq_number = server.next_seq_number();
            let verify_seq_number = server.next_seq_number();
            server.gss_seq_number = exchange_seq_number;

            let session_key = check_if_empty!(server.encryption_params.session_key.as_ref(), "session key is not set");
            let ap_rep = generate_ap_rep(
                session_key,
                validated.ctime,
                validated.cusec,
                exchange_seq_number,
                &acceptor_subkey,
                &encryption_type,
            )?;

            let mut mech_token_out = Vec::new();
            let ap_rep_exchange = Exchange::new(
                MessageType::ApRequest,
                server.conversation_id,
                exchange_seq_number,
                check_if_empty!(server.auth_scheme, "auth scheme is not set"),
                picky_asn1_der::to_vec(&generate_neg(ap_rep, AP_REP_TOKEN_ID))?,
            );
            ap_rep_exchange.encode(&mut mech_token_out)?;
            ap_rep_exchange.encode(&mut server.negoex_messages)?;

            let acceptor_checksum =
                checksum_suite
                    .hasher()
                    .checksum(acceptor_subkey.as_ref(), ACCEPTOR_SIGN, &server.negoex_messages)?;
            let verify = Verify::new(
                MessageType::Verify,
                server.conversation_id,
                verify_seq_number,
                check_if_empty!(server.auth_scheme, "auth scheme is not set"),
                u32::from(&checksum_suite),
                acceptor_checksum,
            );
            verify.encode(&mut mech_token_out)?;
            verify.encode(&mut server.negoex_messages)?;

            let encoded_neg_token_targ = picky_asn1_der::to_vec(&generate_neg_token_targ(mech_token_out, true)?)?;
            let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
            output_token.buffer.write_all(&encoded_neg_token_targ)?;

            server.state = Pku2uState::PubKeyAuth;

            SecurityStatus::Ok
        }
        _ => {
            return Err(Error::new(
                ErrorKind::OutOfSequence,
                format!("Got wrong PKU2U state: {:?}", server.state),
            ));
        }
    };

    Ok(AcceptSecurityContextResult {
        status,
        flags: ServerResponseFlags::empty(),
        expiry: None,
    })
}

/// Validates the initiator's signed PKINIT AS-REQ — the CMS `SignedData` signature over the
/// `AuthPack`, the signing certificate, and the `PKAuthenticator` content binding (`paChecksum`) to
/// `KDC-REQ-BODY` — and, on success, builds the self-issued AS-REP (with its own DH-signed
/// `PA-PK-AS-REP`) and Ticket in response. Populates `server.encryption_params.{encryption_type,
/// session_key}` and `server.ticket_encryption_key`, and updates `server.dh_parameters` with the
/// negotiated Diffie-Hellman values, mirroring what `Pku2u::initialize_security_context_impl` does
/// for the same fields on the initiator side.
fn build_as_rep(server: &mut Pku2u, as_req: &AsReq) -> Result<AsRep> {
    let kdc_req_body = &as_req.0.req_body.0;

    if kdc_req_body.realm.0.to_string() != WELLKNOWN_REALM {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            format!("unexpected PKU2U realm in AS-REQ: {}", *kdc_req_body.realm.0),
        ));
    }
    let cname = check_if_empty!(kdc_req_body.cname.0.as_ref(), "AS-REQ has no cname")
        .0
        .clone();
    let sname = check_if_empty!(kdc_req_body.sname.0.as_ref(), "AS-REQ has no sname")
        .0
        .clone();

    let pa_datas = as_req
        .0
        .padata
        .0
        .as_ref()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "AS-REQ has no pa-data"))?;
    let pa_pk_as_req_data = pa_datas
        .0
        .0
        .iter()
        .find(|pa_data| pa_data.padata_type.0.0 == PA_PK_AS_REQ)
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidToken,
                "AS-REQ is missing PA-PK-AS-REQ pre-authentication data",
            )
        })?;
    let pa_pk_as_req: PaPkAsReq = picky_asn1_der::from_bytes(&pa_pk_as_req_data.padata_data.0.0)?;

    // `signedAuthPack` carries a CMS `ContentInfo`-wrapped `SignedData` (unlike the reply's
    // `dhSignedData`, which is a bare `SignedData` — see `Pku2u::initialize_security_context_impl`'s
    // parsing of `dh_rep_info.dh_signed_data`).
    let wrapper: Wrapper<SignedData> = picky_asn1_der::from_bytes(&pa_pk_as_req.signed_auth_pack.0.0)?;
    if wrapper.content_info.0 != oids::signed_data() {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "PA-PK-AS-REQ signedAuthPack is not CMS SignedData",
        ));
    }
    let signed_data = wrapper.content.0;

    // `validate_server_p2p_certificate` is directionally-agnostic despite its name: it just extracts
    // the RSA public key of the first certificate embedded in `signed_data`. We reuse it here for the
    // *initiator's* certificate.
    let rsa_public_key = validate_server_p2p_certificate(&signed_data)?;
    validate_signed_data(&signed_data, &rsa_public_key)?;
    let client_certificate = extract_signing_certificate(&signed_data)?;
    validate_peer_p2p_certificate(&client_certificate, server.certificate_validation_time())?;
    if !server.config.trusted_client_certificates.contains(&client_certificate) {
        return Err(Error::new(
            ErrorKind::Pku2uCertFailure,
            "PKU2U initiator certificate is not trusted",
        ));
    }
    server.peer_certificate = Some(client_certificate.clone());
    server.peer_certificate_trusted = true;
    let expected_username = generate_as_req_username_from_certificate(&client_certificate)?;
    if cname.name_string.0.len() != 1 || cname.name_string.0[0].to_string() != expected_username {
        return Err(Error::new(
            ErrorKind::Pku2uCertFailure,
            "PKU2U initiator principal does not match its certificate",
        ));
    }

    if signed_data.content_info.content_type.0 != oids::pkinit_auth_data() {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "unexpected content type for the PKINIT AuthPack",
        ));
    }
    let auth_pack_bytes = match &signed_data
        .content_info
        .content
        .as_ref()
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidToken,
                "PA-PK-AS-REQ SignedData has no encapsulated content",
            )
        })?
        .0
    {
        ContentValue::OctetString(data) => &data.0,
        _ => {
            return Err(Error::new(
                ErrorKind::InvalidToken,
                "PA-PK-AS-REQ SignedData encapsulated content is not an octet string",
            ));
        }
    };
    let auth_pack: AuthPack = picky_asn1_der::from_bytes(auth_pack_bytes)?;

    // Content binding (RFC 4556 §3.2.1): `paChecksum` must be the SHA1 digest of `KDC-REQ-BODY`, which
    // binds this specific signed request to this specific AS-REQ and prevents it from being replayed
    // against a different one.
    let encoded_kdc_req_body = picky_asn1_der::to_vec(kdc_req_body)?;
    let mut sha1 = Sha1::new();
    sha1.update(&encoded_kdc_req_body);
    let expected_pa_checksum = sha1.finalize().to_vec();
    let pa_checksum = auth_pack
        .pk_authenticator
        .0
        .pa_checksum
        .0
        .as_ref()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "PKAuthenticator has no paChecksum"))?;
    if pa_checksum.0.0 != expected_pa_checksum {
        return Err(Error::new(
            ErrorKind::MessageAltered,
            "PKAuthenticator paChecksum does not match KDC-REQ-BODY",
        ));
    }

    let now = OffsetDateTime::now_utc();
    let client_time = OffsetDateTime::try_from(auth_pack.pk_authenticator.0.ctime.0.0.clone()).map_err(|err| {
        Error::new(
            ErrorKind::InvalidToken,
            format!("PKAuthenticator ctime is not valid: {err:?}"),
        )
    })?;
    if (now - client_time).abs() > MAX_TIME_SKEW {
        return Err(Error::new(
            ErrorKind::TimeSkew,
            "PKAuthenticator ctime is outside the allowed clock skew",
        ));
    }

    let cipher_suite = select_cipher_suite(&kdc_req_body.etype.0.0)?;

    let client_dh_req_info = auth_pack
        .client_public_value
        .0
        .as_ref()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "AuthPack has no client DH public value"))?;
    if client_dh_req_info.0.key_info.identifier.0 != oids::diffie_hellman() {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "AuthPack client public value does not use Diffie-Hellman",
        ));
    }
    let domain_params = &client_dh_req_info.0.key_info.key_info;
    let p = domain_params.p.as_unsigned_bytes_be().to_vec();
    let g = domain_params.g.as_unsigned_bytes_be().to_vec();
    let q = domain_params.q.as_unsigned_bytes_be().to_vec();
    let (expected_p, expected_g, expected_q) = get_default_parameters();
    if p != expected_p || g != expected_g || q != expected_q {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "PKU2U initiator proposed unsupported Diffie-Hellman parameters",
        ));
    }
    let client_public_value: IntegerAsn1 = picky_asn1_der::from_bytes(client_dh_req_info.0.key_value.payload_view())?;
    let client_public_value = client_public_value.as_unsigned_bytes_be().to_vec();

    let client_nonce = auth_pack
        .client_dh_nonce
        .0
        .as_ref()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "AuthPack has no client DH nonce"))?
        .0
        .0
        .clone();
    if client_nonce.len() != DH_NONCE_LEN {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            format!(
                "invalid client DH nonce length: {}. Expected: {DH_NONCE_LEN}",
                client_nonce.len()
            ),
        ));
    }

    let mut rng = StdRng::try_from_rng(&mut SysRng)?;
    let server_private_key = match generate_private_key(&q, &mut rng) {
        Ok(private_key) => private_key,
        Err(error) => match error {},
    };
    let server_public_value = compute_public_key(&server_private_key, &p, &g)?;

    server.dh_parameters.base = g;
    server.dh_parameters.modulus = p.clone();
    server.dh_parameters.q = q;
    server.dh_parameters.private_key = server_private_key.clone();
    server.dh_parameters.other_public_key = Some(client_public_value.clone());
    server.dh_parameters.client_nonce = Some(
        client_nonce
            .clone()
            .try_into()
            .map_err(|_| Error::new(ErrorKind::InvalidToken, "invalid client DH nonce length"))?,
    );

    let server_nonce = *check_if_empty!(server.dh_parameters.server_nonce.as_ref(), "server DH nonce is not set");

    // This is the DH-negotiated *transport* key: it protects the AS-REP's `EncKdcRepPart` in transit
    // and is discarded afterwards. The *real* session key used for the Ticket and all subsequent
    // messages is a freshly-generated, unrelated key (see `session_key` below) — mirroring exactly
    // how a real PKINIT KDC decouples the DH transport key from the ticket's session key.
    let dh_derived_key = generate_key(
        &client_public_value,
        &server_private_key,
        &p,
        Some(DhNonce {
            client_nonce: &client_nonce,
            server_nonce: &server_nonce,
        }),
        cipher_suite.cipher().as_ref(),
    )?;

    let mut rng = StdRng::try_from_rng(&mut SysRng)?;
    let session_key = generate_random_symmetric_key(&cipher_suite, &mut rng);
    let ticket_encryption_key = generate_random_symmetric_key(&cipher_suite, &mut rng);

    let now_krb_time = KerberosTime::from(GeneralizedTime::from(now));
    let ticket_flags = KerberosFlags::from(BitString::with_bytes(
        (TICKET_FLAG_INITIAL | TICKET_FLAG_PRE_AUTHENT).to_be_bytes().to_vec(),
    ));

    let enc_ticket_part = EncTicketPart::from(EncTicketPartInner {
        flags: ExplicitContextTag0::from(ticket_flags.clone()),
        key: ExplicitContextTag1::from(EncryptionKey {
            key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![u8::from(&cipher_suite)])),
            key_value: ExplicitContextTag1::from(OctetStringAsn1::from(session_key.clone())),
        }),
        crealm: ExplicitContextTag2::from(kdc_req_body.realm.0.clone()),
        cname: ExplicitContextTag3::from(cname.clone()),
        transited: ExplicitContextTag4::from(TransitedEncoding {
            tr_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![0])),
            contents: ExplicitContextTag1::from(OctetStringAsn1::from(Vec::new())),
        }),
        auth_time: ExplicitContextTag5::from(now_krb_time.clone()),
        starttime: Optional::from(Some(ExplicitContextTag6::from(now_krb_time.clone()))),
        endtime: ExplicitContextTag7::from(kdc_req_body.till.0.clone()),
        renew_till: Optional::from(None),
        caddr: Optional::from(None),
        authorization_data: Optional::from(None),
    });

    let cipher = cipher_suite.cipher();
    let encoded_enc_ticket_part = picky_asn1_der::to_vec(&enc_ticket_part)?;
    let encrypted_enc_ticket_part = cipher.encrypt(&ticket_encryption_key, TICKET_REP, &encoded_enc_ticket_part)?;

    let ticket = Ticket::from(TicketInner {
        tkt_vno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        realm: ExplicitContextTag1::from(kdc_req_body.realm.0.clone()),
        sname: ExplicitContextTag2::from(sname.clone()),
        enc_part: ExplicitContextTag3::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![u8::from(&cipher_suite)])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted_enc_ticket_part)),
        }),
    });

    let enc_kdc_rep_part = EncKdcRepPart {
        key: ExplicitContextTag0::from(EncryptionKey {
            key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![u8::from(&cipher_suite)])),
            key_value: ExplicitContextTag1::from(OctetStringAsn1::from(session_key.clone())),
        }),
        last_req: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![LastReqInner {
            lr_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![0])),
            lr_value: ExplicitContextTag1::from(now_krb_time.clone()),
        }])),
        nonce: ExplicitContextTag2::from(kdc_req_body.nonce.0.clone()),
        key_expiration: Optional::from(None),
        flags: ExplicitContextTag4::from(ticket_flags),
        auth_time: ExplicitContextTag5::from(now_krb_time.clone()),
        start_time: Optional::from(Some(ExplicitContextTag6::from(now_krb_time))),
        end_time: ExplicitContextTag7::from(kdc_req_body.till.0.clone()),
        renew_till: Optional::from(None),
        srealm: ExplicitContextTag9::from(kdc_req_body.realm.0.clone()),
        sname: ExplicitContextTag10::from(sname),
        caddr: Optional::from(None),
        encrypted_pa_data: Optional::from(None),
    };

    let encoded_enc_kdc_rep_part = picky_asn1_der::to_vec(&EncAsRepPart::from(enc_kdc_rep_part))?;
    let encrypted_enc_kdc_rep_part = cipher.encrypt(&dh_derived_key, AS_REP_ENC, &encoded_enc_kdc_rep_part)?;

    let pa_data = generate_pa_pk_as_rep(
        server,
        server_public_value,
        auth_pack.pk_authenticator.0.nonce.0.clone(),
    )?;

    server.encryption_params.encryption_type = Some(cipher_suite.clone());
    server.encryption_params.session_key = Some(session_key.into());
    server.ticket_encryption_key = Some(ticket_encryption_key.into());

    Ok(AsRep::from(KdcRep {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![AS_REP_MSG_TYPE])),
        padata: Optional::from(Some(ExplicitContextTag2::from(Asn1SequenceOf::from(vec![pa_data])))),
        crealm: ExplicitContextTag3::from(kdc_req_body.realm.0.clone()),
        cname: ExplicitContextTag4::from(cname),
        ticket: ExplicitContextTag5::from(ticket),
        enc_part: ExplicitContextTag6::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![u8::from(&cipher_suite)])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted_enc_kdc_rep_part)),
        }),
    }))
}

/// Builds the `PA-PK-AS-REP` pre-authentication data: a `DHRepInfo` whose `subjectPublicKey` is our
/// own DH public value and whose `dhSignedData` is a bare CMS `SignedData` (see `build_as_rep`'s note
/// on `signedAuthPack` vs. `dhSignedData` framing) signed with our own configured certificate.
fn generate_pa_pk_as_rep(server: &Pku2u, server_public_value: Vec<u8>, request_nonce: IntegerAsn1) -> Result<PaData> {
    let subject_public_key = BitStringAsn1::from(BitString::with_bytes(picky_asn1_der::to_vec(&IntegerAsn1::from(
        server_public_value,
    ))?));
    let kdc_dh_key_info = KdcDhKeyInfo {
        subject_public_key: ExplicitContextTag0::from(subject_public_key),
        nonce: ExplicitContextTag1::from(request_nonce),
        dh_key_expiration: Optional::from(None),
    };
    let encoded_kdc_dh_key_info = picky_asn1_der::to_vec(&kdc_dh_key_info)?;

    let mut sha1 = Sha1::new();
    sha1.update(&encoded_kdc_dh_key_info);
    let digest = sha1.finalize().to_vec();

    let private_key = server.config.private_key.clone();
    let mut sign_data = move |data: &[u8]| private_key.sign(data);
    let signed_data = SignedData {
        version: CmsVersion::V3,
        digest_algorithms: DigestAlgorithmIdentifiers(Asn1SetOf::from(vec![AlgorithmIdentifier::new_sha1()])),
        content_info: EncapsulatedContentInfo::new(oids::kpinit_dh_key_data(), Some(encoded_kdc_dh_key_info)),
        certificates: Optional::from(CertificateSet(vec![CertificateChoices::Certificate(Asn1RawDer(
            picky_asn1_der::to_vec(&server.config.p2p_certificate)?,
        ))])),
        crls: None,
        signers_infos: SignersInfos(Asn1SetOf::from(vec![generate_signer_info(
            &server.config.p2p_certificate,
            digest,
            &mut sign_data,
        )?])),
    };

    let dh_rep_info = DhRepInfo {
        dh_signed_data: ImplicitContextTag0::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&signed_data)?)),
        server_dh_nonce: Optional::from(Some(ExplicitContextTag1::from(OctetStringAsn1::from(
            check_if_empty!(server.dh_parameters.server_nonce.as_ref(), "server DH nonce is not set").to_vec(),
        )))),
    };
    let pa_pk_as_rep = PaPkAsRep::DhInfo(ExplicitContextTag0::from(dh_rep_info));

    Ok(PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_PK_AS_REP.to_vec())),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&pa_pk_as_rep)?)),
    })
}

/// Selects the first (highest-preference) encryption type offered in the AS-REQ's `KDC-REQ-BODY` that
/// this acceptor supports.
fn select_cipher_suite(offered: &[IntegerAsn1]) -> Result<CipherSuite> {
    offered
        .iter()
        .find_map(|etype| CipherSuite::try_from(etype.0.as_slice()).ok())
        .ok_or_else(|| {
            Error::new(
                ErrorKind::EncryptFailure,
                "none of the client's offered encryption types is supported",
            )
        })
}

/// The subset of a validated AP-REQ the caller needs to build the AP-REP and validate the initiator's
/// NEGOEX `Verify` message.
struct ValidatedApReq {
    ctime: KerberosTime,
    cusec: Microseconds,
    client_time: OffsetDateTime,
    authenticator_subkey: Secret<Vec<u8>>,
    remote_seq_number: u32,
    peer_name: Username,
}

/// Validates the initiator's AP-REQ against the Ticket this acceptor itself issued in [`build_as_rep`]:
/// decrypts the Ticket and Authenticator, checks their name/realm/time consistency (RFC 4120 §3.2.3),
/// validates channel bindings, and validates the "Finished" checksum extension binding the whole
/// AS-REQ/AS-REP transcript (the PKU2U analogue of a TLS Finished message).
fn validate_ap_req(server: &mut Pku2u, ap_req: &ApReq) -> Result<ValidatedApReq> {
    let ticket_key = check_if_empty!(
        server.ticket_encryption_key.as_ref(),
        "ticket encryption key is not set"
    );
    let ticket_enc_part = &ap_req.0.ticket.0.0.enc_part.0;
    let ticket_cipher = CipherSuite::try_from(ticket_enc_part.etype.0.0.as_slice())?.cipher();
    let decoded_enc_ticket_part =
        ticket_cipher.decrypt(ticket_key.as_ref(), TICKET_REP, &ticket_enc_part.cipher.0.0)?;
    let enc_ticket_part: EncTicketPart = picky_asn1_der::from_bytes(&decoded_enc_ticket_part)?;

    let session_key = check_if_empty!(server.encryption_params.session_key.as_ref(), "session key is not set");
    let authenticator_enc_part = &ap_req.0.authenticator.0;
    let authenticator_cipher = CipherSuite::try_from(authenticator_enc_part.etype.0.0.as_slice())?.cipher();
    let decoded_authenticator = authenticator_cipher.decrypt(
        session_key.as_ref(),
        AP_REQ_AUTHENTICATOR,
        &authenticator_enc_part.cipher.0.0,
    )?;
    let authenticator: Authenticator = picky_asn1_der::from_bytes(&decoded_authenticator)?;
    let AuthenticatorInner {
        crealm,
        cname,
        cksum,
        cusec,
        ctime,
        subkey,
        seq_number,
        ..
    } = &authenticator.0;

    // RFC 4120 §3.2.3: the name and realm of the client from the ticket and the authenticator must match.
    if enc_ticket_part.0.crealm.0 != crealm.0 || enc_ticket_part.0.cname.0 != cname.0 {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "the name and realm of the client in ticket and authenticator do not match",
        ));
    }

    let now = OffsetDateTime::now_utc();
    let client_time = OffsetDateTime::try_from(ctime.0.0.clone()).map_err(|err| {
        Error::new(
            ErrorKind::InvalidToken,
            format!("authenticator ctime is not valid: {err:?}"),
        )
    })?;
    if (now - client_time).abs() > MAX_TIME_SKEW {
        return Err(Error::new(
            ErrorKind::TimeSkew,
            "invalid authenticator ctime: time skew is too big",
        ));
    }

    let ticket_start_time = enc_ticket_part
        .0
        .starttime
        .0
        .clone()
        .map(|start_time| start_time.0)
        .unwrap_or_else(|| enc_ticket_part.0.auth_time.0.clone())
        .0;
    let ticket_start_time = OffsetDateTime::try_from(ticket_start_time).map_err(|err| {
        Error::new(
            ErrorKind::InvalidToken,
            format!("ticket start time is not valid: {err:?}"),
        )
    })?;
    if ticket_start_time > now + MAX_TIME_SKEW {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "ticket not yet valid: ticket start time is greater than current time + max time skew",
        ));
    }
    let ticket_end_time = OffsetDateTime::try_from(enc_ticket_part.0.endtime.0.0.clone()).map_err(|err| {
        Error::new(
            ErrorKind::InvalidToken,
            format!("ticket end time is not valid: {err:?}"),
        )
    })?;
    if now > ticket_end_time + MAX_TIME_SKEW {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "ticket is expired: current time is greater than ticket end time + max time skew",
        ));
    }

    let checksum = cksum
        .0
        .as_ref()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "authenticator has no checksum"))?;
    if checksum.0.cksumtype.0.0 != AUTHENTICATOR_CHECKSUM_TYPE {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            format!("unexpected authenticator checksum type: {:?}", checksum.0.cksumtype.0.0),
        ));
    }
    let Some((checksum_value, checksum_extensions)) = checksum.0.checksum.0.0.split_first_chunk::<24>() else {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "authenticator checksum is too short",
        ));
    };

    // Channel bindings (RFC 4121 §4.1.1): bytes [4..20) must be either the MD5 hash of the negotiated
    // channel bindings (if we were given any) or all-zero (if not).
    let expected_channel_binding_hash = match server.channel_bindings.as_ref() {
        Some(channel_bindings) => compute_md5_channel_bindings_hash(channel_bindings)?,
        None => [0; 16],
    };
    if checksum_value[4..20] != expected_channel_binding_hash {
        return Err(Error::new(
            ErrorKind::MessageAltered,
            "authenticator channel bindings do not match",
        ));
    }

    let authenticator_subkey: Secret<Vec<u8>> = subkey
        .0
        .as_ref()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "authenticator has no subkey"))?
        .0
        .key_value
        .0
        .0
        .clone()
        .into();

    // The "Finished" extension (draft-zhu-pku2u §6): a checksum over the whole AS-REQ/AS-REP GSS-API
    // transcript, proving the initiator saw the exact AS-REP we sent (and thus that nothing tampered
    // with it in transit).
    let finished_extension = find_authenticator_extension(checksum_extensions, GSS_EXTS_FINISHED).ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidToken,
            "authenticator checksum has no Finished (GSS_EXTS_FINISHED) extension",
        )
    })?;
    let finished: KrbFinished = picky_asn1_der::from_bytes(finished_extension)?;
    let checksum_suite = check_if_empty!(
        server.encryption_params.encryption_type.as_ref(),
        "encryption type is not set"
    )
    .cipher()
    .checksum_type();
    let expected_finished_checksum = checksum_suite.hasher().checksum(
        authenticator_subkey.as_ref(),
        KEY_USAGE_FINISHED,
        &server.gss_api_messages,
    )?;
    if finished.gss_mic.0.checksum.0.0 != expected_finished_checksum {
        return Err(Error::new(
            ErrorKind::MessageAltered,
            "bad Finished checksum: AS-REQ/AS-REP transcript does not match",
        ));
    }

    let remote_seq_number = parse_authenticator_seq_number(seq_number)
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "authenticator has no sequence number"))?;
    let Some(principal) = cname.0.name_string.0.first() else {
        return Err(Error::new(ErrorKind::InvalidToken, "authenticator cname is empty"));
    };
    let principal = principal.to_string();
    let (domain, account_name) = principal
        .split_once('\\')
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "PKU2U initiator name is not qualified"))?;
    let peer_name = Username::new_qualified_down_level_logon_name(account_name, domain);

    Ok(ValidatedApReq {
        ctime: ctime.0.clone(),
        cusec: cusec.0.clone(),
        client_time,
        authenticator_subkey,
        remote_seq_number,
        peer_name,
    })
}

fn record_authenticator(ap_req: &ApReq, client_time: OffsetDateTime) -> Result<()> {
    let digest = Sha256::digest(picky_asn1_der::to_vec(ap_req)?);
    let replay_key: [u8; 32] = digest.into();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let mut cache = AUTHENTICATOR_CACHE
        .lock()
        .map_err(|_| Error::new(ErrorKind::InternalError, "PKU2U authenticator cache lock is poisoned"))?;
    cache_authenticator(&mut cache, replay_key, client_time.unix_timestamp(), now)
}

fn cache_authenticator(
    cache: &mut VecDeque<([u8; 32], i64)>,
    replay_key: [u8; 32],
    client_time: i64,
    now: i64,
) -> Result<()> {
    cache.retain(|(_, expiry)| *expiry >= now);
    if cache.iter().any(|(cached, _)| cached == &replay_key) {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "PKU2U authenticator replay detected",
        ));
    }
    if cache.len() >= MAX_AUTHENTICATOR_CACHE_ENTRIES {
        return Err(Error::new(
            ErrorKind::InsufficientMemory,
            "PKU2U authenticator replay cache is full",
        ));
    }
    let expires_at = client_time
        .checked_add(MAX_TIME_SKEW.whole_seconds())
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "PKU2U authenticator expiry overflows"))?;
    cache.push_back((replay_key, expires_at));

    Ok(())
}

/// Parses an `Authenticator`'s optional `seq-number` field (a big-endian `UInt32` per RFC 4120 §5.5.1,
/// stored as a variable-length signed `IntegerAsn1`) into a plain `u32`.
fn parse_authenticator_seq_number(seq_number: &Optional<Option<ExplicitContextTag7<IntegerAsn1>>>) -> Option<u32> {
    let bytes = &seq_number.0.as_ref()?.0.0;
    let mut buf = [0u8; 4];
    let start = bytes.len().saturating_sub(4);
    let slice = &bytes[start..];
    buf[4 - slice.len()..].copy_from_slice(slice);
    Some(u32::from_be_bytes(buf))
}

/// Finds an [`AuthenticatorChecksumExtension`](crate::kerberos::client::generators::AuthenticatorChecksumExtension)-style
/// extension (as encoded by `generate_authenticator`: 4-byte big-endian type, 4-byte big-endian
/// length, then the raw value, repeated) within the extensions area of an authenticator checksum.
fn find_authenticator_extension(mut extensions: &[u8], extension_type: u32) -> Option<&[u8]> {
    while !extensions.is_empty() {
        let ty = u32::from_be_bytes(extensions.get(0..4)?.try_into().ok()?);
        let len = usize::try_from(u32::from_be_bytes(extensions.get(4..8)?.try_into().ok()?)).ok()?;
        let value_end = 8usize.checked_add(len)?;
        let value = extensions.get(8..value_end)?;
        if ty == extension_type {
            return Some(value);
        }
        extensions = &extensions[value_end..];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticator_cache_retains_future_dated_entries_for_the_full_acceptance_window() {
        let mut cache = VecDeque::new();
        let now = 1_000;
        let client_time = now + MAX_TIME_SKEW.whole_seconds();

        cache_authenticator(&mut cache, [1; 32], client_time, now).unwrap();

        assert_eq!(cache.front().unwrap().1, now + 2 * MAX_TIME_SKEW.whole_seconds());
    }

    #[test]
    fn authenticator_cache_does_not_evict_live_entries_at_capacity() {
        let now = 1_000;
        let mut cache = (0..MAX_AUTHENTICATOR_CACHE_ENTRIES)
            .map(|index| {
                let mut key = [0; 32];
                key[..8].copy_from_slice(&u64::try_from(index).unwrap().to_le_bytes());
                (key, now + 1)
            })
            .collect::<VecDeque<_>>();
        let first = cache.front().copied().unwrap();

        let error = cache_authenticator(&mut cache, [0xff; 32], now, now).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::InsufficientMemory);
        assert_eq!(cache.len(), MAX_AUTHENTICATOR_CACHE_ENTRIES);
        assert_eq!(cache.front().copied(), Some(first));
    }
}
