//! Per-connection Oracle session: a TNS/TTC relay that terminates O5LOGON on both
//! legs, with Warpgate's shared database authorization and SQL audit.
//!
//! The session opens the **real** database leg before the client authenticates
//! and relays its genuine handshake, so the client negotiates against the
//! actual database. That is what makes both thin (python-oracledb, JDBC thin,
//! go-ora) and thick/OCI clients work: a thick client's SNS/ANO packet is
//! answered by the real database, not by us.
//!
//! 1. **Dual-mode TCP/TCPS**: a first byte of 0x16 (a TLS ClientHello) means
//!    TCPS, TLS from the first byte; anything else is a plain-TCP CONNECT.
//! 2. **Routing**: the client's CONNECT descriptor names a `SERVICE_NAME`; the
//!    one Oracle target configured with that service name (case-insensitively)
//!    is selected. None or more than one ⇒ TNS REFUSE.
//! 3. **Database leg**: the gateway connects to the target and sends the
//!    client's CONNECT with the descriptor replaced by one built from the
//!    target's configuration ([`target_descriptor`]), so the session can only
//!    reach the authorized service. The real ACCEPT and negotiation are relayed
//!    to the client; until the client's AUTH1 only negotiation packets pass —
//!    a function call or piggyback ends the connection.
//! 4. **O5LOGON with the client**: the gateway runs its own phase one on the
//!    database leg and answers the client with the database's phase-one RETURN
//!    carrying a challenge from the user's stored 12c verifier (a deterministic
//!    decoy when there is none, so unknown usernames are not revealed). From the
//!    client's AUTH2 it recovers the password.
//! 5. **Authorization** goes through [`run_db_authorization`], exactly as for
//!    PostgreSQL and MySQL: IP block, user lockout, the password checked against
//!    the user's Warpgate password credential, credential policy, failed-attempt
//!    accounting, target authorization and administrator approval. A policy that
//!    needs a factor Oracle cannot carry (OTP, web approval) denies the login.
//! 6. **Database login**: the gateway answers the database's challenge with the
//!    target's credentials, checks the database's own proof, and hands the
//!    client the database's phase-two RETURN with only `AUTH_SVR_RESPONSE`
//!    swapped. TTC is then relayed both ways with the SQL audit.
//!
//! Everything before authorization runs under [`LOGIN_TIMEOUT`], and the
//! listener caps how many logins may be in progress at once, because each holds
//! a database connection.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use rustls::ServerConfig;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit};
use tokio::task::JoinHandle;
use tracing::{info, info_span, warn};
use url::Url;
use warpgate_common::auth::AuthSelector;
use warpgate_common::{Protocol, Secret, TargetOptions, TargetOracleOptions, UserSessionId};
use warpgate_core::{
    AuthOkPermit, ConfigProvider, DbAuthTransport, Services, WarpgateServerHandle,
    run_db_authorization,
};
use warpgate_oracle_tns::client_info::{ClientInfo, ReportedClient};
use warpgate_oracle_tns::constants::{field_version, version};
use warpgate_oracle_tns::handshake::{
    build_refuse, data_payload, disable_oob, parse_connect, target_descriptor, with_connect_data,
};
use warpgate_oracle_tns::negotiation::{
    ThickLayout, is_thick_request, parse_auth_request_pairs, parse_auth1_request,
    parse_auth2_request, parse_client_datatypes, server_protocol_field_version,
};
use warpgate_oracle_tns::o5logon::{
    Verifier12c, recover_password, server_combo_key, server_response, server_sesskey,
    verify_password,
};
use warpgate_oracle_tns::server_auth::{
    build_phase_one_return, substitute_svr_response, substitute_svr_response_thick,
};
use warpgate_oracle_tns::ttc::AuthPair;
use warpgate_tls::{MaybeTlsStream, PrefixedStream};

use crate::client::{
    Negotiated, TargetLeg, connect_and_accept, db_auth_phase_one, db_auth_phase_two, desc_field,
    resolve_password, set_db_server_time_zone, target_uses_tls,
};
use crate::error::OracleError;
use crate::stream::{ServerStream, TargetStream, random_fixed, read_packet, ttc_func, ttc_type};

/// TLS record ContentType for a handshake (ClientHello) — the first byte of a
/// TCPS connection. A plain TNS CONNECT's first byte is the packet-length high
/// byte (0x00 for the sub-256-byte CONNECT), so 0x16 cleanly selects TCPS.
const TLS_HANDSHAKE_RECORD: u8 = 0x16;

/// How long an unauthenticated client has to finish the handshake and send its
/// AUTH2. The database connection opened for it is held no longer than this.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(60);

/// How long the gateway's own login to the database may take once the user is
/// authorized.
const DB_LOGIN_TIMEOUT: Duration = Duration::from_secs(30);

const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_mins(10);

/// TTC message types and AUTH function codes (`TNS_MSG_TYPE_*`, `TNS_FUNC_*`).
const TTC_FUNCTION: u8 = 3;
const TTC_PIGGYBACK: u8 = 17;
const FUNC_AUTH_PHASE_ONE: u8 = 118;
const FUNC_AUTH_PHASE_TWO: u8 = 115;

type ClientStream<S> = ServerStream<PrefixedStream<S>>;

pub struct OracleSession<S: AsyncRead + AsyncWrite + Send + Unpin> {
    services: Services,
    server_handle: Arc<Mutex<WarpgateServerHandle>>,
    id: UserSessionId,
    remote_address: SocketAddr,
    tls_config: Arc<ServerConfig>,
    stream: S,
    login_permit: OwnedSemaphorePermit,
}

/// A connection that has completed O5LOGON with the client, before Warpgate
/// authorization.
struct ClientLogin<S: AsyncRead + AsyncWrite + Send + Unpin> {
    cr: ReadHalf<ClientStream<S>>,
    cw: WriteHalf<ClientStream<S>>,
    db: TargetLeg,
    negotiated: Negotiated,
    target_name: String,
    options: TargetOracleOptions,
    username: String,
    client_descriptor: String,
    client_pairs: Vec<AuthPair>,
    db_ret1: Vec<u8>,
    /// The client-leg combo key; `None` when the client's key material was
    /// malformed, in which case the login is denied before it is needed.
    combo_key: Option<[u8; 32]>,
    /// The password the client proved, or empty when O5LOGON failed — either
    /// way it is what Warpgate's password check sees.
    password: Secret<String>,
}

/// The result of the unauthenticated part of a login.
enum PreAuth<S: AsyncRead + AsyncWrite + Send + Unpin> {
    LoggedIn(Box<ClientLogin<S>>),
    /// The connection was refused or the client went away; nothing to do.
    Done,
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin + 'static> OracleSession<S> {
    pub async fn new(
        server_handle: Arc<Mutex<WarpgateServerHandle>>,
        services: Services,
        stream: S,
        tls_config: ServerConfig,
        remote_address: SocketAddr,
        login_permit: OwnedSemaphorePermit,
    ) -> Self {
        let id = server_handle.lock().await.user_session_id();
        Self {
            services,
            server_handle,
            id,
            remote_address,
            tls_config: Arc::new(tls_config),
            stream,
            login_permit,
        }
    }

    pub fn make_logging_span(&self) -> tracing::Span {
        let client_ip = self.remote_address.ip().to_string();
        info_span!("Oracle", session = %self.id, %client_ip)
    }

    pub async fn run(self) -> Result<(), OracleError> {
        let Self {
            services,
            server_handle,
            id,
            remote_address,
            tls_config,
            stream,
            login_permit,
        } = self;

        let login = if let Ok(result) = tokio::time::timeout(
            LOGIN_TIMEOUT,
            client_login(&services, stream, tls_config, remote_address),
        )
        .await
        {
            result?
        } else {
            warn!("Oracle login did not complete within {LOGIN_TIMEOUT:?}; closing");
            return Ok(());
        };
        let PreAuth::LoggedIn(login) = login else {
            return Ok(());
        };
        let ClientLogin {
            cr,
            mut cw,
            mut db,
            negotiated,
            target_name,
            options,
            username,
            client_descriptor,
            client_pairs,
            db_ret1,
            combo_key,
            password,
        } = *login;

        // --- Warpgate authorization, shared with PostgreSQL and MySQL ---
        let selector = AuthSelector::User {
            username: username.clone(),
            target_name: target_name.clone(),
        };
        let mut transport = OracleAuthTransport {
            password: Some(password),
        };
        let Some(approved) =
            run_db_authorization(&mut transport, &services, id, selector, remote_address.ip())
                .await?
        else {
            info!(user = %username, target = %target_name, "Oracle login denied");
            return Ok(());
        };
        let Some(combo_key) = combo_key else {
            return Err(OracleError::Protocol(
                "authorized a login without a client-leg session key".into(),
            ));
        };
        let approved = approved.narrow::<TargetOracleOptions>()?;
        if approved.target().name != target_name {
            return Err(OracleError::Protocol(
                "authorized target differs from the routed one".into(),
            ));
        }
        let admitted = server_handle
            .lock()
            .await
            .register_approved_target_session(approved)
            .await?;
        info!(user = %username, target = %target_name, "Oracle user authenticated");

        // --- the gateway's own login to the database, then hand the client the
        //     database's session RETURN with only the proof swapped ---
        let reported = ReportedClient::from_login(&client_descriptor, &client_pairs);
        let db_login = async {
            let password = resolve_password(admitted.options(), &*services.secret_backends).await?;
            let db_ret2 = db_auth_phase_two(
                &mut db,
                &db_ret1,
                admitted.options().username.as_bytes(),
                password.as_bytes(),
                &reported,
                negotiated,
            )
            .await?;
            // Run the session in the database server's own time zone. Best
            // effort: a failure leaves the session usable, just in DBTIMEZONE.
            if let Err(e) = set_db_server_time_zone(&mut db, negotiated).await {
                warn!(error = %e, "Could not set the session to the database server's time zone");
            }
            Ok::<_, OracleError>(db_ret2)
        };
        let db_ret2 = tokio::time::timeout(DB_LOGIN_TIMEOUT, db_login)
            .await
            .map_err(|_| {
                OracleError::Protocol("login to the target database timed out".into())
            })??;

        let proof = server_response(&combo_key, &random_fixed::<16>());
        let client_ret2 = if negotiated.thick_layout.is_some() {
            substitute_svr_response_thick(&db_ret2, &proof)?
        } else {
            substitute_svr_response(&db_ret2, &proof)?
        };
        cw.write_all(&client_ret2).await?;
        cw.flush().await?;
        drop(login_permit);
        info!("Oracle login established; relaying TTC");

        // --- relay TTC both ways, auditing each client EXECUTE ---
        let idle_timeout = match parse_idle_timeout(options.idle_timeout.as_deref()) {
            IdlePolicy::Disabled => None,
            IdlePolicy::Timeout(timeout) => Some(timeout),
        };
        let activity = Arc::new(Activity::new());
        let (dr, dw) = db.into_split();
        tokio::select! {
            () = pump_client_to_db(cr, dw, negotiated, activity.clone()) => {}
            () = pump_db_to_client(dr, cw, negotiated.large, activity.clone()) => {}
            () = watch_idle(idle_timeout, activity) => {}
        }
        Ok(())
    }
}

/// Everything up to and including the client's AUTH2, run under
/// [`LOGIN_TIMEOUT`] by the caller.
async fn client_login<S: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    services: &Services,
    mut stream: S,
    tls_config: Arc<ServerConfig>,
    remote_address: SocketAddr,
) -> Result<PreAuth<S>, OracleError> {
    // --- dual-mode TCP / TCPS: the peeked byte is replayed via PrefixedStream
    //     so the stream stays intact for the TLS handshake or the first read ---
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).await?;
    let prefixed = PrefixedStream::new(stream, Bytes::copy_from_slice(&first));
    let client_stream: ClientStream<S> = MaybeTlsStream::new(prefixed);
    let mut client_stream = if first == [TLS_HANDSHAKE_RECORD] {
        client_stream.upgrade(tls_config, Bytes::new()).await?
    } else {
        client_stream
    };

    // --- client CONNECT (2-byte length during the handshake); the descriptor is
    //     inline or in a follow-on DATA packet ---
    let connect = read_packet(&mut client_stream, false).await?;
    let creq = parse_connect(&connect)?;
    let mut descriptor = creq.connect_data.clone();
    if !creq.connect_data_complete {
        let more = read_packet(&mut client_stream, false).await?;
        if let Ok(payload) = data_payload(&more) {
            descriptor.extend_from_slice(payload);
        }
    }
    let client_descriptor = String::from_utf8_lossy(&descriptor).into_owned();

    // --- route to the target by the descriptor's SERVICE_NAME ---
    let Some(service_name) = desc_field(&client_descriptor, "SERVICE_NAME=") else {
        refuse(&mut client_stream, "no SERVICE_NAME in connect descriptor").await?;
        warn!("Oracle CONNECT carried no SERVICE_NAME; refusing");
        return Ok(PreAuth::Done);
    };
    let Some((target_name, options)) = resolve_oracle_target(services, &service_name).await? else {
        refuse(&mut client_stream, "unknown service name").await?;
        warn!(service_name = ?service_name, "No single Oracle target for SERVICE_NAME; refusing");
        return Ok(PreAuth::Done);
    };

    // --- don't spend a database connection on an IP login protection has
    //     already blocked; a lookup error fails closed ---
    let remote_ip = remote_address.ip();
    if let Some(block_info) = services
        .login_protection
        .check_ip_blocked(&remote_ip)
        .await?
    {
        warn!(ip = %remote_ip, expires_at = %block_info.expires_at, "Oracle auth from blocked IP; refusing");
        return Ok(PreAuth::Done);
    }

    // --- open the database leg with the target's own descriptor, and relay the
    //     real ACCEPT to the client ---
    let use_tls = target_uses_tls(&options);
    let Some(service) = options.service_name.as_deref() else {
        return Err(OracleError::Protocol(
            "routed target has no service name".into(),
        ));
    };
    let db_descriptor = target_descriptor(
        use_tls,
        &options.host,
        options.port,
        service,
        &client_descriptor,
    )
    .ok_or_else(|| {
        OracleError::Protocol("target host or service name unusable in a connect descriptor".into())
    })?;
    let mut packets = with_connect_data(&connect, db_descriptor.as_bytes())?;
    // We cannot relay TCP urgent data, so have the database negotiate in-band
    // breaks instead of an OOB break check that would stall the login.
    if let Some(first_packet) = packets.first_mut() {
        disable_oob(first_packet)?;
    }
    let client_hello = packets.concat();
    let (db_stream, db_accept) = connect_and_accept(
        &options.host,
        options.port,
        use_tls,
        options.tls.verify,
        &client_hello,
    )
    .await?;
    // version >= 315 => DATA packets use the 4-byte large-SDU length form; the
    // client adopts the same version from the relayed ACCEPT, so one `large`
    // governs the framing on both legs.
    let srv_version = u16::from_be_bytes([
        db_accept.get(8).copied().unwrap_or(0),
        db_accept.get(9).copied().unwrap_or(0),
    ]);
    let large = srv_version >= version::MIN_LARGE_SDU;
    client_stream.write_all(&relay_accept(db_accept)).await?;
    client_stream.flush().await?;

    // --- relay the pre-auth negotiation until AUTH1. Both directions run
    //     concurrently: a thick/OCI client pipelines PROTOCOL/DATATYPE and an
    //     SNS/ANO packet before AUTH1, so a lockstep relay deadlocks. By the
    //     time AUTH1 arrives the client has consumed every negotiation reply,
    //     so the stop signal cancels the DB->client task at a packet boundary
    //     and hands its halves back. ---
    let (mut cr, cw) = split(client_stream);
    let (dr, mut dw) = split(db_stream);
    let stop = Arc::new(Notify::new());
    let mut db_relay = AbortOnDrop(tokio::spawn(relay_negotiation_replies::<S>(
        dr,
        cw,
        large,
        stop.clone(),
    )));
    // Keep the client's (first) DATATYPES: whether it set CONV_LENGTH, which
    // fixes the encoding of CHR fields (username, SQL text) on this leg, and
    // the field version it settled on.
    let mut client_datatypes = None;
    let auth1 = loop {
        let pkt = read_packet(&mut cr, large).await?;
        let msg_type = (pkt.get(4) == Some(&0x06))
            .then(|| ttc_type(&pkt))
            .flatten();
        match (msg_type, ttc_func(&pkt)) {
            (Some(TTC_FUNCTION), Some(FUNC_AUTH_PHASE_ONE)) => break pkt,
            // Nothing but negotiation may reach the database before the user
            // is authenticated.
            (Some(TTC_FUNCTION | TTC_PIGGYBACK), _) => {
                warn!("Oracle client sent a call before authenticating; closing");
                return Ok(PreAuth::Done);
            }
            _ => {}
        }
        if client_datatypes.is_none() {
            client_datatypes = parse_client_datatypes(&pkt);
        }
        dw.write_all(&pkt).await?;
        dw.flush().await?;
    };
    stop.notify_one();
    let (dr, mut cw, observed_field_version) = (&mut db_relay.0)
        .await
        .map_err(|e| OracleError::Protocol(format!("pre-auth relay task failed: {e}")))?;
    let mut db = TargetLeg::new(dr, dw);

    // The TTC field version negotiated with the real server governs whether the
    // thin AUTH / EXECUTE preambles carry a `token_num` ub8. Prefer the value
    // seen in the server's PROTOCOL response; failing that, map the ACCEPT's
    // TNS version (23ai's 323+ carries token_num, 19c's 318 does not). The
    // session runs at the lower of the client's and the server's.
    let server_field_version = observed_field_version.unwrap_or(if srv_version >= 323 {
        field_version::TOKEN_NUM_MIN
    } else {
        field_version::PRE_23AI
    });
    let ttc_field_version = client_datatypes
        .and_then(|d| d.field_version)
        .map_or(server_field_version, |client| {
            client.min(server_field_version)
        });
    // Without a DATATYPES we cannot know the CHR encoding; assume the
    // python-oracledb form and say so, as the SQL audit may then be off.
    let conv_length = client_datatypes.map_or_else(
        || {
            warn!(
                "Oracle client sent no DATATYPES before AUTH; assuming length-prefixed CHR fields"
            );
            true
        },
        |d| d.conv_length,
    );
    let thick_layout =
        if is_thick_request(&auth1) {
            Some(ThickLayout::of_auth_request(&auth1).ok_or_else(|| {
                OracleError::Protocol("unrecognized OCI AUTH request layout".into())
            })?)
        } else {
            None
        };
    let negotiated = Negotiated {
        large,
        thick_layout,
        ttc_field_version,
        conv_length,
    };

    // --- AUTH1: the target is already known, so only the user part of the
    //     selector counts ---
    let a1 = parse_auth1_request(&auth1, ttc_field_version)?;
    let username = match AuthSelector::from(a1.username.as_str()) {
        AuthSelector::User { username, .. } => username,
        AuthSelector::Ticket { .. } => {
            warn!(
                "Oracle ticket authentication is not supported (O5LOGON needs a stored verifier)"
            );
            return Ok(PreAuth::Done);
        }
    };
    let (verifier, has_verifier) = match stored_verifier(services, &username).await? {
        Some(verifier) => (verifier, true),
        None => (
            Verifier12c::decoy(decoy_seed(), username.to_lowercase().as_bytes()),
            false,
        ),
    };

    // --- the gateway's phase one on the database leg: its RETURN is both the
    //     database's challenge for our later phase two and the template for the
    //     client's challenge, whose trailing status layout only the live
    //     database gets right for this client and version ---
    let mut client_pairs = parse_auth_request_pairs(&auth1, ttc_field_version).unwrap_or_default();
    let db_ret1 = db_auth_phase_one(
        &mut db,
        options.username.as_bytes(),
        &ReportedClient::from_login(&client_descriptor, &client_pairs),
        negotiated,
    )
    .await?;
    let part_a: [u8; 48] = random_fixed();
    let challenge = build_phase_one_return(
        &db_ret1,
        &verifier,
        &server_sesskey(&verifier, &part_a),
        thick_layout.is_some(),
    )?;
    cw.write_all(&challenge).await?;
    cw.flush().await?;

    // --- AUTH2: record what the client says about itself (the attributes
    //     Oracle shows in v$session) — client-asserted, so escaped in the log —
    //     then recover the password it proved ---
    let auth2 = read_packet(&mut cr, large).await?;
    client_pairs.extend(parse_auth_request_pairs(&auth2, ttc_field_version).unwrap_or_default());
    let client = ClientInfo::from_login(&client_descriptor, &client_pairs);
    info!(
        os_user = ?client.os_user,
        machine = ?client.machine,
        terminal = ?client.terminal,
        program = ?client.program,
        process = ?client.process,
        client_driver = ?client.driver,
        client_version = ?client.version,
        "Oracle client"
    );
    let a2 = parse_auth2_request(&auth2, ttc_field_version)?;
    let combo_key = server_combo_key(&verifier, &part_a, &a2.sesskey_ct);
    let recovered = combo_key.and_then(|key| recover_password(&key, &a2.auth_password));
    let proven = match recovered {
        Some(candidate) => {
            let verifier = verifier.clone();
            tokio::task::spawn_blocking(move || {
                verify_password(&verifier, &candidate).then_some(candidate)
            })
            .await
            .map_err(|e| OracleError::Protocol(format!("password check failed: {e}")))?
        }
        None => None,
    };
    if !has_verifier {
        warn!(
            user = ?username,
            "No Oracle verifier for this user; it is created when their password is set while the Oracle listener is enabled"
        );
    }
    // Whatever O5LOGON proved (nothing, for a decoy or a wrong password) goes to
    // Warpgate's own password check, which also does the failure accounting.
    let password = proven
        .filter(|_| has_verifier)
        .and_then(|p| String::from_utf8(p).ok())
        .unwrap_or_default();

    Ok(PreAuth::LoggedIn(Box::new(ClientLogin {
        cr,
        cw,
        db,
        negotiated,
        target_name,
        options,
        username,
        client_descriptor,
        client_pairs,
        db_ret1,
        combo_key,
        password: Secret::new(password),
    })))
}

/// Relay database -> client during the pre-auth negotiation, until `stop`.
/// Watches the server's PROTOCOL response for the negotiated TTC field version.
async fn relay_negotiation_replies<S: AsyncRead + AsyncWrite + Send + Unpin>(
    mut dr: ReadHalf<TargetStream>,
    mut cw: WriteHalf<ClientStream<S>>,
    large: bool,
    stop: Arc<Notify>,
) -> (
    ReadHalf<TargetStream>,
    WriteHalf<ClientStream<S>>,
    Option<u8>,
) {
    let mut observed_field_version: Option<u8> = None;
    loop {
        tokio::select! {
            biased;
            () = stop.notified() => break,
            r = read_packet(&mut dr, large) => match r {
                Ok(pkt) => {
                    if observed_field_version.is_none() && ttc_type(&pkt) == Some(1) {
                        observed_field_version = server_protocol_field_version(&pkt);
                    }
                    if cw.write_all(&pkt).await.is_err() || cw.flush().await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            },
        }
    }
    (dr, cw, observed_field_version)
}

/// Aborts the task when dropped, so an early return never leaves it holding
/// the connection halves.
struct AbortOnDrop<T>(JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn refuse<W: AsyncWrite + Unpin>(stream: &mut W, detail: &str) -> Result<(), OracleError> {
    stream.write_all(&build_refuse(12514, detail)).await?;
    stream.flush().await?;
    Ok(())
}

/// The user's stored 12c verifier, if the user exists and has one.
async fn stored_verifier(
    services: &Services,
    username: &str,
) -> Result<Option<Verifier12c>, OracleError> {
    let Some(user) = warpgate_db_entities::User::Entity::find()
        .filter(warpgate_db_entities::User::Entity::username_eq_ci(username))
        .one(&services.db)
        .await
        .map_err(warpgate_common::WarpgateError::from)?
    else {
        return Ok(None);
    };
    let Some(cred) = warpgate_db_entities::OracleCredential::Entity::find()
        .filter(warpgate_db_entities::OracleCredential::Column::UserId.eq(user.id))
        .one(&services.db)
        .await
        .map_err(warpgate_common::WarpgateError::from)?
    else {
        return Ok(None);
    };
    Ok(Some(Verifier12c {
        vfr_data: decode_fixed(&cred.vfr_data)?,
        vgen_count: u32::try_from(cred.vgen_count)
            .map_err(|_| OracleError::Protocol("negative verifier iteration count".into()))?,
        csk_salt: decode_fixed(&cred.csk_salt)?,
        sder_count: u32::try_from(cred.sder_count)
            .map_err(|_| OracleError::Protocol("negative verifier iteration count".into()))?,
        password_key: decode_fixed(&cred.password_key)?,
    }))
}

/// Per-process key for [`Verifier12c::decoy`].
fn decoy_seed() -> &'static [u8; 32] {
    static SEED: OnceLock<[u8; 32]> = OnceLock::new();
    SEED.get_or_init(random_fixed)
}

/// What [`run_db_authorization`] needs from an Oracle login. O5LOGON has already
/// delivered the password, so "prompting" hands it over once. Oracle cannot show
/// a web-approval link or a message mid-login, so those deny, and a denial is
/// delivered by closing the connection.
struct OracleAuthTransport {
    password: Option<Secret<String>>,
}

impl DbAuthTransport for OracleAuthTransport {
    type Error = OracleError;

    const PROTOCOL: Protocol = crate::common::PROTOCOL_NAME;
    const SUPPORTS_WEB_APPROVAL: bool = false;

    async fn prompt_password(&mut self) -> Result<Option<Secret<String>>, OracleError> {
        Ok(self.password.take())
    }

    async fn send_auth_ok(&mut self, _permit: AuthOkPermit) -> Result<(), OracleError> {
        // The client is answered after the gateway's own database login.
        Ok(())
    }

    async fn external_url(&mut self) -> Result<Url, OracleError> {
        Err(OracleError::Protocol(
            "web approval is not available for Oracle".into(),
        ))
    }

    async fn send_web_approval_prompt(
        &mut self,
        _url: &Url,
        _identification: &str,
    ) -> Result<bool, OracleError> {
        Ok(false)
    }

    async fn send_denied(&mut self) -> Result<(), OracleError> {
        Ok(())
    }
}

/// Find the Oracle target configured with the client's `SERVICE_NAME`
/// (case-insensitively, as Oracle service names are). Routing happens before the
/// user is known, so it is by service name alone; more than one match is a
/// misconfiguration and is refused rather than guessed.
async fn resolve_oracle_target(
    services: &Services,
    service_name: &str,
) -> Result<Option<(String, TargetOracleOptions)>, OracleError> {
    let mut matches = services
        .config_provider
        .list_targets()
        .await?
        .into_iter()
        .filter_map(|target| match target.options {
            TargetOptions::Oracle(options)
                if options
                    .service_name
                    .as_deref()
                    .is_some_and(|s| s.eq_ignore_ascii_case(service_name)) =>
            {
                Some((target.name, options))
            }
            _ => None,
        });
    let first = matches.next();
    if first.is_some() && matches.next().is_some() {
        warn!(service_name = ?service_name, "Several Oracle targets share this service name");
        return Ok(None);
    }
    Ok(first)
}

/// Adapt the database's own ACCEPT for relay to the client, clearing only the
/// bits that would push the login off the classic, cleartext O5LOGON path we
/// must terminate independently on both legs:
///   * NSI flag `NA_REQUIRED` (offset 22, bit 0x10) — don't force native
///     encryption, so the relayed TTC stays readable for the audit;
///   * in the `flags2` word (big-endian u32 at offset 41..45) the `FAST_AUTH`
///     (0x1000_0000) and `EOR` (0x0200_0000) bits — keep the two-phase O5LOGON.
///
/// Every other negotiated bit is left exactly as the real server produced it,
/// so the client and the database keep a consistent view of the session —
/// zeroing the whole `flags2` word makes a strict OCI client fail with ORA-609.
fn relay_accept(mut accept: Vec<u8>) -> Vec<u8> {
    if let Some(flags1) = accept.get_mut(22) {
        *flags1 &= !0x10; // TNS_NSI_NA_REQUIRED
    }
    if let Some(flags2) = accept.get_mut(41..45) {
        let mut word = [0u8; 4];
        word.copy_from_slice(flags2);
        let cleared = u32::from_be_bytes(word) & !0x1000_0000 & !0x0200_0000; // FAST_AUTH, EOR
        flags2.copy_from_slice(&cleared.to_be_bytes());
    }
    accept
}

/// When either direction last carried a packet, for the idle timeout.
struct Activity {
    start: Instant,
    last_ms: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last_ms: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        let now = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_ms.store(now, Ordering::Relaxed);
    }

    fn idle_for(&self) -> Duration {
        let last = Duration::from_millis(self.last_ms.load(Ordering::Relaxed));
        self.start.elapsed().saturating_sub(last)
    }
}

/// Ends the session once neither direction has carried a packet for `timeout`.
async fn watch_idle(timeout: Option<Duration>, activity: Arc<Activity>) {
    let Some(timeout) = timeout else {
        return std::future::pending().await;
    };
    loop {
        let idle = activity.idle_for();
        if idle >= timeout {
            info!(
                idle_seconds = idle.as_secs(),
                timeout_seconds = timeout.as_secs(),
                "Session idle timeout exceeded, closing connection"
            );
            return;
        }
        tokio::time::sleep(timeout.saturating_sub(idle)).await;
    }
}

/// Whether the packet's TTC body mentions an EXECUTE call (function 94)
/// anywhere, e.g. behind a piggyback the parser does not know.
fn mentions_execute(pkt: &[u8]) -> bool {
    use warpgate_oracle_tns::execute::FUNC_EXECUTE;
    pkt.get(10..)
        .is_some_and(|body| body.windows(2).any(|w| w == [TTC_FUNCTION, FUNC_EXECUTE]))
}

/// Relay client -> database, logging each EXECUTE's SQL for the audit.
async fn pump_client_to_db<R, W>(
    mut cr: R,
    mut dw: W,
    negotiated: Negotiated,
    activity: Arc<Activity>,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use warpgate_oracle_tns::audit::{AuditRecord, SqlAuditor};
    use warpgate_oracle_tns::execute::{
        FUNC_EXECUTE, OPTION_PARSE, parse_execute, parse_execute_thick,
    };

    let mut auditor = SqlAuditor::new();
    while let Ok(pkt) = read_packet(&mut cr, negotiated.large).await {
        activity.touch();
        if pkt.get(4) == Some(&0x06) {
            // A second login on an established session would run under the
            // target's account without passing Warpgate; end the session.
            if ttc_type(&pkt) == Some(TTC_FUNCTION)
                && matches!(
                    ttc_func(&pkt),
                    Some(FUNC_AUTH_PHASE_ONE | FUNC_AUTH_PHASE_TWO)
                )
            {
                warn!("Oracle client tried to log in again inside the session; closing");
                break;
            }
            // The EXECUTE framing differs for thick/OCI clients. The thin parser
            // needs the negotiated field version to place `token_num` and the
            // client's CONV_LENGTH to read the SQL text (raw for OJDBC).
            let call = if negotiated.thick_layout.is_some() {
                parse_execute_thick(&pkt)
            } else {
                parse_execute(&pkt, negotiated.ttc_field_version, negotiated.conv_length)
            };
            match call {
                Ok(call) => {
                    if call.function == FUNC_EXECUTE
                        && call.options & OPTION_PARSE != 0
                        && call.sql.is_none()
                    {
                        warn!(
                            cursor_id = call.cursor_id,
                            "Oracle EXECUTE parsed but its SQL text could not be captured"
                        );
                    }
                    match auditor.record(call) {
                        Some(AuditRecord::Statement { sql, .. }) => info!(query = ?sql, "Query"),
                        Some(AuditRecord::ReExecute { cursor_id, sql }) => {
                            info!(cursor_id, query = ?sql, "Re-execute");
                        }
                        None => {}
                    }
                }
                // An EXECUTE we cannot parse (SQL longer than one packet, an
                // unknown piggyback) would otherwise vanish from the audit.
                Err(_) if mentions_execute(&pkt) => {
                    warn!(
                        "Oracle call could not be parsed; it may contain SQL missing from the audit"
                    );
                }
                Err(_) => {}
            }
        }
        if dw.write_all(&pkt).await.is_err() || dw.flush().await.is_err() {
            break;
        }
    }
}

/// Relay database -> client.
async fn pump_db_to_client<R, W>(mut dr: R, mut cw: W, large: bool, activity: Arc<Activity>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    while let Ok(pkt) = read_packet(&mut dr, large).await {
        activity.touch();
        if cw.write_all(&pkt).await.is_err() || cw.flush().await.is_err() {
            break;
        }
    }
}

enum IdlePolicy {
    /// No idle timeout: the proxy never closes an idle session.
    Disabled,
    Timeout(Duration),
}

/// Parse a target's `idle_timeout` like the PostgreSQL protocol does: empty
/// means the default, zero disables it, and an invalid value falls back to
/// [`DEFAULT_IDLE_TIMEOUT`].
fn parse_idle_timeout(value: Option<&str>) -> IdlePolicy {
    let Some(trimmed) = value.map(str::trim).filter(|s| !s.is_empty()) else {
        return IdlePolicy::Timeout(DEFAULT_IDLE_TIMEOUT);
    };
    match humantime::parse_duration(trimmed) {
        Ok(duration) if duration.is_zero() => IdlePolicy::Disabled,
        Ok(duration) => IdlePolicy::Timeout(duration),
        Err(error) => {
            warn!(
                timeout_string = %trimmed,
                error = %error,
                "Invalid idle_timeout value, falling back to default"
            );
            IdlePolicy::Timeout(DEFAULT_IDLE_TIMEOUT)
        }
    }
}

/// Hex-decode a stored verifier column into a fixed-size byte array.
fn decode_fixed<const N: usize>(hexstr: &str) -> Result<[u8; N], OracleError> {
    let bytes = hex::decode(hexstr)?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        OracleError::Protocol(format!(
            "verifier field: expected {N} bytes, got {}",
            v.len()
        ))
    })
}
