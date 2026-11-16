//! The target (database) leg: the gateway acting as an Oracle *client*.
//!
//! [`connect_and_accept`] opens the database leg and drives the CONNECT
//! handshake (following RESEND/REDIRECT) to the **real** ACCEPT, which the
//! session relays to the client *before* authentication; the pre-auth
//! PROTOCOL/DATATYPE/SNS negotiation is then relayed to this same leg, which is
//! what makes both thin and thick/OCI clients work.
//!
//! The gateway's own O5LOGON login to the target runs on the already-open,
//! already-negotiated leg in two steps: [`db_auth_phase_one`] when the client's
//! AUTH1 arrives (its RETURN is the template for the client's challenge), and
//! [`db_auth_phase_two`] with the target's resolved credentials (via
//! [`resolve_password`]) once the user is authorized, returning the database's
//! phase-two RETURN after checking the database's own proof. [`login_to_db`]
//! runs both steps for the admin connection test.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::net::TcpStream;
use tracing::info;
use warpgate_common::{DatabaseTargetAuth, SecretResolver, TargetOracleOptions};
use warpgate_oracle_tns::client_auth::{
    build_phase_one_request, build_phase_one_request_thick, build_phase_two_request,
    build_phase_two_request_thick,
};
use warpgate_oracle_tns::client_crypto::client_derive;
use warpgate_oracle_tns::client_info::ReportedClient;
use warpgate_oracle_tns::execute::{
    SET_DB_SERVER_TIME_ZONE, ThickLayout, build_execute_request, build_thick_set_time_zone_request,
};
use warpgate_oracle_tns::handshake::parse_redirect;
use warpgate_oracle_tns::o5logon::verify_server_response;
use warpgate_oracle_tns::packet::{Header, PacketType};
use warpgate_oracle_tns::server_auth::svr_response;
use warpgate_oracle_tns::ttc::{AuthPair, parse_return_key_values, parse_return_key_values_thick};
use warpgate_tls::{MaybeTlsStream, TlsMode, configure_tls_connector};

use crate::error::OracleError;
use crate::stream::{TargetStream, random_fixed, random_vec, read_packet};

/// How long opening the database connection (TCP and TLS) may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Upper bound on the PBKDF2 iteration counts a database asks the gateway to
/// run. Oracle uses 4096 and 3; the bound keeps a malicious or spoofed database
/// from tying up a worker thread.
const MAX_PBKDF2_ITERATIONS: u32 = 100_000;

/// The TTC parameters a session settled on, which govern how both legs frame
/// AUTH and EXECUTE calls.
#[derive(Clone, Copy)]
pub struct Negotiated {
    /// DATA packets use the 4-byte length form (version >= 315).
    pub large: bool,
    /// The OCI request layout of a thick/OCI client; `None` for thin.
    pub thick_layout: Option<ThickLayout>,
    pub ttc_field_version: u8,
    pub conv_length: bool,
}

/// The database leg after the CONNECT handshake, split into halves so the
/// session's pre-auth relay could own the read half.
pub struct TargetLeg {
    dr: ReadHalf<TargetStream>,
    dw: WriteHalf<TargetStream>,
}

impl TargetLeg {
    pub const fn new(dr: ReadHalf<TargetStream>, dw: WriteHalf<TargetStream>) -> Self {
        Self { dr, dw }
    }

    pub fn into_split(self) -> (ReadHalf<TargetStream>, WriteHalf<TargetStream>) {
        (self.dr, self.dw)
    }

    pub async fn send(&mut self, packet: &[u8]) -> Result<(), OracleError> {
        self.dw.write_all(packet).await?;
        self.dw.flush().await?;
        Ok(())
    }

    pub async fn recv(&mut self, large: bool) -> Result<Vec<u8>, OracleError> {
        Ok(read_packet(&mut self.dr, large).await?)
    }
}

/// Resolve the target database's password from its configured auth, via the
/// Warpgate secret backends. Oracle O5LOGON has no RDS-IAM-token equivalent, so
/// an IAM-role target is rejected rather than silently falling back.
pub async fn resolve_password(
    options: &TargetOracleOptions,
    secrets: &dyn SecretResolver,
) -> Result<String, OracleError> {
    match &options.auth {
        DatabaseTargetAuth::Password(auth) => Ok(auth
            .password
            .resolve(secrets)
            .await?
            .expose_secret()
            .clone()),
        DatabaseTargetAuth::IamRole(_) => Err(OracleError::Protocol(
            "IAM-role auth is not supported for Oracle targets".into(),
        )),
    }
}

/// Whether the target's TLS mode means the DB leg is TCPS.
pub fn target_uses_tls(options: &TargetOracleOptions) -> bool {
    options.tls.mode != TlsMode::Disabled
}

/// Connect to `host:port`, optionally over TCPS, as a [`TargetStream`].
async fn connect_target(
    host: &str,
    port: u16,
    use_tls: bool,
    verify: bool,
) -> Result<TargetStream, OracleError> {
    let connect = async {
        let tcp = TcpStream::connect((host, port)).await?;
        tcp.set_nodelay(true)?;
        let stream: TargetStream = MaybeTlsStream::new(tcp);
        if !use_tls {
            return Ok(stream);
        }
        let client_config = Arc::new(configure_tls_connector(!verify, false, None).await?);
        let server_name = host
            .to_string()
            .try_into()
            .map_err(|_| OracleError::InvalidDomainName)?;
        Ok(stream
            .upgrade((server_name, client_config), Bytes::new())
            .await?)
    };
    tokio::time::timeout(CONNECT_TIMEOUT, connect)
        .await
        .map_err(|_| OracleError::Protocol(format!("connecting to {host}:{port} timed out")))?
}

/// Open the DB leg and drive the CONNECT handshake to ACCEPT, sending
/// `client_hello` (the CONNECT, plus its DATA packet when the descriptor did not
/// fit inline) and following a listener RESEND (send it again) or REDIRECT
/// (reconnect to the address it hands back, as Oracle clients do for RAC/SCAN).
///
/// Returns the stream positioned just after the ACCEPT, together with the raw
/// ACCEPT packet so the session can relay the real negotiated capabilities to
/// the client. The whole handshake uses the 2-byte packet length; DATA packets
/// switch to the large form afterwards.
pub async fn connect_and_accept(
    host: &str,
    port: u16,
    use_tls: bool,
    verify: bool,
    client_hello: &[u8],
) -> Result<(TargetStream, Vec<u8>), OracleError> {
    let mut host = host.to_string();
    let mut port = port;
    for _ in 0..3 {
        let mut stream = connect_target(&host, port, use_tls, verify).await?;
        loop {
            stream.write_all(client_hello).await?;
            stream.flush().await?;
            let resp = tokio::time::timeout(CONNECT_TIMEOUT, read_packet(&mut stream, false))
                .await
                .map_err(|_| {
                    OracleError::Protocol("the target listener did not answer the CONNECT".into())
                })??;
            match Header::parse(&resp, false)?.packet_type {
                PacketType::Accept => return Ok((stream, resp)),
                PacketType::Resend => {}
                PacketType::Redirect => {
                    let desc = parse_redirect(&resp)?;
                    let (h, p) = redirect_addr(&desc).ok_or_else(|| {
                        OracleError::Protocol(format!("unparseable REDIRECT: {desc}"))
                    })?;
                    info!(host = %h, port = p, "Following the target listener's REDIRECT");
                    host = h;
                    port = p;
                    break; // reconnect to the redirected address
                }
                PacketType::Refuse => {
                    return Err(OracleError::Protocol(
                        "target REFUSEd the connection".into(),
                    ));
                }
                other => {
                    return Err(OracleError::Protocol(format!(
                        "unexpected DB CONNECT reply: {other:?}"
                    )));
                }
            }
        }
    }
    Err(OracleError::Protocol(
        "too many REDIRECTs following the target".into(),
    ))
}

/// Authenticate the gateway to the target over the already-open,
/// already-negotiated DB leg and return the database's phase-two RETURN:
/// [`db_auth_phase_one`] then [`db_auth_phase_two`], thin framing only. With no
/// client behind it, it reports the gateway itself ([`ReportedClient::gateway`]).
pub async fn login_to_db(
    db: &mut TargetLeg,
    db_user: &[u8],
    db_password: &[u8],
    negotiated: Negotiated,
) -> Result<Vec<u8>, OracleError> {
    let client = ReportedClient::gateway();
    let ret1 = db_auth_phase_one(db, db_user, &client, negotiated).await?;
    db_auth_phase_two(db, &ret1, db_user, db_password, &client, negotiated).await
}

/// Phase one of the gateway's own login on the DB leg: send AUTH1 for the
/// target user and return the database's phase-one RETURN (its O5LOGON
/// challenge). It needs no password, so the session runs it before answering
/// the client's AUTH1 and builds that answer from this RETURN. It reports
/// `client`'s OS user, machine, terminal, program and process to the DB.
pub async fn db_auth_phase_one(
    db: &mut TargetLeg,
    db_user: &[u8],
    client: &ReportedClient,
    negotiated: Negotiated,
) -> Result<Vec<u8>, OracleError> {
    // The gateway logs in on the leg the real client already negotiated with the
    // target, so its thin AUTH requests must match what was negotiated there: a
    // pre-23ai (19c) server neither sends nor expects the `token_num` ub8, and a
    // client that negotiated without CONV_LENGTH (OJDBC) left the server
    // expecting a raw username. The thick builders ignore both.
    let phase_one = match negotiated.thick_layout {
        Some(layout) => build_phase_one_request_thick(layout, db_user, 5, client),
        None => build_phase_one_request(
            db_user,
            5,
            negotiated.ttc_field_version,
            negotiated.conv_length,
            client,
        ),
    };
    db.send(&phase_one).await?;

    // Skip any stray MARKER (TNS type 0x0c) before the phase-one RETURN, bounded
    // to avoid spinning. A BREAK, though, is the DB rejecting our request:
    // skipping it would leave the DB waiting for our RESET, so surface its error.
    let mut pkt = db.recv(negotiated.large).await?;
    let mut guard = 0;
    while is_marker(&pkt) && guard < 4 {
        if is_break(&pkt) {
            let error = read_break_error(db, negotiated.large).await;
            return Err(OracleError::Protocol(format!(
                "target database rejected the gateway's login request: {error}"
            )));
        }
        pkt = db.recv(negotiated.large).await?;
        guard += 1;
    }
    Ok(pkt)
}

/// Phase two of the gateway's own login: answer the challenge in the DB's
/// phase-one RETURN `ret1` with the target's password, check the database's
/// AUTH_SVR_RESPONSE proof, and return its phase-two RETURN (the session
/// parameters). It reports `client`'s driver name and version to the DB.
pub async fn db_auth_phase_two(
    db: &mut TargetLeg,
    ret1: &[u8],
    db_user: &[u8],
    db_password: &[u8],
    client: &ReportedClient,
    negotiated: Negotiated,
) -> Result<Vec<u8>, OracleError> {
    let thick = negotiated.thick_layout.is_some();
    let p1 = if thick {
        parse_return_key_values_thick(ret1)?
    } else {
        parse_return_key_values(ret1)?
    };
    let vfr = hex::decode(value_of(&p1, "AUTH_VFR_DATA")?)?;
    let csk = hex::decode(value_of(&p1, "AUTH_PBKDF2_CSK_SALT")?)?;
    let srv_sess = hex::decode(value_of(&p1, "AUTH_SESSKEY")?)?;
    let vgen = parse_count(value_of(&p1, "AUTH_PBKDF2_VGEN_COUNT")?)?;
    let sder = parse_count(value_of(&p1, "AUTH_PBKDF2_SDER_COUNT")?)?;

    let password = db_password.to_vec();
    let part_b = random_vec(srv_sess.len());
    let auth = tokio::task::spawn_blocking(move || {
        client_derive(
            &password,
            &vfr,
            vgen,
            &csk,
            sder,
            &srv_sess,
            &part_b,
            &random_fixed::<16>(),
            &random_fixed::<16>(),
        )
    })
    .await
    .map_err(|e| OracleError::Protocol(format!("deriving the login keys failed: {e}")))?
    .ok_or_else(|| OracleError::Protocol("target sent a malformed AUTH_SESSKEY".into()))?;

    let phase_two = match negotiated.thick_layout {
        Some(layout) => build_phase_two_request_thick(layout, db_user, 6, &auth, client),
        None => build_phase_two_request(
            db_user,
            6,
            &auth,
            negotiated.ttc_field_version,
            negotiated.conv_length,
            client,
        ),
    };
    db.send(&phase_two).await?;

    let ret2 = db.recv(negotiated.large).await?;
    if Header::parse(&ret2, negotiated.large)?.packet_type == PacketType::Marker {
        // A MARKER here means the DB is signalling an error (bad credentials).
        let error = read_break_error(db, negotiated.large).await;
        return Err(OracleError::AuthFailed(format!(
            "target database rejected the gateway credentials: {error}"
        )));
    }
    // Only a database that knows the password can produce this proof; without
    // the check, anything answering on the target's address would be accepted.
    if !verify_server_response(&auth.combo_key, &svr_response(&ret2, thick)?) {
        return Err(OracleError::Protocol(
            "target database failed to prove it knows the target password".into(),
        ));
    }
    info!("Authenticated at target database");
    Ok(ret2)
}

/// Put the freshly logged-in DB session in the database server's own UTC offset
/// — the one `SYSDATE` / `SYSTIMESTAMP` follow — so `CURRENT_DATE` and
/// `CURRENT_TIMESTAMP` agree with `SYSDATE` as they do for a client in the
/// server's zone. Without it the session gets `DBTIMEZONE`, which is often UTC
/// even when the server's clock is not. The offset is read by the database
/// itself, so nothing is configured per target.
///
/// Runs one EXECUTE on the DB leg after [`db_auth_phase_two`] and before the
/// client is handed the session, so it never interleaves with client traffic:
/// thin-framed, or for a thick/OCI session a replay of a captured OCI request.
/// Which OCI EXECUTE layout the session uses cannot be known before the
/// client's first call, so a thick session tries the narrow one and, if the DB
/// rejects its framing (ORA-03146, after which the session carries on
/// normally), the wide one.
pub async fn set_db_server_time_zone(
    db: &mut TargetLeg,
    negotiated: Negotiated,
) -> Result<(), OracleError> {
    let attempts: &[Option<ThickLayout>] = if negotiated.thick_layout.is_some() {
        &[Some(ThickLayout::Narrow), Some(ThickLayout::Wide)]
    } else {
        &[None]
    };
    // Sequence 7 onwards follows the gateway's AUTH calls (5, 6).
    for (attempt, (seq, layout)) in (7u8..).zip(attempts).enumerate() {
        let request = match layout {
            Some(layout) => {
                build_thick_set_time_zone_request(*layout, seq, negotiated.ttc_field_version)?
            }
            None => build_execute_request(
                SET_DB_SERVER_TIME_ZONE,
                seq,
                negotiated.ttc_field_version,
                negotiated.conv_length,
            ),
        };
        db.send(&request).await?;
        // The reply (a few hundred bytes) is one DATA packet ending in the call
        // status; an error shows up as a BREAK or as ORA- text in that status.
        let reply = db.recv(negotiated.large).await?;
        let error = if is_break(&reply) {
            Some(read_break_error(db, negotiated.large).await)
        } else {
            ora_error(&reply)
        };
        match error {
            None => return Ok(()),
            Some(e) if e.starts_with("ORA-03146") && attempt + 1 < attempts.len() => {}
            Some(e) => {
                return Err(OracleError::Protocol(format!(
                    "setting the session time zone failed: {e}"
                )));
            }
        }
    }
    Err(OracleError::Protocol(
        "setting the session time zone failed: no OCI layout accepted".into(),
    ))
}

/// TNS MARKER payload byte `[10]` value of a BREAK (the server aborting a call
/// with an error), as opposed to a RESET (2).
const MARKER_TYPE_BREAK: u8 = 1;

fn is_marker(pkt: &[u8]) -> bool {
    pkt.get(4) == Some(&PacketType::Marker.to_u8())
}

fn is_break(pkt: &[u8]) -> bool {
    is_marker(pkt) && pkt.get(10) == Some(&MARKER_TYPE_BREAK)
}

/// The first `ORA-` error text in a packet, up to the end of its line.
fn ora_error(pkt: &[u8]) -> Option<String> {
    let pos = pkt.windows(4).position(|w| w == b"ORA-")?;
    let text = pkt.split_at(pos).1;
    let end = text
        .iter()
        .position(|&b| b == b'\n' || b == 0)
        .unwrap_or(text.len());
    Some(
        String::from_utf8_lossy(text.split_at(end).0)
            .trim()
            .to_owned(),
    )
}

/// Answer a server BREAK with a RESET marker so the DB sends its error, and
/// return that error's `ORA-` text. Best effort and time-bounded: it only
/// enriches the failure that the caller reports anyway.
async fn read_break_error(db: &mut TargetLeg, large: bool) -> String {
    const RESET: [u8; 3] = [0x01, 0x00, 0x02];
    let mut reset = if large {
        vec![0, 0, 0, 11, PacketType::Marker.to_u8(), 0, 0, 0]
    } else {
        vec![0, 11, 0, 0, PacketType::Marker.to_u8(), 0, 0, 0]
    };
    reset.extend_from_slice(&RESET);
    if db.send(&reset).await.is_err() {
        return "connection lost".into();
    }
    let read = async {
        // The DB answers with its own RESET marker, then the error DATA packet.
        for _ in 0..4 {
            let pkt = db.recv(large).await.ok()?;
            if let Some(error) = ora_error(&pkt) {
                return Some(error);
            }
        }
        None
    };
    tokio::time::timeout(Duration::from_secs(5), read)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "no error text received".into())
}

/// Look up a key's value in a parsed RETURN key/value list.
fn value_of<'a>(pairs: &'a [AuthPair], key: &str) -> Result<&'a [u8], OracleError> {
    pairs
        .iter()
        .find(|p| p.key == key)
        .map(|p| p.value.as_slice())
        .ok_or_else(|| OracleError::Protocol(format!("server RETURN missing {key}")))
}

/// Parse a PBKDF2 iteration count carried as decimal ASCII.
fn parse_count(bytes: &[u8]) -> Result<u32, OracleError> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .filter(|n| (1..=MAX_PBKDF2_ITERATIONS).contains(n))
        .ok_or_else(|| OracleError::Protocol("invalid PBKDF2 iteration count".into()))
}

/// Extract `(host, port)` from a REDIRECT connect descriptor's ADDRESS.
fn redirect_addr(desc: &str) -> Option<(String, u16)> {
    let host = desc_field(desc, "HOST=")?;
    let port = desc_field(desc, "PORT=")?.parse().ok()?;
    Some((host, port))
}

/// Read a single `KEY=VALUE` field out of a TNS connect descriptor string,
/// stopping at the next `)` or `,`. Shared by the REDIRECT follow and the
/// session's SERVICE_NAME routing.
pub fn desc_field(desc: &str, key: &str) -> Option<String> {
    let start = desc.find(key)? + key.len();
    let rest = desc.get(start..)?;
    let end = rest.find([')', ',']).unwrap_or(rest.len());
    Some(rest.get(..end)?.trim().to_string())
}

/// Split a connected [`TargetStream`] into a [`TargetLeg`].
pub fn target_leg(stream: TargetStream) -> TargetLeg {
    let (dr, dw) = split(stream);
    TargetLeg::new(dr, dw)
}
