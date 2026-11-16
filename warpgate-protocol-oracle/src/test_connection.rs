//! Standalone "test connection" for an Oracle target (the admin-UI button).
//!
//! The live proxy ([`crate::session`]) never *builds* a CONNECT/PROTOCOL/DATATYPE
//! packet — it relays the client's. A connection test has no client, so this
//! module builds those three request packets itself and then reuses the proxy's
//! own client-leg code ([`connect_and_accept`] + [`login_to_db`]) to drive a full
//! O5LOGON login to the target with the target's *own* credentials.
//!
//! A success proves host/port reachability, TLS (when the target is TCPS), and
//! that the listener knows the configured service name; when the server also
//! completes the (version-specific) synthetic login handshake it additionally
//! verifies the stored target credentials. The connect/accept check is the hard
//! pass/fail; the credential login is best-effort, because the synthetic
//! PROTOCOL/DATATYPE packets are captured from one client version and a server
//! that will not complete them must not fail the whole test (real clients relay
//! their own negotiation through the proxy). This is still strictly more than the
//! SSH "check host key" button.
//!
//! ## How the request packets are built
//!
//! * **CONNECT** — byte-compatible with a real python-oracledb 23ai thin CONNECT
//!   (a capture a live Oracle 23ai server ACCEPTed): a 74-byte CONNECT header
//!   plus the connect descriptor, carried inline in the CONNECT packet when it
//!   fits the 230-byte connect-data window (`TNS_MAX_CONNECT_DATA`) or in a
//!   following DATA packet when longer — the listener hard-closes the socket if
//!   the wrong form is used for a given length. Only the descriptor
//!   (host/port/service name) and the length fields that depend on it differ from
//!   that capture; every capability/version/flag byte is reused verbatim, so a
//!   real listener treats it exactly like the real client.
//! * **PROTOCOL / DATATYPE** — carry no secret and no service name, so they are
//!   replayed verbatim from the same capture. They use the large-length (4-byte)
//!   DATA framing, i.e. they assume the negotiated version is >= 315 (large SDU),
//!   which every supported Oracle release satisfies.

use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use warpgate_common::{SecretResolver, TargetOracleOptions};
use warpgate_oracle_tns::constants::{field_version, version};
use warpgate_oracle_tns::handshake::{target_descriptor, with_connect_data};
use warpgate_oracle_tns::negotiation::parse_client_datatypes;

use crate::client::{
    Negotiated, TargetLeg, connect_and_accept, login_to_db, resolve_password, target_leg,
    target_uses_tls,
};
use crate::error::OracleError;

/// Overall wall-clock budget for the whole test, so a black-holed host or a
/// wedged database cannot hang the admin request.
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Captured python-oracledb 23ai CONNECT header (74 bytes, 2-byte length form).
/// Reused verbatim except for the connect-data length at `[24..26]`, which
/// [`build_connect`] patches to the length of the descriptor it appends. A live
/// Oracle 23ai server ACCEPTed this exact header.
const CONNECT_HEADER_HEX: &str = "004a000001000000013f012c0401200020004f98000000010153004a00000000848400000000000000000000000000000000000000000000000000002000000020000000000000000001";

/// Captured TTC PROTOCOL request (msg type 1) — a large-length DATA packet.
const PROTOCOL_REQUEST_HEX: &str = "0000001d060000000000010600707974686f6e2d6f7261636c65646200";

/// Captured TTC DATATYPE request (msg type 2) — a large-length DATA packet.
const DATATYPE_REQUEST_HEX: &str = "00000a5c0600000000000269036903033506000000ea180018010100000000002990030703000100cf000004010000001000000c2000b80008440005003e02000000000000030b0200000000000500000000000100010001000000020002000a00000008000800010000000c000c000a0000001700170001000000180018000100000019001900010000001a001a00010000001b001b000a0000001c001c00010000001d001d00010000001e001e00010000001f001f0001000000200020000100000021002100010000000a000a00010000000b000b00010000002800280001000000290029000100000075007500010000007800780001000001220122000100000123012300010000012401240001000001250125000100000126012600010000012a012a00010000012b012b00010000012c012c00010000012d012d00010000012e012e00010000012f012f000100000130013000010000013101310001000001320132000100000133013300010000013401340001000001350135000100000136013600010000013701370001000001380138000100000139013900010000013b013b00010000013c013c00010000013d013d00010000013e013e00010000013f013f000100000140014000010000014101410001000001420142000100000143014300010000014701470001000001480148000100000149014900010000014b014b00010000014d014d00010000014e014e00010000014f014f000100000150015000010000015101510001000001520152000100000153015300010000015401540001000001550155000100000156015600010000015701570001000001580158000100000159015900010000015a015a00010000015c015c00010000015d015d00010000016201620001000001630163000100000167016700010000016b016b00010000017c017c00010000017d017d00010000017e017e00010000017f017f00010000018001800001000001810181000100000182018200010000018301830001000001840184000100000185018500010000018601860001000001870187000100000189018900010000018a018a00010000018b018b00010000018c018c00010000018d018d00010000018e018e00010000018f018f00010000019001900001000001910191000100000194019400010000019501950001000001960196000100000197019700010000019d019d00010000019e019e00010000019f019f0001000001a001a00001000001a101a10001000001a201a20001000001a301a30001000001a401a40001000001a501a50001000001a601a60001000001a701a70001000001a801a80001000001a901a90001000001aa01aa0001000001ab01ab0001000001ad01ad0001000001ae01ae0001000001af01af0001000001b001b00001000001b101b10001000001c101c10001000001c201c20001000001c601c60001000001c701c70001000001c801c80001000001c901c90001000001ca01ca0001000001cb01cb0001000001cc01cc0001000001cd01cd0001000001ce01ce0001000001cf01cf0001000001d201d20001000001d301d30001000001d401d40001000001d501d50001000001d601d60001000001d701d70001000001d801d80001000001d901d90001000001da01da0001000001db01db0001000001dc01dc0001000001dd01dd0001000001de01de0001000001df01df0001000001e001e00001000001e101e10001000001e201e20001000001e301e30001000001e401e40001000001e501e50001000001e601e60001000001ea01ea0001000001eb01eb0001000001ec01ec0001000001ed01ed0001000001ee01ee0001000001ef01ef0001000001f001f00001000001f201f20001000001f301f30001000001f401f40001000001f501f50001000001f601f60001000001fd01fd0001000001fe01fe0001000002010201000100000202020200010000020402040001000002050205000100000206020600010000020702070001000002080208000100000209020900010000020a020a00010000020b020b00010000020c020c00010000020d020d00010000020e020e00010000020f020f000100000210021000010000021102110001000002120212000100000213021300010000021402140001000002150215000100000216021600010000021702170001000002180218000100000219021900010000021a021a00010000021b021b00010000021c021c00010000021d021d00010000021e021e00010000021f021f0001000002300230000100000235023500010000023c023c00010000023d023d00010000023e023e00010000023f023f000100000240024000010000024202420001000002330233000100000234023400010000024302430001000002440244000100000245024500010000024602460001000002470247000100000248024800010000024902490001000000030002000a000000040002000a0000000500010001000000060002000a000000070002000a00000009000100010000000f000100010000002700270001000000440002000a0000005b0002000a0000005e000100010000005f001700010000006000600001000000610060000100000064006400010000006500650001000000660066000100000068000b00010000006a006a00010000006c006d00010000006d006d00010000006e006f00010000006f006f0001000000700070000100000071007100010000007200720001000000730073000100000074006600010000007700770001000000c600c600010000009200920001000000980002000a000000990002000a0000009a0002000a0000009b000100010000009c000c000a000000ac0002000a000000b200b20001000000b300b30001000000b400b40001000000b500b50001000000b600b60001000000b700b70001000000b8000c000a000000b900b90001000000ba00ba0001000000bb00bb0001000000bc00bc0001000000bd00bd0001000000be00be0001000000c300700001000000c400710001000000c500720001000000d000d00001000000e700e70001000000e800e70001000000e900e90001000000f1006d0001000000fc00fc00010000024e024e00010000024f024f000100000250025000010000026502650001000002660266000100000267026700010000026802680001000002630263000100000264026400010000025102510001000002520252000100000253025300010000025402540001000002550255000100000256025600010000025702570001000002580258000100000259025900010000025a025a00010000025b025b00010000025c025c00010000025d025d00010000026e026e00010000026f026f00010000027002700001000002710271000100000272027200010000027302730001000002740274000100000275027500010000027602760001000002770277000100000278027800010000027d027d00010000027e027e00010000027c027c00010000027f027f0001000002970297000100000280028000010000028c028c0001000002860286000100000287028700010000007f007f00010000029402940001000002950295000100000299029900010000029d029d00010000029e029e000100000000";

/// Test that the gateway can reach, negotiate with, and authenticate to the
/// target Oracle database using the target's own configured credentials.
///
/// Returns a human-readable success description. On failure the returned error's
/// `{:#}` form explains which step failed (reachability, TLS, unknown service, or
/// bad credentials). Reuses the proxy client leg, so a success here exercises the
/// same path a real proxied login takes.
pub async fn test_connection(
    options: &TargetOracleOptions,
    secrets: &dyn SecretResolver,
) -> Result<String> {
    match tokio::time::timeout(TEST_TIMEOUT, run_test(options, secrets)).await {
        Ok(result) => result,
        Err(_) => bail!(
            "timed out after {}s connecting to {}:{}",
            TEST_TIMEOUT.as_secs(),
            options.host,
            options.port
        ),
    }
}

async fn run_test(options: &TargetOracleOptions, secrets: &dyn SecretResolver) -> Result<String> {
    let service_name = options
        .service_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("this Oracle target has no service name configured"))?;

    let password = resolve_password(options, secrets)
        .await
        .context("resolving the target password")?;

    let use_tls = target_uses_tls(options);
    let verify = options.tls.verify;

    // Open the DB leg: forward a CONNECT carrying the target's service name and
    // follow RESEND/REDIRECT to the real ACCEPT.
    let client_hello = build_connect(&options.host, options.port, service_name, use_tls)?;
    let (db_stream, db_accept) =
        connect_and_accept(&options.host, options.port, use_tls, verify, &client_hello)
            .await
            .map_err(|e| map_connect_error(e, service_name, use_tls))?;

    // The client adopts the server's negotiated version from the ACCEPT; version
    // >= 315 switches DATA packets to the 4-byte (large-SDU) length form, which
    // the captured PROTOCOL/DATATYPE requests already use.
    let srv_version = u16::from_be_bytes([
        db_accept.get(8).copied().unwrap_or(0),
        db_accept.get(9).copied().unwrap_or(0),
    ]);
    let large = srv_version >= version::MIN_LARGE_SDU;

    let mut db = target_leg(db_stream);
    let endpoint = format!("{}:{}", options.host, options.port);
    let transport = if use_tls { "TLS (TCPS)" } else { "plain TCP" };

    // connect+accept already proved reachability, TLS and that the listener knows
    // the service name. The synthetic PROTOCOL/DATATYPE/O5LOGON login additionally
    // checks the credentials — but those captured request packets are specific to a
    // 23ai client, so a database that will not complete that handshake (e.g. a
    // different version) must NOT fail the whole test. Only a genuine credential
    // rejection is a hard error; an unsupported handshake degrades to a qualified
    // success, since real clients negotiate directly through the proxy rather than
    // with these synthetic packets.
    match verify_login(&mut db, &options.username, password.as_bytes(), large).await {
        Ok(()) => Ok(format!(
            "Connected to Oracle service \"{service_name}\" at {endpoint} over {transport} and authenticated as \"{}\" — login verified.",
            options.username,
        )),
        Err(LoginOutcome::BadCredentials) => Err(anyhow!(
            "reached Oracle service \"{service_name}\" at {endpoint} and negotiated the protocol, but the database rejected the credentials — check the target username and password"
        )),
        Err(LoginOutcome::HandshakeUnsupported(detail)) => Ok(format!(
            "Reached Oracle service \"{service_name}\" at {endpoint} over {transport}: the listener accepted the connection and the service name is valid. The credential check could not complete on this database ({detail}) — its login handshake differs from the captured 23ai one. Real clients negotiate directly through the proxy, so this alone does not mean they can't connect, but the target credentials were not verified here."
        )),
    }
}

/// Why the best-effort verification login stopped.
enum LoginOutcome {
    /// The database ran the handshake and actively rejected the credentials.
    BadCredentials,
    /// The database would not complete the synthetic login handshake (e.g. a
    /// version whose PROTOCOL/DATATYPE differs from the captured one). This says
    /// nothing about whether the credentials are correct.
    HandshakeUnsupported(String),
}

/// Drive the synthetic PROTOCOL + DATATYPE negotiation and a thin O5LOGON login,
/// distinguishing a real credential rejection from a handshake the server will not
/// complete, so the caller can treat only the former as a hard failure.
async fn verify_login(
    db: &mut TargetLeg,
    username: &str,
    password: &[u8],
    large: bool,
) -> Result<(), LoginOutcome> {
    let protocol = decode_hex(PROTOCOL_REQUEST_HEX)
        .map_err(|e| LoginOutcome::HandshakeUnsupported(format!("{e:#}")))?;
    let datatype = decode_hex(DATATYPE_REQUEST_HEX)
        .map_err(|e| LoginOutcome::HandshakeUnsupported(format!("{e:#}")))?;

    // PROTOCOL + DATATYPE negotiation must precede AUTH; replies are read and
    // discarded. Any I/O failure here means the server did not accept the captured
    // request for its version — not a credential problem.
    db.send(&protocol)
        .await
        .map_err(|e| LoginOutcome::HandshakeUnsupported(format!("sending PROTOCOL: {e}")))?;
    db.recv(large)
        .await
        .map_err(|e| LoginOutcome::HandshakeUnsupported(format!("negotiating PROTOCOL: {e}")))?;
    db.send(&datatype)
        .await
        .map_err(|e| LoginOutcome::HandshakeUnsupported(format!("sending DATATYPE: {e}")))?;
    db.recv(large)
        .await
        .map_err(|e| LoginOutcome::HandshakeUnsupported(format!("negotiating DATATYPE: {e}")))?;

    // This path replays 23ai-captured PROTOCOL/DATATYPE requests, so the
    // synthetic client is 23ai-shaped and its thin AUTH preambles carry
    // `token_num`. A pre-23ai server rejects the 23ai DATATYPE before auth
    // anyway (surfaced as HandshakeUnsupported), so a 23ai field version is the
    // correct and only reachable choice here.
    // The captured DATATYPE is python-oracledb's, which sets CONV_LENGTH.
    let conv_length = parse_client_datatypes(&datatype).is_none_or(|d| d.conv_length);
    let negotiated = Negotiated {
        large,
        thick_layout: None,
        ttc_field_version: field_version::TOKEN_NUM_MIN,
        conv_length,
    };
    login_to_db(db, username.as_bytes(), password, negotiated)
        .await
        .map(|_| ())
        .map_err(|e| match e {
            OracleError::AuthFailed(_) => LoginOutcome::BadCredentials,
            other => LoginOutcome::HandshakeUnsupported(format!("{other:#}")),
        })
}

/// Build a client CONNECT for the target: the captured known-good
/// python-oracledb 23ai CONNECT header around the same descriptor the session
/// sends ([`target_descriptor`]), inline or in a following DATA packet as its
/// length requires (the listener hard-closes the socket on the wrong form).
fn build_connect(host: &str, port: u16, service_name: &str, use_tls: bool) -> Result<Vec<u8>> {
    let header = decode_hex(CONNECT_HEADER_HEX)?;
    let descriptor = target_descriptor(
        use_tls,
        host,
        port,
        service_name,
        "(CID=(PROGRAM=warpgate)(HOST=warpgate)(USER=warpgate))",
    )
    .context("the target host or service name cannot be used in a connect descriptor")?;
    Ok(with_connect_data(&header, descriptor.as_bytes())?.concat())
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    hex::decode(s.trim()).context("decoding a captured TNS request blob")
}

/// Turn a DB-leg connect failure into a message that points at the likely cause,
/// distinguishing an unknown service name (TNS REFUSE / ORA-12514) from a plain
/// TCP or TLS failure.
fn map_connect_error(err: OracleError, service_name: &str, use_tls: bool) -> anyhow::Error {
    let detail = format!("{err:#}");
    match &err {
        OracleError::Protocol(m) if m.contains("REFUSE") => anyhow!(
            "the Oracle listener refused the connection — the service name \"{service_name}\" is most likely unknown to it (ORA-12514)"
        ),
        OracleError::Io(_) => anyhow!("could not reach the target (TCP connect failed): {detail}"),
        OracleError::Tls(_) | OracleError::TlsSetup(_) | OracleError::InvalidDomainName
            if use_tls =>
        {
            anyhow!("the TLS handshake with the target failed: {detail}")
        }
        _ => anyhow!("could not open the Oracle connection: {detail}"),
    }
}
