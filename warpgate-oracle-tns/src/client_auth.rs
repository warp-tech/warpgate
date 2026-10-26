//! Client-side AUTH request builders — the gateway as an Oracle *client* toward
//! the target database. These are the inverse of the request parsers in
//! `negotiation`, producing the phase-one (func 118) and phase-two (func 115)
//! FUNCTION request DATA packets. The thin body layout follows python-oracledb
//! `auth.pyx::_write_message` and is the exact inverse of
//! `negotiation::{parse_auth1_request, parse_auth2_request}`.

use crate::client_crypto::ClientAuth;
use crate::client_info::ReportedClient;
use crate::constants::field_version;
use crate::crypto::hex_upper;
use crate::negotiation::ThickLayout;
use crate::ttc::Writer;

/// TTC message type of a FUNCTION call (`TNS_MSG_TYPE_FUNCTION`).
const MSG_TYPE_FUNCTION: u8 = 3;
/// Function code for AUTH phase one (`TNS_FUNC_AUTH_PHASE_ONE`).
const FUNC_AUTH_PHASE_ONE: u8 = 118;
/// Function code for AUTH phase two (`TNS_FUNC_AUTH_PHASE_TWO`).
const FUNC_AUTH_PHASE_TWO: u8 = 115;
/// Phase-one `auth_mode`: `TNS_AUTH_MODE_LOGON`.
const AUTH_MODE_LOGON: u32 = 0x0000_0001;
/// Phase-two `auth_mode`: `LOGON | WITH_PASSWORD`.
const AUTH_MODE_WITH_PASSWORD: u32 = 0x0000_0101;
/// TNS packet type byte for a DATA packet (`TNS_PACKET_TYPE_DATA`).
const PACKET_TYPE_DATA: u8 = 0x06;
/// 8-byte TNS header + 2-byte data-flags preceding a DATA packet's TTC body.
const DATA_HEADER_LEN: usize = 10;

/// Prepend the post-handshake DATA packet header (version 319, 4-byte length
/// form) and the zero data-flags to a TTC message `body`.
///
/// Layout: `[0..4]` total packet length (u32 BE, incl. header), `[4]` = `0x06`
/// (DATA), `[5]` = 0, `[6..8]` = 0, `[8..10]` = `0x0000` data-flags, then `body`.
fn wrap_data_packet(body: &[u8]) -> Vec<u8> {
    let total = (DATA_HEADER_LEN + body.len()) as u32;
    let mut pkt = Vec::with_capacity(DATA_HEADER_LEN + body.len());
    pkt.extend_from_slice(&total.to_be_bytes()); // [0..4] total packet length
    pkt.push(PACKET_TYPE_DATA); // [4] packet type = DATA
    pkt.push(0x00); // [5] packet flags
    pkt.extend_from_slice(&[0x00, 0x00]); // [6..8] header checksum (unused)
    pkt.extend_from_slice(&[0x00, 0x00]); // [8..10] data flags
    pkt.extend_from_slice(body);
    pkt
}

/// Write the common FUNCTION request preamble, up to and including the username.
///
/// The exact inverse of `negotiation::parse_preamble`. The `token_num` ub8 is
/// emitted **only** when the negotiated `ttc_field_version >= TOKEN_NUM_MIN`
/// (23ai-level) — a pre-23ai (19c) server neither sends nor expects it, so the
/// gateway must omit it on the DB leg too, or the server misparses the login.
/// With `conv_length` (the client's DATATYPES set
/// [`encoding::CONV_LENGTH`](crate::constants::encoding::CONV_LENGTH), as
/// python-oracledb and go-ora do) the username is emitted as a single chunked
/// byte string — a 1-byte length then the raw bytes, the form `Reader::bytes`
/// reads — NOT via `Writer::bytes_with_length`, which would prefix a redundant
/// `ub4`. Without it (Oracle JDBC thin) the server sizes the username by
/// `user_len` alone, so it is written raw. Assumes `username.len() <= 252`.
#[allow(clippy::too_many_arguments)]
fn write_preamble(
    w: &mut Writer,
    function_code: u8,
    seq: u8,
    username: &[u8],
    auth_mode: u32,
    num_pairs: u32,
    ttc_field_version: u8,
    conv_length: bool,
) {
    w.u8(MSG_TYPE_FUNCTION);
    w.u8(function_code);
    w.u8(seq);
    if ttc_field_version >= field_version::TOKEN_NUM_MIN {
        w.ub8(0); // token_num, present only at 23ai-level field versions
    }
    w.u8(1); // has_user pointer
    w.ub4(username.len() as u32); // user_len
    w.ub4(auth_mode);
    w.u8(1); // pointer (authivl)
    w.ub4(num_pairs);
    w.u8(1); // pointer (authovl)
    w.u8(1); // pointer (authovln)
    if conv_length {
        w.u8(username.len() as u8); // single-chunk length (mirrors Reader::bytes)
    }
    w.raw(username);
}

/// Build the phase-one AUTH FUNCTION request (func 118) for `username`,
/// reporting `client`'s OS user, machine, terminal, program and process.
///
/// `ttc_field_version` is the version negotiated with the target DB; it governs
/// the preamble's `token_num`, and `conv_length` the username encoding (see
/// [`write_preamble`]).
pub fn build_phase_one_request(
    username: &[u8],
    seq: u8,
    ttc_field_version: u8,
    conv_length: bool,
    client: &ReportedClient,
) -> Vec<u8> {
    let mut w = Writer::new();
    write_preamble(
        &mut w,
        FUNC_AUTH_PHASE_ONE,
        seq,
        username,
        AUTH_MODE_LOGON,
        5,
        ttc_field_version,
        conv_length,
    );
    w.key_value(b"AUTH_TERMINAL", &client.terminal, 0);
    w.key_value(b"AUTH_PROGRAM_NM", &client.program, 0);
    w.key_value(b"AUTH_MACHINE", &client.machine, 0);
    w.key_value(b"AUTH_PID", &client.process, 0);
    w.key_value(b"AUTH_SID", &client.os_user, 0);
    wrap_data_packet(&w.buf)
}

/// Build the phase-two AUTH FUNCTION request (func 115) carrying the derived
/// O5LOGON material and `client`'s driver name and version. The binary proof
/// values are uppercase-hex encoded onto the wire, mirroring the `hex::decode`
/// the parser applies on the way back. `ttc_field_version` and `conv_length`
/// shape the preamble as in [`build_phase_one_request`].
///
/// It sends no `AUTH_ALTER_SESSION`: the gateway used to force UTC there,
/// shifting `CURRENT_DATE` away from `SYSDATE`. The server only accepts plain
/// `ALTER SESSION SET` options in it (a PL/SQL block fails the login with
/// ORA-02248), so the gateway sets the session time zone with a separate
/// statement after login instead.
pub fn build_phase_two_request(
    username: &[u8],
    seq: u8,
    auth: &ClientAuth,
    ttc_field_version: u8,
    conv_length: bool,
    client: &ReportedClient,
) -> Vec<u8> {
    let mut w = Writer::new();
    write_preamble(
        &mut w,
        FUNC_AUTH_PHASE_TWO,
        seq,
        username,
        AUTH_MODE_WITH_PASSWORD,
        7,
        ttc_field_version,
        conv_length,
    );
    w.key_value(b"AUTH_SESSKEY", hex_upper(&auth.sesskey_ct).as_bytes(), 1);
    w.key_value(
        b"AUTH_PBKDF2_SPEEDY_KEY",
        hex_upper(&auth.speedy_key).as_bytes(),
        0,
    );
    w.key_value(
        b"AUTH_PASSWORD",
        hex_upper(&auth.auth_password).as_bytes(),
        0,
    );
    w.key_value(b"SESSION_CLIENT_CHARSET", b"873", 0);
    w.key_value(b"SESSION_CLIENT_DRIVER_NAME", &client.driver, 0);
    w.key_value(b"SESSION_CLIENT_VERSION", &client.version, 0);
    w.key_value(b"AUTH_CONNECT_STRING", b"", 0);
    wrap_data_packet(&w.buf)
}

/// OCI argument-pointer sentinel: `0xFE` and seven `0xFF` (the server only
/// distinguishes a present pointer from a null one).
const OCI_POINTER: [u8; 8] = [0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

/// Build a thick/OCI AUTH FUNCTION request in `layout` (the one the client's
/// own AUTH used on this session, which the DB now expects).
///
/// Every byte comes from the gateway: msg type, `function_code`, `seq`, then the
/// argument pointers and `u32` fields — the username buffer size (OCI declares
/// three bytes per character), `auth_mode`, `num_pairs`, which a wide layout
/// follows with a zero `u32`. Nothing is copied from the client's request, in
/// particular not its `auth_mode`, whose privilege bits (SYSDBA, SYSOPER, ...)
/// would otherwise reach the DB under the target's credentials. Byte-identical
/// to real SQL*Plus requests of both layouts (see the tests). The username and
/// `pairs` follow, in the OCI client framing ([`Writer::key_value_thick_client`]).
fn thick_request(
    layout: ThickLayout,
    function_code: u8,
    seq: u8,
    auth_mode: u32,
    username: &[u8],
    pairs: &[(&[u8], &[u8], u32)],
) -> Vec<u8> {
    let mut w = Writer::new();
    w.raw(&[MSG_TYPE_FUNCTION, function_code, seq]);
    w.raw(&OCI_POINTER); // username
    w.raw(&((username.len() * 3) as u32).to_le_bytes());
    w.raw(&auth_mode.to_le_bytes());
    w.raw(&OCI_POINTER); // key/value list
    w.raw(&(pairs.len() as u32).to_le_bytes());
    if layout == ThickLayout::Wide {
        w.raw(&0u32.to_le_bytes());
    }
    w.raw(&OCI_POINTER); // authovl
    w.raw(&OCI_POINTER); // authovln
    w.u8(username.len() as u8);
    w.raw(username);
    for (key, value, flag) in pairs {
        w.key_value_thick_client(key, value, *flag);
    }
    wrap_data_packet(&w.buf)
}

/// Thick/OCI variant of [`build_phase_one_request`] — used on the gateway's DB
/// leg when the client (and therefore the relayed negotiation) is a thick/OCI
/// client, so the database expects the thick FUNCTION framing in `layout`.
pub fn build_phase_one_request_thick(
    layout: ThickLayout,
    username: &[u8],
    seq: u8,
    client: &ReportedClient,
) -> Vec<u8> {
    thick_request(
        layout,
        FUNC_AUTH_PHASE_ONE,
        seq,
        AUTH_MODE_LOGON,
        username,
        &[
            (b"AUTH_TERMINAL", &client.terminal, 0),
            (b"AUTH_PROGRAM_NM", &client.program, 0),
            (b"AUTH_MACHINE", &client.machine, 0),
            (b"AUTH_PID", &client.process, 0),
            (b"AUTH_SID", &client.os_user, 0),
        ],
    )
}

/// Thick/OCI variant of [`build_phase_two_request`], in `layout`.
pub fn build_phase_two_request_thick(
    layout: ThickLayout,
    username: &[u8],
    seq: u8,
    auth: &ClientAuth,
    client: &ReportedClient,
) -> Vec<u8> {
    let sesskey = hex_upper(&auth.sesskey_ct);
    let speedy_key = hex_upper(&auth.speedy_key);
    let password = hex_upper(&auth.auth_password);
    thick_request(
        layout,
        FUNC_AUTH_PHASE_TWO,
        seq,
        AUTH_MODE_WITH_PASSWORD,
        username,
        &[
            (b"AUTH_SESSKEY", sesskey.as_bytes(), 1),
            (b"AUTH_PBKDF2_SPEEDY_KEY", speedy_key.as_bytes(), 0),
            (b"AUTH_PASSWORD", password.as_bytes(), 0),
            (b"SESSION_CLIENT_CHARSET", b"873", 0),
            (b"SESSION_CLIENT_DRIVER_NAME", &client.driver, 0),
            (b"SESSION_CLIENT_VERSION", &client.version, 0),
            (b"AUTH_CONNECT_STRING", b"", 0),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::negotiation::{parse_auth1_request, parse_auth2_request};

    /// A built DATA packet must start with the DATA type byte and carry its own
    /// total length (incl. header) in the big-endian u32 at bytes `[0..4]`.
    fn assert_data_packet_framing(pkt: &[u8]) {
        assert_eq!(pkt[4], PACKET_TYPE_DATA, "byte[4] is the DATA packet type");
        let declared = u32::from_be_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
        assert_eq!(
            declared as usize,
            pkt.len(),
            "header length == packet length"
        );
    }

    #[test]
    fn phase_one_round_trips_through_parser() {
        // Both the 23ai (token_num present) and the 19c (token_num absent) forms,
        // each with a length-prefixed (python/go-ora) and a raw (OJDBC) username,
        // must round-trip when built and parsed at the same field version.
        for fv in [27u8, field_version::PRE_23AI] {
            for conv_length in [true, false] {
                let pkt = build_phase_one_request(
                    b"appuser",
                    1,
                    fv,
                    conv_length,
                    &ReportedClient::gateway(),
                );
                assert_data_packet_framing(&pkt);
                let req = parse_auth1_request(&pkt, fv).unwrap();
                assert_eq!(req.username, "appuser", "fv={fv} conv_length={conv_length}");
                assert_eq!(req.seq, 1);
            }
        }
    }

    #[test]
    fn phase_one_19c_is_one_byte_shorter() {
        // The only wire difference is the single `token_num` ub8(0) byte, which
        // the 19c form omits.
        let p23 = build_phase_one_request(
            b"appuser",
            1,
            field_version::TOKEN_NUM_MIN,
            true,
            &ReportedClient::gateway(),
        );
        let p19 = build_phase_one_request(
            b"appuser",
            1,
            field_version::PRE_23AI,
            true,
            &ReportedClient::gateway(),
        );
        assert_eq!(p23.len(), p19.len() + 1);
    }

    #[test]
    fn raw_username_drops_only_the_length_byte() {
        // Without CONV_LENGTH (OJDBC) the username follows the pointer bytes
        // directly, exactly as OJDBC 23.2 sends it to a 19c server.
        let chunked = build_phase_one_request(
            b"BIS",
            5,
            field_version::PRE_23AI,
            true,
            &ReportedClient::gateway(),
        );
        let raw = build_phase_one_request(
            b"BIS",
            5,
            field_version::PRE_23AI,
            false,
            &ReportedClient::gateway(),
        );
        assert_eq!(raw.len() + 1, chunked.len());
        let body = &raw[DATA_HEADER_LEN..];
        // msg, func, seq, has_user, ub4 len, ub4 mode, ptr, ub4 5 pairs, ptr, ptr
        assert_eq!(
            &body[..16],
            &[3, 118, 5, 1, 1, 3, 1, 1, 1, 1, 5, 1, 1, b'B', b'I', b'S']
        );
    }

    #[test]
    fn phase_two_round_trips_through_parser() {
        let auth = ClientAuth {
            combo_key: [0u8; 32],
            sesskey_ct: vec![0xAB; 48],
            speedy_key: vec![0xCD; 80],
            auth_password: vec![0xEF; 32],
        };
        for fv in [27u8, field_version::PRE_23AI] {
            for conv_length in [true, false] {
                let pkt = build_phase_two_request(
                    b"appuser",
                    2,
                    &auth,
                    fv,
                    conv_length,
                    &ReportedClient::gateway(),
                );
                assert_data_packet_framing(&pkt);
                let req = parse_auth2_request(&pkt, fv).unwrap();
                assert_eq!(req.username, "appuser", "fv={fv} conv_length={conv_length}");
                assert_eq!(req.seq, 2);
                assert_eq!(req.sesskey_ct, vec![0xAB; 48]);
                assert_eq!(req.speedy_key, vec![0xCD; 80]);
                assert_eq!(req.auth_password, vec![0xEF; 32]);
            }
        }
    }

    // Real thick AUTH requests: OCI 19.8 against 23ai (narrow, 47-byte
    // preamble) and SQL*Plus 19 against 19c (wide, 51 bytes, user "wgtest").
    const THICK_AUTH1_23AI: &str = include_str!("../tests/fixtures/ttc/thick_auth1_req.hex");
    const THICK_AUTH1_19C: &str = include_str!("../tests/fixtures/ttc/thick_auth1_req_19c.hex");

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s.trim()).unwrap()
    }

    #[test]
    fn thick_preamble_matches_real_oci_requests_of_both_layouts() {
        for (template, layout, user, preamble_len) in [
            (THICK_AUTH1_23AI, ThickLayout::Narrow, &b"appuser"[..], 47),
            (THICK_AUTH1_19C, ThickLayout::Wide, &b"wgtest"[..], 51),
        ] {
            let real = unhex(template);
            let ours = build_phase_one_request_thick(layout, user, 2, &ReportedClient::gateway());
            assert_data_packet_framing(&ours);
            // Same seq, user and pair count as the capture: identical through
            // the username (preamble + ub1 length + name).
            let n = preamble_len + 1 + user.len();
            assert_eq!(
                &ours[DATA_HEADER_LEN..DATA_HEADER_LEN + n],
                &real[DATA_HEADER_LEN..DATA_HEADER_LEN + n]
            );
            let req = parse_auth1_request(&ours, 0).unwrap();
            assert_eq!(req.username, String::from_utf8_lossy(user));
            assert_eq!(req.seq, 2);
        }
    }

    #[test]
    fn thick_auth_mode_is_the_gateways_own() {
        // Whatever privilege bits a client asks for, the DB leg logs on plainly.
        for layout in [ThickLayout::Narrow, ThickLayout::Wide] {
            let one = build_phase_one_request_thick(layout, b"BIS", 5, &ReportedClient::gateway());
            assert_eq!(
                u32::from_le_bytes(
                    one[DATA_HEADER_LEN + 15..DATA_HEADER_LEN + 19]
                        .try_into()
                        .unwrap()
                ),
                AUTH_MODE_LOGON
            );
            let auth = ClientAuth {
                combo_key: [0; 32],
                sesskey_ct: vec![0xAB; 32],
                speedy_key: vec![0xCD; 80],
                auth_password: vec![0xEF; 32],
            };
            let two =
                build_phase_two_request_thick(layout, b"BIS", 6, &auth, &ReportedClient::gateway());
            assert_eq!(
                u32::from_le_bytes(
                    two[DATA_HEADER_LEN + 15..DATA_HEADER_LEN + 19]
                        .try_into()
                        .unwrap()
                ),
                AUTH_MODE_WITH_PASSWORD
            );
        }
    }

    #[test]
    fn thick_pairs_declare_buffers_like_oci() {
        let pkt =
            build_phase_one_request_thick(ThickLayout::Wide, b"BIS", 5, &ReportedClient::gateway());
        let body = &pkt[DATA_HEADER_LEN..];
        let at = 51 + 1 + 3;
        assert_eq!(
            u32::from_le_bytes(body[11..15].try_into().unwrap()),
            9,
            "3 bytes per char of BIS"
        );
        assert_eq!(
            u32::from_le_bytes(body[at..at + 4].try_into().unwrap()),
            39,
            "AUTH_TERMINAL as 13 * 3"
        );
    }

    #[test]
    fn requests_carry_the_reported_client() {
        use crate::negotiation::parse_auth_request_pairs;
        let client = ReportedClient {
            os_user: b"ivan".to_vec(),
            machine: b"WS-12_warpgate".to_vec(),
            terminal: b"unknown".to_vec(),
            program: b"toad.exe".to_vec(),
            process: b"4242".to_vec(),
            driver: b"jdbcthin".to_vec(),
            version: b"318767104".to_vec(),
        };
        let auth = ClientAuth {
            combo_key: [0; 32],
            sesskey_ct: vec![0xAB; 48],
            speedy_key: vec![0xCD; 80],
            auth_password: vec![0xEF; 32],
        };
        let value = |pkt: &[u8], fv: u8, key: &str| {
            parse_auth_request_pairs(pkt, fv)
                .unwrap()
                .into_iter()
                .find(|p| p.key == key)
                .unwrap()
                .value
        };
        let fv = field_version::PRE_23AI;
        for (one, two, fv) in [
            (
                build_phase_one_request(b"BIS", 5, fv, true, &client),
                build_phase_two_request(b"BIS", 6, &auth, fv, true, &client),
                fv,
            ),
            (
                build_phase_one_request_thick(ThickLayout::Wide, b"BIS", 5, &client),
                build_phase_two_request_thick(ThickLayout::Wide, b"BIS", 6, &auth, &client),
                0,
            ),
        ] {
            assert_eq!(value(&one, fv, "AUTH_SID"), client.os_user);
            assert_eq!(value(&one, fv, "AUTH_MACHINE"), client.machine);
            assert_eq!(value(&one, fv, "AUTH_TERMINAL"), client.terminal);
            assert_eq!(value(&one, fv, "AUTH_PROGRAM_NM"), client.program);
            assert_eq!(value(&one, fv, "AUTH_PID"), client.process);
            assert_eq!(value(&two, fv, "SESSION_CLIENT_DRIVER_NAME"), client.driver);
            assert_eq!(value(&two, fv, "SESSION_CLIENT_VERSION"), client.version);
        }
    }

    #[test]
    fn thick_phase_two_round_trips_through_parser() {
        let auth = ClientAuth {
            combo_key: [0u8; 32],
            sesskey_ct: vec![0xAB; 32],
            speedy_key: vec![0xCD; 80],
            auth_password: vec![0xEF; 32],
        };
        for layout in [ThickLayout::Narrow, ThickLayout::Wide] {
            let pkt = build_phase_two_request_thick(
                layout,
                b"alice",
                3,
                &auth,
                &ReportedClient::gateway(),
            );
            assert_data_packet_framing(&pkt);
            let req = parse_auth2_request(&pkt, 0).unwrap();
            assert_eq!(req.username, "alice");
            assert_eq!(req.seq, 3);
            assert_eq!(req.sesskey_ct, vec![0xAB; 32]);
            assert_eq!(req.speedy_key, vec![0xCD; 80]);
            assert_eq!(req.auth_password, vec![0xEF; 32]);
        }
    }
}
