//! Classic-flow negotiation: static PROTOCOL/DATATYPE replay and parsing of the
//! client's AUTH FUNCTION requests.
//!
//! The gateway (acting as the Oracle server) answers the client's PROTOCOL and
//! DATATYPE negotiation by replaying the captured server responses verbatim, and
//! parses the client's phase-one (func 118) and phase-two (func 115) AUTH
//! FUNCTION requests to recover the username and — for phase two — the
//! `AUTH_SESSKEY` / `AUTH_PBKDF2_SPEEDY_KEY` / `AUTH_PASSWORD` values.
//!
//! The request body layout is transcribed from python-oracledb
//! `impl/thin/messages/auth.pyx::_write_message` and validated byte-exact against
//! the real captured packets in `tests/fixtures/ttc/{auth1,auth2}_req.hex`.

use crate::constants::field_version;
use crate::error::{Error, Result};
use crate::packet::array_at;
use crate::ttc::{AuthPair, DATA_PAYLOAD_OFFSET, Reader, read_bytes_thick};

/// TTC message type of a FUNCTION call (`TNS_MSG_TYPE_FUNCTION`).
const MSG_TYPE_FUNCTION: u8 = 3;
/// Function code for AUTH phase one (`TNS_FUNC_AUTH_PHASE_ONE`).
const FUNC_AUTH_PHASE_ONE: u8 = 118;
/// Function code for AUTH phase two (`TNS_FUNC_AUTH_PHASE_TWO`).
const FUNC_AUTH_PHASE_TWO: u8 = 115;
/// Longest AUTH username accepted (Oracle's own limit is 128 bytes).
const MAX_USERNAME_LEN: usize = 256;

/// Extract the server's negotiated TTC field version from its PROTOCOL response
/// DATA packet (TTC `msg_type == 1`): the value the client clamps to and then
/// uses to decide whether it emits `token_num` in every later FUNCTION preamble.
/// Returns `None` if `pkt` is not a well-formed PROTOCOL response.
///
/// Mirrors python-oracledb `protocol.pyx::_process_protocol_info`: after the TTC
/// message-type byte come the 1-byte server version, a zero byte, the
/// NUL-terminated server banner, the u16-LE charset id, the 1-byte server flags,
/// a u16-LE element count (then that many 5-byte elements), a u16-BE `fdo`
/// length (then that many `fdo` bytes), and finally the server's compile
/// capabilities as a `ub1`-length byte string whose byte
/// [`field_version::CAPS_INDEX`] is the field version. Validated against real
/// 23ai (= 27) and 19c (= 12) PROTOCOL responses.
pub fn server_protocol_field_version(pkt: &[u8]) -> Option<u8> {
    let body = pkt.get(DATA_PAYLOAD_OFFSET..)?;
    if *body.first()? != crate::constants::msg::PROTOCOL {
        return None;
    }
    // server version (ub1) + a zero byte.
    let mut i = 1usize + 1 + 1;
    // NUL-terminated server banner.
    let nul = body.get(i..)?.iter().position(|&b| b == 0)?;
    i += nul + 1;
    i += 2; // charset id (u16 LE)
    i += 1; // server flags (ub1)
    let num_elem = u16::from_le_bytes(body.get(i..i + 2)?.try_into().ok()?) as usize;
    i = i.checked_add(2)?.checked_add(num_elem.checked_mul(5)?)?;
    let fdo_len = u16::from_be_bytes(body.get(i..i + 2)?.try_into().ok()?) as usize;
    i = i.checked_add(2)?.checked_add(fdo_len)?;
    // The compile-caps array is small (tens of bytes), so it is always the
    // short `ub1`-length form, never the 0xFE/0xFF long/NULL indicators.
    let caps_len = *body.get(i)? as usize;
    if caps_len == 0xFE || caps_len == 0xFF {
        return None;
    }
    i += 1;
    let caps = body.get(i..i + caps_len)?;
    caps.get(field_version::CAPS_INDEX).copied()
}

/// What the gateway needs from a client's DATATYPES request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientDataTypes {
    /// The [`encoding::CONV_LENGTH`](crate::constants::encoding::CONV_LENGTH)
    /// flag: whether the server will expect length-prefixed CHR fields (the AUTH
    /// username, the EXECUTE SQL text) from this client for the session.
    pub conv_length: bool,
    /// The TTC field version from the client's compile capabilities — the client
    /// already lowered it to the server's, so the session's effective field
    /// version is the minimum of this and the server's. `None` if the caps are
    /// too short to carry it.
    pub field_version: Option<u8>,
}

/// Parse a client's DATATYPES request (a DATA packet with TTC `msg_type == 2`).
/// Returns `None` for any other packet.
///
/// Layout (python-oracledb `DataTypesMessage`): msg type, u16-LE charset, u16-LE
/// ncharset, the encoding-flags byte, then the compile capabilities as a
/// `ub1`-length byte string whose byte [`field_version::CAPS_INDEX`] is the
/// field version.
pub fn parse_client_datatypes(pkt: &[u8]) -> Option<ClientDataTypes> {
    if pkt.get(4) != Some(&crate::constants::packet::DATA) {
        return None;
    }
    let body = pkt.get(DATA_PAYLOAD_OFFSET..)?;
    if *body.first()? != crate::constants::msg::DATA_TYPES {
        return None;
    }
    let flags = *body.get(5)?;
    let caps_len = *body.get(6)? as usize;
    let field_version = body
        .get(7..7 + caps_len)
        .and_then(|caps| caps.get(field_version::CAPS_INDEX))
        .copied();
    Some(ClientDataTypes {
        conv_length: flags & crate::constants::encoding::CONV_LENGTH != 0,
        field_version,
    })
}

/// Fields recovered from a FUNCTION request preamble; the reader is left
/// positioned at the first key/value pair.
struct Preamble {
    seq: u8,
    username: String,
    num_pairs: u32,
}

/// Parse the common FUNCTION request preamble and the (optional) username.
///
/// Layout: `msg_type`, `function_code`, `seq`, `token_num` (ub8 — **only** when
/// the negotiated `ttc_field_version >= TOKEN_NUM_MIN`, e.g. 23ai; a 19c client
/// omits it), `has_user`, `user_len` (ub4), `auth_mode` (ub4), a pointer byte,
/// `num_pairs` (ub4), two pointer bytes, then — when `has_user` — the username
/// as a single chunked byte string (`Reader::bytes`, not `bytes_with_length`).
///
/// Reading `token_num` unconditionally against a pre-23ai target drifts the
/// cursor by one byte and reads the username as garbage, so the gateway must
/// pass the version negotiated with the real server (see
/// [`server_protocol_field_version`]).
fn parse_preamble(
    r: &mut Reader<'_>,
    expected_func: u8,
    ttc_field_version: u8,
) -> Result<Preamble> {
    if r.u8()? != MSG_TYPE_FUNCTION {
        return Err(Error::Invalid("not a FUNCTION message"));
    }
    if r.u8()? != expected_func {
        return Err(Error::Invalid("unexpected AUTH function code"));
    }
    let seq = r.u8()?;
    if ttc_field_version >= field_version::TOKEN_NUM_MIN {
        let _token_num = r.ub8()?; // present only at 23ai-level field versions
    }
    let has_user = r.u8()?;
    let user_len = r.ub4()? as usize;
    let _auth_mode = r.ub4()?;
    let _ = r.u8()?; // pointer (authivl)
    let num_pairs = r.ub4()?;
    let _ = r.u8()?; // pointer (authovl)
    let _ = r.u8()?; // pointer (authovln)
    let username = if has_user != 0 {
        String::from_utf8_lossy(&read_username(r, user_len)?).into_owned()
    } else {
        String::new()
    };
    Ok(Preamble {
        seq,
        username,
        num_pairs,
    })
}

/// Read the login username from a thin FUNCTION preamble, using the preamble's
/// `user_len` as the authoritative length. Two thin drivers encode it
/// differently after the pointer bytes, and the gateway must accept both:
///
///   * **python-oracledb / go-ora** write it as a chunked byte string — a
///     leading `ub1` length (equal to `user_len`) then the bytes;
///   * **Oracle JDBC thin (OJDBC)** writes the raw bytes directly, with no
///     leading length, sized only by the `user_len` field.
///
/// Disambiguation is unambiguous for real usernames: the optional leading length
/// equals `user_len`, while a username's first byte is printable ASCII
/// (`>= 0x20`), so when `user_len <= 0x1F` the two never collide. For a longer
/// `user_len` we only skip a leading byte that exactly equals it (the chunked
/// form's invariant); a mis-split would merely yield an unknown user and fail
/// closed, never a wrong-user match.
fn read_username(r: &mut Reader<'_>, user_len: usize) -> Result<Vec<u8>> {
    if user_len == 0 {
        return Ok(Vec::new());
    }
    // `user_len` comes from the client before authentication; Oracle usernames
    // are at most 128 bytes, so anything longer is malformed.
    if user_len > MAX_USERNAME_LEN {
        return Err(Error::Invalid("AUTH username too long"));
    }
    let first = r.u8()?;
    if first as usize == user_len {
        // Chunked form: `first` was the length prefix; the bytes follow.
        r.take_bytes(user_len)
    } else {
        // Raw form (OJDBC): `first` is already the first username byte.
        let rest = r.take_bytes(user_len - 1)?;
        let mut out = Vec::with_capacity(user_len);
        out.push(first);
        out.extend_from_slice(&rest);
        Ok(out)
    }
}

/// All key/value pairs of a client AUTH request — phase one (func 118) or two
/// (func 115), thin or thick: the O5LOGON fields and what the client reports
/// about itself, which Oracle shows in `v$session` (`AUTH_SID` = OS user,
/// `AUTH_MACHINE`, `AUTH_TERMINAL`, `AUTH_PROGRAM_NM`, `AUTH_PID`; in phase two
/// also `SESSION_CLIENT_DRIVER_NAME` and `SESSION_CLIENT_VERSION`).
/// `ttc_field_version` places the thin `token_num` as in [`parse_auth1_request`].
pub fn parse_auth_request_pairs(packet: &[u8], ttc_field_version: u8) -> Result<Vec<AuthPair>> {
    let payload = packet.get(DATA_PAYLOAD_OFFSET..).unwrap_or(&[]);
    let func = *payload.get(1).ok_or(Error::Truncated {
        need: DATA_PAYLOAD_OFFSET + 2,
        got: packet.len(),
    })?;
    if func != FUNC_AUTH_PHASE_ONE && func != FUNC_AUTH_PHASE_TWO {
        return Err(Error::Invalid("unexpected AUTH function code"));
    }
    let mut pairs = Vec::new();
    if is_thick_function(payload) {
        let user_at = thick_username_offset(payload).ok_or(Error::Invalid(
            "thick AUTH request without the expected argument pointers",
        ))?;
        let num_pairs = u32::from_le_bytes(array_at(payload, 27)?);
        let [user_len] = array_at::<1>(payload, user_at)?;
        let mut i = user_at + 1 + usize::from(user_len);
        for _ in 0..num_pairs {
            let key = read_bytes_thick(payload, &mut i)?;
            let value = read_bytes_thick(payload, &mut i)?;
            let flag = u32::from_le_bytes(array_at(payload, i)?);
            i += 4;
            pairs.push(AuthPair {
                key: String::from_utf8_lossy(&key).into_owned(),
                value,
                flag,
            });
        }
    } else {
        let mut r = Reader::at_data_payload(packet);
        let pre = parse_preamble(&mut r, func, ttc_field_version)?;
        for _ in 0..pre.num_pairs {
            let (key, value, flag) = r.key_value()?;
            pairs.push(AuthPair {
                key: String::from_utf8_lossy(&key).into_owned(),
                value,
                flag,
            });
        }
    }
    Ok(pairs)
}

/// A parsed phase-one AUTH FUNCTION request (func 118).
#[derive(Debug, Clone)]
pub struct Auth1Request {
    /// The TTC sequence number from the request preamble.
    pub seq: u8,
    /// The login username, decoded UTF-8 (lossy).
    pub username: String,
}

/// Detect the OCI/thick FUNCTION-call encoding. A thick client marshals the
/// call's argument pointers as `0xFE` followed by an 8-byte sentinel (a thin
/// client writes a single 0x00/0x01 byte), so the first argument byte after
/// `(msg_type, func, seq)` — TTC payload offset 3 — is `0xFE`. Thin always has a
/// zero there (the `token_num` ub8 is 0 on 23ai).
fn is_thick_function(payload: &[u8]) -> bool {
    payload.get(3) == Some(&0xFE)
}

/// Whether a client AUTH FUNCTION `packet` (a DATA packet) uses the thick/OCI
/// framing rather than the thin one. The gateway reads this from the client's
/// first AUTH request to decide which framing to speak on both legs.
pub fn is_thick_request(packet: &[u8]) -> bool {
    is_thick_function(packet.get(DATA_PAYLOAD_OFFSET..).unwrap_or(&[]))
}

/// Offset, in a thick FUNCTION payload, of the username's `ub1` length: right
/// after the fourth argument pointer (`0xFE` + seven `0xFF`). OCI versions put
/// different fields between the pointers — a 19c client adds a zero `u32` after
/// `num_pairs`, giving a 51-byte preamble where 23ai has 47 — so the pointers
/// are the stable landmark.
pub fn thick_username_offset(payload: &[u8]) -> Option<usize> {
    let mut pointers = 0;
    let mut i = 3;
    while let Some(&[first, ref rest @ ..]) = payload.get(i..).and_then(|p| p.first_chunk::<8>()) {
        if first == 0xFE && rest.iter().all(|&b| b == 0xFF) {
            pointers += 1;
            i += 8;
            if pointers == 4 {
                return Some(i);
            }
        } else {
            i += 1;
        }
    }
    None
}

/// How a thick/OCI request marshals its FUNCTION call. `Wide` follows several
/// `u32` fields with a zero `u32` — an AUTH preamble of 51 bytes where a narrow
/// one is 47. It depends on the client *and* the server it negotiated with (OCI
/// 19.8 against 23ai: narrow; SQL*Plus 19 and 23 against 19c: wide AUTH), and
/// can even differ between the AUTH and the EXECUTE calls of one session
/// (SQL*Plus 23 against 19c sends narrow EXECUTEs), so each is found separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThickLayout {
    Narrow,
    Wide,
}

impl ThickLayout {
    /// The layout of a client's thick AUTH request (from its preamble length),
    /// or `None` for one not seen yet.
    pub fn of_auth_request(packet: &[u8]) -> Option<Self> {
        let payload = packet.get(DATA_PAYLOAD_OFFSET..)?;
        match thick_username_offset(payload)? {
            47 => Some(Self::Narrow),
            51 => Some(Self::Wide),
            _ => None,
        }
    }
}

/// Extract the login username from a thick FUNCTION body. The username is the
/// first length-prefixed (`ub1`) printable-ASCII string after the 3-byte
/// `(msg_type, func, seq)` header: the OCI argument pointers that precede it are
/// `0xFE`/`0xFF` sentinels and the integer fields are zero, so none forms a
/// printable run, and the username sits immediately before the first key/value
/// pair. Returns an empty string if none is found.
fn thick_username(payload: &[u8]) -> String {
    let mut i = 3;
    while let Some((&len, rest)) = payload.get(i..).and_then(<[u8]>::split_first) {
        let len = usize::from(len);
        if (1..=30).contains(&len)
            && let Some(s) = rest.get(..len)
            && s.iter().all(|&b| (0x21..=0x7e).contains(&b))
        {
            return String::from_utf8_lossy(s).into_owned();
        }
        i += 1;
    }
    String::new()
}

/// Read a key/value pair's value by key name from a thick FUNCTION body. Thick
/// frames each string as `<u32 little-endian outer length> <ub1 length> <bytes>`
/// (an outer length of 0 means an absent value with no inner length). We locate
/// the ASCII `key` and return the raw bytes of the value string that follows it,
/// or `None` if the key is absent or the framing runs past the buffer.
fn thick_value_after_key(payload: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let pos = payload.windows(key.len()).position(|w| w == key)?;
    let mut i = pos + key.len();
    let outer = u32::from_le_bytes(payload.get(i..i + 4)?.try_into().ok()?);
    i += 4;
    if outer == 0 {
        return Some(Vec::new());
    }
    let vlen = *payload.get(i)? as usize;
    i += 1;
    Some(payload.get(i..i + vlen)?.to_vec())
}

/// Parse a client phase-one AUTH request from a DATA `packet`.
///
/// `ttc_field_version` is the TTC field version negotiated with the real server
/// (see [`server_protocol_field_version`]); it governs whether the thin preamble
/// carries a `token_num`. It is ignored on the thick/OCI path, whose preamble
/// never carries one.
pub fn parse_auth1_request(packet: &[u8], ttc_field_version: u8) -> Result<Auth1Request> {
    let payload = packet.get(DATA_PAYLOAD_OFFSET..).unwrap_or(&[]);
    if is_thick_function(payload) {
        if payload.first() != Some(&MSG_TYPE_FUNCTION) {
            return Err(Error::Invalid("not a FUNCTION message"));
        }
        if payload.get(1) != Some(&FUNC_AUTH_PHASE_ONE) {
            return Err(Error::Invalid("unexpected AUTH function code"));
        }
        let [seq] = array_at::<1>(payload, 2)?;
        return Ok(Auth1Request {
            seq,
            username: thick_username(payload),
        });
    }
    let mut r = Reader::at_data_payload(packet);
    let pre = parse_preamble(&mut r, FUNC_AUTH_PHASE_ONE, ttc_field_version)?;
    Ok(Auth1Request {
        seq: pre.seq,
        username: pre.username,
    })
}

/// A parsed phase-two AUTH FUNCTION request (func 115), carrying the client's
/// O5LOGON proof material (hex-decoded to raw bytes).
#[derive(Debug, Clone)]
pub struct Auth2Request {
    /// The TTC sequence number from the request preamble.
    pub seq: u8,
    /// The login username, decoded UTF-8 (lossy).
    pub username: String,
    /// `AUTH_SESSKEY`: the client's encrypted session key.
    pub sesskey_ct: Vec<u8>,
    /// `AUTH_PBKDF2_SPEEDY_KEY`: the 12c PBKDF2 "speedy" key.
    pub speedy_key: Vec<u8>,
    /// `AUTH_PASSWORD`: the encrypted password.
    pub auth_password: Vec<u8>,
}

/// Parse a client phase-two AUTH request from a DATA `packet`, extracting the
/// three O5LOGON pairs. Their values are uppercase-hex ASCII and are
/// `hex::decode`d to bytes. Returns [`Error::Invalid`] if a required pair is
/// absent or its value is not valid hex.
///
/// `ttc_field_version` governs the thin preamble's `token_num` exactly as in
/// [`parse_auth1_request`].
pub fn parse_auth2_request(packet: &[u8], ttc_field_version: u8) -> Result<Auth2Request> {
    let payload = packet.get(DATA_PAYLOAD_OFFSET..).unwrap_or(&[]);
    if is_thick_function(payload) {
        if payload.first() != Some(&MSG_TYPE_FUNCTION) {
            return Err(Error::Invalid("not a FUNCTION message"));
        }
        if payload.get(1) != Some(&FUNC_AUTH_PHASE_TWO) {
            return Err(Error::Invalid("unexpected AUTH function code"));
        }
        let hex_value = |key: &[u8]| -> Result<Vec<u8>> {
            let v = thick_value_after_key(payload, key)
                .ok_or(Error::Invalid("missing thick AUTH pair"))?;
            hex::decode(&v).map_err(|_| Error::Invalid("AUTH value is not hex"))
        };
        return Ok(Auth2Request {
            seq: payload.get(2).copied().unwrap_or(0),
            username: thick_username(payload),
            sesskey_ct: hex_value(b"AUTH_SESSKEY")?,
            speedy_key: hex_value(b"AUTH_PBKDF2_SPEEDY_KEY")?,
            auth_password: hex_value(b"AUTH_PASSWORD")?,
        });
    }
    let mut r = Reader::at_data_payload(packet);
    let pre = parse_preamble(&mut r, FUNC_AUTH_PHASE_TWO, ttc_field_version)?;

    let mut sesskey_ct = None;
    let mut speedy_key = None;
    let mut auth_password = None;
    for _ in 0..pre.num_pairs {
        let (key, value, _flag) = r.key_value()?;
        let field = if key == b"AUTH_SESSKEY" {
            &mut sesskey_ct
        } else if key == b"AUTH_PBKDF2_SPEEDY_KEY" {
            &mut speedy_key
        } else if key == b"AUTH_PASSWORD" {
            &mut auth_password
        } else {
            continue;
        };
        *field = Some(hex::decode(&value).map_err(|_| Error::Invalid("AUTH value is not hex"))?);
    }

    Ok(Auth2Request {
        seq: pre.seq,
        username: pre.username,
        sesskey_ct: sesskey_ct.ok_or(Error::Invalid("missing AUTH_SESSKEY"))?,
        speedy_key: speedy_key.ok_or(Error::Invalid("missing AUTH_PBKDF2_SPEEDY_KEY"))?,
        auth_password: auth_password.ok_or(Error::Invalid("missing AUTH_PASSWORD"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real captured classic-flow client FUNCTION requests from Oracle 23ai
    // (TTC field version 27, so the preamble carries a `token_num`).
    const AUTH1_REQ: &str = include_str!("../tests/fixtures/ttc/auth1_req.hex");
    const AUTH2_REQ: &str = include_str!("../tests/fixtures/ttc/auth2_req.hex");
    // Real captured classic-flow phase-one request from Oracle 19c (TTC field
    // version 12, so the preamble carries NO `token_num`). Captured from the
    // live thin login that this fix unblocks (user "wgtest").
    const AUTH1_REQ_19C: &str = include_str!("../tests/fixtures/ttc/auth1_req_19c.hex");
    // Real captured 19c phase-one request from the Oracle JDBC thin driver
    // (OJDBC 23.2): same field version 12, but the username is raw bytes sized
    // by `user_len` with NO leading chunked-length byte (unlike python-oracledb).
    const AUTH1_REQ_19C_JDBC: &str = include_str!("../tests/fixtures/ttc/auth1_req_19c_jdbc.hex");
    // Real captured 23ai and 19c server PROTOCOL responses.
    const PROTOCOL_RESP_23AI: &str = include_str!("../tests/fixtures/ttc/protocol_resp.hex");
    const PROTOCOL_RESP_19C: &str = include_str!("../tests/fixtures/ttc/protocol_resp_19c.hex");
    // Real captured thick/OCI (sqlplus Instant Client) FUNCTION requests, whose
    // marshalling differs from the thin client's.
    const THICK_AUTH1_REQ: &str = include_str!("../tests/fixtures/ttc/thick_auth1_req.hex");
    const THICK_AUTH2_REQ: &str = include_str!("../tests/fixtures/ttc/thick_auth2_req.hex");

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s.trim()).unwrap()
    }

    /// A real 23ai server PROTOCOL response.
    fn protocol_response() -> Vec<u8> {
        unhex(include_str!("../tests/fixtures/ttc/protocol_resp.hex"))
    }

    #[test]
    fn parses_client_datatypes() {
        // DATA header + data flags, then the real leading bytes of each driver's
        // DATATYPES request: msg 2, charset 873, ncharset 873, encoding flags,
        // and the start of the compile caps (field version at index 7).
        let datatypes = |flags: u8, caps: &[u8]| {
            let mut pkt = vec![0, 0, 0, 0, 6, 0, 0, 0, 0, 0];
            pkt.extend_from_slice(&[2, 0x69, 0x03, 0x69, 0x03, flags, caps.len() as u8]);
            pkt.extend_from_slice(caps);
            pkt
        };
        // python-oracledb 3.x: CONV_LENGTH, field version 24.
        let python = datatypes(
            0x03,
            &[0x06, 0x00, 0x00, 0x00, 0xea, 0x18, 0x00, 0x18, 0x01],
        );
        assert_eq!(
            parse_client_datatypes(&python),
            Some(ClientDataTypes {
                conv_length: true,
                field_version: Some(24)
            })
        );
        // OJDBC 23.2: no CONV_LENGTH, field version 19.
        let ojdbc = datatypes(
            0x01,
            &[0x06, 0x01, 0x00, 0x00, 0xea, 0x04, 0x01, 0x13, 0x01],
        );
        assert_eq!(
            parse_client_datatypes(&ojdbc),
            Some(ClientDataTypes {
                conv_length: false,
                field_version: Some(19)
            })
        );
        // Caps too short to reach the field version.
        let short_caps = datatypes(0x01, &[0x06, 0x01]);
        assert_eq!(
            parse_client_datatypes(&short_caps).unwrap().field_version,
            None
        );
    }

    #[test]
    fn client_datatypes_rejects_other_and_short_packets() {
        assert_eq!(parse_client_datatypes(&protocol_response()), None);
        // byte 10 == 2 but not a DATA packet (a MARKER).
        let mut marker = vec![0, 0, 0, 11, 0x0c, 0, 0, 0, 1, 0, 2];
        assert_eq!(parse_client_datatypes(&marker), None);
        // DATA packet whose DATATYPES body is cut short before the flags byte.
        marker[4] = 6;
        assert_eq!(parse_client_datatypes(&marker), None);
        assert_eq!(parse_client_datatypes(&[]), None);
    }

    #[test]
    fn thick_auth_layout_follows_the_preamble_length() {
        let pkt = |h: &str| unhex(h);
        assert_eq!(
            ThickLayout::of_auth_request(&pkt(THICK_AUTH1_REQ)),
            Some(ThickLayout::Narrow)
        );
        assert_eq!(
            ThickLayout::of_auth_request(&pkt(include_str!(
                "../tests/fixtures/ttc/thick_auth1_req_19c.hex"
            ))),
            Some(ThickLayout::Wide)
        );
        assert_eq!(ThickLayout::of_auth_request(&pkt(AUTH1_REQ)), None, "thin");
    }

    #[test]
    fn parses_phase_one_request() {
        // 23ai: field version >= 18, so the preamble carries a token_num.
        let req = parse_auth1_request(&unhex(AUTH1_REQ), 27).unwrap();
        assert_eq!(req.username, "appuser");
        assert_eq!(req.seq, 1);
    }

    #[test]
    fn parses_phase_one_request_19c() {
        // 19c: field version 12 (< 18), so there is NO token_num. Parsing it
        // with a 23ai-level version would read the username as garbage (the
        // original bug); parsing it with the negotiated 12 recovers it.
        let pkt = unhex(AUTH1_REQ_19C);
        let req = parse_auth1_request(&pkt, field_version::PRE_23AI).unwrap();
        assert_eq!(req.username, "wgtest");
        assert_eq!(req.seq, 1);
        // Guard against regressing to the unconditional read: parsing the real
        // 19c packet as if it were 23ai must NOT yield the real username.
        let wrong = parse_auth1_request(&pkt, field_version::TOKEN_NUM_MIN).unwrap();
        assert_ne!(wrong.username, "wgtest");
    }

    #[test]
    fn parses_phase_one_request_19c_jdbc() {
        // Oracle JDBC thin writes the username raw (no leading length byte); the
        // gateway must still recover it from `user_len`. OJDBC uppercases the
        // unquoted username, so expect "WGTEST" (matched case-insensitively at
        // the DB layer).
        let req = parse_auth1_request(&unhex(AUTH1_REQ_19C_JDBC), field_version::PRE_23AI).unwrap();
        assert_eq!(req.username, "WGTEST");
        assert_eq!(req.seq, 1);
    }

    #[test]
    fn parses_phase_two_request() {
        let req = parse_auth2_request(&unhex(AUTH2_REQ), 27).unwrap();
        assert_eq!(req.username, "appuser");
        assert_eq!(req.seq, 2);
        // Observed byte-exact against auth2_req.hex.
        assert_eq!(req.sesskey_ct.len(), 32);
        assert_eq!(req.speedy_key.len(), 80);
        assert_eq!(req.auth_password.len(), 32);
    }

    #[test]
    fn parses_thick_phase_one_request() {
        // The thick/OCI preamble never carries a token_num, so the field-version
        // argument is irrelevant: pass 0 to prove it is ignored on this path.
        let req = parse_auth1_request(&unhex(THICK_AUTH1_REQ), 0).unwrap();
        assert_eq!(req.username, "appuser");
        assert_eq!(req.seq, 2);
    }

    #[test]
    fn parses_thick_phase_two_request() {
        let req = parse_auth2_request(&unhex(THICK_AUTH2_REQ), 0).unwrap();
        assert_eq!(req.username, "appuser");
        assert_eq!(req.seq, 3);
        // Same O5LOGON material as the thin flow, differently framed on the wire.
        assert_eq!(req.sesskey_ct.len(), 32);
        assert_eq!(req.speedy_key.len(), 80);
        assert_eq!(req.auth_password.len(), 32);
    }

    #[test]
    fn rejects_wrong_function_code() {
        // The phase-two request (func 115) must not parse as phase one.
        assert_eq!(
            parse_auth1_request(&unhex(AUTH2_REQ), 27).unwrap_err(),
            Error::Invalid("unexpected AUTH function code")
        );
    }

    #[test]
    fn extracts_server_field_version() {
        // Real PROTOCOL responses: 23ai negotiates a field version >= the
        // token_num threshold, 19c negotiates below it.
        let v23 = server_protocol_field_version(&unhex(PROTOCOL_RESP_23AI)).unwrap();
        let v19 = server_protocol_field_version(&unhex(PROTOCOL_RESP_19C)).unwrap();
        assert_eq!(v23, 27);
        assert_eq!(v19, 12);
        assert!(v23 >= field_version::TOKEN_NUM_MIN, "23ai sends token_num");
        assert!(v19 < field_version::TOKEN_NUM_MIN, "19c omits token_num");
    }

    #[test]
    fn server_field_version_rejects_non_protocol_packet() {
        // An AUTH FUNCTION packet is not a PROTOCOL response.
        assert_eq!(server_protocol_field_version(&unhex(AUTH1_REQ)), None);
    }
}
