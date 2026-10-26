//! Server-side auth RETURN messages (phase one / phase two): what the gateway,
//! acting as the Oracle server, sends in response to the client's AUTH
//! phase-one (func 118) and phase-two (func 115) requests. Both are built from
//! the real database's own RETURN to the gateway, so every session parameter
//! and status layout is the database's; only the O5LOGON values change.

use crate::crypto::hex_upper;
use crate::error::{Error, Result};
use crate::o5logon::Verifier12c;
use crate::packet::array_at;
use crate::ttc::{
    AuthPair, DATA_PAYLOAD_OFFSET, Writer, parse_return_key_values_thick_with_end,
    parse_return_key_values_with_end,
};

/// Verifier-type flag Oracle rides on the `AUTH_VFR_DATA` pair (12c verifier).
const AUTH_VFR_DATA_FLAG: u32 = 0x4815;

/// Prepend the 8-byte DATA packet header and the 2-byte data-flags to a TTC
/// body. Header: a 4-byte big-endian total length (the handshake is complete
/// and the negotiated version >= 315, so the 4-byte length form applies),
/// `0x06` (DATA type), `0x00` (flags), then two reserved zero bytes; the
/// data-flags are two more zero bytes. The length value includes the header.
fn wrap_data_packet(body: &[u8]) -> Vec<u8> {
    let total = (DATA_PAYLOAD_OFFSET + body.len()) as u32;
    let mut pkt = Vec::with_capacity(DATA_PAYLOAD_OFFSET + body.len());
    pkt.extend_from_slice(&total.to_be_bytes()); // [0..4] total packet length
    pkt.push(0x06); // [4] DATA packet type
    pkt.push(0x00); // [5] header flags
    pkt.extend_from_slice(&[0x00, 0x00]); // [6..8] reserved
    pkt.extend_from_slice(&[0x00, 0x00]); // [8..10] data-flags
    pkt.extend_from_slice(body);
    pkt
}

/// Build the phase-one auth RETURN for the client — the gateway's reply to the
/// client's FUNCTION func=118 — from the database's own phase-one RETURN
/// (`db_ret1`, its reply to the gateway's AUTH1 on the same, client-negotiated
/// DB leg).
///
/// Only the O5LOGON challenge is replaced: `AUTH_SESSKEY` (the caller's
/// `sesskey_ct`) and the verifier parameters (`AUTH_VFR_DATA`, the PBKDF2 salt
/// and counts) from the user's Warpgate verifier; a missing one is appended.
/// Every other pair and, above all, the trailing status message are the DB's
/// own. That status' layout depends on the server, the client and the
/// negotiated versions — a 19c server answers OCI with 144 bytes where a 23ai
/// one sends 71, and a thin 19c session must not get the 20c fields — so a
/// replayed capture always fits some clients and hangs or breaks others.
/// `thick` selects the OCI framing the client negotiated.
pub fn build_phase_one_return(
    db_ret1: &[u8],
    v: &Verifier12c,
    sesskey_ct: &[u8],
    thick: bool,
) -> Result<Vec<u8>> {
    let (mut pairs, end) = if thick {
        parse_return_key_values_thick_with_end(db_ret1)?
    } else {
        parse_return_key_values_with_end(db_ret1)?
    };
    let msg_type = *db_ret1.get(DATA_PAYLOAD_OFFSET).ok_or(Error::Truncated {
        need: DATA_PAYLOAD_OFFSET + 1,
        got: db_ret1.len(),
    })?;

    let challenge = [
        ("AUTH_SESSKEY", hex_upper(sesskey_ct).into_bytes(), None),
        (
            "AUTH_VFR_DATA",
            hex_upper(&v.vfr_data).into_bytes(),
            Some(AUTH_VFR_DATA_FLAG),
        ),
        (
            "AUTH_PBKDF2_CSK_SALT",
            hex_upper(&v.csk_salt).into_bytes(),
            None,
        ),
        (
            "AUTH_PBKDF2_VGEN_COUNT",
            v.vgen_count.to_string().into_bytes(),
            None,
        ),
        (
            "AUTH_PBKDF2_SDER_COUNT",
            v.sder_count.to_string().into_bytes(),
            None,
        ),
    ];
    for (key, value, flag) in challenge {
        match pairs.iter_mut().find(|p| p.key == key) {
            Some(pair) => {
                pair.value = value;
                pair.flag = flag.unwrap_or(pair.flag);
            }
            None => pairs.push(AuthPair {
                key: key.into(),
                value,
                flag: flag.unwrap_or(0),
            }),
        }
    }

    let mut w = Writer::new();
    w.u8(msg_type);
    if thick {
        w.raw(&(pairs.len() as u16).to_le_bytes());
    } else {
        w.ub2(pairs.len() as u16);
    }
    for p in &pairs {
        if thick {
            w.key_value_thick(p.key.as_bytes(), &p.value, p.flag);
        } else {
            w.key_value(p.key.as_bytes(), &p.value, p.flag);
        }
    }
    w.raw(db_ret1.get(end..).ok_or(Error::Truncated {
        need: end,
        got: db_ret1.len(),
    })?);
    Ok(wrap_data_packet(&w.buf))
}

/// Where the value of the `AUTH_SVR_RESPONSE` pair sits in a phase-two RETURN:
/// thin framing is `ub4` length, `ub1` chunk length, bytes; thick framing is a
/// raw little-endian `u32` outer length, `ub1` length, bytes.
fn svr_response_span(packet: &[u8], thick: bool) -> Result<std::ops::Range<usize>> {
    const KEY: &[u8] = b"AUTH_SVR_RESPONSE";
    let key_pos = packet
        .windows(KEY.len())
        .position(|w| w == KEY)
        .ok_or(Error::Invalid("RETURN has no AUTH_SVR_RESPONSE pair"))?;
    let after_key = key_pos + KEY.len();
    let (start, len) = if thick {
        let len = array_at::<1>(packet, after_key + 4)?;
        (after_key + 5, usize::from(len[0]))
    } else {
        let mut r = crate::ttc::Reader::new(packet, after_key);
        let value_len = r.ub4()? as usize;
        let chunk_len = r.u8()? as usize;
        if chunk_len != value_len {
            return Err(Error::Invalid("AUTH_SVR_RESPONSE is not a single chunk"));
        }
        (r.pos(), value_len)
    };
    let end = start + len;
    if end > packet.len() {
        return Err(Error::Truncated {
            need: end,
            got: packet.len(),
        });
    }
    Ok(start..end)
}

/// The `AUTH_SVR_RESPONSE` ciphertext of a phase-two RETURN (hex-decoded).
pub fn svr_response(packet: &[u8], thick: bool) -> Result<Vec<u8>> {
    let span = svr_response_span(packet, thick)?;
    let hex_value = packet
        .get(span)
        .ok_or(Error::Invalid("AUTH_SVR_RESPONSE out of range"))?;
    hex::decode(hex_value).map_err(|_| Error::Invalid("AUTH_SVR_RESPONSE is not hex"))
}

/// Return a copy of a phase-two RETURN packet with the `AUTH_SVR_RESPONSE`
/// value replaced by `svr_response_ct` (uppercase-hex encoded) in place.
///
/// This is how the proxy relays the *real* database's session RETURN to the
/// client while swapping only the mutual-auth proof — recomputed under the
/// client-leg combo key. The replacement must be the same length as the
/// original value (both are 48-byte ciphertexts → 96 hex chars), so the packet
/// framing and length header are preserved untouched.
pub fn substitute_svr_response(packet: &[u8], svr_response_ct: &[u8]) -> Result<Vec<u8>> {
    substitute(packet, svr_response_ct, false)
}

/// Thick/OCI variant of [`substitute_svr_response`] (see [`svr_response_span`]
/// for the framing).
pub fn substitute_svr_response_thick(packet: &[u8], svr_response_ct: &[u8]) -> Result<Vec<u8>> {
    substitute(packet, svr_response_ct, true)
}

fn substitute(packet: &[u8], svr_response_ct: &[u8], thick: bool) -> Result<Vec<u8>> {
    let span = svr_response_span(packet, thick)?;
    let new_value = hex_upper(svr_response_ct).into_bytes();
    if new_value.len() != span.len() {
        return Err(Error::Invalid("AUTH_SVR_RESPONSE length mismatch"));
    }
    let mut out = packet.to_vec();
    out.get_mut(span)
        .ok_or(Error::Invalid("AUTH_SVR_RESPONSE out of range"))?
        .copy_from_slice(&new_value);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ttc::parse_return_key_values;

    fn find<'a>(pairs: &'a [AuthPair], key: &str) -> &'a AuthPair {
        pairs.iter().find(|p| p.key == key).expect("pair present")
    }

    /// Every packet we build must be a well-formed DATA packet whose 4-byte
    /// big-endian length header matches its real length.
    fn assert_data_packet(pkt: &[u8]) {
        assert_eq!(pkt[4], 0x06, "DATA packet type byte");
        let len = u32::from_be_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]) as usize;
        assert_eq!(len, pkt.len(), "length header equals actual packet length");
    }

    // Real phase-one RETURNs, each the DB's reply to an AUTH1: 23ai to
    // python-oracledb, and 19c to python-oracledb (thin) and to SQL*Plus 19
    // (thick/OCI, whose 144-byte status differs from 23ai's 71 bytes).
    const AUTH1_RESP_23AI: &str = include_str!("../tests/fixtures/ttc/auth1_resp.hex");
    const AUTH1_RESP_19C: &str = include_str!("../tests/fixtures/ttc/auth1_resp_19c.hex");
    const THICK_AUTH1_RESP_19C: &str =
        include_str!("../tests/fixtures/ttc/thick_auth1_resp_19c.hex");

    fn verifier() -> Verifier12c {
        Verifier12c::from_password(b"pw", [0x11; 16], 4096, [0x22; 16], 3)
    }

    /// The rebuilt RETURN must carry our challenge, keep every other DB pair,
    /// and end with exactly the DB's own status trailer.
    fn check_rebuilt(template_hex: &str, thick: bool) {
        let template = hex::decode(template_hex.trim()).unwrap();
        let parse = |p: &[u8]| {
            if thick {
                parse_return_key_values_thick_with_end(p).unwrap()
            } else {
                parse_return_key_values_with_end(p).unwrap()
            }
        };
        let (db_pairs, db_end) = parse(&template);
        let v = verifier();
        let pkt = build_phase_one_return(&template, &v, &[0xAB; 32], thick).unwrap();
        assert_data_packet(&pkt);

        let (pairs, end) = parse(&pkt);
        assert_eq!(
            &pkt[end..],
            &template[db_end..],
            "status trailer is the DB's"
        );
        assert_eq!(
            find(&pairs, "AUTH_SESSKEY").value,
            hex_upper(&[0xAB; 32]).into_bytes()
        );
        let vfr = find(&pairs, "AUTH_VFR_DATA");
        assert_eq!(vfr.value, hex_upper(&v.vfr_data).into_bytes());
        assert_eq!(vfr.flag, 0x4815, "verifier type rides in the pair flag");
        assert_eq!(
            find(&pairs, "AUTH_PBKDF2_CSK_SALT").value,
            hex_upper(&v.csk_salt).into_bytes()
        );
        assert_eq!(find(&pairs, "AUTH_PBKDF2_VGEN_COUNT").value, b"4096");
        assert_eq!(find(&pairs, "AUTH_PBKDF2_SDER_COUNT").value, b"3");
        let dbid = db_pairs
            .iter()
            .find(|p| p.key.starts_with("AUTH_GLOBALLY_UNIQUE_DBID"))
            .unwrap();
        assert_eq!(
            find(&pairs, &dbid.key),
            dbid,
            "other DB pairs pass through unchanged"
        );
        assert_eq!(pairs.len(), db_pairs.len());
    }

    #[test]
    fn phase_one_from_23ai_thin_template() {
        check_rebuilt(AUTH1_RESP_23AI, false);
    }

    #[test]
    fn phase_one_from_19c_thin_template() {
        check_rebuilt(AUTH1_RESP_19C, false);
    }

    #[test]
    fn phase_one_from_19c_thick_template() {
        let template = hex::decode(THICK_AUTH1_RESP_19C.trim()).unwrap();
        let (_, end) = parse_return_key_values_thick_with_end(&template).unwrap();
        assert_eq!(template.len() - end, 144, "19c OCI status trailer");
        check_rebuilt(THICK_AUTH1_RESP_19C, true);
    }

    #[test]
    fn phase_one_appends_a_missing_challenge_pair() {
        // A template without the PBKDF2 pairs (e.g. an 11g-verifier DB user)
        // still yields a complete 12c challenge for the client.
        let mut w = Writer::new();
        w.u8(8);
        w.ub2(2);
        w.key_value(b"AUTH_SESSKEY", &[b'0'; 64], 0);
        w.key_value(b"AUTH_VFR_DATA", &[b'1'; 20], 0xb152);
        w.raw(&[4, 0]);
        let template = wrap_data_packet(&w.buf);
        let pkt = build_phase_one_return(&template, &verifier(), &[0xAB; 32], false).unwrap();
        let (pairs, end) = parse_return_key_values_with_end(&pkt).unwrap();
        assert_eq!(pairs.len(), 5);
        assert_eq!(find(&pairs, "AUTH_VFR_DATA").flag, 0x4815);
        assert_eq!(find(&pairs, "AUTH_PBKDF2_SDER_COUNT").value, b"3");
        assert_eq!(&pkt[end..], &[4, 0]);
    }

    #[test]
    fn substitution_rejects_a_truncated_packet() {
        let base = hex::decode(AUTH2_RESP_23AI.trim()).unwrap();
        let key = base
            .windows(17)
            .position(|w| w == b"AUTH_SVR_RESPONSE")
            .unwrap();
        assert!(substitute_svr_response(&base[..key + 30], &[0x11; 48]).is_err());
        assert!(substitute_svr_response_thick(&base[..key + 30], &[0x11; 48]).is_err());
    }

    #[test]
    fn phase_one_rejects_a_truncated_template() {
        let template = hex::decode(AUTH1_RESP_19C.trim()).unwrap();
        assert!(build_phase_one_return(&template[..60], &verifier(), &[0xAB; 32], false).is_err());
    }

    // The real phase-two RETURN of Oracle 23ai to python-oracledb.
    const AUTH2_RESP_23AI: &str = include_str!("../tests/fixtures/ttc/auth2_resp.hex");

    #[test]
    fn substitutes_svr_response_in_place() {
        let base = hex::decode(AUTH2_RESP_23AI.trim()).unwrap();
        let swapped = substitute_svr_response(&base, &[0x11; 48]).unwrap();
        assert_eq!(base.len(), swapped.len(), "packet length is preserved");
        let pairs = parse_return_key_values(&swapped).unwrap();
        assert_eq!(
            find(&pairs, "AUTH_SVR_RESPONSE").value,
            hex_upper(&[0x11; 48]).into_bytes()
        );
        assert!(
            pairs.iter().any(|p| p.key == "AUTH_SESSION_ID"),
            "all other pairs are left intact"
        );
        assert_eq!(svr_response(&swapped, false).unwrap(), vec![0x11; 48]);
    }
}
