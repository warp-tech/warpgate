//! Parser for the TTC EXECUTE call (OALL8, function 94) and its re-execute
//! variants (4 / 78), extracting the SQL text for audit, and builder for the
//! gateway's own EXECUTE on the DB leg.

use crate::constants::field_version;
use crate::error::{Error, Result};
pub use crate::negotiation::ThickLayout;
use crate::packet::array_at;

/// Full execute ("OALL8") — carries the SQL text when the statement is parsed.
pub const FUNC_EXECUTE: u8 = 94;
/// Re-execute of an already-parsed cursor (no SQL text).
pub const FUNC_REEXECUTE: u8 = 4;
/// Re-execute and fetch (no SQL text).
pub const FUNC_REEXECUTE_AND_FETCH: u8 = 78;

/// Execute option bit: the statement is being parsed (its SQL text is present).
pub const OPTION_PARSE: u32 = 0x01;

/// The audit-relevant fields of a client EXECUTE call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecuteCall {
    /// TTC function code (94 full execute, 4 / 78 re-execute).
    pub function: u8,
    /// Cursor id (0 on first parse, non-zero when re-running a statement).
    pub cursor_id: u32,
    /// Execute options bitmask.
    pub options: u32,
    /// SQL text, present only when the statement is parsed in this call.
    pub sql: Option<String>,
}

/// Parse a client EXECUTE DATA packet (TTC message type 3, function 94/4/78).
///
/// Follows python-oracledb `execute.pyx::_write_execute_message`: after the
/// function preamble come `options` and `cursor_id`, then a fixed run of
/// pointer/`ub4` metadata fields, and finally — when the statement is being
/// parsed (`options & OPTION_PARSE`) — the SQL text as a single chunked byte
/// string. Re-execute variants (4 / 78) carry no SQL text.
///
/// `ttc_field_version` is the version negotiated with the real server: the
/// `token_num` ub8 in the FUNCTION/piggyback preamble is present only at
/// 23ai-level versions (`>= TOKEN_NUM_MIN`). A 19c client omits it, so reading
/// it unconditionally drifts the cursor and loses the SQL text for the audit —
/// the same root cause as the AUTH-parser bug.
///
/// `conv_length` is whether the client's DATATYPES set
/// [`encoding::CONV_LENGTH`](crate::constants::encoding::CONV_LENGTH): with it
/// (python-oracledb, go-ora) the SQL text is a chunked byte string; without it
/// (Oracle JDBC thin) it is exactly `sql length` raw bytes, and reading a length
/// byte would drop the first character and run on into the bind data.
pub fn parse_execute(
    packet: &[u8],
    ttc_field_version: u8,
    conv_length: bool,
) -> Result<ExecuteCall> {
    // TTC data-message type for a function call (`TNS_MSG_TYPE_FUNCTION`).
    const MSG_TYPE_FUNCTION: u8 = 3;
    // A piggyback rides at the start of the next call (close cursors, etc.).
    const MSG_TYPE_PIGGYBACK: u8 = 17;
    const FUNC_CLOSE_CURSORS: u8 = 105;

    let mut r = crate::ttc::Reader::at_data_payload(packet);

    // Skip any leading piggyback messages — python-oracledb prepends these
    // (most often close-cursors) before the real function call, so the EXECUTE
    // we want is not always the first TTC message. A piggyback header is
    // msg_type, function code, seq, token; the close-cursors body is a `ub4`
    // count then that many `ub4` cursor ids.
    // `token_num` rides in both the piggyback header and the main preamble, and
    // only at 23ai-level field versions (see the doc comment).
    let has_token_num = ttc_field_version >= field_version::TOKEN_NUM_MIN;
    let function = loop {
        match r.u8()? {
            MSG_TYPE_FUNCTION => break r.u8()?,
            MSG_TYPE_PIGGYBACK => {
                let code = r.u8()?;
                r.u8()?; // sequence
                if has_token_num {
                    r.ub8()?; // token number
                }
                if code == FUNC_CLOSE_CURSORS {
                    let count = r.ub4()?;
                    r.u8()?; // pointer to the cursor-id array
                    for _ in 0..count {
                        r.ub4()?;
                    }
                } else {
                    return Err(crate::error::Error::Invalid(
                        "unsupported piggyback before execute",
                    ));
                }
            }
            _ => return Err(crate::error::Error::Invalid("not a TTC function message")),
        }
    };
    r.u8()?; // sequence
    if has_token_num {
        r.ub8()?; // token number
    }

    match function {
        FUNC_EXECUTE => {
            let options = r.ub4()?;
            let cursor_id = r.ub4()?;

            // Cursor-id pointer + SQL length (both pyx branches write u8 + ub4).
            r.u8()?; // cursor-id pointer
            let sql_len = r.ub4()? as usize; // sql length (bytes)
            r.u8()?; // al8i4 vector pointer
            r.ub4()?; // al8i4 array length (13)

            // Fixed metadata run, mirroring `_write_execute_message` field order.
            r.u8()?; // al8o4 pointer
            r.u8()?; // al8o4l pointer
            r.ub4()?; // prefetch buffer size
            r.ub4()?; // prefetch number of rows (num_iters)
            r.ub4()?; // maximum long size
            r.u8()?; // binds pointer
            r.ub4()?; // number of binds
            r.u8()?; // al8app pointer
            r.u8()?; // al8txn pointer
            r.u8()?; // al8txl pointer
            r.u8()?; // al8kv pointer
            r.u8()?; // al8kvl pointer
            r.u8()?; // defines pointer
            r.ub4()?; // number of defines
            r.ub4()?; // registration id lsb
            r.u8()?; // al8objlist pointer
            r.u8()?; // al8objlen pointer
            r.u8()?; // al8blv pointer
            r.ub4()?; // al8blvl
            r.u8()?; // al8dnam pointer
            r.ub4()?; // al8dnaml
            r.ub4()?; // registration id msb
            r.u8()?; // al8pidmlrc pointer
            r.ub4()?; // al8pidmlrcbl
            r.u8()?; // al8pidmlrcl pointer
            r.u8()?; // al8sqlsig pointer (12.2)
            r.ub4()?; // SQL signature length
            r.u8()?; // SQL id pointer
            r.ub4()?; // allocated size of SQL id
            r.u8()?; // length-of-SQL-id pointer
            r.u8()?; // chunk ids pointer (12.2 ext1)
            r.ub4()?; // number of chunk ids

            // The SQL text follows, present exactly when the statement is parsed
            // in this call: a chunked byte string, or raw without CONV_LENGTH.
            let sql = if options & OPTION_PARSE != 0 {
                let text = if conv_length {
                    r.bytes()?
                } else {
                    r.take_bytes(sql_len)?
                };
                Some(String::from_utf8_lossy(&text).into_owned())
            } else {
                None
            };

            Ok(ExecuteCall {
                function,
                cursor_id,
                options,
                sql,
            })
        }
        FUNC_REEXECUTE | FUNC_REEXECUTE_AND_FETCH => {
            // Re-execute body: cursor id, iterations, two option words; no SQL.
            let cursor_id = r.ub4()?;
            r.ub4()?; // number of iterations
            let options = r.ub4()?;
            r.ub4()?; // second option word
            Ok(ExecuteCall {
                function,
                cursor_id,
                options,
                sql: None,
            })
        }
        _ => Err(crate::error::Error::Invalid("unexpected TTC function code")),
    }
}

/// Build a one-shot EXECUTE (func 94: parse + execute on a new cursor, no binds,
/// no defines) for a non-query statement such as a PL/SQL block — the inverse
/// of [`parse_execute`], following python-oracledb
/// `execute.pyx::_write_execute_message`. Used by the gateway to run its own
/// statement on the DB leg, so it must match what the client negotiated there:
/// `ttc_field_version` gates `token_num` and the 12.2 fields, and
/// `conv_length` the SQL-text framing.
pub fn build_execute_request(
    sql: &[u8],
    seq: u8,
    ttc_field_version: u8,
    conv_length: bool,
) -> Vec<u8> {
    use crate::constants::exec_option;
    use crate::ttc::Writer;
    /// `al8i4[9]` DML options: allow implicit result sets (python sends it on
    /// every executed non-query).
    const DML_IMPLICIT_RESULTSET: u32 = 0x8000;
    /// TNS_MAX_LONG_LENGTH: the maximum LONG size the client accepts.
    const MAX_LONG_LENGTH: u32 = 0x7fff_ffff;

    let mut w = Writer::new();
    w.u8(3); // msg type (function)
    w.u8(FUNC_EXECUTE);
    w.u8(seq);
    if ttc_field_version >= field_version::TOKEN_NUM_MIN {
        w.ub8(0); // token number
    }
    w.ub4(exec_option::PARSE | exec_option::EXECUTE);
    w.ub4(0); // cursor id (new cursor)
    w.u8(1); // pointer (cursor id)
    w.ub4(sql.len() as u32);
    w.u8(1); // pointer (al8i4 vector)
    w.ub4(13); // al8i4 array length
    w.u8(0); // pointer (al8o4)
    w.u8(0); // pointer (al8o4l)
    w.ub4(0); // prefetch buffer size
    w.ub4(1); // prefetch number of rows (one execution)
    w.ub4(MAX_LONG_LENGTH);
    w.u8(0); // pointer (binds)
    w.ub4(0); // number of binds
    for _ in 0..5 {
        w.u8(0); // pointers al8app, al8txn, al8txl, al8kv, al8kvl
    }
    w.u8(0); // pointer (defines)
    w.ub4(0); // number of defines
    w.ub4(0); // registration id
    w.u8(0); // pointer (al8objlist)
    w.u8(1); // pointer (al8objlen)
    w.u8(0); // pointer (al8blv)
    w.ub4(0); // al8blvl
    w.u8(0); // pointer (al8dnam)
    w.ub4(0); // al8dnaml
    w.ub4(0); // registration id msb
    w.u8(0); // pointer (al8pidmlrc)
    w.ub4(0); // al8pidmlrcbl
    w.u8(0); // pointer (al8pidmlrcl)
    if ttc_field_version >= field_version::V12_2 {
        w.u8(0); // pointer (al8sqlsig)
        w.ub4(0); // SQL signature length
        w.u8(0); // pointer (SQL id)
        w.ub4(0); // allocated size of SQL id
        w.u8(0); // pointer (length of SQL id)
        if ttc_field_version >= field_version::V12_2_EXT1 {
            w.u8(0); // pointer (chunk ids)
            w.ub4(0); // number of chunk ids
        }
    }
    if conv_length {
        w.bytes_with_length(sql);
    } else {
        w.raw(sql);
    }
    // al8i4: parse, execution count, then zeros except the DML options.
    for v in [1, 1, 0, 0, 0, 0, 0, 0, 0, DML_IMPLICIT_RESULTSET, 0, 0, 0] {
        w.ub4(v);
    }

    let mut pkt = Vec::with_capacity(crate::ttc::DATA_PAYLOAD_OFFSET + w.buf.len());
    pkt.extend_from_slice(&((crate::ttc::DATA_PAYLOAD_OFFSET + w.buf.len()) as u32).to_be_bytes());
    pkt.extend_from_slice(&[crate::constants::packet::DATA, 0, 0, 0, 0, 0]);
    pkt.extend_from_slice(&w.buf);
    pkt
}

/// The statement the gateway runs on the DB leg right after its own login to
/// put the session in the database server's own UTC offset (the one `SYSDATE`
/// and `SYSTIMESTAMP` follow), so `CURRENT_DATE` agrees with `SYSDATE`.
pub const SET_DB_SERVER_TIME_ZONE: &[u8] =
    b"BEGIN EXECUTE IMMEDIATE 'ALTER SESSION SET TIME_ZONE = ''' || TO_CHAR(SYSTIMESTAMP, 'TZH:TZM') || ''''; END;";

/// Thick/OCI EXECUTEs of [`SET_DB_SERVER_TIME_ZONE`] as SQL*Plus 19 (wide) and
/// 23 (narrow) sent them to a 19c server (field version 12). Building OCI's
/// OALL8 field by field is layout-specific, so the gateway replays these,
/// patching only the sequence and dropping the fields an older field version
/// lacks. Which layout a session's EXECUTEs use is not known before the
/// client's first call (SQL*Plus 23 against 19c sends a wide AUTH but narrow
/// EXECUTEs), so the caller tries one and falls back to the other on ORA-03146.
const THICK_SET_TZ_WIDE: &str = include_str!("templates/thick_execute_tz_wide.hex");
const THICK_SET_TZ_NARROW: &str = include_str!("templates/thick_execute_tz_narrow.hex");

/// The thick/OCI request running [`SET_DB_SERVER_TIME_ZONE`] in `layout` at
/// `ttc_field_version`.
///
/// Below 12.2 the EXECUTE lacks the fields [`build_execute_request`] gates the
/// same way: SQL signature / SQL id from 12.2, chunk ids from 12.2 EXT1. OCI
/// sends them as 8-byte pointers and layout-sized integers, all null/zero and
/// right before the SQL text, so dropping that many zero bytes there yields
/// the older layout — byte-identical to what SQL*Plus 12.1 (field version 7)
/// sends. Without it a 12.1 session rejects the call with ORA-01009.
pub fn build_thick_set_time_zone_request(
    layout: ThickLayout,
    seq: u8,
    ttc_field_version: u8,
) -> Result<Vec<u8>> {
    const POINTER: usize = 8;
    const BAD_TEMPLATE: Error = Error::Invalid("malformed time-zone EXECUTE template");
    let (template, int) = match layout {
        ThickLayout::Wide => (THICK_SET_TZ_WIDE, 8),
        ThickLayout::Narrow => (THICK_SET_TZ_NARROW, 4),
    };
    let mut pkt = hex::decode(template.trim()).map_err(|_| BAD_TEMPLATE)?;
    *pkt.get_mut(crate::ttc::DATA_PAYLOAD_OFFSET + 2)
        .ok_or(BAD_TEMPLATE)? = seq;

    let mut absent = 0;
    if ttc_field_version < field_version::V12_2 {
        absent += 3 * POINTER + 2 * int; // SQL signature, SQL id
    }
    if ttc_field_version < field_version::V12_2_EXT1 {
        absent += POINTER + int; // chunk ids
    }
    if absent > 0 {
        let sql_at = pkt
            .windows(SET_DB_SERVER_TIME_ZONE.len())
            .position(|w| w == SET_DB_SERVER_TIME_ZONE)
            .ok_or(BAD_TEMPLATE)?;
        // The fields end at the statement's length byte, right before the text.
        let fields_end = sql_at.checked_sub(1).ok_or(BAD_TEMPLATE)?;
        let fields_start = fields_end.checked_sub(absent).ok_or(BAD_TEMPLATE)?;
        if pkt
            .get(fields_start..fields_end)
            .is_none_or(|f| f.iter().any(|&b| b != 0))
        {
            return Err(BAD_TEMPLATE);
        }
        pkt.drain(fields_start..fields_end);
        let len = pkt.len() as u32;
        pkt.get_mut(..4)
            .ok_or(BAD_TEMPLATE)?
            .copy_from_slice(&len.to_be_bytes());
    }
    Ok(pkt)
}

/// Thick/OCI variant of [`parse_execute`]. The OCI EXECUTE metadata run is
/// version-specific and differs field-by-field from the thin one, so instead of
/// mirroring every pointer/length field we anchor on the part that is stable and
/// reliably decodable: `options` and `cursor_id` are raw little-endian `u32`s
/// right after `(msg_type, func, seq)` — a thick EXECUTE carries no `token_num`
/// — followed by the always-present cursor-id pointer (`0xFE` + 7 bytes, or a
/// single `0x00` when null) and then the SQL length. The SQL text itself is a
/// self-describing `ub1`-length byte string whose length is `sql_length / 3`
/// (OCI sizes it in a 3-byte-per-char unit); we locate that exact-length run
/// beginning with an ASCII letter, which is unambiguous because the metadata we
/// skip over is binary (`0x00`/`0xFF`/`0xFE`).
pub fn parse_execute_thick(packet: &[u8]) -> Result<ExecuteCall> {
    let pay = packet.get(crate::ttc::DATA_PAYLOAD_OFFSET..).unwrap_or(&[]);
    // A function message at the start of the body: return it as-is (including a
    // parse EXECUTE whose SQL we could not locate — sql = None — so the caller
    // can flag the audit miss rather than drop it silently).
    if pay.first() == Some(&3) {
        return parse_execute_thick_at(pay, 0);
    }
    // Otherwise the EXECUTE sits behind one or more thick piggybacks
    // (close-cursors): scan for the (msg_type=3, func=94) marker and parse the
    // first candidate that yields SQL text. A spurious byte-pair match fails to
    // produce a valid SQL frame and is skipped.
    for (k, pair) in pay.windows(2).enumerate() {
        if pair == [3, FUNC_EXECUTE]
            && let Ok(call) = parse_execute_thick_at(pay, k)
            && call.sql.is_some()
        {
            return Ok(call);
        }
    }
    Err(crate::error::Error::Invalid("no thick execute found"))
}

/// Parse a thick EXECUTE/re-execute whose function message begins at `start`
/// within the TTC body `pay` (see [`parse_execute_thick`]).
fn parse_execute_thick_at(pay: &[u8], start: usize) -> Result<ExecuteCall> {
    let u32le = |o: usize| -> Option<u32> { array_at(pay, o).ok().map(u32::from_le_bytes) };
    if pay.get(start) != Some(&3) {
        return Err(crate::error::Error::Invalid("not a TTC function message"));
    }
    let function = *pay
        .get(start + 1)
        .ok_or(crate::error::Error::Invalid("short thick execute"))?;
    match function {
        FUNC_EXECUTE => {
            let options =
                u32le(start + 3).ok_or(crate::error::Error::Invalid("short thick execute"))?;
            let cursor_id =
                u32le(start + 7).ok_or(crate::error::Error::Invalid("short thick execute"))?;
            // cursor-id pointer: present (0xFE + 7 bytes) or null (one 0x00 byte).
            // Some OCI/server combinations put zero bytes before a present
            // pointer (a 19c session's PL/SQL execute has one), so look past up
            // to four of them for the 0xFE.
            let mut o = start + 11;
            let pointer = (0..=4).find(|&n| pay.get(o + n) == Some(&0xFE));
            match pointer {
                Some(skip)
                    if pay
                        .get(o..o + skip)
                        .is_some_and(|z| z.iter().all(|&b| b == 0)) =>
                {
                    o += skip + 8;
                }
                _ => o += 1,
            }
            let sql_length =
                u32le(o).ok_or(crate::error::Error::Invalid("short thick execute"))? as usize;
            let sql = if options & OPTION_PARSE != 0 && sql_length >= 3 {
                locate_sql_thick(pay, o + 4, sql_length)
                    .map(|s| String::from_utf8_lossy(s).into_owned())
            } else {
                None
            };
            Ok(ExecuteCall {
                function,
                cursor_id,
                options,
                sql,
            })
        }
        FUNC_REEXECUTE | FUNC_REEXECUTE_AND_FETCH => {
            let cursor_id = u32le(start + 3).unwrap_or(0);
            Ok(ExecuteCall {
                function,
                cursor_id,
                options: 0,
                sql: None,
            })
        }
        _ => Err(crate::error::Error::Invalid("unexpected TTC function code")),
    }
}

/// Locate a thick EXECUTE's SQL text. `sql_length` is the OCI-declared size in a
/// 3-byte-per-character unit, so the statement's *byte* length is between
/// `sql_length / 3` (all single-byte/ASCII) and `sql_length` (all 3-byte UTF-8).
/// We find the first `ub1`-length byte string in that range, beginning with an
/// ASCII letter (a SQL keyword) and free of NUL bytes, at or after `from`.
/// SQL*Plus counts a terminating NUL in some statements (`... FROM SYS.DUAL\0`),
/// so one trailing NUL is allowed and dropped. Anchoring on the real `ub1` byte
/// length — not on the derived character count — keeps multibyte SQL from being
/// missed, and the letter/NUL checks reject a coincidental binary field of a
/// matching length.
fn locate_sql_thick(pay: &[u8], from: usize, sql_length: usize) -> Option<&[u8]> {
    let min = sql_length / 3;
    if min == 0 {
        return None;
    }
    let mut k = from;
    while let Some((&len, rest)) = pay.get(k..).and_then(<[u8]>::split_first) {
        let len = usize::from(len);
        if (min..=sql_length).contains(&len)
            && let Some(text) = rest.get(..len)
            && text.first().is_some_and(u8::is_ascii_alphabetic)
        {
            let text = text.strip_suffix(&[0]).unwrap_or(text);
            if !text.contains(&0) {
                return Some(text);
            }
        }
        k += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ttc::{DATA_PAYLOAD_OFFSET, Writer};

    // Real thick/OCI (sqlplus) EXECUTE for `SELECT 'X' FROM dual`.
    const THICK_EXECUTE_REQ: &str = include_str!("../tests/fixtures/ttc/thick_execute_req.hex");

    // Real 97-byte EXECUTE request captured from python-oracledb against 23ai:
    // `select 1 from dual`, parsed on a fresh cursor.
    const EXECUTE_REQ: &str = include_str!("../tests/fixtures/ttc/execute_req.hex");
    // Real EXECUTE requests from Oracle JDBC thin 23.2 against 19c (field
    // version 12, DATATYPES without CONV_LENGTH, so the SQL text is raw): a
    // plain query, and a bound query behind a close-cursors piggyback.
    const EXECUTE_REQ_19C_JDBC: &str =
        include_str!("../tests/fixtures/ttc/execute_req_19c_jdbc.hex");
    const EXECUTE_REQ_19C_JDBC_BIND: &str =
        include_str!("../tests/fixtures/ttc/execute_req_19c_jdbc_bind.hex");

    // Real python-oracledb 3.4 EXECUTE of a PL/SQL block against 19c (field
    // version 12, CONV_LENGTH, sequence 3): the gateway's own statement shape.
    const EXECUTE_REQ_19C_PLSQL: &str =
        include_str!("../tests/fixtures/ttc/execute_req_19c_plsql.hex");
    const SET_TZ_PLSQL: &[u8] = SET_DB_SERVER_TIME_ZONE;

    #[test]
    fn builds_execute_byte_exact_with_python_oracledb() {
        let built = build_execute_request(SET_TZ_PLSQL, 3, field_version::PRE_23AI, true);
        assert_eq!(hex::encode(&built), EXECUTE_REQ_19C_PLSQL.trim());
    }

    #[test]
    fn built_execute_round_trips_through_parser() {
        for fv in [field_version::PRE_23AI, FV_23AI] {
            for conv_length in [true, false] {
                let pkt = build_execute_request(SET_TZ_PLSQL, 7, fv, conv_length);
                let call = parse_execute(&pkt, fv, conv_length).unwrap();
                assert_eq!(call.function, FUNC_EXECUTE);
                assert_eq!(call.cursor_id, 0);
                assert_eq!(
                    call.sql.as_deref().map(str::as_bytes),
                    Some(SET_TZ_PLSQL),
                    "fv={fv} conv_length={conv_length}"
                );
            }
        }
    }

    #[test]
    fn parses_real_ojdbc_execute_with_raw_sql() {
        let pkt = hex::decode(EXECUTE_REQ_19C_JDBC.trim()).unwrap();
        let call = parse_execute(&pkt, field_version::PRE_23AI, false).unwrap();
        assert_eq!(call.function, FUNC_EXECUTE);
        assert_eq!(
            call.sql.as_deref(),
            Some("SELECT USER, SYS_CONTEXT('USERENV','SESSION_USER') FROM dual")
        );

        // Behind a close-cursors piggyback, and the bind data that follows the
        // SQL must not leak into the audited text.
        let pkt = hex::decode(EXECUTE_REQ_19C_JDBC_BIND.trim()).unwrap();
        let call = parse_execute(&pkt, field_version::PRE_23AI, false).unwrap();
        assert_eq!(
            call.sql.as_deref(),
            Some("SELECT level n, SYSDATE d FROM dual CONNECT BY level <= :1 ")
        );
    }

    #[test]
    fn raw_sql_read_as_chunked_loses_the_first_character() {
        // The pre-fix behaviour: treating OJDBC's raw text as chunked reads 'S'
        // (0x53 = 83) as a length byte. With fewer than 83 bytes left the
        // statement drops out of the audit entirely...
        let pkt = hex::decode(EXECUTE_REQ_19C_JDBC.trim()).unwrap();
        assert!(parse_execute(&pkt, field_version::PRE_23AI, true).is_err());
        // ...otherwise it is logged without its first character and runs on
        // into the bind data that follows the 59-byte statement.
        let pkt = hex::decode(EXECUTE_REQ_19C_JDBC_BIND.trim()).unwrap();
        let sql = parse_execute(&pkt, field_version::PRE_23AI, true)
            .unwrap()
            .sql
            .unwrap();
        assert!(sql.starts_with("ELECT level n"), "{sql}");
        assert!(!sql.ends_with(":1 "), "runs past the statement: {sql:?}");
    }

    #[test]
    fn raw_sql_longer_than_the_packet_is_an_error() {
        // A statement split across packets: the declared length runs past the
        // end of this one, which must be a clean error, not a panic or a
        // giant allocation.
        let pkt = hex::decode(EXECUTE_REQ_19C_JDBC.trim()).unwrap();
        let cut = &pkt[..pkt.len() - 40];
        assert!(parse_execute(cut, field_version::PRE_23AI, false).is_err());
    }

    /// Wrap a TTC body as a DATA packet (10-byte header + data flags) so the
    /// parser's `at_data_payload` offset lands on the body.
    fn data_packet(body: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0u8; DATA_PAYLOAD_OFFSET];
        pkt.extend_from_slice(body);
        pkt
    }

    /// Build a full-execute (func 94) TTC body for a freshly parsed cursor,
    /// mirroring `_write_execute_message` field-for-field. The `token_num` byte
    /// is written only at 23ai-level field versions, matching the real wire.
    fn full_execute_body(options: u32, sql: &[u8], ttc_field_version: u8) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(3); // msg type (function)
        w.u8(FUNC_EXECUTE);
        w.u8(1); // sequence
        if ttc_field_version >= field_version::TOKEN_NUM_MIN {
            w.ub8(0); // token number
        }
        w.ub4(options);
        w.ub4(0); // cursor id (0 => parse)
        w.u8(1);
        w.ub4(sql.len() as u32); // sql length
        w.u8(1);
        w.ub4(13); // al8i4 array length
        w.u8(0);
        w.u8(0);
        w.ub4(0); // prefetch buffer size
        w.ub4(2); // num_iters
        w.ub4(0x7fff_ffff); // maximum long size
        w.u8(0);
        w.ub4(0); // number of binds
        w.u8(0);
        w.u8(0);
        w.u8(0);
        w.u8(0);
        w.u8(0);
        w.u8(0);
        w.ub4(0); // number of defines
        w.ub4(0); // registration id lsb
        w.u8(0);
        w.u8(1);
        w.u8(0);
        w.ub4(0); // al8blvl
        w.u8(0);
        w.ub4(0); // al8dnaml
        w.ub4(0); // registration id msb
        w.u8(0);
        w.ub4(0); // al8pidmlrcbl
        w.u8(0);
        w.u8(0);
        w.ub4(0); // SQL signature length
        w.u8(0);
        w.ub4(0); // allocated size of SQL id
        w.u8(0);
        w.u8(0);
        w.ub4(0); // number of chunk ids
        w.bytes_with_length(sql); // SQL text
        w.ub4(1); // al8i4[0] parse
        w.buf
    }

    #[test]
    fn locate_sql_thick_spans_ascii_and_multibyte() {
        // ASCII: byte length == char count == sql_length / 3.
        let ascii = b"SELECT 1 FROM dual"; // 18 bytes
        let mut buf = vec![0x00u8, 0xff, 0xfe, 0x00]; // binary metadata preamble
        buf.push(ascii.len() as u8);
        buf.extend_from_slice(ascii);
        assert_eq!(locate_sql_thick(&buf, 0, 18 * 3), Some(&ascii[..]));

        // Multibyte: a 2-byte 'é' makes the byte length exceed the char count,
        // so the old `ub1 == sql_length/3` match would miss it; the window does not.
        let multi = "SELECT é".as_bytes(); // 8 chars, 9 bytes
        let mut buf2 = vec![0x00u8, 0x00];
        buf2.push(multi.len() as u8);
        buf2.extend_from_slice(multi);
        assert_eq!(locate_sql_thick(&buf2, 0, 8 * 3), Some(&multi[..]));

        // A statement containing a NUL is rejected (not a text frame).
        let mut buf3 = vec![0x00u8];
        buf3.push(4);
        buf3.extend_from_slice(&[b'A', 0x00, b'B', b'C']);
        assert_eq!(locate_sql_thick(&buf3, 0, 4 * 3), None);
    }

    /// A 23ai-level field version (token_num present), for the real 23ai
    /// fixtures and the builder-based tests.
    const FV_23AI: u8 = field_version::TOKEN_NUM_MIN;

    #[test]
    fn parses_real_thick_execute_request() {
        let pkt = hex::decode(THICK_EXECUTE_REQ.trim()).unwrap();
        let call = parse_execute_thick(&pkt).unwrap();
        assert_eq!(call.function, FUNC_EXECUTE);
        assert_eq!(call.cursor_id, 0);
        assert_eq!(call.options, 0x8061);
        assert!(call.options & OPTION_PARSE != 0);
        assert_eq!(call.sql.as_deref(), Some("SELECT 'X' FROM dual"));
    }

    // SQL*Plus 19 (wide) and 23 (narrow) EXECUTEs against 19c, each behind a
    // close-cursors piggyback.
    const THICK_EXECUTE_19C_WIDE: &str =
        include_str!("../tests/fixtures/ttc/thick_execute_req_19c_wide.hex");
    const THICK_EXECUTE_19C_NARROW: &str =
        include_str!("../tests/fixtures/ttc/thick_execute_req_19c_narrow.hex");

    #[test]
    fn parses_19c_thick_executes_of_both_layouts() {
        for fixture in [THICK_EXECUTE_19C_WIDE, THICK_EXECUTE_19C_NARROW] {
            let call = parse_execute_thick(&hex::decode(fixture.trim()).unwrap()).unwrap();
            assert_eq!(call.function, FUNC_EXECUTE);
            assert_eq!(
                call.sql.as_deref(),
                Some("SELECT owner, object_name FROM all_objects WHERE rownum <= 3")
            );
        }
    }

    #[test]
    fn thick_sql_with_a_counted_trailing_nul_is_captured() {
        // SQL*Plus's own login statements: a plain SELECT, and a PL/SQL call
        // with a bind behind a close-cursors piggyback (wide layout).
        let parse = |h: &str| {
            parse_execute_thick(&hex::decode(h.trim()).unwrap())
                .unwrap()
                .sql
        };
        assert_eq!(
            parse(include_str!(
                "../tests/fixtures/ttc/thick_execute_req_19c_nul.hex"
            ))
            .as_deref(),
            Some(
                "SELECT DECODE(USER, 'XS$NULL',  XS_SYS_CONTEXT('XS$SESSION','USERNAME'), USER) FROM SYS.DUAL"
            )
        );
        assert_eq!(
            parse(include_str!(
                "../tests/fixtures/ttc/thick_execute_req_19c_piggyback_bind.hex"
            ))
            .as_deref(),
            Some("BEGIN DBMS_APPLICATION_INFO.SET_MODULE(:1,NULL); END;")
        );
    }

    #[test]
    fn thick_set_time_zone_templates_carry_the_statement() {
        // Also the audit regression: the PL/SQL execute has a zero byte before
        // its cursor-id pointer, which used to hide its SQL text.
        for layout in [ThickLayout::Wide, ThickLayout::Narrow] {
            for fv in [7, field_version::V12_2, field_version::V12_2_EXT1, 12] {
                let pkt = build_thick_set_time_zone_request(layout, 7, fv).unwrap();
                assert_eq!(
                    pkt[crate::ttc::DATA_PAYLOAD_OFFSET + 2],
                    7,
                    "sequence patched"
                );
                let len = u32::from_be_bytes(pkt[..4].try_into().unwrap()) as usize;
                assert_eq!(len, pkt.len());
                let call = parse_execute_thick(&pkt).unwrap();
                assert_eq!(call.cursor_id, 0);
                assert!(call.options & OPTION_PARSE != 0);
                assert_eq!(
                    call.sql.as_deref().map(str::as_bytes),
                    Some(SET_DB_SERVER_TIME_ZONE)
                );
            }
        }
    }

    #[test]
    fn thick_set_time_zone_matches_sqlplus_12_1() {
        // SQL*Plus 12.1 against 19c negotiates field version 7; its own run of
        // the statement (sequence 24) is the narrow template minus the 12.2
        // fields.
        let captured = hex::decode(
            include_str!("../tests/fixtures/ttc/thick_execute_tz_narrow_12_1.hex").trim(),
        )
        .unwrap();
        assert_eq!(
            build_thick_set_time_zone_request(ThickLayout::Narrow, 24, 7).unwrap(),
            captured
        );
        let full = build_thick_set_time_zone_request(ThickLayout::Narrow, 24, 12).unwrap();
        assert_eq!(full.len(), captured.len() + 44);
    }

    #[test]
    fn parses_real_execute_request() {
        let pkt = hex::decode(EXECUTE_REQ.trim()).unwrap();
        // The fixture was captured against 23ai (token_num present).
        let call = parse_execute(&pkt, FV_23AI, true).unwrap();
        assert_eq!(call.function, 94);
        assert_eq!(call.cursor_id, 0);
        assert_eq!(call.options, 0x8061);
        assert!(call.options & OPTION_PARSE != 0);
        assert_eq!(call.sql.as_deref(), Some("select 1 from dual"));
    }

    #[test]
    fn parses_19c_execute_without_token_num() {
        // A pre-23ai client omits token_num. Built and parsed at a 19c field
        // version, the SQL must still be recovered; parsing the same 19c bytes
        // as if they were 23ai must NOT (it would drift the cursor), which is
        // exactly the audit-path analogue of the AUTH bug.
        let body = full_execute_body(0x8061, b"select 1 from dual", field_version::PRE_23AI);
        let pkt = data_packet(&body);
        let call = parse_execute(&pkt, field_version::PRE_23AI, true).unwrap();
        assert_eq!(call.function, FUNC_EXECUTE);
        assert_eq!(call.sql.as_deref(), Some("select 1 from dual"));
        let wrong = parse_execute(&pkt, FV_23AI, true);
        assert!(
            wrong.as_ref().map(|c| c.sql.as_deref()) != Ok(Some("select 1 from dual")),
            "parsing 19c bytes as 23ai must not recover the SQL"
        );
    }

    #[test]
    fn rejects_wrong_message_type() {
        let mut pkt = hex::decode(EXECUTE_REQ.trim()).unwrap();
        pkt[DATA_PAYLOAD_OFFSET] = 0x06; // not TNS_MSG_TYPE_FUNCTION (3)
        assert_eq!(
            parse_execute(&pkt, FV_23AI, true),
            Err(Error::Invalid("not a TTC function message"))
        );
    }

    #[test]
    fn rejects_unexpected_function() {
        let mut w = Writer::new();
        w.u8(3); // valid msg type
        w.u8(99); // unknown function code
        w.u8(0); // sequence
        w.ub8(0); // token number
        let pkt = data_packet(&w.buf);
        assert_eq!(
            parse_execute(&pkt, FV_23AI, true),
            Err(Error::Invalid("unexpected TTC function code"))
        );
    }

    #[test]
    fn recovers_long_sql_via_chunked_form() {
        // Over the 252-byte short cap, so the SQL rides the 0xFE chunked form.
        let long_sql = format!("select {} from dual", "x".repeat(300));
        assert!(long_sql.len() > 252, "must exceed the short-length cap");
        let pkt = data_packet(&full_execute_body(0x8061, long_sql.as_bytes(), FV_23AI));
        let call = parse_execute(&pkt, FV_23AI, true).unwrap();
        assert_eq!(call.function, FUNC_EXECUTE);
        assert_eq!(call.cursor_id, 0);
        assert_eq!(call.options & OPTION_PARSE, OPTION_PARSE);
        assert_eq!(call.sql.as_deref(), Some(long_sql.as_str()));
    }

    #[test]
    fn reexecute_carries_no_sql() {
        let mut w = Writer::new();
        w.u8(3);
        w.u8(FUNC_REEXECUTE);
        w.u8(5); // sequence
        w.ub8(0); // token number
        w.ub4(42); // cursor id
        w.ub4(1); // number of iterations
        w.ub4(0x20); // options_1
        w.ub4(0); // options_2
        let pkt = data_packet(&w.buf);
        let call = parse_execute(&pkt, FV_23AI, true).unwrap();
        assert_eq!(call.function, FUNC_REEXECUTE);
        assert_eq!(call.cursor_id, 42);
        assert_eq!(call.options, 0x20);
        assert_eq!(call.sql, None);
    }

    #[test]
    fn parses_execute_behind_close_cursors_piggyback() {
        // Real traffic prepends a close-cursors piggyback (17/105) before the
        // EXECUTE; the parser must skip it and still extract the SQL. Exercise
        // both field versions so the piggyback's own token_num gating is covered.
        for fv in [FV_23AI, field_version::PRE_23AI] {
            let mut body = Writer::new();
            body.u8(17); // piggyback
            body.u8(105); // close cursors
            body.u8(9); // sequence
            if fv >= field_version::TOKEN_NUM_MIN {
                body.ub8(0); // token number
            }
            body.ub4(2); // two cursors to close
            body.u8(1); // pointer to the cursor-id array
            body.ub4(11);
            body.ub4(22);
            body.raw(&full_execute_body(0x8061, b"select 1 from dual", fv));
            let pkt = data_packet(&body.buf);
            let call = parse_execute(&pkt, fv, true).unwrap();
            assert_eq!(call.function, FUNC_EXECUTE, "fv={fv}");
            assert_eq!(call.sql.as_deref(), Some("select 1 from dual"), "fv={fv}");
        }
    }
}
