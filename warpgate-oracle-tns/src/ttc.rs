//! TTC data-message primitives: Oracle's variable-length integers (`ubN`),
//! chunked byte strings, and the key/value pairs used by the auth messages.
//!
//! Transcribed from python-oracledb `impl/base/buffer.pyx` and validated by
//! round-tripping and by parsing real captured auth packets (`tests/fixtures/ttc/`):
//! - `ubN`: one length byte (high bit = sign, ignored for unsigned) then that
//!   many big-endian bytes; a length of 0 means the value 0.
//! - byte string: one `ub1` length; 0 or `0xFF` (NULL) means empty; `0xFE`
//!   introduces chunks, each a `ub4` length then raw bytes, terminated by a
//!   `ub4` 0; otherwise that many raw bytes follow.
//! - key/value (`write_bytes_with_two_lengths`): a `ub4` total length, then the
//!   chunked byte string, for the key and the value, then a `ub4` flag.

use crate::error::{Error, Result};
use crate::packet::array_at;

pub(crate) const MAX_SHORT_LENGTH: usize = 252; // TNS_MAX_SHORT_LENGTH
const LONG_LENGTH_INDICATOR: u8 = 0xFE; // TNS_LONG_LENGTH_INDICATOR
const NULL_LENGTH_INDICATOR: u8 = 0xFF; // TNS_NULL_LENGTH_INDICATOR
const CHUNK_SIZE: usize = 32767; // TNS_CHUNK_SIZE
/// Offset of the TTC message within a DATA packet: 8-byte header + 2 data-flags.
pub const DATA_PAYLOAD_OFFSET: usize = 10;

/// A cursor over a TTC byte buffer.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub const fn new(buf: &'a [u8], pos: usize) -> Self {
        Reader { buf, pos }
    }

    /// A reader positioned at the TTC message of a DATA packet.
    pub const fn at_data_payload(packet: &'a [u8]) -> Self {
        Reader::new(packet, DATA_PAYLOAD_OFFSET)
    }

    pub const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// The reader's current byte offset into the buffer.
    pub const fn pos(&self) -> usize {
        self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(Error::Invalid("length overflow"))?;
        let slice = self.buf.get(self.pos..end).ok_or(Error::Truncated {
            need: end,
            got: self.buf.len(),
        })?;
        self.pos = end;
        Ok(slice)
    }

    pub fn u8(&mut self) -> Result<u8> {
        let pos = self.pos;
        self.take(1)?.first().copied().ok_or(Error::Truncated {
            need: pos + 1,
            got: self.buf.len(),
        })
    }

    /// Read exactly `n` raw bytes (no length prefix).
    pub fn take_bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        Ok(self.take(n)?.to_vec())
    }

    fn read_int(&mut self, max: usize) -> Result<u64> {
        let length_byte = self.u8()?;
        let len = (length_byte & 0x7f) as usize;
        if len == 0 {
            return Ok(0);
        }
        if len > max {
            return Err(Error::Invalid("ubN integer longer than its type"));
        }
        let bytes = self.take(len)?;
        Ok(bytes.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
    }

    pub fn ub2(&mut self) -> Result<u16> {
        Ok(self.read_int(2)? as u16)
    }

    pub fn ub4(&mut self) -> Result<u32> {
        Ok(self.read_int(4)? as u32)
    }

    pub fn ub8(&mut self) -> Result<u64> {
        self.read_int(8)
    }

    /// Read a chunked byte string.
    pub fn bytes(&mut self) -> Result<Vec<u8>> {
        let length = self.u8()?;
        if length == 0 || length == NULL_LENGTH_INDICATOR {
            return Ok(Vec::new());
        }
        if length == LONG_LENGTH_INDICATOR {
            let mut out = Vec::new();
            loop {
                let chunk = self.ub4()? as usize;
                if chunk == 0 {
                    break;
                }
                out.extend_from_slice(self.take(chunk)?);
            }
            Ok(out)
        } else {
            Ok(self.take(length as usize)?.to_vec())
        }
    }

    /// Read a `ub4` length then (if non-zero) the chunked byte string.
    pub fn bytes_with_length(&mut self) -> Result<Vec<u8>> {
        let n = self.ub4()?;
        if n == 0 { Ok(Vec::new()) } else { self.bytes() }
    }

    /// Read one key/value/flag triple.
    pub fn key_value(&mut self) -> Result<(Vec<u8>, Vec<u8>, u32)> {
        let key = self.bytes_with_length()?;
        let value = self.bytes_with_length()?;
        let flag = self.ub4()?;
        Ok((key, value, flag))
    }
}

/// A growable TTC message builder.
#[derive(Default)]
pub struct Writer {
    pub buf: Vec<u8>,
}

impl Writer {
    pub const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn u16be(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u32be(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn raw(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn ub2(&mut self, v: u16) {
        if v == 0 {
            self.u8(0);
        } else if u8::try_from(v).is_ok() {
            self.u8(1);
            self.u8(v as u8);
        } else {
            self.u8(2);
            self.u16be(v);
        }
    }

    pub fn ub4(&mut self, v: u32) {
        if v == 0 {
            self.u8(0);
        } else if u8::try_from(v).is_ok() {
            self.u8(1);
            self.u8(v as u8);
        } else if u16::try_from(v).is_ok() {
            self.u8(2);
            self.u16be(v as u16);
        } else {
            self.u8(4);
            self.u32be(v);
        }
    }

    pub fn ub8(&mut self, v: u64) {
        if v == 0 {
            self.u8(0);
        } else if u8::try_from(v).is_ok() {
            self.u8(1);
            self.u8(v as u8);
        } else if u16::try_from(v).is_ok() {
            self.u8(2);
            self.u16be(v as u16);
        } else if u32::try_from(v).is_ok() {
            self.u8(4);
            self.u32be(v as u32);
        } else {
            self.u8(8);
            self.buf.extend_from_slice(&v.to_be_bytes());
        }
    }

    /// Write a chunked byte string (a `ub1` length for short data, else the
    /// `0xFE` long form with `ub4`-framed chunks terminated by a `ub4` 0).
    pub fn bytes_with_length(&mut self, data: &[u8]) {
        if data.len() <= MAX_SHORT_LENGTH {
            self.u8(data.len() as u8);
            self.raw(data);
        } else {
            self.u8(LONG_LENGTH_INDICATOR);
            for chunk in data.chunks(CHUNK_SIZE) {
                self.ub4(chunk.len() as u32);
                self.raw(chunk);
            }
            self.ub4(0);
        }
    }

    /// Write a `ub4` length then (if non-empty) the chunked byte string.
    pub fn bytes_with_two_lengths(&mut self, data: &[u8]) {
        self.ub4(data.len() as u32);
        if !data.is_empty() {
            self.bytes_with_length(data);
        }
    }

    /// Write one key/value/flag triple (the auth message pair encoding).
    pub fn key_value(&mut self, key: &[u8], value: &[u8], flag: u32) {
        self.bytes_with_two_lengths(key);
        self.bytes_with_two_lengths(value);
        self.ub4(flag);
    }

    /// Thick/OCI framing of a length-prefixed byte string as a *server* writes
    /// it: a raw little-endian `u32` outer length equal to the data length, then
    /// — if non-empty — a `ub1` length and the raw bytes. A client declares
    /// three bytes per character instead ([`Self::bytes_thick_client`]). Values
    /// longer than the `ub1` short form (252 bytes) are cut to it.
    pub fn bytes_thick(&mut self, data: &[u8]) {
        let data = data.split_at(data.len().min(MAX_SHORT_LENGTH)).0;
        self.buf
            .extend_from_slice(&(data.len() as u32).to_le_bytes());
        if !data.is_empty() {
            self.u8(data.len() as u8);
            self.raw(data);
        }
    }

    /// Write one key/value/flag triple in the thick/OCI framing (the flag is a
    /// raw little-endian `u32`).
    pub fn key_value_thick(&mut self, key: &[u8], value: &[u8], flag: u32) {
        self.bytes_thick(key);
        self.bytes_thick(value);
        self.buf.extend_from_slice(&flag.to_le_bytes());
    }

    /// [`Self::bytes_thick`] as an OCI *client* writes it: the outer length is
    /// the buffer size it declares, three bytes per character (0 when empty).
    /// A 19c server rejects the exact length there with ORA-03146.
    pub fn bytes_thick_client(&mut self, data: &[u8]) {
        let data = data.split_at(data.len().min(MAX_SHORT_LENGTH)).0;
        self.buf
            .extend_from_slice(&((data.len() * 3) as u32).to_le_bytes());
        if !data.is_empty() {
            self.u8(data.len() as u8);
            self.raw(data);
        }
    }

    /// [`Self::key_value_thick`] in the OCI client framing ([`Self::bytes_thick_client`]).
    pub fn key_value_thick_client(&mut self, key: &[u8], value: &[u8], flag: u32) {
        self.bytes_thick_client(key);
        self.bytes_thick_client(value);
        self.buf.extend_from_slice(&flag.to_le_bytes());
    }
}

/// One key/value pair returned by the server, with its trailing flag (the
/// verifier type for `AUTH_VFR_DATA`, otherwise a plain flag).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthPair {
    pub key: String,
    pub value: Vec<u8>,
    pub flag: u32,
}

/// Parse the key/value list of a server auth RETURN message
/// (`[msg_type u8][num_params ub2][ (key, value, flag) ... ]`). Mirrors
/// python-oracledb `auth.pyx::_process_return_parameters`.
pub fn parse_return_key_values(packet: &[u8]) -> Result<Vec<AuthPair>> {
    Ok(parse_return_key_values_with_end(packet)?.0)
}

/// [`parse_return_key_values`], also returning the offset in `packet` just past
/// the last pair — where the RETURN's trailing status message begins.
pub fn parse_return_key_values_with_end(packet: &[u8]) -> Result<(Vec<AuthPair>, usize)> {
    let mut r = Reader::at_data_payload(packet);
    let _msg_type = r.u8()?;
    let num_params = r.ub2()?;
    let mut pairs = Vec::with_capacity(num_params as usize);
    for _ in 0..num_params {
        let (k, v, flag) = r.key_value()?;
        pairs.push(AuthPair {
            key: String::from_utf8_lossy(&k).into_owned(),
            value: v,
            flag,
        });
    }
    Ok((pairs, r.pos()))
}

/// Read one thick/OCI length-prefixed byte string at `*i`: a raw little-endian
/// `u32` outer length, then — if non-zero — a `ub1` length and that many bytes.
pub(crate) fn read_bytes_thick(payload: &[u8], i: &mut usize) -> Result<Vec<u8>> {
    let outer = u32::from_le_bytes(array_at(payload, *i)?);
    *i += 4;
    if outer == 0 {
        return Ok(Vec::new());
    }
    let [len] = array_at::<1>(payload, *i)?;
    let len = usize::from(len);
    *i += 1;
    let end = i
        .checked_add(len)
        .ok_or(Error::Invalid("length overflow"))?;
    let bytes = payload
        .get(*i..end)
        .ok_or(Error::Truncated {
            need: end,
            got: payload.len(),
        })?
        .to_vec();
    *i = end;
    Ok(bytes)
}

/// Parse the key/value list of a thick/OCI server auth RETURN. The header is
/// `[msg_type u8][num_params u16 little-endian]`; each pair is a thick byte
/// string (see [`read_bytes_thick`]) for the key and the value, then a raw
/// little-endian `u32` flag. Mirrors the framing captured from a real OCI 23ai
/// server (the thin [`parse_return_key_values`] uses the compact `ubN` form).
pub fn parse_return_key_values_thick(packet: &[u8]) -> Result<Vec<AuthPair>> {
    Ok(parse_return_key_values_thick_with_end(packet)?.0)
}

/// [`parse_return_key_values_thick`], also returning the offset in `packet`
/// just past the last pair — where the RETURN's trailing status message begins.
pub fn parse_return_key_values_thick_with_end(packet: &[u8]) -> Result<(Vec<AuthPair>, usize)> {
    let payload = packet.get(DATA_PAYLOAD_OFFSET..).ok_or(Error::Truncated {
        need: DATA_PAYLOAD_OFFSET,
        got: packet.len(),
    })?;
    let mut i = 1usize; // skip the message-type byte
    let num_params = u16::from_le_bytes(array_at(payload, i)?);
    i += 2;
    let mut pairs = Vec::with_capacity(num_params as usize);
    for _ in 0..num_params {
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
    Ok((pairs, DATA_PAYLOAD_OFFSET + i))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find<'a>(pairs: &'a [AuthPair], key: &str) -> Option<&'a AuthPair> {
        pairs.iter().find(|p| p.key == key)
    }

    #[test]
    fn ub_round_trips() {
        for v in [0u32, 1, 255, 256, 4096, 65535, 65536, 0x4815, u32::MAX] {
            let mut w = Writer::new();
            w.ub4(v);
            let got = Reader::new(&w.buf, 0).ub4().unwrap();
            assert_eq!(got, v, "ub4 round trip for {v}");
        }
        for v in [0u16, 1, 255, 256, 4096, 65535] {
            let mut w = Writer::new();
            w.ub2(v);
            assert_eq!(Reader::new(&w.buf, 0).ub2().unwrap(), v);
        }
    }

    #[test]
    fn key_value_round_trips_short_and_long() {
        let long_value = vec![0xABu8; 300]; // exercises the 0xFE chunked form
        let mut w = Writer::new();
        w.key_value(b"AUTH_SESSKEY", b"DEADBEEF", 1);
        w.key_value(b"AUTH_VFR_DATA", b"C6D4", 0x4815);
        w.key_value(b"BIG", &long_value, 0);

        let mut r = Reader::new(&w.buf, 0);
        let (k, v, f) = r.key_value().unwrap();
        assert_eq!(k, b"AUTH_SESSKEY");
        assert_eq!(v, b"DEADBEEF");
        assert_eq!(f, 1);
        let (k, _v, f) = r.key_value().unwrap();
        assert_eq!(k, b"AUTH_VFR_DATA");
        assert_eq!(f, 0x4815);
        let (k, v, _f) = r.key_value().unwrap();
        assert_eq!(k, b"BIG");
        assert_eq!(v, long_value);
    }

    // Real 372-byte phase-one RETURN from Oracle 23ai (classic flow).
    const AUTH1_RESP: &str = include_str!("../tests/fixtures/ttc/auth1_resp.hex");
    // Real 1984-byte phase-two RETURN (login established).
    const AUTH2_RESP: &str = include_str!("../tests/fixtures/ttc/auth2_resp.hex");

    #[test]
    fn parses_real_phase_one_return() {
        let pkt = hex::decode(AUTH1_RESP.trim()).unwrap();
        let pairs = parse_return_key_values(&pkt).unwrap();

        // The five phase-one fields the client needs are all present and decoded.
        assert!(find(&pairs, "AUTH_SESSKEY").is_some());
        let vfr = find(&pairs, "AUTH_VFR_DATA").unwrap();
        assert_eq!(vfr.flag, 0x4815, "verifier type rides in the pair flag");
        assert_eq!(vfr.value.len(), 32, "16-byte salt as 32 hex chars");
        assert_eq!(
            find(&pairs, "AUTH_PBKDF2_VGEN_COUNT").unwrap().value,
            b"4096"
        );
        assert_eq!(find(&pairs, "AUTH_PBKDF2_SDER_COUNT").unwrap().value, b"3");
        assert!(find(&pairs, "AUTH_PBKDF2_CSK_SALT").is_some());
    }

    #[test]
    fn parses_real_phase_two_return() {
        let pkt = hex::decode(AUTH2_RESP.trim()).unwrap();
        let pairs = parse_return_key_values(&pkt).unwrap();
        // Phase two carries the mutual-auth proof plus session identifiers.
        assert!(find(&pairs, "AUTH_SVR_RESPONSE").is_some());
        assert!(find(&pairs, "AUTH_SESSION_ID").is_some());
        assert!(pairs.len() > 10, "full session establishment response");
    }
}
