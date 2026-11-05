//! TNS connection handshake: parse the client CONNECT, build the server
//! ACCEPT/REFUSE, and parse a listener REDIRECT (for the database leg).
//!
//! Field offsets are validated against real Oracle 23ai traffic (see
//! `tests/fixtures/`) and go-ora `v2/network/{connect,accept,redirect,refuse}_packet.go`.
//! The whole handshake uses the 2-byte packet length (the 4-byte form only
//! appears for DATA packets once the handshake is complete and version >= 315).

use crate::constants::{connect_flag, gso, nsi};
use crate::error::{Error, Result};
use crate::packet::{HEADER_LEN, Header, PacketType, be_u16, be_u32};

/// Parsed client CONNECT request (the fields the proxy needs to answer).
#[derive(Debug, Clone)]
pub struct ConnectRequest {
    pub version: u16,
    pub lo_version: u16,
    pub service_options: u16,
    pub sdu: u32,
    pub tdu: u32,
    /// NSI flags byte (ACFL0). The real 23ai client sends 0x84
    /// (`SUPPORT_SECURITY_RENEG | NA_DISABLED`), i.e. it refuses ANO itself.
    pub nsi_flags: u8,
    /// The connect-data descriptor when it is carried inline in the CONNECT
    /// packet. Empty when `connect_data_complete` is false.
    pub connect_data: Vec<u8>,
    /// False when the descriptor was too long to fit inline and the client will
    /// send it in one or more following DATA packets (read them with
    /// [`data_payload`]).
    pub connect_data_complete: bool,
}

impl ConnectRequest {
    /// Does the client indicate it wants native network encryption REQUIRED?
    /// (If so the proxy cannot read the stream and must refuse.)
    pub const fn requires_native_encryption(&self) -> bool {
        self.nsi_flags & nsi::NA_REQUIRED != 0
    }
}

/// Parse a CONNECT packet. `pkt` must start at the TNS header; bytes beyond the
/// header's own `length` (e.g. a coalesced follow-on DATA packet) are ignored.
pub fn parse_connect(pkt: &[u8]) -> Result<ConnectRequest> {
    let hdr = Header::parse(pkt, false)?;
    if hdr.packet_type != PacketType::Connect {
        return Err(Error::Invalid("not a CONNECT packet"));
    }
    let version = be_u16(pkt, 8)?;
    let lo_version = be_u16(pkt, 10)?;
    let service_options = be_u16(pkt, 12)?;
    let connect_data_len = be_u16(pkt, 24)? as usize;
    let data_offset = be_u16(pkt, 26)? as usize;
    let nsi_flags = *pkt.get(32).ok_or(Error::Truncated {
        need: 33,
        got: pkt.len(),
    })?;

    // SDU/TDU: the 32-bit (large-SDU) fields carry the real value; fall back to
    // the legacy 16-bit fields if the packet is too short to hold them.
    let sdu = be_u32(pkt, 58).or_else(|_| be_u16(pkt, 14).map(u32::from))?;
    let tdu = be_u32(pkt, 62).or_else(|_| be_u16(pkt, 16).map(u32::from))?;

    // The descriptor is inline only when the packet extends past `data_offset`.
    // When it is too long, the client sends length == data_offset here and the
    // descriptor follows in DATA packets.
    let hdr_len = hdr.length as usize;
    let inline = hdr_len > data_offset && connect_data_len > 0;
    let connect_data = if inline {
        let end = data_offset + connect_data_len;
        pkt.get(data_offset..end)
            .ok_or(Error::Truncated {
                need: end,
                got: pkt.len(),
            })?
            .to_vec()
    } else {
        Vec::new()
    };

    Ok(ConnectRequest {
        version,
        lo_version,
        service_options,
        sdu,
        tdu,
        nsi_flags,
        connect_data,
        connect_data_complete: inline,
    })
}

/// Strip out-of-band break support from a client CONNECT before it is relayed to
/// the database, as if the client had set `DISABLE_OOB=ON`.
///
/// A relay cannot forward TCP urgent data, so the OOB break check the server
/// asks for (`CHECK_OOB`) cannot succeed through it: the database answers the
/// client's check MARKER with a RESET_OOB CONTROL and then stalls (OJDBC thin
/// hangs before its PROTOCOL reply). Clearing the client's OOB service options
/// and its `CHECK_OOB` connect flag makes the database itself negotiate in-band
/// breaks, so both legs agree and no check is attempted. Only the CONNECT's
/// fixed fields are touched; a coalesced follow-on DATA packet is left alone.
pub fn disable_oob(pkt: &mut [u8]) -> Result<()> {
    let hdr = Header::parse(pkt, false)?;
    if hdr.packet_type != PacketType::Connect {
        return Err(Error::Invalid("not a CONNECT packet"));
    }
    let service_options = be_u16(pkt, 12)? & !gso::OOB_MASK;
    put(pkt, 12, &service_options.to_be_bytes())?;
    // `connect_flags_2` exists only when the fixed part reaches offset 74.
    let data_offset = be_u16(pkt, 26)? as usize;
    if data_offset >= 74 && hdr.length as usize >= 74 {
        let flags = be_u32(pkt, 70)? & !connect_flag::CHECK_OOB;
        put(pkt, 70, &flags.to_be_bytes())?;
    }
    Ok(())
}

/// Longest connect descriptor a client puts inline in its CONNECT; a longer one
/// follows in a DATA packet (python-oracledb's `TNS_MAX_CONNECT_DATA`).
const MAX_INLINE_CONNECT_DATA: usize = 230;

/// The connect descriptor the gateway sends the database in place of the
/// client's: the target's own address and service name, so the session lands
/// exactly on the service the user was authorized for whatever else the
/// client's descriptor said, plus the client's `CID` (program, host, user) for
/// the listener log, stripped of anything that could change the descriptor's
/// structure. `None` if the configured host or service name is not usable in a
/// descriptor.
pub fn target_descriptor(
    use_tls: bool,
    host: &str,
    port: u16,
    service_name: &str,
    client_descriptor: &str,
) -> Option<String> {
    let structural =
        |v: &str| v.is_empty() || v.contains(['(', ')', '=']) || v.chars().any(char::is_control);
    if structural(host) || structural(service_name) {
        return None;
    }
    let cid = |key: &str| {
        crate::client_info::cid_field(client_descriptor, key)
            .map(|v| {
                v.chars()
                    .filter(|c| !c.is_control() && !matches!(c, '(' | ')' | '=' | '"' | '\''))
                    .take(64)
                    .collect::<String>()
            })
            .unwrap_or_default()
    };
    let protocol = if use_tls { "TCPS" } else { "TCP" };
    Some(format!(
        "(DESCRIPTION=(ADDRESS=(PROTOCOL={protocol})(HOST={host})(PORT={port}))\
         (CONNECT_DATA=(SERVICE_NAME={service_name})\
         (CID=(PROGRAM={})(HOST={})(USER={}))))",
        cid("PROGRAM"),
        cid("HOST"),
        cid("USER"),
    ))
}

/// Rebuild a client CONNECT around `descriptor`, keeping the client's own fixed
/// fields (versions, SDU, options) so the database negotiates with what the
/// client supports. Returns the packets to send in order: the CONNECT and, when
/// the descriptor is too long to go inline, a DATA packet carrying it — the same
/// split a client makes.
pub fn with_connect_data(connect: &[u8], descriptor: &[u8]) -> Result<Vec<Vec<u8>>> {
    let hdr = Header::parse(connect, false)?;
    if hdr.packet_type != PacketType::Connect {
        return Err(Error::Invalid("not a CONNECT packet"));
    }
    let data_offset = usize::from(be_u16(connect, 26)?);
    let fixed = connect.get(..data_offset).ok_or(Error::Truncated {
        need: data_offset,
        got: connect.len(),
    })?;
    let too_long = || Error::Invalid("connect descriptor too long");
    let data_len = u16::try_from(descriptor.len()).map_err(|_| too_long())?;
    let mut head = fixed.to_vec();
    put(&mut head, 24, &data_len.to_be_bytes())?;
    let inline = descriptor.len() <= MAX_INLINE_CONNECT_DATA;
    if inline {
        head.extend_from_slice(descriptor);
    }
    let head_len = u16::try_from(head.len()).map_err(|_| too_long())?;
    put(&mut head, 0, &head_len.to_be_bytes())?;
    if inline {
        return Ok(vec![head]);
    }
    let data_total = u16::try_from(HEADER_LEN + 2 + descriptor.len()).map_err(|_| too_long())?;
    let mut data = Vec::with_capacity(usize::from(data_total));
    data.extend_from_slice(&data_total.to_be_bytes()); // [0..2] packet length
    data.extend_from_slice(&[0, 0]); // [2..4] packet checksum
    data.push(PacketType::Data.to_u8()); // [4] packet type
    data.extend_from_slice(&[0, 0, 0]); // [5] flags, [6..8] header checksum
    data.extend_from_slice(&[0, 0]); // [8..10] data flags
    data.extend_from_slice(descriptor);
    Ok(vec![head, data])
}

/// Return the payload of a DATA packet (bytes after the 8-byte header and the
/// 2-byte data-flags field) — e.g. the connect descriptor that follows a
/// CONNECT whose descriptor did not fit inline.
pub fn data_payload(pkt: &[u8]) -> Result<&[u8]> {
    let hdr = Header::parse(pkt, false)?;
    if hdr.packet_type != PacketType::Data {
        return Err(Error::Invalid("not a DATA packet"));
    }
    pkt.get(HEADER_LEN + 2..).ok_or(Error::Truncated {
        need: HEADER_LEN + 2,
        got: pkt.len(),
    })
}

/// Build a REFUSE packet carrying an Oracle error code the client can surface
/// (e.g. 12514 invalid service name). Layout per go-ora `refuse_packet.go`.
pub fn build_refuse(err_code: u32, detail: &str) -> Vec<u8> {
    let message = format!(
        "(DESCRIPTION=(ERR={err_code})(ERROR_STACK=(ERROR=(CODE={err_code})(MESSAGE=\"{detail}\")))))"
    );
    let data = message.as_bytes();
    let total = (HEADER_LEN + 4 + data.len()) as u16;
    let mut b = Vec::with_capacity(usize::from(total));
    b.extend_from_slice(&total.to_be_bytes()); // [0..2] packet length
    b.extend_from_slice(&[0, 0]); // [2..4] packet checksum
    b.push(PacketType::Refuse.to_u8()); // [4] packet type
    b.extend_from_slice(&[0, 0, 0]); // [5] flags, [6..8] header checksum
    b.extend_from_slice(&[0, 0]); // [8], [9] user/system reason
    b.extend_from_slice(&(data.len() as u16).to_be_bytes()); // [10..12] data length
    b.extend_from_slice(data);
    b
}

/// Parse a listener REDIRECT (used on the database leg): the payload is the new
/// connect descriptor, optionally followed by a NUL and reconnect data.
pub fn parse_redirect(pkt: &[u8]) -> Result<String> {
    let hdr = Header::parse(pkt, false)?;
    if hdr.packet_type != PacketType::Redirect {
        return Err(Error::Invalid("not a REDIRECT packet"));
    }
    let data_len = be_u16(pkt, 8)? as usize;
    let start = HEADER_LEN + 2;
    let raw = pkt.get(start..start + data_len).ok_or(Error::Truncated {
        need: start + data_len,
        got: pkt.len(),
    })?;
    // The descriptor is the part before any NUL separator.
    let descriptor = raw.split(|&c| c == 0).next().unwrap_or(raw);
    Ok(String::from_utf8_lossy(descriptor).into_owned())
}

/// Overwrite the bytes of `b` at `off` with `bytes`, bounds-checked.
fn put(b: &mut [u8], off: usize, bytes: &[u8]) -> Result<()> {
    let got = b.len();
    off.checked_add(bytes.len())
        .and_then(|end| b.get_mut(off..end))
        .ok_or(Error::Truncated {
            need: off.saturating_add(bytes.len()),
            got,
        })?
        .copy_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s.trim()).unwrap()
    }

    // A real 423-byte CONNECT (CONNECT packet + coalesced follow-on DATA) from
    // Oracle 23ai via python-oracledb thin.
    const CONNECT_FIXTURE: &str = include_str!("../tests/fixtures/connect_client.hex");
    // A real 61-byte ACCEPT from the same server.
    const ACCEPT_FIXTURE: &str = include_str!("../tests/fixtures/accept_server.hex");

    #[test]
    fn parses_real_connect() {
        let buf = unhex(CONNECT_FIXTURE);
        let req = parse_connect(&buf).unwrap();
        assert_eq!(req.version, 319);
        assert_eq!(req.lo_version, 300);
        assert_eq!(req.service_options, 0x0401);
        assert_eq!(req.sdu, 8192);
        assert_eq!(req.tdu, 8192);
        assert_eq!(req.nsi_flags, 0x84);
        assert!(!req.requires_native_encryption());
        // This descriptor was too long to fit inline (339 bytes).
        assert!(!req.connect_data_complete);
    }

    #[test]
    fn disable_oob_clears_only_the_oob_bits() {
        // Dress the real CONNECT up as OJDBC thin with OOB on: service options
        // 0x0c41 and CHECK_OOB plus an unrelated bit in connect_flags_2.
        let mut buf = unhex(CONNECT_FIXTURE);
        buf[12..14].copy_from_slice(&0x0c41u16.to_be_bytes());
        buf[70..74].copy_from_slice(&0x0000_0101u32.to_be_bytes());
        let before = buf.clone();

        disable_oob(&mut buf).unwrap();

        assert_eq!(parse_connect(&buf).unwrap().service_options, 0x0041);
        assert_eq!(be_u32(&buf, 70).unwrap(), 0x0000_0100);
        for (i, (a, b)) in before.iter().zip(&buf).enumerate() {
            if !(12..14).contains(&i) && !(70..74).contains(&i) {
                assert_eq!(a, b, "byte {i} must be untouched");
            }
        }
    }

    #[test]
    fn disable_oob_rejects_non_connect() {
        let mut accept = unhex(ACCEPT_FIXTURE);
        assert!(disable_oob(&mut accept).is_err());
    }

    #[test]
    fn disable_oob_leaves_bytes_past_a_short_fixed_part_alone() {
        // An older CONNECT whose connect data starts before offset 74 has no
        // connect_flags_2; bytes 70..74 are then connect data and must survive.
        let mut buf = unhex(CONNECT_FIXTURE);
        buf[12..14].copy_from_slice(&0x0c41u16.to_be_bytes());
        buf[26..28].copy_from_slice(&58u16.to_be_bytes());
        buf[70..74].copy_from_slice(&0x0000_0001u32.to_be_bytes());
        disable_oob(&mut buf).unwrap();
        assert_eq!(be_u16(&buf, 12).unwrap(), 0x0041);
        assert_eq!(be_u32(&buf, 70).unwrap(), 0x0000_0001);
    }

    #[test]
    fn disable_oob_rejects_truncated_connect_without_panicking() {
        let full = unhex(CONNECT_FIXTURE);
        for len in [0, 4, 8, 13, 26, 72] {
            let mut cut = full[..len].to_vec();
            assert!(disable_oob(&mut cut).is_err(), "len {len}");
        }
    }

    #[test]
    fn reads_connect_descriptor_from_follow_on_data() {
        let buf = unhex(CONNECT_FIXTURE);
        let hdr = Header::parse(&buf, false).unwrap();
        let follow = &buf[hdr.length as usize..]; // the coalesced DATA packet
        let payload = data_payload(follow).unwrap();
        let text = String::from_utf8_lossy(payload);
        assert!(text.starts_with("(DESCRIPTION="));
        assert!(text.contains("(SERVICE_NAME=FREEPDB1)"));
    }

    #[test]
    fn rebuilt_connect_carries_only_the_target_descriptor() {
        let client = "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=allowed)(SERVICE_NAME=other)\
                      (CID=(PROGRAM=sql)plus)(HOST=ws(1))(USER=ivan=x))))";
        let desc = target_descriptor(true, "db.internal", 1522, "orclpdb1", client).unwrap();
        assert_eq!(
            desc,
            "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCPS)(HOST=db.internal)(PORT=1522))\
             (CONNECT_DATA=(SERVICE_NAME=orclpdb1)(CID=(PROGRAM=sql)(HOST=ws1)(USER=ivanx))))"
        );
        assert!(target_descriptor(false, "db", 1521, "a)(SERVICE_NAME=b", client).is_none());
        assert!(target_descriptor(false, "", 1521, "svc", client).is_none());

        let original = unhex(CONNECT_FIXTURE);
        let packets = with_connect_data(&original, desc.as_bytes()).unwrap();
        assert_eq!(packets.len(), 1, "a short descriptor goes inline");
        let rebuilt = parse_connect(&packets[0]).unwrap();
        assert_eq!(rebuilt.connect_data, desc.as_bytes());
        let ours = parse_connect(&original).unwrap();
        assert_eq!((rebuilt.version, rebuilt.sdu), (ours.version, ours.sdu));
    }

    #[test]
    fn long_target_descriptor_follows_in_a_data_packet() {
        let desc = format!(
            "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME={})))",
            "s".repeat(300)
        );
        let packets = with_connect_data(&unhex(CONNECT_FIXTURE), desc.as_bytes()).unwrap();
        assert_eq!(packets.len(), 2);
        let connect = parse_connect(&packets[0]).unwrap();
        assert!(!connect.connect_data_complete);
        assert_eq!(data_payload(&packets[1]).unwrap(), desc.as_bytes());
        let total = u16::from_be_bytes([packets[0][0], packets[0][1]]) as usize;
        assert_eq!(total, packets[0].len());
    }

    #[test]
    fn refuse_carries_error_code() {
        let r = build_refuse(12514, "service not known");
        let hdr = Header::parse(&r, false).unwrap();
        assert_eq!(hdr.packet_type, PacketType::Refuse);
        let msg = String::from_utf8_lossy(&r[12..]);
        assert!(msg.contains("(ERR=12514)"));
    }
}
