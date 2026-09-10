use bytes::{Buf, Bytes};
use warpgate_database_protocols::mysql::io::{MySqlBufExt, MySqlBufMutExt};
use warpgate_database_protocols::mysql::protocol::Capabilities;

use crate::error::MySqlError;

/// What the client is to receive in place of a packet read from the target.
pub enum Relayed {
    Verbatim,
    Rewritten(Vec<u8>),
    /// The packet has no equivalent in the client's framing
    Dropped,
}

/// Relays one command response from the target back to the client, rewriting
/// the packets whose layout depends on capabilities the two sides disagree on.
///
/// The target is only picked after the client handshake is already on the wire,
/// so the client can have negotiated capabilities the target turns out to lack
/// (the target set is derived from the client's, so it is never the other way
/// round). Two of them change how a response is framed:
///
/// - `DEPRECATE_EOF` replaces the EOF packet after the column definitions and
///   the one after the rows with a single trailing OK packet,
/// - `SESSION_TRACK` makes the `info` string at the end of an OK packet
///   length-encoded instead of running to the end of the packet.
///
/// Everything else - column definitions, rows, ERR packets - is framing-neutral
/// and passes through untouched.
pub struct ResponseRelay {
    client: Capabilities,
    target: Capabilities,
    seen_first: bool,
    /// Whether the next EOF packet ends the response rather than the column
    /// definitions
    columns_done: bool,
}

impl ResponseRelay {
    /// For COM_QUERY, which answers either with a bare OK/ERR or with a result
    /// set: column definitions first, then rows.
    pub const fn result_set(client: Capabilities, target: Capabilities) -> Self {
        Self {
            client,
            target,
            seen_first: false,
            columns_done: false,
        }
    }

    /// For responses that end at the first EOF - a single OK/ERR packet, or the
    /// bare column definition list of COM_FIELD_LIST.
    pub const fn single(client: Capabilities, target: Capabilities) -> Self {
        Self {
            columns_done: true,
            ..Self::result_set(client, target)
        }
    }

    /// Returns what to send to the client, and whether this packet ended the
    /// response.
    pub fn next(&mut self, packet: &Bytes) -> Result<(Relayed, bool), MySqlError> {
        let header = packet.first().copied();
        let first = !std::mem::replace(&mut self.seen_first, true);

        // OK as the first packet means there is no result set; later packets
        // starting with 0x00 are rows with an empty first column
        if first && header == Some(0) {
            return Ok((self.rewrite_ok(packet)?, true));
        }

        // 0xff is not a valid length-encoded value prefix, so no row or column
        // definition can start with it
        if header == Some(0xff) {
            return Ok((Relayed::Verbatim, true));
        }

        // Rows can also start with 0xfe (a length-encoded value >= 2^24); real
        // EOF and terminating OK packets are shorter than these thresholds. A
        // column count never takes that form, so the first packet of a response
        // starting with 0xfe is always an EOF too - the empty column list of a
        // COM_FIELD_LIST.
        if header == Some(0xfe) {
            if self.target.contains(Capabilities::DEPRECATE_EOF) {
                if packet.len() < 0xff_ffff {
                    return Ok((self.rewrite_ok(packet)?, true));
                }
            } else if packet.len() < 9 {
                if self.columns_done {
                    return Ok((self.eof_as_ok(packet)?, true));
                }
                self.columns_done = true;
                return Ok((
                    if self.client.contains(Capabilities::DEPRECATE_EOF) {
                        Relayed::Dropped
                    } else {
                        Relayed::Verbatim
                    },
                    false,
                ));
            }
        }

        Ok((Relayed::Verbatim, false))
    }

    /// Re-encodes an OK packet for a client that tracks session state against a
    /// target that doesn't. Only the trailing `info` string differs; such a
    /// target never sets `SERVER_SESSION_STATE_CHANGED`, so no tracking data
    /// follows it.
    fn rewrite_ok(&self, packet: &Bytes) -> Result<Relayed, MySqlError> {
        if !self.client.contains(Capabilities::SESSION_TRACK)
            || self.target.contains(Capabilities::SESSION_TRACK)
        {
            return Ok(Relayed::Verbatim);
        }

        let mut buf = packet.clone();
        let mut out = vec![take(&mut buf, 1)?.get_u8()];
        out.put_uint_lenenc(take_uint_lenenc(&mut buf)?);
        out.put_uint_lenenc(take_uint_lenenc(&mut buf)?);
        // Status and warnings, framing-neutral
        out.extend_from_slice(&take(&mut buf, 4)?);
        out.put_bytes_lenenc(&buf);
        Ok(Relayed::Rewritten(out))
    }

    /// Builds the OK packet a `DEPRECATE_EOF` client expects at the end of a
    /// result set out of the EOF packet the target sent instead.
    fn eof_as_ok(&self, packet: &Bytes) -> Result<Relayed, MySqlError> {
        if !self.client.contains(Capabilities::DEPRECATE_EOF) {
            return Ok(Relayed::Verbatim);
        }

        let (Some(warnings), Some(status)) = (packet.get(1..3), packet.get(3..5)) else {
            return Err(MySqlError::ProtocolError("truncated EOF packet".to_owned()));
        };

        // Both carry the same two fields in opposite order; the OK packet adds
        // an affected row count, a last insert id and an `info` string, all
        // empty at the end of a result set
        let mut out = vec![0xfe, 0, 0];
        out.extend_from_slice(status);
        out.extend_from_slice(warnings);
        if self.client.contains(Capabilities::SESSION_TRACK) {
            out.push(0);
        }
        Ok(Relayed::Rewritten(out))
    }
}

fn take(buf: &mut Bytes, len: usize) -> Result<Bytes, MySqlError> {
    if buf.len() < len {
        return Err(MySqlError::ProtocolError("truncated OK packet".to_owned()));
    }
    Ok(buf.split_to(len))
}

/// Length-checked [`MySqlBufExt::get_uint_lenenc`], which panics on a short
/// buffer.
fn take_uint_lenenc(buf: &mut Bytes) -> Result<u64, MySqlError> {
    let len = match buf.first() {
        Some(0xfc) => 3,
        Some(0xfd) => 4,
        Some(0xfe) => 9,
        _ => 1,
    };
    Ok(take(buf, len)?.get_uint_lenenc())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn legacy() -> Capabilities {
        Capabilities::PROTOCOL_41
    }

    fn modern() -> Capabilities {
        Capabilities::PROTOCOL_41 | Capabilities::DEPRECATE_EOF | Capabilities::SESSION_TRACK
    }

    fn relayed(relay: &mut ResponseRelay, packet: &[u8]) -> (Option<Vec<u8>>, bool) {
        let (relayed, done) = relay.next(&Bytes::copy_from_slice(packet)).unwrap();
        let out = match relayed {
            Relayed::Verbatim => Some(packet.to_vec()),
            Relayed::Rewritten(bytes) => Some(bytes),
            Relayed::Dropped => None,
        };
        (out, done)
    }

    #[test]
    fn legacy_target_result_set_gets_deprecate_eof_framing() {
        let mut relay = ResponseRelay::result_set(modern(), legacy());
        // Column count, then a column definition
        assert_eq!(
            relayed(&mut relay, b"\x01"),
            (Some(b"\x01".to_vec()), false)
        );
        assert_eq!(
            relayed(&mut relay, b"\x03def"),
            (Some(b"\x03def".to_vec()), false)
        );
        // The EOF after the column definitions doesn't exist for the client
        assert_eq!(relayed(&mut relay, b"\xfe\x00\x00\x02\x00"), (None, false));
        // A row, and a row whose first column is long enough to start with 0xfe
        assert_eq!(
            relayed(&mut relay, b"\x011"),
            (Some(b"\x011".to_vec()), false)
        );
        let long_row = [&b"\xfe"[..], &[0; 16]].concat();
        assert_eq!(
            relayed(&mut relay, &long_row),
            (Some(long_row.clone()), false)
        );
        // The EOF after the rows becomes the terminating OK packet
        assert_eq!(
            relayed(&mut relay, b"\xfe\x07\x00\x02\x00"),
            (Some(b"\xfe\x00\x00\x02\x00\x07\x00\x00".to_vec()), true)
        );
    }

    #[test]
    fn matching_capabilities_pass_through() {
        for caps in [legacy(), modern()] {
            let mut relay = ResponseRelay::result_set(caps, caps);
            relayed(&mut relay, b"\x01");
            relayed(&mut relay, b"\x03def");
            assert_eq!(
                relayed(&mut relay, b"\xfe\x00\x00\x02\x00"),
                (
                    Some(b"\xfe\x00\x00\x02\x00".to_vec()),
                    caps.contains(Capabilities::DEPRECATE_EOF)
                )
            );
        }
    }

    #[test]
    fn ok_packet_info_becomes_length_encoded() {
        let mut relay = ResponseRelay::single(modern(), legacy());
        assert_eq!(
            relayed(&mut relay, b"\x00\x01\x00\x02\x00\x00\x00Rows matched: 1"),
            (
                Some(b"\x00\x01\x00\x02\x00\x00\x00\x0fRows matched: 1".to_vec()),
                true
            )
        );
    }

    #[test]
    fn column_list_ends_at_its_only_eof() {
        let mut relay = ResponseRelay::single(modern(), legacy());
        assert_eq!(
            relayed(&mut relay, b"\x03def"),
            (Some(b"\x03def".to_vec()), false)
        );
        assert_eq!(
            relayed(&mut relay, b"\xfe\x00\x00\x02\x00"),
            (Some(b"\xfe\x00\x00\x02\x00\x00\x00\x00".to_vec()), true)
        );
    }

    #[test]
    fn empty_column_list_ends_at_its_only_packet() {
        let mut relay = ResponseRelay::single(modern(), legacy());
        assert_eq!(
            relayed(&mut relay, b"\xfe\x00\x00\x02\x00"),
            (Some(b"\xfe\x00\x00\x02\x00\x00\x00\x00".to_vec()), true)
        );
    }

    #[test]
    fn truncated_eof_is_an_error() {
        let mut relay = ResponseRelay::single(modern(), legacy());
        relay.next(&Bytes::from_static(b"\x03def")).unwrap();
        assert!(relay.next(&Bytes::from_static(b"\xfe\x00")).is_err());
    }
}
