//! TNS packet framing: the 8-byte header, packet types, and byte helpers.
//!
//! Header layout (big-endian), validated against real traffic and go-ora
//! `v2/network/packets.go`:
//! ```text
//!   [0:2] length (u16)         during the handshake; becomes a u32 at [0:4]
//!                              only once the handshake is complete AND the
//!                              negotiated version >= 315 (large SDU)
//!   [4]   packet type
//!   [5]   flags
//!   [6:8] header checksum (0)
//! ```
//! The length field is the **total** packet size, header included.

use crate::constants::packet as pt;
use crate::error::{Error, Result};

pub const HEADER_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Connect,
    Accept,
    Ack,
    Refuse,
    Redirect,
    Data,
    Null,
    Abort,
    Resend,
    Marker,
    Control,
    Other(u8),
}

impl PacketType {
    pub const fn from_u8(v: u8) -> Self {
        match v {
            pt::CONNECT => Self::Connect,
            pt::ACCEPT => Self::Accept,
            pt::ACKNOWLEDGE => Self::Ack,
            pt::REFUSE => Self::Refuse,
            pt::REDIRECT => Self::Redirect,
            pt::DATA => Self::Data,
            pt::NULL => Self::Null,
            pt::ABORT => Self::Abort,
            pt::RESEND => Self::Resend,
            pt::MARKER => Self::Marker,
            pt::CONTROL => Self::Control,
            other => Self::Other(other),
        }
    }

    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Connect => pt::CONNECT,
            Self::Accept => pt::ACCEPT,
            Self::Ack => pt::ACKNOWLEDGE,
            Self::Refuse => pt::REFUSE,
            Self::Redirect => pt::REDIRECT,
            Self::Data => pt::DATA,
            Self::Null => pt::NULL,
            Self::Abort => pt::ABORT,
            Self::Resend => pt::RESEND,
            Self::Marker => pt::MARKER,
            Self::Control => pt::CONTROL,
            Self::Other(v) => v,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub length: u32,
    pub packet_type: PacketType,
    pub flags: u8,
}

impl Header {
    /// Parse an 8-byte header. `large_length` selects the u32 length encoding
    /// (handshake complete and negotiated version >= 315); during the handshake
    /// it is always `false`.
    pub fn parse(buf: &[u8], large_length: bool) -> Result<Self> {
        let Some(&[l0, l1, l2, l3, packet_type, flags, _, _]) = buf.first_chunk::<HEADER_LEN>()
        else {
            return Err(Error::Truncated {
                need: HEADER_LEN,
                got: buf.len(),
            });
        };
        let length = if large_length {
            u32::from_be_bytes([l0, l1, l2, l3])
        } else {
            u32::from(u16::from_be_bytes([l0, l1]))
        };
        Ok(Self {
            length,
            packet_type: PacketType::from_u8(packet_type),
            flags,
        })
    }

    pub fn write(&self, large_length: bool) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        if large_length {
            h[0..4].copy_from_slice(&self.length.to_be_bytes());
        } else {
            h[0..2].copy_from_slice(&(self.length as u16).to_be_bytes());
        }
        h[4] = self.packet_type.to_u8();
        h[5] = self.flags;
        h
    }
}

/// The `N` bytes of `buf` at `off`, bounds- and overflow-checked.
pub(crate) fn array_at<const N: usize>(buf: &[u8], off: usize) -> Result<[u8; N]> {
    off.checked_add(N)
        .and_then(|end| buf.get(off..end))
        .and_then(|b| b.first_chunk::<N>())
        .copied()
        .ok_or(Error::Truncated {
            need: off.saturating_add(N),
            got: buf.len(),
        })
}

/// Read a big-endian u16 at `off`, bounds-checked.
pub(crate) fn be_u16(buf: &[u8], off: usize) -> Result<u16> {
    array_at(buf, off).map(u16::from_be_bytes)
}

/// Read a big-endian u32 at `off`, bounds-checked.
pub(crate) fn be_u32(buf: &[u8], off: usize) -> Result<u32> {
    array_at(buf, off).map(u32::from_be_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips_u16() {
        let h = Header {
            length: 423,
            packet_type: PacketType::Connect,
            flags: 0,
        };
        let bytes = h.write(false);
        assert_eq!(bytes[0..2], 423u16.to_be_bytes());
        assert_eq!(bytes[4], pt::CONNECT);
        let parsed = Header::parse(&bytes, false).unwrap();
        assert_eq!(parsed, h);
    }

    #[test]
    fn header_round_trips_u32_large() {
        let h = Header {
            length: 100_000,
            packet_type: PacketType::Data,
            flags: 0,
        };
        let bytes = h.write(true);
        assert_eq!(bytes[0..4], 100_000u32.to_be_bytes());
        let parsed = Header::parse(&bytes, true).unwrap();
        assert_eq!(parsed, h);
    }

    #[test]
    fn type_mapping_is_total() {
        for v in 0u8..=20 {
            assert_eq!(PacketType::from_u8(v).to_u8(), v);
        }
    }

    #[test]
    fn parse_rejects_short_buffer() {
        assert!(matches!(
            Header::parse(&[0, 1, 2], false),
            Err(Error::Truncated { .. })
        ));
    }
}
