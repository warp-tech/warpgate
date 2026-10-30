//! Initiate Multitransport Request and Response PDU types.
//!
//! Defined in [\[MS-RDPBCGR\] 2.2.15.1] and [\[MS-RDPBCGR\] 2.2.15.2].
//!
//! [\[MS-RDPBCGR\] 2.2.15.1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/de783158-8b01-4818-8fb0-62523a5b3490
//! [\[MS-RDPBCGR\] 2.2.15.2]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/44044233-e498-46f8-8e16-1ffa595a8e8b

use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, ensure_fixed_part_size, invalid_field_err,
    read_padding, write_padding,
};

use crate::rdp::headers::{BasicSecurityHeader, BasicSecurityHeaderFlags};

/// Length of the security cookie used for transport binding validation.
const SECURITY_COOKIE_LEN: usize = 16;

/// Requested transport protocol for multitransport bootstrapping.
///
/// Defined in [\[MS-RDPBCGR\] 2.2.15.1], `requestedProtocol` field.
///
/// [\[MS-RDPBCGR\] 2.2.15.1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/de783158-8b01-4818-8fb0-62523a5b3490
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u16)]
pub enum RequestedProtocol {
    /// Reliable UDP transport (RDPEUDP2 + TLS).
    ///
    /// `INITIATE_REQUEST_PROTOCOL_UDPFECR`
    UdpFecR = 0x0001,
    /// Lossy UDP transport (RDPEUDP + DTLS, with forward error correction).
    ///
    /// `INITIATE_REQUEST_PROTOCOL_UDPFECL`
    UdpFecL = 0x0002,
}

impl RequestedProtocol {
    fn from_u16(val: u16) -> Option<Self> {
        match val {
            0x0001 => Some(Self::UdpFecR),
            0x0002 => Some(Self::UdpFecL),
            _ => None,
        }
    }

    #[expect(
        clippy::as_conversions,
        reason = "repr(u16) guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u16(self) -> u16 {
        self as u16
    }
}

/// Server Initiate Multitransport Request PDU.
///
/// Sent by the server on the IO channel after licensing to bootstrap a
/// sideband UDP transport. The `request_id` and `security_cookie` are
/// echoed by the client in the tunnel creation request over the new
/// transport, binding the two connections together.
///
/// A server may send up to two of these — one for reliable and one for
/// lossy UDP.
///
/// Defined in [\[MS-RDPBCGR\] 2.2.15.1].
///
/// [\[MS-RDPBCGR\] 2.2.15.1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/de783158-8b01-4818-8fb0-62523a5b3490
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct MultitransportRequestPdu {
    pub security_header: BasicSecurityHeader,
    /// Unique ID correlating this request with the tunnel creation request.
    pub request_id: u32,
    /// Which transport protocol the server is requesting.
    pub requested_protocol: RequestedProtocol,
    /// 16-byte random cookie for transport binding validation.
    pub security_cookie: [u8; SECURITY_COOKIE_LEN],
}

impl MultitransportRequestPdu {
    const NAME: &'static str = "MultitransportRequestPdu";

    const FIXED_PART_SIZE: usize = BasicSecurityHeader::FIXED_PART_SIZE
        + 4 /* requestId */
        + 2 /* requestedProtocol */
        + 2 /* reserved */
        + SECURITY_COOKIE_LEN /* securityCookie */;
}

impl Encode for MultitransportRequestPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        self.security_header.encode(dst)?;
        dst.write_u32(self.request_id);
        dst.write_u16(self.requested_protocol.as_u16());
        write_padding!(dst, 2);
        dst.write_slice(&self.security_cookie);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for MultitransportRequestPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let security_header = BasicSecurityHeader::decode(src)?;

        if !security_header.flags.contains(BasicSecurityHeaderFlags::TRANSPORT_REQ) {
            return Err(invalid_field_err!("securityHeader", "expected TRANSPORT_REQ flag"));
        }

        let request_id = src.read_u32();

        let protocol_raw = src.read_u16();
        let requested_protocol = RequestedProtocol::from_u16(protocol_raw)
            .ok_or_else(|| invalid_field_err!("requestedProtocol", "unknown protocol value"))?;

        read_padding!(src, 2);

        let security_cookie: [u8; SECURITY_COOKIE_LEN] = src.read_array();

        Ok(Self {
            security_header,
            request_id,
            requested_protocol,
            security_cookie,
        })
    }
}

/// Client Initiate Multitransport Response PDU.
///
/// Sent by the client on the IO channel after the UDP transport is
/// established (or has failed). The `request_id` must match the
/// corresponding server request.
///
/// Defined in [\[MS-RDPBCGR\] 2.2.15.2].
///
/// [\[MS-RDPBCGR\] 2.2.15.2]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/44044233-e498-46f8-8e16-1ffa595a8e8b
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct MultitransportResponsePdu {
    pub security_header: BasicSecurityHeader,
    /// Request ID matching the server's Initiate Multitransport Request.
    pub request_id: u32,
    /// HRESULT indicating success or failure of the transport setup.
    pub hr_response: u32,
}

impl MultitransportResponsePdu {
    const NAME: &'static str = "MultitransportResponsePdu";

    const FIXED_PART_SIZE: usize = BasicSecurityHeader::FIXED_PART_SIZE
        + 4 /* requestId */
        + 4 /* hrResponse */;

    /// `S_OK` — multitransport connection established.
    ///
    /// Per [\[MS-RDPBCGR\] 2.2.15.2], this MUST only be sent to servers that
    /// advertised `SOFTSYNC_TCP_TO_UDP` in the GCC `MultiTransportChannelData`.
    ///
    /// [\[MS-RDPBCGR\] 2.2.15.2]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/44044233-e498-46f8-8e16-1ffa595a8e8b
    pub const S_OK: u32 = 0x0000_0000;

    /// `E_ABORT` — client was unable to establish the multitransport connection.
    pub const E_ABORT: u32 = 0x8000_4004;

    /// Create a success response for the given request ID.
    pub fn success(request_id: u32) -> Self {
        Self {
            security_header: BasicSecurityHeader {
                flags: BasicSecurityHeaderFlags::TRANSPORT_RSP,
            },
            request_id,
            hr_response: Self::S_OK,
        }
    }

    /// Create a failure response for the given request ID.
    pub fn abort(request_id: u32) -> Self {
        Self {
            security_header: BasicSecurityHeader {
                flags: BasicSecurityHeaderFlags::TRANSPORT_RSP,
            },
            request_id,
            hr_response: Self::E_ABORT,
        }
    }

    /// Whether this response indicates success.
    pub fn is_success(&self) -> bool {
        self.hr_response == Self::S_OK
    }
}

impl Encode for MultitransportResponsePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        self.security_header.encode(dst)?;
        dst.write_u32(self.request_id);
        dst.write_u32(self.hr_response);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for MultitransportResponsePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let security_header = BasicSecurityHeader::decode(src)?;

        if !security_header.flags.contains(BasicSecurityHeaderFlags::TRANSPORT_RSP) {
            return Err(invalid_field_err!("securityHeader", "expected TRANSPORT_RSP flag"));
        }

        let request_id = src.read_u32();
        let hr_response = src.read_u32();

        Ok(Self {
            security_header,
            request_id,
            hr_response,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_WIRE: &[u8] = &[
        // BasicSecurityHeader (4 bytes)
        0x02, 0x00, // flags = TRANSPORT_REQ (0x0002)
        0x00, 0x00, // flagsHi = 0
        // Payload (24 bytes)
        0x2A, 0x00, 0x00, 0x00, // requestId = 42
        0x01, 0x00, // requestedProtocol = UdpFecR (0x0001)
        0x00, 0x00, // reserved
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, // securityCookie
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
    ];

    const RESPONSE_SUCCESS_WIRE: &[u8] = &[
        // BasicSecurityHeader (4 bytes)
        0x04, 0x00, // flags = TRANSPORT_RSP (0x0004)
        0x00, 0x00, // flagsHi = 0
        // Payload (8 bytes)
        0x2A, 0x00, 0x00, 0x00, // requestId = 42
        0x00, 0x00, 0x00, 0x00, // hrResponse = S_OK
    ];

    const RESPONSE_ABORT_WIRE: &[u8] = &[
        // BasicSecurityHeader (4 bytes)
        0x04, 0x00, // flags = TRANSPORT_RSP (0x0004)
        0x00, 0x00, // flagsHi = 0
        // Payload (8 bytes)
        0x07, 0x00, 0x00, 0x00, // requestId = 7
        0x04, 0x40, 0x00, 0x80, // hrResponse = E_ABORT (0x80004004)
    ];

    #[test]
    fn decode_request() {
        let pdu = ironrdp_core::decode::<MultitransportRequestPdu>(REQUEST_WIRE).unwrap();
        assert_eq!(pdu.request_id, 42);
        assert_eq!(pdu.requested_protocol, RequestedProtocol::UdpFecR);
        assert_eq!(pdu.security_cookie, [0xAB; 16]);
    }

    #[test]
    fn encode_request() {
        let pdu = MultitransportRequestPdu {
            security_header: BasicSecurityHeader {
                flags: BasicSecurityHeaderFlags::TRANSPORT_REQ,
            },
            request_id: 42,
            requested_protocol: RequestedProtocol::UdpFecR,
            security_cookie: [0xAB; 16],
        };
        let encoded = ironrdp_core::encode_vec(&pdu).unwrap();
        assert_eq!(encoded.as_slice(), REQUEST_WIRE);
    }

    #[test]
    fn request_round_trip() {
        let original = MultitransportRequestPdu {
            security_header: BasicSecurityHeader {
                flags: BasicSecurityHeaderFlags::TRANSPORT_REQ,
            },
            request_id: 0xDEAD_BEEF,
            requested_protocol: RequestedProtocol::UdpFecL,
            security_cookie: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        };
        let encoded = ironrdp_core::encode_vec(&original).unwrap();
        let decoded = ironrdp_core::decode::<MultitransportRequestPdu>(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn request_size() {
        assert_eq!(MultitransportRequestPdu::FIXED_PART_SIZE, 28);
    }

    #[test]
    fn decode_response_success() {
        let pdu = ironrdp_core::decode::<MultitransportResponsePdu>(RESPONSE_SUCCESS_WIRE).unwrap();
        assert_eq!(pdu.request_id, 42);
        assert!(pdu.is_success());
    }

    #[test]
    fn decode_response_abort() {
        let pdu = ironrdp_core::decode::<MultitransportResponsePdu>(RESPONSE_ABORT_WIRE).unwrap();
        assert_eq!(pdu.request_id, 7);
        assert_eq!(pdu.hr_response, MultitransportResponsePdu::E_ABORT);
        assert!(!pdu.is_success());
    }

    #[test]
    fn encode_response_success() {
        let pdu = MultitransportResponsePdu::success(42);
        let encoded = ironrdp_core::encode_vec(&pdu).unwrap();
        assert_eq!(encoded.as_slice(), RESPONSE_SUCCESS_WIRE);
    }

    #[test]
    fn encode_response_abort() {
        let pdu = MultitransportResponsePdu::abort(7);
        let encoded = ironrdp_core::encode_vec(&pdu).unwrap();
        assert_eq!(encoded.as_slice(), RESPONSE_ABORT_WIRE);
    }

    #[test]
    fn response_round_trip() {
        let original = MultitransportResponsePdu::success(0xCAFE_BABE);
        let encoded = ironrdp_core::encode_vec(&original).unwrap();
        let decoded = ironrdp_core::decode::<MultitransportResponsePdu>(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn response_size() {
        assert_eq!(MultitransportResponsePdu::FIXED_PART_SIZE, 12);
    }

    #[test]
    fn decode_request_wrong_flags() {
        let bad_wire: &[u8] = &[
            0x04, 0x00, // flags = TRANSPORT_RSP (wrong for request)
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(ironrdp_core::decode::<MultitransportRequestPdu>(bad_wire).is_err());
    }

    #[test]
    fn decode_request_unknown_protocol() {
        let bad_wire: &[u8] = &[
            0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0x00, // unknown protocol
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(ironrdp_core::decode::<MultitransportRequestPdu>(bad_wire).is_err());
    }
}
