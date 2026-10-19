//! PDUs used during the Connection Initiation stage

use core::fmt;

use bitflags::bitflags;
use ironrdp_core::{ReadCursor, WriteCursor, ensure_size, invalid_field_err, unexpected_message_type_err};
use tap::prelude::*;

use crate::tpdu::{TpduCode, TpduHeader};
use crate::tpkt::TpktHeader;
use crate::x224::X224Pdu;
use crate::{DecodeResult, EncodeResult, Pdu as _, impl_x224_pdu_pod};

bitflags! {
    /// A 32-bit, unsigned integer that contains flags indicating the supported security protocols.
    ///
    /// Used to negotiate the security protocol to use during the Connection Initiation phase using
    /// the [`ConnectionConfirm`] and [`ConnectionRequest`] messages.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct SecurityProtocol: u32 {
        /// PROTOCOL_SSL, TLS + login subsystem (winlogon.exe)
        const SSL = 0x0000_0001;
        /// PROTOCOL_HYBRID, TLS + Credential Security Support Provider protocol (CredSSP)
        const HYBRID = 0x0000_0002;
        /// PROTOCOL_RDSTLS, RDSTLS protocol
        const RDSTLS = 0x0000_0004;
        /// PROTOCOL_HYBRID_EX, TLS + Credential Security Support Provider protocol (CredSSP) coupled with the Early User Authorization Result PDU
        const HYBRID_EX = 0x0000_0008;
        /// PROTOCOL_RDSAAD, RDS-AAD-Auth Security
        const RDSAAD = 0x0000_0010;
    }
}

impl SecurityProtocol {
    /// Returns true if no enhanced security protocol is enabled
    ///
    /// The PROTOCOL_RDP bitmask is defined as 0x00000000.
    /// Hence, this is logically equivalent to `SecurityProtocol::is_empty()`, but more explicit in the intention.
    ///
    /// As a server, to convey that the standard RDP security protocol has been chosen, no flag must be set.
    /// As a client, the standard RDP security is always implied because there is no flag to set or unset.
    pub fn is_standard_rdp_security(self) -> bool {
        self.is_empty()
    }
}

impl fmt::Display for SecurityProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_standard_rdp_security() {
            write!(f, "STANDARD_RDP_SECURITY")
        } else {
            bitflags::parser::to_writer(self, f)
        }
    }
}

bitflags! {
    /// Holds the negotiation protocol flags of the *request* message.
    ///
    /// # MSDN
    ///
    /// * [RDP Negotiation Request (RDP_NEG_REQ)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/902b090b-9cb3-4efc-92bf-ee13373371e3)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct RequestFlags: u8 {
        const RESTRICTED_ADMIN_MODE_REQUIRED = 0x01;
        const REDIRECTED_AUTHENTICATION_MODE_REQUIRED = 0x02;
        const CORRELATION_INFO_PRESENT = 0x08;

        const _ = !0;
    }
}

bitflags! {
    /// Holds the negotiation protocol flags of the *response* message.
    ///
    /// # MSDN
    ///
    /// * [RDP Negotiation Response (RDP_NEG_RSP)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b2975bdc-6d56-49ee-9c57-f2ff3a0b6817)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ResponseFlags: u8 {
        const EXTENDED_CLIENT_DATA_SUPPORTED = 0x01;
        const DYNVC_GFX_PROTOCOL_SUPPORTED = 0x02;
        const RDP_NEG_RSP_RESERVED = 0x04;
        const RESTRICTED_ADMIN_MODE_SUPPORTED = 0x08;
        const REDIRECTED_AUTHENTICATION_MODE_SUPPORTED = 0x10;

        const _ = !0;
    }
}

/// A 32-bit, unsigned integer that specifies the negotiation failure code
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct FailureCode(u32);

impl FailureCode {
    /// The server requires that the client support Enhanced RDP Security (section 5.4)
    /// with either TLS 1.0, 1.1 or 1.2 (section 5.4.5.1) or CredSSP (section 5.4.5.2).
    /// If only CredSSP was requested then the server only supports TLS.
    pub const SSL_REQUIRED_BY_SERVER: Self = Self(1);
    /// The server is configured to only use Standard RDP Security mechanisms (section
    /// 5.3) and does not support any External Security Protocols (section 5.4.5).
    pub const SSL_NOT_ALLOWED_BY_SERVER: Self = Self(2);
    /// The server does not possess a valid authentication certificate and cannot
    /// initialize the External Security Protocol Provider (section 5.4.5).
    pub const SSL_CERT_NOT_ON_SERVER: Self = Self(3);
    /// The list of requested security protocols is not consistent with the current
    /// security protocol in effect. This error is only possible when the Direct
    /// Approach (sections 5.4.2.2 and 1.3.1.2) is used and an External Security
    /// Protocol (section 5.4.5) is already being used.
    pub const INCONSISTENT_FLAGS: Self = Self(4);
    /// The server requires that the client support Enhanced RDP Security (section 5.4)
    /// with CredSSP (section 5.4.5.2).
    pub const HYBRID_REQUIRED_BY_SERVER: Self = Self(5);
    /// The server requires that the client support Enhanced RDP Security (section
    /// 5.4) with TLS 1.0, 1.1 or 1.2 (section 5.4.5.1) and certificate-based client
    /// authentication.
    pub const SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER: Self = Self(6);
}

impl From<u32> for FailureCode {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<FailureCode> for u32 {
    fn from(value: FailureCode) -> Self {
        value.0
    }
}

impl fmt::Display for FailureCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::SSL_REQUIRED_BY_SERVER => {
                write!(f, "enhanced RDP security required by server")
            }
            Self::SSL_NOT_ALLOWED_BY_SERVER => {
                write!(f, "enhanced RDP security not allowed by server")
            }
            Self::SSL_CERT_NOT_ON_SERVER => {
                write!(f, "no valid TLS authentication certificate on server")
            }
            Self::INCONSISTENT_FLAGS => {
                write!(f, "inconsistent flags for security protocols")
            }
            Self::HYBRID_REQUIRED_BY_SERVER => {
                write!(f, "CredSSP enhanced RDP security required by server")
            }
            Self::SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER => {
                write!(f, "TLS certificate-based client authentication required by server")
            }
            _ => write!(f, "unknown failure code: {}", self.0),
        }
    }
}

/// The kind of the negotiation request message.
///
/// # MSDN
///
/// * [Client X.224 Connection Request PDU](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/18a27ef9-6f9a-4501-b000-94b1fe3c2c10)
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum NegoRequestData {
    RoutingToken(RoutingToken),
    Cookie(Cookie),
}

impl NegoRequestData {
    pub fn routing_token(value: String) -> Self {
        Self::RoutingToken(RoutingToken(value))
    }

    pub fn cookie(value: String) -> Self {
        Self::Cookie(Cookie(value))
    }

    pub fn read(src: &mut ReadCursor<'_>) -> DecodeResult<Option<Self>> {
        match RoutingToken::read(src)? {
            Some(token) => Ok(Some(Self::RoutingToken(token))),
            None => Cookie::read(src)?.map(Self::Cookie).pipe(Ok),
        }
    }

    pub fn write(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        match self {
            NegoRequestData::RoutingToken(token) => token.write(dst),
            NegoRequestData::Cookie(cookie) => cookie.write(dst),
        }
    }

    pub fn size(&self) -> usize {
        match self {
            NegoRequestData::RoutingToken(token) => token.size(),
            NegoRequestData::Cookie(cookie) => cookie.size(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Cookie(pub String);

impl Cookie {
    const PREFIX: &'static str = "Cookie: mstshash=";

    pub fn read(src: &mut ReadCursor<'_>) -> DecodeResult<Option<Self>> {
        read_nego_data(src, "Cookie", Self::PREFIX)?.map(Self).pipe(Ok)
    }

    pub fn write(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        write_nego_data(dst, "Cookie", Self::PREFIX, &self.0)
    }

    pub fn size(&self) -> usize {
        Self::PREFIX.len() + self.0.len() + 2
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct RoutingToken(pub String);

impl RoutingToken {
    const PREFIX: &'static str = "Cookie: msts=";

    pub fn read(src: &mut ReadCursor<'_>) -> DecodeResult<Option<Self>> {
        read_nego_data(src, "RoutingToken", Self::PREFIX)?.map(Self).pipe(Ok)
    }

    pub fn write(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        write_nego_data(dst, "RoutingToken", Self::PREFIX, &self.0)
    }

    pub fn size(&self) -> usize {
        Self::PREFIX.len() + self.0.len() + 2
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct NegoMsgType(u8);

impl NegoMsgType {
    const REQUEST: Self = Self(0x01);
    const RESPONSE: Self = Self(0x02);
    const FAILURE: Self = Self(0x03);
}

impl From<u8> for NegoMsgType {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<NegoMsgType> for u8 {
    fn from(value: NegoMsgType) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRequest {
    pub nego_data: Option<NegoRequestData>,
    pub flags: RequestFlags,
    pub protocol: SecurityProtocol,
}

impl_x224_pdu_pod!(ConnectionRequest);

impl ConnectionRequest {
    const RDP_NEG_REQ_SIZE: u16 = 8;
}

impl<'de> X224Pdu<'de> for ConnectionRequest {
    const X224_NAME: &'static str = "Client X.224 Connection Request";

    const TPDU_CODE: TpduCode = TpduCode::CONNECTION_REQUEST;

    fn x224_body_encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if let Some(nego_data) = &self.nego_data {
            nego_data.write(dst)?;
        }

        // [MS-RDPBCGR] mentions the following payload as optional, but it appears that on recent
        // versions of Windows, the server always expect to find this payload.
        dst.write_u8(u8::from(NegoMsgType::REQUEST));
        dst.write_u8(self.flags.bits());
        dst.write_u16(Self::RDP_NEG_REQ_SIZE);
        dst.write_u32(self.protocol.bits());

        if self.flags.contains(RequestFlags::CORRELATION_INFO_PRESENT) {
            // TODO(#111): support for RDP_NEG_CORRELATION_INFO
            return Err(invalid_field_err(
                Self::NAME,
                "flags",
                "CORRECTION_INFO_PRESENT flag is set, but not supported by IronRDP",
            ));
        }

        Ok(())
    }

    fn x224_body_decode(src: &mut ReadCursor<'de>, _: &TpktHeader, tpdu: &TpduHeader) -> DecodeResult<Self> {
        let variable_part_size = tpdu.variable_part_size();

        ensure_size!(in: src, size: variable_part_size);

        let nego_data = NegoRequestData::read(src)?;

        let Some(variable_part_rest_size) =
            variable_part_size.checked_sub(nego_data.as_ref().map(|data| data.size()).unwrap_or(0))
        else {
            return Err(invalid_field_err(
                Self::NAME,
                "TPDU header variable part",
                "advertised size too small",
            ));
        };

        if variable_part_rest_size >= usize::from(Self::RDP_NEG_REQ_SIZE) {
            let msg_type = NegoMsgType::from(src.read_u8());

            if msg_type != NegoMsgType::REQUEST {
                return Err(unexpected_message_type_err!(Self::NAME, u8::from(msg_type)));
            }

            let flags = RequestFlags::from_bits_retain(src.read_u8());

            if flags.contains(RequestFlags::CORRELATION_INFO_PRESENT) {
                // TODO(#111): support for RDP_NEG_CORRELATION_INFO
                return Err(invalid_field_err(
                    Self::NAME,
                    "flags",
                    "CORRECTION_INFO_PRESENT flag is set, but not supported by IronRDP",
                ));
            }

            let _length = src.read_u16();

            let protocol = SecurityProtocol::from_bits_retain(src.read_u32());

            Ok(Self {
                nego_data,
                flags,
                protocol,
            })
        } else {
            Ok(Self {
                nego_data,
                flags: RequestFlags::empty(),
                protocol: SecurityProtocol::empty(),
            })
        }
    }

    fn tpdu_header_variable_part_size(&self) -> usize {
        let optional_nego_data_size = self.nego_data.as_ref().map(|data| data.size()).unwrap_or(0);
        optional_nego_data_size + usize::from(Self::RDP_NEG_REQ_SIZE)
    }

    fn tpdu_user_data_size(&self) -> usize {
        0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionConfirm {
    Response {
        flags: ResponseFlags,
        protocol: SecurityProtocol,
    },
    Failure {
        code: FailureCode,
    },
}

impl_x224_pdu_pod!(ConnectionConfirm);

impl ConnectionConfirm {
    const RDP_NEG_RSP: u16 = 8;

    const RDP_NEG_FAILURE: u16 = 8;
}

impl<'de> X224Pdu<'de> for ConnectionConfirm {
    const X224_NAME: &'static str = "Server X.224 Connection Confirm";

    const TPDU_CODE: TpduCode = TpduCode::CONNECTION_CONFIRM;

    fn x224_body_encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        match self {
            ConnectionConfirm::Response { flags, protocol } => {
                dst.write_u8(u8::from(NegoMsgType::RESPONSE));
                dst.write_u8(flags.bits());
                dst.write_u16(Self::RDP_NEG_RSP);
                dst.write_u32(protocol.bits());
            }
            ConnectionConfirm::Failure { code } => {
                dst.write_u8(u8::from(NegoMsgType::FAILURE));
                dst.write_u8(0);
                dst.write_u16(Self::RDP_NEG_RSP);
                dst.write_u32(u32::from(*code));
            }
        }

        Ok(())
    }

    fn x224_body_decode(src: &mut ReadCursor<'de>, _: &TpktHeader, tpdu: &TpduHeader) -> DecodeResult<Self> {
        let variable_part_size = tpdu.variable_part_size();

        ensure_size!(in: src, size: variable_part_size);

        if variable_part_size > 0 {
            ensure_size!(in: src, size: 8); // message type (1) + flags (1) + length (2) + code / protocol (4)

            match NegoMsgType::from(src.read_u8()) {
                NegoMsgType::RESPONSE => {
                    let flags = ResponseFlags::from_bits_retain(src.read_u8());
                    let _length = src.read_u16();
                    let protocol = SecurityProtocol::from_bits_retain(src.read_u32());

                    Ok(Self::Response { flags, protocol })
                }
                NegoMsgType::FAILURE => {
                    let _flags = src.read_u8();
                    let _length = src.read_u16();
                    let code = FailureCode::from(src.read_u32());

                    Ok(Self::Failure { code })
                }
                unexpected => Err(unexpected_message_type_err!(Self::X224_NAME, u8::from(unexpected))),
            }
        } else {
            Ok(Self::Response {
                flags: ResponseFlags::empty(),
                protocol: SecurityProtocol::empty(),
            })
        }
    }

    fn tpdu_header_variable_part_size(&self) -> usize {
        match self {
            ConnectionConfirm::Response { .. } => usize::from(Self::RDP_NEG_RSP),
            ConnectionConfirm::Failure { .. } => usize::from(Self::RDP_NEG_FAILURE),
        }
    }

    fn tpdu_user_data_size(&self) -> usize {
        0
    }
}

fn read_nego_data(src: &mut ReadCursor<'_>, ctx: &'static str, prefix: &str) -> DecodeResult<Option<String>> {
    if src.len() < prefix.len() + 2 {
        return Ok(None);
    }

    if src.peek_slice(prefix.len()) != prefix.as_bytes() {
        return Ok(None);
    }

    src.advance(prefix.len());

    let identifier_start = src.pos();

    while src.peek_u16() != 0x0A0D {
        src.advance(1);
        ensure_size!(ctx: ctx, in: src, size: 2);
    }

    let identifier_end = src.pos();

    src.advance(2);

    let data = core::str::from_utf8(&src.inner()[identifier_start..identifier_end])
        .map_err(|_| invalid_field_err(ctx, "identifier", "not valid UTF-8"))?
        .to_owned();

    Ok(Some(data))
}

fn write_nego_data(dst: &mut WriteCursor<'_>, ctx: &'static str, prefix: &str, value: &str) -> EncodeResult<()> {
    ensure_size!(ctx: ctx, in: dst, size: prefix.len() + value.len() + 2);

    dst.write_slice(prefix.as_bytes());
    dst.write_slice(value.as_bytes());
    dst.write_u16(0x0A0D);

    Ok(())
}
