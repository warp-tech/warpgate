use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, ensure_fixed_part_size, invalid_field_err,
};

use crate::rdp::client_info::ClientInfo;
use crate::rdp::headers::{BasicSecurityHeader, BasicSecurityHeaderFlags};

pub mod autodetect;
pub mod capability_sets;
pub mod client_info;
pub mod finalization_messages;
pub mod headers;
pub mod multitransport;
pub mod refresh_rectangle;
pub mod server_error_info;
pub mod server_license;
pub mod session_info;
pub mod suppress_output;
pub mod vc;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ClientInfoPdu {
    pub security_header: BasicSecurityHeader,
    pub client_info: ClientInfo,
}

impl ClientInfoPdu {
    const NAME: &'static str = "ClientInfoPDU";

    const FIXED_PART_SIZE: usize = BasicSecurityHeader::FIXED_PART_SIZE + ClientInfo::FIXED_PART_SIZE;
}

impl Encode for ClientInfoPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        self.security_header.encode(dst)?;
        self.client_info.encode(dst)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        self.security_header.size() + self.client_info.size()
    }
}

impl<'de> Decode<'de> for ClientInfoPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let security_header = BasicSecurityHeader::decode(src)?;
        if !security_header.flags.contains(BasicSecurityHeaderFlags::INFO_PKT) {
            return Err(invalid_field_err!("securityHeader", "got invalid security header"));
        }

        let client_info = ClientInfo::decode(src)?;

        Ok(Self {
            security_header,
            client_info,
        })
    }
}
