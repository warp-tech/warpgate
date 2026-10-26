#[cfg(test)]
mod tests;

use bitflags::bitflags;
use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, ensure_fixed_part_size, ensure_size,
};

const FLAGS_FIELD_SIZE: usize = 4;
const CHUNK_SIZE_FIELD_SIZE: usize = 4;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct VirtualChannelFlags: u32 {
        const NO_COMPRESSION = 0;
        const COMPRESSION_SERVER_TO_CLIENT = 1;
        const COMPRESSION_CLIENT_TO_SERVER_8K = 2;

        const _ = !0;
    }
}

/// The VirtualChannel structure is used to advertise virtual channel support characteristics. This capability is sent by both client and server.
///
/// # Fields
///
/// * `flags` - virtual channel compression flags
/// * `chunk_size` - when sent from server to client, this field contains the maximum allowed size of a virtual channel chunk and MUST be greater than or equal to 1600 and less than or equal to 16256.
///   When sent from client to server, the value in this field is ignored by the server. This value is not verified in IronRDP and MUST be verified on the caller's side
///
/// # MSDN
///
/// * [Virtual Channel Capability Set](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/a8593178-80c0-4b80-876c-cb77e62cecfc)
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct VirtualChannel {
    pub flags: VirtualChannelFlags,
    pub chunk_size: Option<u32>,
}

impl VirtualChannel {
    const NAME: &'static str = "VirtualChannel";

    const FIXED_PART_SIZE: usize = FLAGS_FIELD_SIZE;
}

impl Encode for VirtualChannel {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u32(self.flags.bits());

        if let Some(value) = self.chunk_size {
            dst.write_u32(value);
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.chunk_size.map(|_| CHUNK_SIZE_FIELD_SIZE).unwrap_or(0)
    }
}

macro_rules! try_or_return {
    ($expr:expr, $ret:expr) => {
        match $expr {
            Ok(v) => v,
            Err(_) => return Ok($ret),
        }
    };
}

impl<'de> Decode<'de> for VirtualChannel {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let flags = VirtualChannelFlags::from_bits_retain(src.read_u32());

        let mut virtual_channel_pdu = Self {
            flags,
            chunk_size: None,
        };

        virtual_channel_pdu.chunk_size = Some(try_or_return!(src.try_read_u32(), virtual_channel_pdu));

        Ok(virtual_channel_pdu)
    }
}
