use ironrdp_core::{Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, ensure_fixed_part_size};

const CLIENT_FLAGS_SIZE: usize = 4;
const SERVER_MCS_MESSAGE_CHANNEL_ID_SIZE: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ClientMessageChannelData;

impl ClientMessageChannelData {
    const NAME: &'static str = "ClientMessageChannelData";

    const FIXED_PART_SIZE: usize = CLIENT_FLAGS_SIZE;
}

impl Encode for ClientMessageChannelData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u32(0); // flags

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for ClientMessageChannelData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let _flags = src.read_u32(); // is unused

        Ok(Self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ServerMessageChannelData {
    pub mcs_message_channel_id: u16,
}

impl ServerMessageChannelData {
    const NAME: &'static str = "ServerMessageChannelData";

    const FIXED_PART_SIZE: usize = SERVER_MCS_MESSAGE_CHANNEL_ID_SIZE;
}

impl Encode for ServerMessageChannelData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(self.mcs_message_channel_id);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for ServerMessageChannelData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let mcs_message_channel_id = src.read_u16();

        Ok(Self { mcs_message_channel_id })
    }
}
