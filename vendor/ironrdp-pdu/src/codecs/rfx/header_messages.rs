use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, cast_length, ensure_fixed_part_size,
    invalid_field_err,
};

const SYNC_MAGIC: u32 = 0xCACC_ACCA;
const SYNC_VERSION: u16 = 0x0100;
const CODECS_NUMBER: u8 = 1;
const CODEC_ID: u8 = 1;
const CODEC_VERSION: u16 = 0x0100;
const CHANNEL_ID: u8 = 0;

// [2.2.2.2.1] TS_RFX_SYNC
//
// [2.2.2.2.1]: https://learn.microsoft.com/pt-br/openspecs/windows_protocols/ms-rdprfx/f01b81b6-1a8f-49fd-9543-081fbc8e1831
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct SyncPdu;

impl SyncPdu {
    const NAME: &'static str = "RfxSync";

    const FIXED_PART_SIZE: usize = 4 /* magic */ + 2 /* version */;
}

impl Encode for SyncPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u32(SYNC_MAGIC);
        dst.write_u16(SYNC_VERSION);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for SyncPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let magic = src.read_u32();
        if magic != SYNC_MAGIC {
            return Err(invalid_field_err!("magic", "Invalid sync magic"));
        }
        let version = src.read_u16();
        if version != SYNC_VERSION {
            return Err(invalid_field_err!("version", "Invalid sync version"));
        }

        Ok(Self)
    }
}

/// [2.2.2.2.2] TS_RFX_CODEC_VERSIONS
///
/// [2.2.2.2.2]: https://learn.microsoft.com/pt-br/openspecs/windows_protocols/ms-rdprfx/2650e6c2-faf7-4858-b169-828db842b663
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct CodecVersionsPdu;

impl CodecVersionsPdu {
    const NAME: &'static str = "RfxCodecVersions";

    const FIXED_PART_SIZE: usize = 1 /* numCodecs */ + CodecVersion::FIXED_PART_SIZE /* codecs */;
}

impl Encode for CodecVersionsPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u8(CODECS_NUMBER);
        CodecVersion.encode(dst)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for CodecVersionsPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let codec_number = src.read_u8();
        if codec_number != CODECS_NUMBER {
            return Err(invalid_field_err!("codec_number", "Invalid codec number"));
        }

        let _codec_version = CodecVersion::decode(src)?;

        Ok(Self)
    }
}

/// [2.2.2.2.3] TS_RFX_CHANNELS
///
/// [2.2.2.2.3]: https://learn.microsoft.com/pt-br/openspecs/windows_protocols/ms-rdprfx/c6efba0b-f59e-4d8e-8d76-840c41edce5b
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ChannelsPdu(pub Vec<RfxChannel>);

impl ChannelsPdu {
    const NAME: &'static str = "RfxChannels";

    const FIXED_PART_SIZE: usize = 1 /* numChannels */;
}

impl Encode for ChannelsPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u8(cast_length!("num_channels", self.0.len())?);
        for channel in &self.0 {
            channel.encode(dst)?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.0.iter().map(|channel| channel.size()).sum::<usize>()
    }
}

impl<'de> Decode<'de> for ChannelsPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let num_channels = usize::from(src.read_u8());
        let channels = core::iter::repeat_with(|| RfxChannel::decode(src))
            .take(num_channels)
            .collect::<DecodeResult<Vec<_>>>()?;

        Ok(Self(channels))
    }
}

/// [2.2.2.1.3] TS_RFX_CHANNELT
///
/// [2.2.2.1.3]: https://learn.microsoft.com/pt-br/openspecs/windows_protocols/ms-rdprfx/4060f07e-9d73-454d-841e-131a93aca675
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct RfxChannel {
    pub width: i16,
    pub height: i16,
}

impl RfxChannel {
    const NAME: &'static str = "RfxChannel";

    const FIXED_PART_SIZE: usize = 1 /* channelId */ + 2 /* width */ + 2 /* height */;
}

impl Encode for RfxChannel {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u8(CHANNEL_ID);
        dst.write_i16(self.width);
        dst.write_i16(self.height);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for RfxChannel {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let channel_id = src.read_u8();
        if channel_id != CHANNEL_ID {
            return Err(invalid_field_err!("channelId", "Invalid channel ID"));
        }

        let width = src.read_i16();
        let height = src.read_i16();

        Ok(Self { width, height })
    }
}

/// [2.2.2.1.4] TS_RFX_CODEC_VERSIONT
///
/// [2.2.2.1.4] https://learn.microsoft.com/pt-br/openspecs/windows_protocols/ms-rdprfx/024fee4a-197d-479e-a68f-861933a34b06
#[derive(Debug, Clone, PartialEq)]
struct CodecVersion;

impl CodecVersion {
    const NAME: &'static str = "RfxCodecVersion";

    const FIXED_PART_SIZE: usize = 1 /* codecId */ + 2 /* codecVersion */;
}

impl Encode for CodecVersion {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u8(CODEC_ID);
        dst.write_u16(CODEC_VERSION);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for CodecVersion {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let codec_id = src.read_u8();
        if codec_id != CODEC_ID {
            return Err(invalid_field_err!("codec_id", "Invalid codec ID"));
        }
        let codec_version = src.read_u16();
        if codec_version != CODEC_VERSION {
            return Err(invalid_field_err!("codec_version", "Invalid codec version"));
        }

        Ok(Self)
    }
}
