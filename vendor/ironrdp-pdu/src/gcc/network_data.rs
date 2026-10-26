use std::borrow::Cow;
use std::str;

use bitflags::bitflags;
use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, cast_length, ensure_fixed_part_size,
    ensure_size, invalid_field_err, read_padding, write_padding,
};
use num_integer::Integer as _;

const CHANNELS_MAX: usize = 31;

const CLIENT_CHANNEL_OPTIONS_SIZE: usize = 4;
const CLIENT_CHANNEL_SIZE: usize = ChannelName::SIZE + CLIENT_CHANNEL_OPTIONS_SIZE;

const SERVER_IO_CHANNEL_SIZE: usize = 2;
const SERVER_CHANNEL_COUNT_SIZE: usize = 2;
const SERVER_CHANNEL_SIZE: usize = 2;

/// An 8-byte array containing a null-terminated collection of seven ANSI characters
/// with the purpose of uniquely identifying a channel.
///
/// In RDP, an ANSI character is a 8-bit Windows-1252 character set unit. ANSI character set
/// is using all the code values from 0 to 255, as such any u8 value is a valid ANSI character.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChannelName {
    /// INVARIANT: A null-terminated 8-byte array.
    /// INVARIANT: Contains at most seven ANSI characters.
    inner: Cow<'static, [u8; Self::SIZE]>,
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for ChannelName {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Generate up to seven ANSI characters then enforce the null terminator,
        // preserving both INVARIANTs on the inner array.
        let len = u.int_in_range::<usize>(0..=Self::SIZE - 1)?;
        let mut bytes = [0u8; Self::SIZE];
        let payload = u.bytes(len)?;
        bytes[..len].copy_from_slice(payload);
        Ok(Self {
            inner: Cow::Owned(bytes),
        })
    }
}

impl ChannelName {
    pub const SIZE: usize = 8;

    /// Creates a channel name using the provided array, ensuring the last byte is always the null terminator.
    pub const fn new(mut value: [u8; Self::SIZE]) -> Self {
        value[Self::SIZE - 1] = 0; // ensure the last byte is always the null terminator

        Self {
            inner: Cow::Owned(value),
        }
    }

    /// Converts an UTF-8 string into a channel name by copying up to 7 bytes.
    pub fn from_utf8(value: &str) -> Option<Self> {
        let mut inner = [0; Self::SIZE];

        value
            .chars()
            .take(Self::SIZE - 1)
            .zip(inner.iter_mut())
            .try_for_each(|(src, dst)| {
                let c = u8::try_from(src).ok()?;
                c.is_ascii().then(|| *dst = c)
            })?;

        Some(Self {
            inner: Cow::Owned(inner),
        })
    }

    /// Converts a static u8 array into a channel name without copy.
    ///
    /// # Panics
    ///
    /// Panics if input is not null-terminated.
    pub const fn from_static(value: &'static [u8; 8]) -> Self {
        // ensure the last byte is always the null terminator
        if value[Self::SIZE - 1] != 0 {
            panic!("channel name must be null-terminated")
        }

        Self {
            inner: Cow::Borrowed(value),
        }
    }

    /// Returns the underlying raw representation of the channel name (an 8-byte array).
    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        self.inner.as_ref()
    }

    pub fn as_str(&self) -> Option<&str> {
        if self.inner.iter().all(u8::is_ascii) {
            #[expect(clippy::missing_panics_doc, reason = "never panics per invariant on self.inner")]
            let terminator_idx = self
                .inner
                .iter()
                .position(|c| *c == 0)
                .expect("null-terminated ASCII string");

            #[expect(clippy::missing_panics_doc, reason = "never panics per invariant on self.inner")]
            Some(str::from_utf8(&self.inner[..terminator_idx]).expect("ASCII characters"))
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ClientNetworkData {
    pub channels: Vec<ChannelDef>,
}

impl ClientNetworkData {
    const NAME: &'static str = "ClientNetworkData";

    const FIXED_PART_SIZE: usize = 4 /* channelCount */;
}

impl Encode for ClientNetworkData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u32(cast_length!("channelCount", self.channels.len())?);

        for channel in self.channels.iter().take(CHANNELS_MAX) {
            channel.encode(dst)?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.channels.len() * CLIENT_CHANNEL_SIZE
    }
}

impl<'de> Decode<'de> for ClientNetworkData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let channel_count = cast_length!("channelCount", src.read_u32())?;

        if channel_count > CHANNELS_MAX {
            return Err(invalid_field_err!("channelCount", "invalid channel count"));
        }

        let mut channels = Vec::with_capacity(channel_count);
        for _ in 0..channel_count {
            channels.push(ChannelDef::decode(src)?);
        }

        Ok(Self { channels })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ServerNetworkData {
    pub channel_ids: Vec<u16>,
    pub io_channel: u16,
}

impl ServerNetworkData {
    const NAME: &'static str = "ServerNetworkData";

    const FIXED_PART_SIZE: usize = SERVER_IO_CHANNEL_SIZE + SERVER_CHANNEL_COUNT_SIZE;

    fn padding_needed(&self) -> bool {
        self.channel_ids.len().is_odd()
    }
}

impl Encode for ServerNetworkData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u16(self.io_channel);
        dst.write_u16(cast_length!("channelIdLen", self.channel_ids.len())?);

        for channel_id in self.channel_ids.iter() {
            dst.write_u16(*channel_id);
        }

        // The size in bytes of the Server Network Data structure MUST be a multiple of 4.
        // If the channelCount field contains an odd value, then the size of the channelIdArray
        // (and by implication the entire Server Network Data structure) will not be a multiple of 4.
        // In this scenario, the Pad field MUST be present and it is used to add an additional
        // 2 bytes to the size of the Server Network Data structure.
        if self.padding_needed() {
            write_padding!(dst, 2);
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        let padding_size = if self.padding_needed() { 2 } else { 0 };

        Self::FIXED_PART_SIZE + self.channel_ids.len() * SERVER_CHANNEL_SIZE + padding_size
    }
}

impl<'de> Decode<'de> for ServerNetworkData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let io_channel = src.read_u16();
        let channel_count = cast_length!("channelCount", src.read_u16())?;

        ensure_size!(in: src, size: channel_count * 2);
        let mut channel_ids = Vec::with_capacity(channel_count);
        for _ in 0..channel_count {
            channel_ids.push(src.read_u16());
        }

        let result = Self {
            io_channel,
            channel_ids,
        };

        if src.len() >= 2 {
            read_padding!(src, 2);
        }

        Ok(result)
    }
}

/// Channel Definition Structure (CHANNEL_DEF)
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ChannelDef {
    pub name: ChannelName,
    pub options: ChannelOptions,
}

impl ChannelDef {
    const NAME: &'static str = "ChannelDef";

    const FIXED_PART_SIZE: usize = CLIENT_CHANNEL_SIZE;
}

impl Encode for ChannelDef {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_slice(self.name.as_bytes());
        dst.write_u32(self.options.bits());

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for ChannelDef {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let name = src.read_array();
        let name = ChannelName::new(name);

        let options = ChannelOptions::from_bits(src.read_u32())
            .ok_or_else(|| invalid_field_err!("options", "invalid channel options"))?;

        Ok(Self { name, options })
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct ChannelOptions: u32 {
        const INITIALIZED = 0x8000_0000;
        const ENCRYPT_RDP = 0x4000_0000;
        const ENCRYPT_SC = 0x2000_0000;
        const ENCRYPT_CS = 0x1000_0000;
        const PRI_HIGH = 0x0800_0000;
        const PRI_MED = 0x0400_0000;
        const PRI_LOW = 0x0200_0000;
        const COMPRESS_RDP = 0x0080_0000;
        const COMPRESS = 0x0040_0000;
        const SHOW_PROTOCOL = 0x0020_0000;
        const REMOTE_CONTROL_PERSISTENT = 0x0010_0000;
    }
}
