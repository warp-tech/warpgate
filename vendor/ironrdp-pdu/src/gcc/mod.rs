use ironrdp_core::{
    Decode, DecodeErrorKind, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, cast_length, decode,
    ensure_fixed_part_size, ensure_size, invalid_field_err,
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

pub mod conference_create;

mod cluster_data;
mod core_data;
mod message_channel_data;
mod monitor_data;
mod monitor_extended_data;
mod multi_transport_channel_data;
mod network_data;
mod security_data;

pub use self::cluster_data::{ClientClusterData, RedirectionFlags, RedirectionVersion};
pub use self::conference_create::{ConferenceCreateRequest, ConferenceCreateResponse};
pub use self::core_data::RdpVersion;
pub use self::core_data::client::{
    ClientColorDepth, ClientCoreData, ClientCoreOptionalData, ClientEarlyCapabilityFlags, ColorDepth, ConnectionType,
    HighColorDepth, IME_FILE_NAME_SIZE, KeyboardType, SecureAccessSequence, SupportedColorDepths,
};
pub use self::core_data::server::{ServerCoreData, ServerCoreOptionalData, ServerEarlyCapabilityFlags};
pub use self::message_channel_data::{ClientMessageChannelData, ServerMessageChannelData};
pub use self::monitor_data::{
    ClientMonitorData, MONITOR_COUNT_SIZE, MONITOR_FLAGS_SIZE, MONITOR_SIZE, Monitor, MonitorFlags,
};
pub use self::monitor_extended_data::{ClientMonitorExtendedData, ExtendedMonitorInfo, MonitorOrientation};
pub use self::multi_transport_channel_data::{MultiTransportChannelData, MultiTransportFlags};
pub use self::network_data::{ChannelDef, ChannelName, ChannelOptions, ClientNetworkData, ServerNetworkData};
pub use self::security_data::{ClientSecurityData, EncryptionLevel, EncryptionMethod, ServerSecurityData};

macro_rules! user_header_try {
    ($e:expr) => {
        match $e {
            Ok(user_header) => user_header,
            Err(e) if matches!(e.kind(), DecodeErrorKind::NotEnoughBytes { .. }) => break,
            Err(e) => return Err(e),
        }
    };
}

const USER_DATA_HEADER_SIZE: usize = 4;

/// 2.2.1.3 Client MCS Connect Initial PDU with GCC Conference Create Request
///
/// [2.2.1.3]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/db6713ee-1c0e-4064-a3b3-0fac30b4037b
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ClientGccBlocks {
    pub core: ClientCoreData,
    pub security: ClientSecurityData,
    /// According to [MSDN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/c1bea8bd-069c-4437-9769-db5d27935225),
    /// the Client GCC blocks MUST contain Core, Security, Network GCC blocks.
    /// But the FreeRDP does not send the Network GCC block if it does not have channels to join,
    /// and what is surprising - Windows RDP server accepts this GCC block.
    /// Because of this, the Network GCC block is made optional in IronRDP.
    pub network: Option<ClientNetworkData>,
    pub cluster: Option<ClientClusterData>,
    pub monitor: Option<ClientMonitorData>,
    pub message_channel: Option<ClientMessageChannelData>,
    pub multi_transport_channel: Option<MultiTransportChannelData>,
    pub monitor_extended: Option<ClientMonitorExtendedData>,
}

impl ClientGccBlocks {
    const NAME: &'static str = "ClientGccBlocks";

    pub fn channel_names(&self) -> Option<Vec<ChannelDef>> {
        self.network.as_ref().map(|network| network.channels.clone())
    }
}

impl Encode for ClientGccBlocks {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        UserDataHeader::encode(dst, ClientGccType::CoreData.as_u16(), &self.core)?;
        UserDataHeader::encode(dst, ClientGccType::SecurityData.as_u16(), &self.security)?;

        if let Some(ref network) = self.network {
            UserDataHeader::encode(dst, ClientGccType::NetworkData.as_u16(), network)?;
        }
        if let Some(ref cluster) = self.cluster {
            UserDataHeader::encode(dst, ClientGccType::ClusterData.as_u16(), cluster)?;
        }
        if let Some(ref monitor) = self.monitor {
            UserDataHeader::encode(dst, ClientGccType::MonitorData.as_u16(), monitor)?;
        }
        if let Some(ref message_channel) = self.message_channel {
            UserDataHeader::encode(dst, ClientGccType::MessageChannelData.as_u16(), message_channel)?;
        }
        if let Some(ref multi_transport_channel) = self.multi_transport_channel {
            UserDataHeader::encode(
                dst,
                ClientGccType::MultiTransportChannelData.as_u16(),
                multi_transport_channel,
            )?;
        }
        if let Some(ref monitor_extended) = self.monitor_extended {
            UserDataHeader::encode(dst, ClientGccType::MonitorExtendedData.as_u16(), monitor_extended)?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        let mut size = self.core.size() + self.security.size() + USER_DATA_HEADER_SIZE * 2;

        if let Some(ref network) = self.network {
            size += network.size() + USER_DATA_HEADER_SIZE;
        }
        if let Some(ref cluster) = self.cluster {
            size += cluster.size() + USER_DATA_HEADER_SIZE;
        }
        if let Some(ref monitor) = self.monitor {
            size += monitor.size() + USER_DATA_HEADER_SIZE;
        }
        if let Some(ref message_channel) = self.message_channel {
            size += message_channel.size() + USER_DATA_HEADER_SIZE;
        }
        if let Some(ref multi_transport_channel) = self.multi_transport_channel {
            size += multi_transport_channel.size() + USER_DATA_HEADER_SIZE;
        }
        if let Some(ref monitor_extended) = self.monitor_extended {
            size += monitor_extended.size() + USER_DATA_HEADER_SIZE;
        }

        size
    }
}

impl<'de> Decode<'de> for ClientGccBlocks {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let mut core = None;
        let mut security = None;
        let mut network = None;
        let mut cluster = None;
        let mut monitor = None;
        let mut message_channel = None;
        let mut multi_transport_channel = None;
        let mut monitor_extended = None;

        loop {
            let (ty, cur) = user_header_try!(UserDataHeader::decode(src));

            match ty {
                ClientGccType::CoreData => core = Some(decode(cur)?),
                ClientGccType::SecurityData => security = Some(decode(cur)?),
                ClientGccType::NetworkData => network = Some(decode(cur)?),
                ClientGccType::ClusterData => cluster = Some(decode(cur)?),
                ClientGccType::MonitorData => monitor = Some(decode(cur)?),
                ClientGccType::MessageChannelData => message_channel = Some(decode(cur)?),
                ClientGccType::MonitorExtendedData => monitor_extended = Some(decode(cur)?),
                ClientGccType::MultiTransportChannelData => multi_transport_channel = Some(decode(cur)?),
            };
        }

        Ok(Self {
            core: core.ok_or_else(|| invalid_field_err!("core", "required GCC core is absent"))?,
            security: security.ok_or_else(|| invalid_field_err!("security", "required GCC security is absent"))?,
            network,
            cluster,
            monitor,
            message_channel,
            multi_transport_channel,
            monitor_extended,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ServerGccBlocks {
    pub core: ServerCoreData,
    pub network: ServerNetworkData,
    pub security: ServerSecurityData,
    pub message_channel: Option<ServerMessageChannelData>,
    pub multi_transport_channel: Option<MultiTransportChannelData>,
}

impl ServerGccBlocks {
    const NAME: &'static str = "ServerGccBlocks";

    pub fn channel_ids(&self) -> Vec<u16> {
        self.network.channel_ids.clone()
    }
    pub fn global_channel_id(&self) -> u16 {
        self.network.io_channel
    }
}

impl Encode for ServerGccBlocks {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        UserDataHeader::encode(dst, ServerGccType::CoreData.as_u16(), &self.core)?;
        UserDataHeader::encode(dst, ServerGccType::NetworkData.as_u16(), &self.network)?;
        UserDataHeader::encode(dst, ServerGccType::SecurityData.as_u16(), &self.security)?;

        if let Some(ref message_channel) = self.message_channel {
            UserDataHeader::encode(dst, ServerGccType::MessageChannelData.as_u16(), message_channel)?;
        }
        if let Some(ref multi_transport_channel) = self.multi_transport_channel {
            UserDataHeader::encode(
                dst,
                ServerGccType::MultiTransportChannelData.as_u16(),
                multi_transport_channel,
            )?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        let mut size = self.core.size() + self.network.size() + self.security.size() + USER_DATA_HEADER_SIZE * 3;

        if let Some(ref message_channel) = self.message_channel {
            size += message_channel.size() + USER_DATA_HEADER_SIZE;
        }
        if let Some(ref multi_transport_channel) = self.multi_transport_channel {
            size += multi_transport_channel.size() + USER_DATA_HEADER_SIZE;
        }

        size
    }
}

impl<'de> Decode<'de> for ServerGccBlocks {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let mut core = None;
        let mut network = None;
        let mut security = None;
        let mut message_channel = None;
        let mut multi_transport_channel = None;

        loop {
            let (ty, cur) = user_header_try!(UserDataHeader::decode(src));

            match ty {
                ServerGccType::CoreData => core = Some(decode(cur)?),
                ServerGccType::NetworkData => network = Some(decode(cur)?),
                ServerGccType::SecurityData => security = Some(decode(cur)?),
                ServerGccType::MessageChannelData => message_channel = Some(decode(cur)?),
                ServerGccType::MultiTransportChannelData => multi_transport_channel = Some(decode(cur)?),
            };
        }

        Ok(Self {
            core: core.ok_or_else(|| invalid_field_err!("core", "required GCC core is absent"))?,
            network: network.ok_or_else(|| invalid_field_err!("network", "required GCC network is absent"))?,
            security: security.ok_or_else(|| invalid_field_err!("security", "required GCC security is absent"))?,
            message_channel,
            multi_transport_channel,
        })
    }
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, FromPrimitive)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum ClientGccType {
    CoreData = 0xC001,
    SecurityData = 0xC002,
    NetworkData = 0xC003,
    ClusterData = 0xC004,
    MonitorData = 0xC005,
    MessageChannelData = 0xC006,
    MonitorExtendedData = 0xC008,
    MultiTransportChannelData = 0xC00A,
}

impl ClientGccType {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, FromPrimitive)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum ServerGccType {
    CoreData = 0x0C01,
    SecurityData = 0x0C02,
    NetworkData = 0x0C03,
    MessageChannelData = 0x0C04,
    MultiTransportChannelData = 0x0C08,
}

impl ServerGccType {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct UserDataHeader;

impl UserDataHeader {
    const FIXED_PART_SIZE: usize = 2 /* blockType */ + 2 /* blockLen */;

    pub fn encode<T, B>(dst: &mut WriteCursor<'_>, block_type: T, block: &B) -> EncodeResult<()>
    where
        T: Into<u16>,
        B: Encode,
    {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(block_type.into());
        dst.write_u16(cast_length!("blockLen", block.size() + USER_DATA_HEADER_SIZE)?);
        block.encode(dst)?;

        Ok(())
    }

    pub fn decode<'de, T>(src: &mut ReadCursor<'de>) -> DecodeResult<(T, &'de [u8])>
    where
        T: FromPrimitive,
    {
        ensure_fixed_part_size!(in: src);

        let block_type =
            T::from_u16(src.read_u16()).ok_or_else(|| invalid_field_err!("blockType", "invalid GCC type"))?;
        let block_length: usize = cast_length!("blockLen", src.read_u16())?;

        if block_length <= USER_DATA_HEADER_SIZE {
            return Err(invalid_field_err!("blockLen", "invalid UserDataHeader length"));
        }

        let len = block_length - USER_DATA_HEADER_SIZE;
        ensure_size!(in: src, size: len);

        Ok((block_type, src.read_slice(len)))
    }
}
