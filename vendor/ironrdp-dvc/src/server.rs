use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::any::TypeId;
use core::fmt;

use ironrdp_core::{Decode as _, DecodeResult, ReadCursor, impl_as_any, invalid_field_err};
use ironrdp_pdu::{self as pdu, decode_err, encode_err, pdu_other_err};
use ironrdp_svc::{ChannelFlags, CompressionCondition, SvcMessage, SvcProcessor, SvcServerProcessor};
use pdu::PduResult;
use pdu::gcc::ChannelName;
use tracing::debug;

use crate::pdu::{
    CapabilitiesRequestPdu, CapsVersion, ClosePdu, CreateRequestPdu, CreationStatus, DrdynvcClientPdu, DrdynvcServerPdu,
};
use crate::{CompleteData, DvcProcessor, DynamicChannelMut, DynamicChannelRef, encode_dvc_messages};

pub trait DvcServerProcessor: DvcProcessor {}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ChannelState {
    Pending,
    /// `Create Request` has been sent; awaiting `Create Response` from the client.
    Creation,
    Opened,
    CreationFailed(u32),
}

struct DynamicChannel {
    state: ChannelState,
    processor: Box<dyn DvcProcessor>,
    complete_data: CompleteData,
    channel_id: u32,
}

impl Drop for DynamicChannel {
    fn drop(&mut self) {
        if self.state == ChannelState::Opened {
            self.processor.close(self.channel_id);
        }
    }
}

struct DynamicChannelAllocator {
    dynamic_channels: BTreeMap<u32, DynamicChannel>,
    next_channel_id: u32,
}

impl<'a> IntoIterator for &'a DynamicChannelAllocator {
    type Item = (&'a u32, &'a DynamicChannel);

    type IntoIter = alloc::collections::btree_map::Iter<'a, u32, DynamicChannel>;

    fn into_iter(self) -> Self::IntoIter {
        self.dynamic_channels.iter()
    }
}

impl<'a> IntoIterator for &'a mut DynamicChannelAllocator {
    type Item = (&'a u32, &'a mut DynamicChannel);
    type IntoIter = alloc::collections::btree_map::IterMut<'a, u32, DynamicChannel>;
    fn into_iter(self) -> Self::IntoIter {
        self.dynamic_channels.iter_mut()
    }
}

impl DynamicChannelAllocator {
    fn new() -> Self {
        Self {
            dynamic_channels: BTreeMap::new(),
            next_channel_id: 0,
        }
    }

    fn insert_channel<T>(&mut self, processor: T, state: ChannelState) -> u32
    where
        T: DvcServerProcessor + 'static,
    {
        let channel_id = self.next_channel_id;
        self.dynamic_channels
            .insert(channel_id, DynamicChannel::new(processor, channel_id, state));
        self.next_channel_id = self
            .next_channel_id
            .checked_add(1)
            .expect("dynamic channels reaches `u32::MAX`");
        channel_id
    }

    fn get(&self, channel_id: u32) -> Option<&DynamicChannel> {
        self.dynamic_channels.get(&channel_id)
    }

    fn get_mut(&mut self, channel_id: u32) -> Option<&mut DynamicChannel> {
        self.dynamic_channels.get_mut(&channel_id)
    }

    fn remove(&mut self, channel_id: u32) -> Option<DynamicChannel> {
        self.dynamic_channels.remove(&channel_id)
    }
}

impl DynamicChannel {
    fn new<T>(processor: T, channel_id: u32, state: ChannelState) -> Self
    where
        T: DvcServerProcessor + 'static,
    {
        Self {
            state,
            processor: Box::new(processor),
            complete_data: CompleteData::new(),
            channel_id,
        }
    }

    fn processor_type_id(&self) -> TypeId {
        self.processor.as_any().type_id()
    }
}
/// DRDYNVC Static Virtual Channel (the Remote Desktop Protocol: Dynamic Virtual Channel Extension)
///
/// It adds support for dynamic virtual channels (DVC).
pub struct DrdynvcServer {
    dynamic_channels: DynamicChannelAllocator,
    type_id_to_channel_id: BTreeMap<TypeId, u32>,
}

impl fmt::Debug for DrdynvcServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DrdynvcServer([")?;

        for (i, (id, channel)) in self.dynamic_channels.into_iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}:{} ({:?})", id, channel.processor.channel_name(), channel.state)?;
        }

        write!(f, "])")
    }
}

impl DrdynvcServer {
    pub const NAME: ChannelName = ChannelName::from_static(b"drdynvc\0");

    pub fn new() -> Self {
        Self {
            dynamic_channels: DynamicChannelAllocator::new(),
            type_id_to_channel_id: BTreeMap::new(),
        }
    }

    pub fn get_channel_id_by_type<T>(&self) -> Option<u32>
    where
        T: DvcServerProcessor + 'static,
    {
        self.type_id_to_channel_id.get(&TypeId::of::<T>()).copied()
    }

    /// Returns `true` if the DVC channel with the given ID has completed
    /// its creation handshake and is in the `Opened` state.
    pub fn is_channel_opened(&self, channel_id: u32) -> bool {
        self.dynamic_channels
            .get(channel_id)
            .is_some_and(|c| c.state == ChannelState::Opened)
    }

    /// Registers a dynamic channel with the server.
    ///
    /// # Panics
    ///
    /// Panics if the number of registered dynamic channels reaches `u32::MAX`.
    #[must_use]
    pub fn with_dynamic_channel<T>(mut self, channel: T) -> Self
    where
        T: DvcServerProcessor + 'static,
    {
        let channel_id = self.dynamic_channels.insert_channel(channel, ChannelState::Pending);
        self.type_id_to_channel_id.insert(TypeId::of::<T>(), channel_id);
        self
    }

    fn channel_by_id(&mut self, id: u32) -> DecodeResult<&mut DynamicChannel> {
        self.dynamic_channels
            .get_mut(id)
            .ok_or_else(|| invalid_field_err!("DRDYNVC", "", "invalid channel id"))
    }

    pub fn dvc_by_id<T: DvcServerProcessor>(&self, id: u32) -> Option<DynamicChannelRef<'_, T>> {
        let channel = self.dynamic_channels.get(id)?;
        if channel.state != ChannelState::Opened {
            return None;
        }
        channel
            .processor
            .as_any()
            .downcast_ref()
            .map(|p| DynamicChannelRef::new(id, p))
    }

    pub fn dvc_by_id_mut<T: DvcServerProcessor>(&mut self, id: u32) -> Option<DynamicChannelMut<'_, T>> {
        let channel = self.dynamic_channels.get_mut(id)?;
        if channel.state != ChannelState::Opened {
            return None;
        }
        channel
            .processor
            .as_any_mut()
            .downcast_mut()
            .map(|p| DynamicChannelMut::new(id, p))
    }

    /// Creates a new DVC, returns CreateRequest PDU to send to client.
    ///
    /// # Panics
    ///
    /// Panics if the number of registered dynamic channels reaches `u32::MAX`.
    pub fn create_channel<T>(&mut self, channel: T) -> PduResult<SvcMessage>
    where
        T: DvcServerProcessor + 'static,
    {
        let channel_name = channel.channel_name().into();

        let channel_id = self.dynamic_channels.insert_channel(channel, ChannelState::Creation);
        let req = DrdynvcServerPdu::Create(CreateRequestPdu::new(channel_id, channel_name));
        as_svc_msg_with_flag(req)
    }

    fn remove_by_channel_id(&mut self, id: u32) -> Option<DynamicChannel> {
        self.dynamic_channels.remove(id).inspect(|dvc| {
            let type_id = dvc.processor_type_id();

            // Only matters for pre-registered channels
            if let alloc::collections::btree_map::Entry::Occupied(entry) = self.type_id_to_channel_id.entry(type_id)
                && entry.get() == &id
            {
                entry.remove();
            }
        })
    }

    pub fn close_channel(&mut self, channel_id: u32) -> Option<SvcMessage> {
        self.remove_by_channel_id(channel_id)?;
        Some(
            SvcMessage::from(DrdynvcServerPdu::Close(ClosePdu::new(channel_id)))
                .with_flags(ChannelFlags::SHOW_PROTOCOL),
        )
    }
}

impl_as_any!(DrdynvcServer);

impl Default for DrdynvcServer {
    fn default() -> Self {
        Self::new()
    }
}

impl SvcProcessor for DrdynvcServer {
    fn channel_name(&self) -> ChannelName {
        DrdynvcServer::NAME
    }

    fn compression_condition(&self) -> CompressionCondition {
        CompressionCondition::WhenRdpDataIsCompressed
    }

    fn start(&mut self) -> PduResult<Vec<SvcMessage>> {
        let cap = CapabilitiesRequestPdu::new(CapsVersion::V2, None);
        let req = DrdynvcServerPdu::Capabilities(cap);
        let msg = as_svc_msg_with_flag(req)?;
        Ok(alloc::vec![msg])
    }

    fn process(&mut self, payload: &[u8]) -> PduResult<Vec<SvcMessage>> {
        let pdu = decode_dvc_message(payload).map_err(|e| decode_err!(e))?;
        let mut resp = Vec::new();

        match pdu {
            DrdynvcClientPdu::Capabilities(caps_resp) => {
                debug!("Got DVC Capabilities Response PDU: {caps_resp:?}");
                for (id, c) in &mut self.dynamic_channels {
                    if c.state != ChannelState::Pending {
                        continue;
                    }
                    let req = DrdynvcServerPdu::Create(CreateRequestPdu::new(*id, c.processor.channel_name().into()));
                    c.state = ChannelState::Creation;
                    resp.push(as_svc_msg_with_flag(req)?);
                }
            }
            DrdynvcClientPdu::Create(create_resp) => {
                debug!("Got DVC Create Response PDU: {create_resp:?}");
                let id = create_resp.channel_id();
                let c = self.channel_by_id(id).map_err(|e| decode_err!(e))?;
                if c.state != ChannelState::Creation {
                    return Err(pdu_other_err!("invalid channel state"));
                }
                if create_resp.creation_status() != CreationStatus::OK {
                    c.state = ChannelState::CreationFailed(create_resp.creation_status().into());
                    return Ok(resp);
                }
                c.state = ChannelState::Opened;
                let msg = c.processor.start(create_resp.channel_id())?;
                resp.extend(encode_dvc_messages(id, msg, ChannelFlags::SHOW_PROTOCOL).map_err(|e| encode_err!(e))?);
            }
            DrdynvcClientPdu::Close(close) => {
                debug!("Got DVC Close PDU: {close:?}");
                let channel_id = close.channel_id();
                self.remove_by_channel_id(channel_id);
            }
            DrdynvcClientPdu::Data(data) => {
                let channel_id = data.channel_id();
                let c = self.channel_by_id(channel_id).map_err(|e| decode_err!(e))?;
                if c.state != ChannelState::Opened {
                    debug!(?channel_id, ?c.state, "Invalid channel state");
                    return Err(pdu_other_err!("invalid channel state"));
                }
                if let Some(complete) = c.complete_data.process_data(data).map_err(|e| decode_err!(e))? {
                    let msg = c.processor.process(channel_id, &complete)?;
                    resp.extend(
                        encode_dvc_messages(channel_id, msg, ChannelFlags::SHOW_PROTOCOL)
                            .map_err(|e| encode_err!(e))?,
                    );
                }
            }
        }

        Ok(resp)
    }
}

impl SvcServerProcessor for DrdynvcServer {}

fn decode_dvc_message(user_data: &[u8]) -> DecodeResult<DrdynvcClientPdu> {
    DrdynvcClientPdu::decode(&mut ReadCursor::new(user_data))
}

fn as_svc_msg_with_flag(pdu: DrdynvcServerPdu) -> PduResult<SvcMessage> {
    Ok(SvcMessage::from(pdu).with_flags(ChannelFlags::SHOW_PROTOCOL))
}
