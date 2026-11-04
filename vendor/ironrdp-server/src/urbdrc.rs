use core::pin::Pin;
use core::sync::atomic::{AtomicU8, Ordering};
use core::task::{Context, Poll};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use crate::ServerEvent;
use crate::error::{ServerError, ServerErrorExt as _, ServerResult};
use ironrdp_dvc::DynamicChannelId;
use ironrdp_pdu::PduResult;
use ironrdp_rdpeusb::{
    io::{
        CompletionData, DeviceAnnounce, DeviceText, InternalIoControlPacket, IoControlCompletionResult,
        IoControlPacket, RequestId, TransferInCompletionResult, TransferInPacket, TransferOutCompletionResult,
        TransferOutPacket, UsbRetractReason,
    },
    pdu::{
        completion::ts_urb_result::{TsUrbSelectConfigResult, TsUrbSelectInterfaceResult, TsUsbdInterfaceInfoResult},
        utils::{ConfigHandle, PipeHandle},
    },
    server::{UrbdrcControlServerBackend, UrbdrcDeviceServerBackend},
};
use ironrdp_usb::{
    InterfaceSelection, TransferType,
    control::GetDescriptorRequest,
    descriptor::{ConfigurationDescriptorSet, InterfaceDescriptor, ValidConfigurationDescriptorSet},
    endpoint::EndpointAddress,
    transfer::{
        BulkTransferRequest, ControlTransferRequest, FrameNumber, InterruptTransferRequest, IsoCompletion,
        IsochronousPacketCompletion, IsochronousTransferRequest, TransferCompletion, UsbResult,
    },
};
use tokio::sync::oneshot::error::TryRecvError;
use tokio::sync::{mpsc::UnboundedSender, oneshot};

#[derive(Debug)]
pub enum UrbdrcServerMessage {
    AddChan,
    Device {
        dvc_id: u32,
        dev_msg: UrbdrcDeviceServerMessage,
    },
    DeviceClosed {
        dvc_id: DynamicChannelId,
    },
}

#[derive(Debug)]
pub enum UrbdrcDeviceServerMessage {
    QueryDeviceText {
        text_type: u32,
        locale_id: u32,
    },
    IoReq {
        data: ServerDeviceIoReq,
        /// Sender used to return the pending request once it is registered,
        /// before the request is written. `None` when the request expects no
        /// completion.
        tx: oneshot::Sender<Option<PendingIo>>,
    },
    CancelRequest(RequestId),
    Retract(UsbRetractReason),
}

/// Server-to-client USB I/O request data.
#[derive(Debug)]
pub enum ServerDeviceIoReq {
    IoControl(IoControlPacket),
    InternalIoControl(InternalIoControlPacket),
    TransferIn(TransferInPacket),
    TransferOut(TransferOutPacket),
}

/// Creates per-device URBDRC backends.
pub trait DeviceFactory {
    /// Creates the [UrbdrcDeviceServerBackend] for a newly opened device channel.
    fn create_device(&mut self) -> Option<Box<dyn UsbRedirDevice>>;
}

#[derive(Debug, Clone)]
pub(crate) struct UsbControlHandle {
    event_sender: UnboundedSender<ServerEvent>,
}

impl UsbControlHandle {
    pub(crate) fn new(event_sender: UnboundedSender<ServerEvent>) -> Self {
        Self { event_sender }
    }
}

impl UrbdrcControlServerBackend for UsbControlHandle {
    fn create_device_chan(&mut self) -> PduResult<()> {
        let _ = self.event_sender.send(ServerEvent::Usb(UrbdrcServerMessage::AddChan));
        Ok(())
    }
}

/// Handle used by a device backend to send server-to-client requests.
#[derive(Debug, Clone)]
pub struct UsbDeviceHandle {
    sender: UnboundedSender<ServerEvent>,
    device: Arc<ServerUsbDevice>,
}

impl UsbDeviceHandle {
    pub(crate) fn new(sender: UnboundedSender<ServerEvent>, channel_id: DynamicChannelId) -> Self {
        Self {
            sender,
            device: Arc::new(ServerUsbDevice::new(channel_id)),
        }
    }

    /// Per-device state, shared with the server event loop's request router.
    pub(crate) fn device(&self) -> Arc<ServerUsbDevice> {
        Arc::clone(&self.device)
    }

    fn send_device_message(&self, dev_msg: UrbdrcDeviceServerMessage) -> ServerResult<()> {
        self.sender
            .send(ServerEvent::Usb(UrbdrcServerMessage::Device {
                dvc_id: self.device.channel_id,
                dev_msg,
            }))
            .map_err(|_error| ServerError::reason("usb device message", "usb device channel is closing or closed"))
    }

    fn enqueue_io_message(&self, data: ServerDeviceIoReq) -> ServerResult<oneshot::Receiver<Option<PendingIo>>> {
        self.ensure_open()?;

        let (tx, rx) = oneshot::channel();
        self.send_device_message(UrbdrcDeviceServerMessage::IoReq { data, tx })?;

        Ok(rx)
    }

    /// Resolves the server's submission reply into pending-request metadata.
    async fn resolve_pending(&self, rx: oneshot::Receiver<Option<PendingIo>>) -> ServerResult<RawPending> {
        match rx.await {
            Ok(Some(pending)) => Ok(RawPending::new(self.clone(), pending)),
            // The public facade only submits acknowledged requests, so a
            // completion-less (NoAck) reply is an internal contract violation.
            Ok(None) => Err(ServerError::reason(
                "usb pending request",
                "usb request unexpectedly has no pending completion",
            )),
            Err(_) => Err(ServerError::reason(
                "usb pending request",
                "usb device channel is closing or closed",
            )),
        }
    }

    async fn send_io_message(&self, data: ServerDeviceIoReq) -> ServerResult<RawPending> {
        let rx = self.enqueue_io_message(data)?;
        self.resolve_pending(rx).await
    }

    /// Sends a transfer-in request and returns its request metadata once registered.
    async fn transfer_in_request(&self, packet: TransferInPacket) -> ServerResult<RawPending> {
        self.send_io_message(ServerDeviceIoReq::TransferIn(packet)).await
    }

    /// Sends a transfer-out request and returns its request metadata once registered.
    async fn transfer_out_request(&self, packet: TransferOutPacket) -> ServerResult<RawPending> {
        self.send_io_message(ServerDeviceIoReq::TransferOut(packet)).await
    }

    /// Sends a cancel request for a pending I/O request.
    pub(crate) fn cancel_request(&self, request_id: RequestId) -> ServerResult<()> {
        if !self.device.is_open() {
            return Ok(());
        }

        self.send_device_message(UrbdrcDeviceServerMessage::CancelRequest(request_id))
    }

    /// Sends a query-device-text request.
    pub fn query_device_text_request(&self, text_type: u32, locale_id: u32) -> ServerResult<()> {
        self.ensure_open()?;
        self.send_device_message(UrbdrcDeviceServerMessage::QueryDeviceText { text_type, locale_id })
    }

    /// Sends a device-retract request.
    pub fn retract_request(&self, reason: UsbRetractReason) -> ServerResult<()> {
        self.ensure_open()?;
        self.send_device_message(UrbdrcDeviceServerMessage::Retract(reason))
    }

    fn ensure_open(&self) -> ServerResult<()> {
        if self.device.is_open() {
            Ok(())
        } else {
            Err(ServerError::reason(
                "usb device message",
                "usb device channel is closing or closed",
            ))
        }
    }

    /// Submits a transfer on the default control pipe.
    ///
    /// The completion is [`UsbRequestCompletion::Transfer`].
    pub async fn control_transfer(&self, request: ControlTransferRequest<Vec<u8>>) -> ServerResult<PendingRequest> {
        let transfer = ironrdp_rdpeusb::usb::control_transfer(request.setup, request.data)
            .map_err(|e| ServerError::custom("failed to translate usb control transfer", e))?;
        let inner = match transfer {
            ironrdp_rdpeusb::usb::TransferRequest::In(packet) => self.transfer_in_request(packet).await?,
            ironrdp_rdpeusb::usb::TransferRequest::Out(packet) => self.transfer_out_request(packet).await?,
        };

        Ok(PendingRequest::new(inner, PendingOperation::Transfer))
    }

    /// Submits a bulk transfer on an endpoint in the active configuration.
    ///
    /// The completion is [`UsbRequestCompletion::Transfer`].
    pub async fn bulk_transfer(&self, request: BulkTransferRequest<Vec<u8>>) -> ServerResult<PendingRequest> {
        self.submit_data_transfer(request, TransferType::Bulk).await
    }

    /// Submits an interrupt transfer on an endpoint in the active configuration.
    ///
    /// The completion is [`UsbRequestCompletion::Transfer`].
    pub async fn interrupt_transfer(&self, request: InterruptTransferRequest<Vec<u8>>) -> ServerResult<PendingRequest> {
        self.submit_data_transfer(request, TransferType::Interrupt).await
    }

    /// Submits an isochronous transfer.
    ///
    /// The completion is [`UsbRequestCompletion::Isochronous`].
    pub async fn isochronous_transfer(
        &self,
        request: IsochronousTransferRequest<Vec<u8>, Vec<u32>>,
    ) -> ServerResult<PendingRequest> {
        let packet_lengths = request.packets.clone();
        let rx = {
            let state = self.lock_usb_state();
            let pipe = state.resolve_pipe(request.endpoint)?;
            if pipe.transfer_type != TransferType::Isochronous {
                return Err(ServerError::reason(
                    "usb isochronous transfer",
                    "usb endpoint is not isochronous",
                ));
            }
            let transfer = ironrdp_rdpeusb::usb::isochronous(pipe.handle, request, false)
                .map_err(|e| ServerError::custom("failed to translate usb isochronous transfer", e))?;
            let data = match transfer {
                ironrdp_rdpeusb::usb::TransferRequest::In(packet) => ServerDeviceIoReq::TransferIn(packet),
                ironrdp_rdpeusb::usb::TransferRequest::Out(packet) => ServerDeviceIoReq::TransferOut(packet),
            };
            self.enqueue_io_message(data)?
        };
        let inner = self.resolve_pending(rx).await?;

        Ok(PendingRequest::new(
            inner,
            PendingOperation::Isochronous { packet_lengths },
        ))
    }

    /// Submits a standard USB `GET_DESCRIPTOR` request.
    ///
    /// The completion is [`UsbRequestCompletion::Descriptor`].
    pub async fn get_descriptor(&self, request: GetDescriptorRequest) -> ServerResult<PendingRequest> {
        let packet = ironrdp_rdpeusb::usb::get_descriptor(request)
            .map_err(|e| ServerError::custom("failed to translate usb get descriptor", e))?;
        let inner = self.transfer_in_request(packet).await?;

        Ok(PendingRequest::new(inner, PendingOperation::GetDescriptor))
    }

    /// Queries the active USB configuration value.
    ///
    /// The completion is [`UsbRequestCompletion::Value`].
    pub async fn get_configuration(&self) -> ServerResult<PendingRequest> {
        let packet = ironrdp_rdpeusb::usb::get_configuration();
        let inner = self.transfer_in_request(packet).await?;
        Ok(PendingRequest::new(inner, PendingOperation::GetConfiguration))
    }

    /// Selects a USB configuration described by `descriptor`.
    ///
    /// `None` selects configuration zero. `Some` selects the descriptor's
    /// `bConfigurationValue`, with alternate setting zero for every interface.
    /// The descriptor is validated and used only to build the RDPEUSB request
    /// and validate its completion; it is not retained by the handle.
    ///
    /// The completion is [`UsbRequestCompletion::Unit`].
    pub async fn select_configuration(
        &self,
        descriptor: Option<ConfigurationDescriptorSet<'_>>,
    ) -> ServerResult<PendingRequest> {
        // Validation, translation, and plan construction depend only on the
        // caller's descriptor and the immutable announced speed, so they are
        // deliberately kept outside the state critical section.
        let (packet, plan) = match descriptor {
            // Unconfiguring does not depend on the announced device speed.
            None => (
                ironrdp_rdpeusb::usb::unconfigure(),
                ConfigurationSelectionPlan::Unconfigure,
            ),
            Some(descriptor) => {
                let descriptor = descriptor
                    .validate()
                    .map_err(|e| ServerError::custom("invalid usb configuration selection descriptor", e))?;
                let active_interfaces: Vec<InterfaceSelection> = descriptor
                    .as_set()
                    .default_interfaces()
                    .map(|interface| InterfaceSelection {
                        interface: interface.number(),
                        alternate_setting: interface.alternate_setting(),
                    })
                    .collect();
                let packet = ironrdp_rdpeusb::usb::select_configuration(descriptor, &active_interfaces)
                    .map_err(|e| ServerError::custom("failed to translate usb configuration selection", e))?;
                let plan = ConfigurationSelectionPlan::Configure {
                    descriptor: descriptor.as_set().as_bytes().to_vec(),
                    active_interfaces,
                };
                (packet, plan)
            }
        };

        let (rx, transition) = {
            let mut state = self.lock_usb_state();
            let transition = state.reserve_transition(StatefulTransitionKind::SelectConfiguration)?;
            let rx = self.enqueue_io_message(ServerDeviceIoReq::TransferIn(packet))?;
            state.activate_configuration_transition(transition);
            (rx, transition)
        };

        let submission = TransitionGuard::poison_on_drop(self, transition);
        let inner = self.resolve_pending(rx).await?;
        submission.disarm();
        Ok(PendingRequest::new(
            inner,
            PendingOperation::SelectConfiguration { transition, plan },
        ))
    }

    /// Queries the active alternate setting for an interface.
    ///
    /// The completion is [`UsbRequestCompletion::Value`].
    pub async fn get_interface(&self, interface: u8) -> ServerResult<PendingRequest> {
        let packet = ironrdp_rdpeusb::usb::get_interface(interface);
        let inner = self.transfer_in_request(packet).await?;
        Ok(PendingRequest::new(inner, PendingOperation::GetInterface))
    }

    /// Selects an alternate setting for an interface.
    ///
    /// `descriptor` must describe the active configuration. It is validated
    /// and used only to build the RDPEUSB request and validate its completion;
    /// it is not retained by the handle.
    ///
    /// The completion is [`UsbRequestCompletion::Unit`].
    pub async fn select_interface(
        &self,
        descriptor: ConfigurationDescriptorSet<'_>,
        selection: InterfaceSelection,
    ) -> ServerResult<PendingRequest> {
        // Descriptor validation is state-independent and deliberately kept
        // outside the state critical section.
        let descriptor = descriptor
            .validate()
            .map_err(|e| ServerError::custom("invalid usb interface selection descriptor", e))?;

        let (rx, transition) = {
            let mut state = self.lock_usb_state();
            let config_handle = state.interface_plan(descriptor, selection)?;
            let transition = state.reserve_transition(StatefulTransitionKind::SelectInterface {
                interface: selection.interface,
            })?;
            let packet = ironrdp_rdpeusb::usb::select_interface(config_handle, descriptor, selection)
                .map_err(|e| ServerError::custom("failed to translate usb interface selection", e))?;
            let rx = self.enqueue_io_message(ServerDeviceIoReq::TransferIn(packet))?;
            if let Err(error) = state.activate_interface_transition(transition, selection.interface) {
                state.binding = BindingState::Unknown;
                state.transition = TransitionState::Poisoned;
                return Err(error);
            }
            (rx, transition)
        };
        // The plan is only read at completion time; the descriptor copy is
        // deliberately made outside the critical section.
        let plan = InterfaceSelectionPlan {
            selection,
            descriptor: descriptor.as_set().as_bytes().to_vec(),
        };

        let submission = TransitionGuard::poison_on_drop(self, transition);
        let inner = self.resolve_pending(rx).await?;
        submission.disarm();
        Ok(PendingRequest::new(
            inner,
            PendingOperation::SelectInterface { transition, plan },
        ))
    }

    /// Clears an endpoint halt and resets its pipe state.
    ///
    /// The endpoint may use any transfer type: Windows
    /// `SYNC_RESET_PIPE_AND_CLEAR_STALL` applies to every non-default pipe.
    ///
    /// The completion is [`UsbRequestCompletion::Unit`].
    pub async fn clear_halt(&self, endpoint: EndpointAddress) -> ServerResult<PendingRequest> {
        let rx = {
            let state = self.lock_usb_state();
            let pipe = state.resolve_pipe(endpoint)?;
            let packet = ironrdp_rdpeusb::usb::reset_pipe_and_clear_stall(pipe.handle);
            self.enqueue_io_message(ServerDeviceIoReq::TransferIn(packet))?
        };
        let inner = self.resolve_pending(rx).await?;
        Ok(PendingRequest::new(inner, PendingOperation::ClearHalt))
    }

    /// Resets the redirected USB device.
    ///
    /// The completion is [`UsbRequestCompletion::Unit`].
    pub async fn reset_device(&self) -> ServerResult<PendingRequest> {
        let (rx, transition, previous_binding) = {
            let mut state = self.lock_usb_state();
            let transition = state.reserve_transition(StatefulTransitionKind::ResetDevice)?;
            let previous_binding = match &state.binding {
                BindingState::Unconfigured | BindingState::Configured(_) => state.binding.clone(),
                BindingState::Unknown => {
                    return Err(ServerError::reason("usb reset device", "usb binding state is unknown"));
                }
            };
            let packet = ironrdp_rdpeusb::usb::reset_device();
            let rx = self.enqueue_io_message(ServerDeviceIoReq::IoControl(packet))?;
            state.binding = BindingState::Unknown;
            state.transition = TransitionState::InFlight(transition);
            (rx, transition, previous_binding)
        };

        let submission = TransitionGuard::poison_on_drop(self, transition);
        let inner = self.resolve_pending(rx).await?;
        submission.disarm();
        Ok(PendingRequest::new(
            inner,
            PendingOperation::ResetDevice {
                transition,
                previous_binding,
            },
        ))
    }

    /// Queries the host controller's current USB frame number.
    ///
    /// The completion is [`UsbRequestCompletion::FrameNumber`].
    pub async fn current_frame_number(&self) -> ServerResult<PendingRequest> {
        let packet = ironrdp_rdpeusb::usb::current_frame_number();
        let inner = self.transfer_in_request(packet).await?;
        Ok(PendingRequest::new(inner, PendingOperation::CurrentFrameNumber))
    }

    async fn submit_data_transfer(
        &self,
        request: BulkTransferRequest<Vec<u8>>,
        expected_type: TransferType,
    ) -> ServerResult<PendingRequest> {
        let rx = {
            let state = self.lock_usb_state();
            let pipe = state.resolve_pipe(request.endpoint)?;
            if pipe.transfer_type != expected_type {
                return Err(ServerError::reason(
                    "usb data transfer",
                    format!(
                        "usb endpoint {:#04x} is {:?}, not {:?}",
                        request.endpoint.raw(),
                        pipe.transfer_type,
                        expected_type
                    ),
                ));
            }
            let transfer = ironrdp_rdpeusb::usb::bulk_or_interrupt(pipe.handle, request)
                .map_err(|e| ServerError::custom("failed to translate usb data transfer", e))?;
            let data = match transfer {
                ironrdp_rdpeusb::usb::TransferRequest::In(packet) => ServerDeviceIoReq::TransferIn(packet),
                ironrdp_rdpeusb::usb::TransferRequest::Out(packet) => ServerDeviceIoReq::TransferOut(packet),
            };
            self.enqueue_io_message(data)?
        };
        let inner = self.resolve_pending(rx).await?;
        Ok(PendingRequest::new(inner, PendingOperation::Transfer))
    }

    fn lock_usb_state(&self) -> MutexGuard<'_, UsbSharedState> {
        self.device.usb_state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// INVARIANT: `pending` and `usb_state` are never locked at the same time.
/// Completion delivery releases the `pending` guard before the woken caller
/// commits binding state under `usb_state`.
#[derive(Debug)]
pub(crate) struct ServerUsbDevice {
    channel_id: DynamicChannelId,
    /// Kept outside a lock: submission paths check it constantly and
    /// [`RawPending::drop`] reads it, so it must never require one.
    lifecycle: UsbDeviceLifecycle,
    pending: Mutex<HashMap<RequestId, oneshot::Sender<CompletionData>>>,
    usb_state: Mutex<UsbSharedState>,
}

impl ServerUsbDevice {
    fn new(channel_id: DynamicChannelId) -> Self {
        Self {
            channel_id,
            lifecycle: UsbDeviceLifecycle::new(),
            pending: Mutex::new(HashMap::new()),
            usb_state: Mutex::new(UsbSharedState::default()),
        }
    }

    pub(crate) fn is_open(&self) -> bool {
        self.lifecycle.is_open()
    }

    pub(crate) fn mark_retracting(&self) {
        self.lifecycle.mark_retracting();
    }

    pub(crate) fn mark_closed(&self) {
        self.lifecycle.mark_closed();
    }

    pub(crate) fn register_pending(&self, request_id: RequestId) -> PendingIo {
        let (tx, rx) = oneshot::channel();
        if self
            .pending
            .lock()
            .expect("USB pending requests mutex poisoned")
            .insert(request_id, tx)
            .is_some()
        {
            tracing::warn!(
                dvc_id = self.channel_id,
                request_id,
                "Replacing pending USB I/O request"
            );
        }

        PendingIo { rx, id: request_id }
    }

    /// Delivers a completion to the caller waiting on `request_id`.
    ///
    /// Completions are refused once the device is retracting or closed, matching
    /// the check the event loop applies to every other device message. The
    /// RDPEUSB processor already stops reporting completions after
    /// RETRACT_DEVICE, so this only keeps the guarantee local rather than
    /// resting on that behavior.
    pub(crate) fn complete_pending(&self, request_id: RequestId, completion: CompletionData) {
        if !self.is_open() {
            tracing::trace!(
                dvc_id = self.channel_id,
                request_id,
                "Dropping completion for closing or closed USB device"
            );
            return;
        }

        // Bind the removal so the guard is released before the caller is woken:
        // it commits binding state under `usb_state`, and the two locks are
        // never held together.
        let sender = self
            .pending
            .lock()
            .expect("USB pending requests mutex poisoned")
            .remove(&request_id);

        let Some(sender) = sender else {
            tracing::warn!(dvc_id = self.channel_id, request_id, "Missing pending USB I/O request");
            return;
        };

        if sender.send(completion).is_err() {
            tracing::trace!(
                dvc_id = self.channel_id,
                request_id,
                "USB I/O completion receiver dropped"
            );
        }
    }

    /// Drops the tracking for a request that was never written to the channel.
    ///
    /// Pairs with `UrbdrcDeviceServer::abandon_unsent`: no completion will
    /// arrive for such a request, so nothing else would ever remove it.
    pub(crate) fn forget_pending(&self, request_id: RequestId) {
        self.pending
            .lock()
            .expect("USB pending requests mutex poisoned")
            .remove(&request_id);
    }

    pub(crate) fn is_pending(&self, request_id: RequestId) -> bool {
        self.pending
            .lock()
            .expect("USB pending requests mutex poisoned")
            .contains_key(&request_id)
    }

    /// Fails every request still awaiting a completion, returning how many there
    /// were. Dropping the senders wakes each caller with a channel error.
    ///
    /// The pending map outlives the router entry that used to own it, so every
    /// teardown path MUST call this or its callers wait forever.
    pub(crate) fn drain_pending(&self) -> usize {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        let count = pending.len();
        pending.clear();
        count
    }
}

#[derive(Debug)]
struct UsbSharedState {
    binding: BindingState,
    transition: TransitionState,
    next_generation: u64,
}

impl Default for UsbSharedState {
    fn default() -> Self {
        Self {
            binding: BindingState::Unconfigured,
            transition: TransitionState::Idle,
            next_generation: 0,
        }
    }
}

#[derive(Debug, Clone)]
enum BindingState {
    Unconfigured,
    Configured(ConfigurationBinding),
    /// A state-changing request may have invalidated every opaque handle.
    Unknown,
}

#[derive(Debug, Clone)]
struct ConfigurationBinding {
    configuration_value: u8,
    config_handle: ConfigHandle,
    interfaces: BTreeMap<u8, InterfaceBindingState>,
}

#[derive(Debug, Clone)]
enum InterfaceBindingState {
    Bound(InterfaceBinding),
    /// The configuration handle remains usable, but this interface's prior
    /// pipe handles must not be reused.
    Unknown,
}

#[derive(Debug, Clone)]
struct InterfaceBinding {
    alternate_setting: u8,
    pipes: BTreeMap<EndpointAddress, PipeBinding>,
}

#[derive(Debug, Clone, Copy)]
struct PipeBinding {
    handle: PipeHandle,
    transfer_type: TransferType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StatefulTransition {
    generation: u64,
    kind: StatefulTransitionKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatefulTransitionKind {
    SelectConfiguration,
    SelectInterface { interface: u8 },
    ResetDevice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransitionState {
    Idle,
    InFlight(StatefulTransition),
    /// The request was submitted but no terminal completion was observed.
    /// CANCEL_REQUEST has no acknowledgement fence, so another state-changing
    /// request cannot safely recover this channel.
    Poisoned,
}

#[derive(Debug)]
enum ConfigurationSelectionPlan {
    Unconfigure,
    Configure {
        descriptor: Vec<u8>,
        active_interfaces: Vec<InterfaceSelection>,
    },
}

#[derive(Debug)]
struct InterfaceSelectionPlan {
    selection: InterfaceSelection,
    descriptor: Vec<u8>,
}

impl UsbSharedState {
    fn reserve_transition(&mut self, kind: StatefulTransitionKind) -> ServerResult<StatefulTransition> {
        match self.transition {
            TransitionState::Idle => {}
            TransitionState::InFlight(_) => {
                return Err(ServerError::reason(
                    "usb state transition",
                    "another usb state transition is in progress",
                ));
            }
            TransitionState::Poisoned => {
                return Err(ServerError::reason(
                    "usb state transition",
                    "usb binding state is indeterminate after an abandoned transition",
                ));
            }
        }

        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or_else(|| ServerError::reason("usb state transition", "usb state transition generation exhausted"))?;
        Ok(StatefulTransition {
            generation: self.next_generation,
            kind,
        })
    }

    fn activate_configuration_transition(&mut self, transition: StatefulTransition) {
        self.binding = BindingState::Unknown;
        self.transition = TransitionState::InFlight(transition);
    }

    fn activate_interface_transition(&mut self, transition: StatefulTransition, interface: u8) -> ServerResult<()> {
        let BindingState::Configured(binding) = &mut self.binding else {
            return Err(ServerError::reason(
                "usb interface transition",
                "usb device is not configured",
            ));
        };
        let interface_binding = binding.interfaces.get_mut(&interface).ok_or_else(|| {
            ServerError::reason(
                "usb interface transition",
                format!("usb interface {interface} is not active"),
            )
        })?;
        *interface_binding = InterfaceBindingState::Unknown;
        self.transition = TransitionState::InFlight(transition);
        Ok(())
    }

    /// Returns a failed in-flight transition to idle.
    ///
    /// A transition that is no longer current is left untouched, so the caller
    /// can report the original failure without a bookkeeping error masking it.
    fn finish_failed_transition(&mut self, transition: StatefulTransition) {
        if self.transition == TransitionState::InFlight(transition) {
            self.transition = TransitionState::Idle;
        }
    }

    fn poison_transition(&mut self, transition: StatefulTransition) {
        if self.transition == TransitionState::InFlight(transition) {
            self.transition = TransitionState::Poisoned;
        }
    }

    /// Looks up the active pipe binding for `endpoint`.
    fn resolve_pipe(&self, endpoint: EndpointAddress) -> ServerResult<PipeBinding> {
        if endpoint.is_default_control() {
            return Err(ServerError::reason("usb pipe", "usb endpoint zero is not a data pipe"));
        }
        let BindingState::Configured(binding) = &self.binding else {
            return Err(ServerError::reason(
                "usb pipe",
                "usb device has no usable configuration binding",
            ));
        };

        let mut found = None;
        for interface in binding.interfaces.values() {
            let InterfaceBindingState::Bound(interface) = interface else {
                continue;
            };
            let Some(pipe) = interface.pipes.get(&endpoint) else {
                continue;
            };
            if found.replace(*pipe).is_some() {
                return Err(ServerError::reason(
                    "usb pipe",
                    format!("usb endpoint {:#04x} has multiple active pipe bindings", endpoint.raw()),
                ));
            }
        }

        found.ok_or_else(|| {
            ServerError::reason(
                "usb pipe",
                format!("usb endpoint {:#04x} has no active pipe binding", endpoint.raw()),
            )
        })
    }

    /// Validates `selection` against the active binding and returns the
    /// configuration handle.
    fn interface_plan(
        &self,
        descriptor: ValidConfigurationDescriptorSet<'_>,
        selection: InterfaceSelection,
    ) -> ServerResult<ConfigHandle> {
        let BindingState::Configured(binding) = &self.binding else {
            return Err(ServerError::reason(
                "usb interface plan",
                "usb device is not configured",
            ));
        };
        if !binding.interfaces.contains_key(&selection.interface) {
            return Err(ServerError::reason(
                "usb interface plan",
                format!("usb interface {} is not active", selection.interface),
            ));
        }
        if descriptor.as_set().configuration().configuration_value() != binding.configuration_value {
            return Err(ServerError::reason(
                "usb interface plan",
                "descriptor is not the active usb configuration",
            ));
        }
        for (&interface_number, interface_binding) in &binding.interfaces {
            let InterfaceBindingState::Bound(interface_binding) = interface_binding else {
                continue;
            };
            if descriptor
                .as_set()
                .interface(interface_number, interface_binding.alternate_setting)
                .is_none()
            {
                return Err(ServerError::reason(
                    "usb interface plan",
                    "active usb interface binding does not match its descriptor",
                ));
            }
        }
        descriptor
            .as_set()
            .interface(selection.interface, selection.alternate_setting)
            .ok_or_else(|| {
                ServerError::reason(
                    "usb interface plan",
                    format!(
                        "usb interface {} has no alternate setting {}",
                        selection.interface, selection.alternate_setting
                    ),
                )
            })?;

        Ok(binding.config_handle)
    }

    fn ensure_current(&self, transition: StatefulTransition) -> ServerResult<()> {
        if self.transition != TransitionState::InFlight(transition) {
            return Err(ServerError::reason(
                "usb transition",
                "usb transition is no longer current",
            ));
        }
        Ok(())
    }

    // The commit methods below poison an in-flight transition themselves when
    // its expected binding shape has been lost: without an acknowledgement
    // fence for CANCEL_REQUEST the binding cannot be recovered, so the channel
    // must fail closed.

    /// Commits a whole-device binding change (configuration selection or
    /// device reset).
    fn commit_binding(&mut self, transition: StatefulTransition, binding: BindingState) -> ServerResult<()> {
        self.ensure_current(transition)?;
        if !matches!(self.binding, BindingState::Unknown) {
            self.transition = TransitionState::Poisoned;
            return Err(ServerError::reason(
                "usb binding commit",
                "usb binding changed during the transition",
            ));
        }
        self.binding = binding;
        self.transition = TransitionState::Idle;
        Ok(())
    }

    fn commit_interface(
        &mut self,
        transition: StatefulTransition,
        interface_number: u8,
        interface: InterfaceBinding,
    ) -> ServerResult<()> {
        self.ensure_current(transition)?;
        let BindingState::Configured(binding) = &mut self.binding else {
            self.transition = TransitionState::Poisoned;
            return Err(ServerError::reason(
                "usb interface commit",
                "usb configuration binding disappeared during interface selection",
            ));
        };
        if !matches!(
            binding.interfaces.get(&interface_number),
            Some(InterfaceBindingState::Unknown)
        ) {
            self.transition = TransitionState::Poisoned;
            return Err(ServerError::reason(
                "usb interface commit",
                "usb interface binding is no longer current",
            ));
        }
        binding
            .interfaces
            .insert(interface_number, InterfaceBindingState::Bound(interface));
        self.transition = TransitionState::Idle;
        Ok(())
    }
}

/// Drop guard for a stateful transition still owned by an in-progress
/// operation.
///
/// Unless disarmed, dropping the guard applies its exit state to a
/// still-current transition: [`Self::poison_on_drop`] fails the channel closed
/// when a submitted request loses its wait path, while [`Self::finish_on_drop`]
/// returns the transition to idle on completion paths that did not commit.
struct TransitionGuard<'a> {
    handle: &'a UsbDeviceHandle,
    transition: StatefulTransition,
    poison: bool,
}

impl<'a> TransitionGuard<'a> {
    fn poison_on_drop(handle: &'a UsbDeviceHandle, transition: StatefulTransition) -> Self {
        Self {
            handle,
            transition,
            poison: true,
        }
    }

    fn finish_on_drop(handle: &'a UsbDeviceHandle, transition: StatefulTransition) -> Self {
        Self {
            handle,
            transition,
            poison: false,
        }
    }

    /// Hands transition bookkeeping over to the caller.
    #[expect(
        clippy::mem_forget,
        reason = "the guard owns nothing to leak; skipping its drop glue is the hand-off"
    )]
    fn disarm(self) {
        core::mem::forget(self);
    }
}

impl Drop for TransitionGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.handle.lock_usb_state();
        if self.poison {
            state.poison_transition(self.transition);
        } else {
            state.finish_failed_transition(self.transition);
        }
    }
}

fn configuration_binding_from_result(
    plan: &ConfigurationSelectionPlan,
    result: TsUrbSelectConfigResult,
) -> ServerResult<BindingState> {
    let ConfigurationSelectionPlan::Configure {
        descriptor: descriptor_bytes,
        active_interfaces,
    } = plan
    else {
        if !result.interface.is_empty() {
            return Err(ServerError::reason(
                "usb configuration binding",
                format!("usb unconfigure returned {} interface bindings", result.interface.len()),
            ));
        }
        return Ok(BindingState::Unconfigured);
    };
    // The plan bytes were validated at submission, so a parse failure here is
    // a facade bug rather than caller or client input.
    let descriptor = ConfigurationDescriptorSet::parse(descriptor_bytes)
        .map_err(|e| ServerError::custom("stored usb configuration descriptor", e))?;
    if result.interface.len() != active_interfaces.len() {
        return Err(ServerError::reason(
            "usb configuration binding",
            format!(
                "usb selection result returned {} interfaces, expected {}",
                result.interface.len(),
                active_interfaces.len()
            ),
        ));
    }

    let expected = active_interfaces
        .iter()
        .map(|selection| (selection.interface, *selection))
        .collect::<BTreeMap<_, _>>();
    let mut interfaces = BTreeMap::new();
    for interface_result in result.interface {
        let selection = expected.get(&interface_result.interface_number).ok_or_else(|| {
            ServerError::reason(
                "usb configuration binding",
                format!(
                    "usb selection result returned unexpected interface {}",
                    interface_result.interface_number
                ),
            )
        })?;
        let interface = descriptor
            .interface(selection.interface, selection.alternate_setting)
            .ok_or_else(|| {
                ServerError::reason(
                    "usb configuration binding",
                    "selected usb interface descriptor is absent",
                )
            })?;
        let number = interface_result.interface_number;
        let binding = interface_binding_from_result(interface, interface_result)?;
        if interfaces
            .insert(number, InterfaceBindingState::Bound(binding))
            .is_some()
        {
            return Err(ServerError::reason(
                "usb configuration binding",
                format!("usb selection result returned duplicate interface {number}"),
            ));
        }
    }

    Ok(BindingState::Configured(ConfigurationBinding {
        configuration_value: descriptor.configuration().configuration_value(),
        config_handle: result.config_handle,
        interfaces,
    }))
}

fn interface_binding_from_selection_result(
    plan: &InterfaceSelectionPlan,
    result: TsUrbSelectInterfaceResult,
) -> ServerResult<InterfaceBinding> {
    // The plan bytes and selection were validated at submission.
    let descriptor = ConfigurationDescriptorSet::parse(&plan.descriptor)
        .map_err(|e| ServerError::custom("stored usb configuration descriptor", e))?;
    let interface = descriptor
        .interface(plan.selection.interface, plan.selection.alternate_setting)
        .ok_or_else(|| ServerError::reason("usb interface binding", "selected usb interface descriptor is absent"))?;
    interface_binding_from_result(interface, result.interface)
}

fn interface_binding_from_result(
    descriptor: InterfaceDescriptor<'_>,
    result: TsUsbdInterfaceInfoResult,
) -> ServerResult<InterfaceBinding> {
    if result.interface_number != descriptor.number() || result.alternate_setting != descriptor.alternate_setting() {
        return Err(ServerError::reason(
            "usb interface binding",
            format!(
                "usb selection result identifies interface {} alternate {}, expected interface {} alternate {}",
                result.interface_number,
                result.alternate_setting,
                descriptor.number(),
                descriptor.alternate_setting()
            ),
        ));
    }
    let endpoint_count = descriptor.endpoints().count();
    if result.pipes.len() != endpoint_count {
        return Err(ServerError::reason(
            "usb interface binding",
            format!(
                "usb selection result returned {} pipes, expected {endpoint_count}",
                result.pipes.len()
            ),
        ));
    }

    let mut pipes = BTreeMap::new();
    for result_pipe in result.pipes {
        let endpoint = EndpointAddress::from_raw(result_pipe.endpoint_address)
            .map_err(|e| ServerError::custom("usb selection result contains an invalid endpoint", e))?;
        let endpoint_descriptor = descriptor.endpoint(endpoint).ok_or_else(|| {
            ServerError::reason(
                "usb interface binding",
                format!(
                    "usb selection result returned unexpected endpoint {:#04x}",
                    endpoint.raw()
                ),
            )
        })?;
        if pipes
            .insert(
                endpoint,
                PipeBinding {
                    handle: result_pipe.pipe_handle,
                    transfer_type: endpoint_descriptor.transfer_type(),
                },
            )
            .is_some()
        {
            return Err(ServerError::reason(
                "usb interface binding",
                format!(
                    "usb selection result returned duplicate endpoint {:#04x}",
                    endpoint.raw()
                ),
            ));
        }
    }

    Ok(InterfaceBinding {
        alternate_setting: descriptor.alternate_setting(),
        pipes,
    })
}

#[derive(Debug)]
enum PendingOperation {
    GetDescriptor,
    Transfer,
    Isochronous {
        packet_lengths: Vec<u32>,
    },
    GetConfiguration,
    GetInterface,
    SelectConfiguration {
        transition: StatefulTransition,
        plan: ConfigurationSelectionPlan,
    },
    SelectInterface {
        transition: StatefulTransition,
        plan: InterfaceSelectionPlan,
    },
    ClearHalt,
    ResetDevice {
        transition: StatefulTransition,
        previous_binding: BindingState,
    },
    CurrentFrameNumber,
}

/// A submitted USB request awaiting its completion.
///
/// Dropping a request before its completion is available requests
/// cancellation while the device channel remains open.
#[derive(Debug)]
#[must_use = "dropping a pending USB request cancels it"]
pub struct PendingRequest {
    inner: RawPending,
    operation: Option<PendingOperation>,
}

pub struct PendingHandle {
    usb_handle: UsbDeviceHandle,
    req_id: RequestId,
}

impl PendingHandle {
    pub fn cancel(&self) {
        let _ = self.usb_handle.cancel_request(self.req_id);
    }
}

impl PendingRequest {
    fn new(inner: RawPending, operation: PendingOperation) -> Self {
        Self {
            inner,
            operation: Some(operation),
        }
    }

    pub fn pending_handle(&self) -> PendingHandle {
        PendingHandle {
            usb_handle: self.inner.handle.clone(),
            req_id: self.inner.io.id,
        }
    }

    /// Returns a future resolving to the request's completion.
    ///
    /// The [`UsbRequestCompletion`] variant is fixed by the
    /// [`UsbDeviceHandle`] method which submitted this request. USB operation
    /// failures are reported inside the completion; the future's error covers
    /// cancellation, channel closure, and completion-shape failures.
    pub fn wait(self) -> CompletionFut {
        CompletionFut { pending: self }
    }
}

impl Drop for PendingRequest {
    fn drop(&mut self) {
        if let Some(operation) = self.operation.take() {
            operation.abandon(&self.inner.handle);
        }
    }
}

impl PendingOperation {
    /// Translates a raw RDPEUSB completion into this operation's typed
    /// completion, committing binding state for stateful operations.
    fn finish(self, handle: &UsbDeviceHandle, completion: CompletionData) -> ServerResult<UsbRequestCompletion> {
        match self {
            Self::GetDescriptor => Ok(UsbRequestCompletion::Descriptor(
                ironrdp_rdpeusb::usb::get_descriptor_completion(completion)
                    .map_err(|e| ServerError::custom("malformed usb get descriptor completion", e))?,
            )),
            Self::Transfer => Ok(UsbRequestCompletion::Transfer(
                ironrdp_rdpeusb::usb::transfer_completion(completion)
                    .map_err(|e| ServerError::custom("malformed usb transfer completion", e))?,
            )),
            Self::Isochronous { packet_lengths } => Ok(UsbRequestCompletion::Isochronous(
                ironrdp_rdpeusb::usb::isochronous_completion(completion, &packet_lengths)
                    .map_err(|e| ServerError::custom("malformed usb isochronous completion", e))?,
            )),
            Self::GetConfiguration => Ok(UsbRequestCompletion::Value(
                ironrdp_rdpeusb::usb::get_configuration_completion(completion)
                    .map_err(|e| ServerError::custom("malformed usb get configuration completion", e))?,
            )),
            Self::GetInterface => Ok(UsbRequestCompletion::Value(
                ironrdp_rdpeusb::usb::get_interface_completion(completion)
                    .map_err(|e| ServerError::custom("malformed usb get interface completion", e))?,
            )),
            Self::SelectConfiguration { transition, plan } => {
                let finish = TransitionGuard::finish_on_drop(handle, transition);
                let completion = ironrdp_rdpeusb::usb::select_configuration_completion(completion)
                    .map_err(|e| ServerError::custom("malformed usb select configuration completion", e))?;
                let result = match completion {
                    Ok(result) => result,
                    Err(usb_error) => return Ok(UsbRequestCompletion::Unit(Err(usb_error))),
                };
                let binding = configuration_binding_from_result(&plan, result)?;
                finish.disarm();
                handle.lock_usb_state().commit_binding(transition, binding)?;
                Ok(UsbRequestCompletion::Unit(Ok(())))
            }
            Self::SelectInterface { transition, plan } => {
                let finish = TransitionGuard::finish_on_drop(handle, transition);
                let completion = ironrdp_rdpeusb::usb::select_interface_completion(completion)
                    .map_err(|e| ServerError::custom("malformed usb select interface completion", e))?;
                let result = match completion {
                    Ok(result) => result,
                    Err(usb_error) => return Ok(UsbRequestCompletion::Unit(Err(usb_error))),
                };
                let binding = interface_binding_from_selection_result(&plan, result)?;
                finish.disarm();
                handle
                    .lock_usb_state()
                    .commit_interface(transition, plan.selection.interface, binding)?;
                Ok(UsbRequestCompletion::Unit(Ok(())))
            }
            Self::ClearHalt => Ok(UsbRequestCompletion::Unit(
                ironrdp_rdpeusb::usb::pipe_request_completion(completion)
                    .map_err(|e| ServerError::custom("malformed usb clear halt completion", e))?,
            )),
            Self::ResetDevice {
                transition,
                previous_binding,
            } => {
                let finish = TransitionGuard::finish_on_drop(handle, transition);
                let completion = ironrdp_rdpeusb::usb::reset_device_completion(completion)
                    .map_err(|e| ServerError::custom("malformed usb reset device completion", e))?;
                if let Err(usb_error) = completion {
                    return Ok(UsbRequestCompletion::Unit(Err(usb_error)));
                }
                finish.disarm();
                handle.lock_usb_state().commit_binding(transition, previous_binding)?;
                Ok(UsbRequestCompletion::Unit(Ok(())))
            }
            Self::CurrentFrameNumber => Ok(UsbRequestCompletion::FrameNumber(
                ironrdp_rdpeusb::usb::current_frame_number_completion(completion)
                    .map_err(|e| ServerError::custom("malformed usb current frame number completion", e))?,
            )),
        }
    }

    fn abandon(self, handle: &UsbDeviceHandle) {
        let transition = match self {
            Self::SelectConfiguration { transition, .. }
            | Self::SelectInterface { transition, .. }
            | Self::ResetDevice { transition, .. } => transition,
            Self::GetDescriptor
            | Self::Transfer
            | Self::Isochronous { .. }
            | Self::GetConfiguration
            | Self::GetInterface
            | Self::ClearHalt
            | Self::CurrentFrameNumber => return,
        };
        handle.lock_usb_state().poison_transition(transition);
    }
}

/// Completion of a submitted USB request.
///
/// The variant is fixed by the [`UsbDeviceHandle`] method which submitted the
/// request, so a call site can recover its payload with the matching `into_*`
/// accessor.
///
/// USB operation failures are reported inside the payload; a variant is
/// produced whenever the peer returned a well-formed completion.
#[derive(Debug)]
pub enum UsbRequestCompletion {
    /// `GET_DESCRIPTOR` response bytes; see [`UsbDeviceHandle::get_descriptor`].
    Descriptor(UsbResult<Vec<u8>>),
    /// Control, bulk, or interrupt transfer result.
    Transfer(TransferCompletion<Vec<u8>>),
    /// One-byte state query result; see [`UsbDeviceHandle::get_configuration`]
    /// and [`UsbDeviceHandle::get_interface`].
    Value(UsbResult<u8>),
    /// Status of a state-changing or pipe operation.
    Unit(UsbResult<()>),
    /// Host-controller frame number.
    FrameNumber(UsbResult<FrameNumber>),
    /// Acknowledged isochronous transfer result.
    Isochronous(IsoCompletion<Vec<u8>, Vec<IsochronousPacketCompletion>>),
}

/// Future returned by [`PendingRequest::wait`].
///
/// This is a named type so callers can hold many waits in homogeneous
/// collections, such as a `FuturesUnordered`, without boxing. Dropping it
/// before it resolves behaves like dropping the [`PendingRequest`] itself:
/// cancellation is requested while the device channel remains open.
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct CompletionFut {
    pending: PendingRequest,
}

impl Future for CompletionFut {
    type Output = ServerResult<UsbRequestCompletion>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        // Taking the operation up front guarantees the request resolves at
        // most once; it is restored while the completion is not ready.
        let Some(operation) = this.pending.operation.take() else {
            return Poll::Ready(Err(ServerError::reason(
                "usb pending request",
                "usb pending request already completed",
            )));
        };
        match Pin::new(&mut this.pending.inner.io.rx).poll(cx) {
            Poll::Pending => {
                this.pending.operation = Some(operation);
                Poll::Pending
            }
            Poll::Ready(Ok(completion)) => Poll::Ready(operation.finish(&this.pending.inner.handle, completion)),
            Poll::Ready(Err(_)) => {
                // The request is terminal without a completion; apply the same
                // abandonment a drop would, then report why the channel ended.
                operation.abandon(&this.pending.inner.handle);
                Poll::Ready(Err(this.pending.inner.channel_error()))
            }
        }
    }
}

#[derive(Debug)]
struct RawPending {
    handle: UsbDeviceHandle,
    io: PendingIo,
}

/// Identity and completion channel of one in-flight I/O request.
#[derive(Debug)]
pub(crate) struct PendingIo {
    pub(super) rx: oneshot::Receiver<CompletionData>,
    pub(super) id: RequestId,
}

impl Drop for RawPending {
    fn drop(&mut self) {
        if matches!(self.io.rx.try_recv(), Err(TryRecvError::Empty)) && self.handle.device.is_open() {
            let _ = self.handle.cancel_request(self.io.id);
        }
    }
}

impl RawPending {
    pub(crate) fn new(handle: UsbDeviceHandle, io: PendingIo) -> Self {
        Self { handle, io }
    }

    /// Explains a completion channel that ended without delivering a value.
    ///
    /// The sender was dropped without a completion: either a local cancel won
    /// the race against it, or the device channel was torn down. The
    /// distinction is currently observable only through the message text; a
    /// typed server error is planned to restore it.
    fn channel_error(&self) -> ServerError {
        if self.handle.device.is_open() {
            ServerError::reason("usb pending request", "usb request was cancelled before a completion")
        } else {
            ServerError::reason("usb pending request", "usb device channel is closing or closed")
        }
    }
}

pub(crate) struct UsbRedirServer {
    handle: UsbDeviceHandle,
    device: Box<dyn UsbRedirDevice>,
}

pub trait UsbRedirDevice: Send {
    /// Called when the client announces the device with `ADD_DEVICE`.
    fn device_added(&mut self, info: RdpUsbDeviceAnnounceInfo);

    fn device_text(&mut self, device_text: DeviceText);

    /// Called when the redirected USB device channel is closed.
    ///
    /// This is invoked exactly once on every teardown path (client-initiated
    /// channel close, server-initiated retract, and connection teardown) and is
    /// the final callback: no other method is called afterwards.
    ///
    /// Runs on the server task; implementations must not block and should only
    /// enqueue or spawn follow-up work.
    fn close(&mut self) {}
}

#[derive(Debug)]
pub struct RdpUsbDeviceAnnounceInfo {
    pub announce: DeviceAnnounce,
    pub usb_handle: UsbDeviceHandle,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
enum UsbDeviceState {
    Open,
    Retracting,
    Closed,
}

impl UsbDeviceState {
    const fn code(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Retracting => 1,
            Self::Closed => 2,
        }
    }
}

#[derive(Debug)]
pub(crate) struct UsbDeviceLifecycle {
    state: AtomicU8,
}

impl UsbDeviceLifecycle {
    pub(crate) fn new() -> Self {
        Self {
            state: AtomicU8::new(UsbDeviceState::Open.code()),
        }
    }

    pub(crate) fn is_open(&self) -> bool {
        self.state.load(Ordering::Acquire) == UsbDeviceState::Open.code()
    }

    pub(crate) fn mark_retracting(&self) {
        let _ = self.state.compare_exchange(
            UsbDeviceState::Open.code(),
            UsbDeviceState::Retracting.code(),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    pub(crate) fn mark_closed(&self) {
        self.state.store(UsbDeviceState::Closed.code(), Ordering::Release);
    }
}

impl UsbRedirServer {
    pub(crate) fn new(device: Box<dyn UsbRedirDevice>, handle: UsbDeviceHandle) -> Self {
        Self { handle, device }
    }

    fn io_completed(&self, request_id: RequestId, completion: CompletionData) -> PduResult<()> {
        self.handle.device.complete_pending(request_id, completion);
        Ok(())
    }
}

impl UrbdrcDeviceServerBackend for UsbRedirServer {
    fn add_device(&mut self, device: DeviceAnnounce) -> PduResult<()> {
        self.device.device_added(RdpUsbDeviceAnnounceInfo {
            announce: device,
            usb_handle: self.handle.clone(),
        });
        Ok(())
    }

    fn device_text(&mut self, device_text: DeviceText) {
        self.device.device_text(device_text);
    }

    fn io_control_completed(
        &mut self,
        _channel_id: u32,
        request_id: RequestId,
        completion: IoControlCompletionResult,
    ) -> PduResult<()> {
        self.io_completed(request_id, CompletionData::IoControl(completion))
    }

    fn internal_io_control_completed(
        &mut self,
        _channel_id: u32,
        request_id: RequestId,
        completion: IoControlCompletionResult,
    ) -> PduResult<()> {
        self.io_completed(request_id, CompletionData::InternalIoControl(completion))
    }

    fn transfer_in_completed(
        &mut self,
        _channel_id: u32,
        request_id: RequestId,
        completion: TransferInCompletionResult,
    ) -> PduResult<()> {
        self.io_completed(request_id, CompletionData::TransferIn(completion))
    }

    fn transfer_out_completed(
        &mut self,
        _channel_id: u32,
        request_id: RequestId,
        completion: TransferOutCompletionResult,
    ) -> PduResult<()> {
        self.io_completed(request_id, CompletionData::TransferOut(completion))
    }

    fn close(&mut self, channel_id: u32) {
        // Mark first: the event loop's authoritative check then rejects every
        // queued request, so the drain below cannot race a late insert.
        self.handle.device.mark_closed();
        let pending_requests = self.handle.device.drain_pending();
        if pending_requests != 0 {
            tracing::debug!(channel_id, pending_requests, "Failed pending USB requests on close");
        }

        let _ = self
            .handle
            .sender
            .send(ServerEvent::Usb(UrbdrcServerMessage::DeviceClosed {
                dvc_id: channel_id,
            }));
        self.device.close();
    }
}

#[cfg(test)]
mod tests {
    use ironrdp_rdpeusb::pdu::completion::ts_urb_result::{
        TsUsbdInterfaceInfoResult, TsUsbdPipeInfoResult, UsbdPipeType,
    };
    use ironrdp_usb::{TransferType, descriptor::ConfigurationDescriptorSet, endpoint::EndpointAddress};

    use super::interface_binding_from_result;

    const CONFIGURATION: [u8; 32] = [
        9, 2, 32, 0, 1, 1, 0, 0x80, 50, // configuration
        9, 4, 0, 0, 2, 8, 6, 0x50, 0, // interface 0, alternate 0
        7, 5, 0x01, 2, 64, 0, 0, // bulk OUT endpoint 1
        7, 5, 0x82, 2, 64, 0, 0, // bulk IN endpoint 2
    ];

    #[test]
    fn pipe_bindings_use_descriptor_semantics() {
        let binding = interface_binding_from_result(
            interface(),
            interface_result(vec![
                pipe_result(0x01, UsbdPipeType::Interrupt, 101),
                pipe_result(0x82, UsbdPipeType::Isochronous, 102),
            ]),
        )
        .unwrap();

        let out = &binding.pipes[&EndpointAddress::from_raw(0x01).unwrap()];
        assert_eq!(out.handle, 101);
        assert_eq!(out.transfer_type, TransferType::Bulk);
        let input = &binding.pipes[&EndpointAddress::from_raw(0x82).unwrap()];
        assert_eq!(input.handle, 102);
        assert_eq!(input.transfer_type, TransferType::Bulk);
    }

    #[test]
    fn interface_identity_must_match_selection() {
        let mut result = interface_result(vec![
            pipe_result(0x01, UsbdPipeType::Bulk, 101),
            pipe_result(0x82, UsbdPipeType::Bulk, 102),
        ]);
        result.alternate_setting = 1;

        let error = interface_binding_from_result(interface(), result).unwrap_err();
        assert!(error.to_string().contains("identifies interface 0 alternate 1"));
    }

    #[test]
    fn duplicate_endpoint_bindings_are_rejected() {
        let result = interface_result(vec![
            pipe_result(0x01, UsbdPipeType::Bulk, 101),
            pipe_result(0x01, UsbdPipeType::Bulk, 102),
        ]);

        let error = interface_binding_from_result(interface(), result).unwrap_err();
        assert!(error.to_string().contains("duplicate endpoint 0x01"));
    }

    fn interface() -> ironrdp_usb::descriptor::InterfaceDescriptor<'static> {
        ConfigurationDescriptorSet::parse(&CONFIGURATION)
            .unwrap()
            .interface(0, 0)
            .unwrap()
    }

    fn interface_result(pipes: Vec<TsUsbdPipeInfoResult>) -> TsUsbdInterfaceInfoResult {
        TsUsbdInterfaceInfoResult {
            interface_number: 0,
            alternate_setting: 0,
            class: 0xff,
            sub_class: 0xff,
            protocol: 0xff,
            interface_handle: 7,
            pipes,
        }
    }

    fn pipe_result(endpoint_address: u8, pipe_type: UsbdPipeType, pipe_handle: u32) -> TsUsbdPipeInfoResult {
        TsUsbdPipeInfoResult {
            max_packet_size: 1,
            endpoint_address,
            interval: 0xff,
            pipe_type,
            pipe_handle,
            max_transfer_size: 1,
            pipe_flags: u32::MAX,
        }
    }
}
