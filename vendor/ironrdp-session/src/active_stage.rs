use std::sync::Arc;

use ironrdp_bulk::BulkCompressor;
use ironrdp_connector::ConnectionResult;
use ironrdp_connector::connection_activation::ConnectionActivationSequence;
use ironrdp_core::{ReadCursor, WriteBuf};
use ironrdp_displaycontrol::client::DisplayControlClient;
use ironrdp_dvc::{DrdynvcClient, DvcProcessor, DynamicVirtualChannel};
use ironrdp_graphics::pointer::DecodedPointer;
use ironrdp_pdu::geometry::InclusiveRectangle;
use ironrdp_pdu::input::fast_path::{FastPathInput, FastPathInputEvent};
use ironrdp_pdu::rdp::autodetect::AutoDetectRequest;
use ironrdp_pdu::rdp::client_info::CompressionType as PduCompressionType;
use ironrdp_pdu::rdp::headers::ShareDataPdu;
use ironrdp_pdu::rdp::multitransport::MultitransportRequestPdu;
use ironrdp_pdu::slow_path::{self, GraphicsUpdateType};
use ironrdp_pdu::{Action, mcs};
use ironrdp_svc::{SvcMessage, SvcProcessor, SvcProcessorMessages};
use tracing::{debug, info, warn};

use crate::fast_path::UpdateKind;
use crate::image::DecodedImage;
use crate::{SessionError, SessionErrorExt as _, SessionResult, fast_path, x224};

/// Converts the PDU-layer compression type to the bulk crate's compression type.
fn to_bulk_compression_type(ct: PduCompressionType) -> ironrdp_bulk::CompressionType {
    match ct {
        PduCompressionType::K8 => ironrdp_bulk::CompressionType::Rdp4,
        PduCompressionType::K64 => ironrdp_bulk::CompressionType::Rdp5,
        PduCompressionType::Rdp6 => ironrdp_bulk::CompressionType::Rdp6,
        PduCompressionType::Rdp61 => ironrdp_bulk::CompressionType::Rdp61,
    }
}

pub struct ActiveStage {
    x224_processor: x224::Processor,
    fast_path_processor: fast_path::Processor,
    enable_server_pointer: bool,
}

impl ActiveStage {
    pub fn new(connection_result: ConnectionResult) -> Self {
        let x224_processor = x224::Processor::new(
            connection_result.static_channels,
            connection_result.user_channel_id,
            connection_result.io_channel_id,
            connection_result.share_id,
            connection_result.connection_activation,
        );

        // Create bulk decompressor if compression was negotiated
        let bulk_decompressor = connection_result.compression_type.and_then(|ct| {
            let bulk_ct = to_bulk_compression_type(ct);
            match BulkCompressor::new(bulk_ct) {
                Ok(compressor) => {
                    info!(compression_type = %bulk_ct, "Bulk decompressor initialized for FastPath");
                    Some(compressor)
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to create bulk decompressor, compression disabled");
                    None
                }
            }
        });

        let fast_path_processor = fast_path::ProcessorBuilder {
            io_channel_id: connection_result.io_channel_id,
            user_channel_id: connection_result.user_channel_id,
            share_id: connection_result.share_id,
            enable_server_pointer: connection_result.enable_server_pointer,
            pointer_software_rendering: connection_result.pointer_software_rendering,
            bulk_decompressor,
        }
        .build();

        Self {
            x224_processor,
            fast_path_processor,
            enable_server_pointer: connection_result.enable_server_pointer,
        }
    }

    pub fn update_mouse_pos(&mut self, x: u16, y: u16) {
        self.fast_path_processor.update_mouse_pos(x, y);
    }

    /// Encodes outgoing input events and modifies image if necessary (e.g for client-side pointer
    /// rendering).
    pub fn process_fastpath_input(
        &mut self,
        image: &mut DecodedImage,
        events: &[FastPathInputEvent],
    ) -> SessionResult<Vec<ActiveStageOutput>> {
        if events.is_empty() {
            return Ok(Vec::new());
        }

        // Mouse move events are prevalent, so we can preallocate space for
        // response frame + graphics update
        let mut output = Vec::with_capacity(2);

        // Encoding fastpath response frame
        // PERF: unnecessary copy
        let fastpath_input = FastPathInput::new(events.to_vec()).map_err(SessionError::decode)?;
        let frame = ironrdp_core::encode_vec(&fastpath_input).map_err(SessionError::encode)?;
        output.push(ActiveStageOutput::ResponseFrame(frame));

        // If pointer rendering is disabled - we can skip the rest
        if !self.enable_server_pointer {
            return Ok(output);
        }

        // If mouse was moved by client - we should update framebuffer to reflect new
        // pointer position
        let mouse_pos = events.iter().find_map(|event| match event {
            FastPathInputEvent::MouseEvent(event) => Some((event.x_position, event.y_position)),
            FastPathInputEvent::MouseEventEx(event) => Some((event.x_position, event.y_position)),
            _ => None,
        });

        let (mouse_x, mouse_y) = match mouse_pos {
            Some(mouse_pos) => mouse_pos,
            None => return Ok(output),
        };

        // Graphics update is only sent when update is visually changed the framebuffer
        if let Some(rect) = image.move_pointer(mouse_x, mouse_y)? {
            output.push(ActiveStageOutput::GraphicsUpdate(rect));
        }

        Ok(output)
    }

    /// Process a frame received from the server.
    pub fn process(
        &mut self,
        image: &mut DecodedImage,
        action: Action,
        frame: &[u8],
    ) -> SessionResult<Vec<ActiveStageOutput>> {
        let (mut stage_outputs, processor_updates) = match action {
            Action::FastPath => {
                let mut output = WriteBuf::new();
                let processor_updates = self.fast_path_processor.process(image, frame, &mut output)?;
                (
                    vec![ActiveStageOutput::ResponseFrame(output.into_inner())],
                    processor_updates,
                )
            }
            Action::X224 => {
                let x224_outputs = self.x224_processor.process(frame)?;
                let mut stage_outputs = Vec::new();
                let mut processor_updates = Vec::new();

                for output in x224_outputs {
                    match output {
                        x224::ProcessorOutput::GraphicsUpdate(data) => {
                            let updates = process_slow_path_graphics(&mut self.fast_path_processor, image, &data)?;
                            processor_updates.extend(updates);
                        }
                        x224::ProcessorOutput::PointerUpdate(data) => {
                            let updates = process_slow_path_pointer(&mut self.fast_path_processor, image, &data)?;
                            processor_updates.extend(updates);
                        }
                        other => {
                            stage_outputs.push(ActiveStageOutput::try_from(other)?);
                        }
                    }
                }

                (stage_outputs, processor_updates)
            }
        };

        for update in processor_updates {
            match update {
                UpdateKind::None => {}
                UpdateKind::Region(region) => {
                    stage_outputs.push(ActiveStageOutput::GraphicsUpdate(region));
                }
                UpdateKind::PointerDefault => {
                    stage_outputs.push(ActiveStageOutput::PointerDefault);
                }
                UpdateKind::PointerHidden => {
                    stage_outputs.push(ActiveStageOutput::PointerHidden);
                }
                UpdateKind::PointerPosition { x, y } => {
                    stage_outputs.push(ActiveStageOutput::PointerPosition { x, y });
                }
                UpdateKind::PointerBitmap(pointer) => {
                    stage_outputs.push(ActiveStageOutput::PointerBitmap(pointer));
                }
            }
        }

        Ok(stage_outputs)
    }

    pub fn set_fastpath_processor(&mut self, processor: fast_path::Processor) {
        self.fast_path_processor = processor;
    }

    /// Updates the share_id used by the x224 processor for encoding ShareDataPdu.
    /// Must be called during Deactivation-Reactivation if the server assigns a new share_id.
    pub fn set_share_id(&mut self, share_id: u32) {
        self.x224_processor.set_share_id(share_id);
    }

    pub fn set_enable_server_pointer(&mut self, enable_server_pointer: bool) {
        self.enable_server_pointer = enable_server_pointer;
    }

    /// Encodes client-side graceful shutdown request. Note that upon sending this request,
    /// client should wait for server's ShutdownDenied PDU before closing the connection.
    ///
    /// Client-side graceful shutdown is defined in [MS-RDPBCGR]
    ///
    /// [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/27915739-8f77-487e-9927-55008af7fd68
    pub fn graceful_shutdown(&self) -> SessionResult<Vec<ActiveStageOutput>> {
        let mut frame = WriteBuf::new();
        self.x224_processor
            .encode_static(&mut frame, ShareDataPdu::ShutdownRequest)?;

        Ok(vec![ActiveStageOutput::ResponseFrame(frame.into_inner())])
    }

    /// Send a pdu on the static global channel. Typically used to send input events
    pub fn encode_static(&self, output: &mut WriteBuf, pdu: ShareDataPdu) -> SessionResult<usize> {
        self.x224_processor.encode_static(output, pdu)
    }

    pub fn get_svc_processor<T: SvcProcessor + 'static>(&mut self) -> Option<&T> {
        self.x224_processor.get_svc_processor()
    }

    pub fn get_svc_processor_mut<T: SvcProcessor + 'static>(&mut self) -> Option<&mut T> {
        self.x224_processor.get_svc_processor_mut()
    }

    pub fn get_dvc<T: DvcProcessor + 'static>(&mut self) -> Option<&DynamicVirtualChannel> {
        self.x224_processor.get_dvc::<T>()
    }

    pub fn get_dvc_by_channel_id(&mut self, channel_id: u32) -> Option<&DynamicVirtualChannel> {
        self.x224_processor.get_dvc_by_channel_id(channel_id)
    }

    /// Completes user's SVC request with data, required to sent it over the network and returns
    /// a buffer with encoded data.
    pub fn process_svc_processor_messages<C: SvcProcessor + 'static>(
        &self,
        messages: SvcProcessorMessages<C>,
    ) -> SessionResult<Vec<u8>> {
        self.x224_processor.process_svc_processor_messages(messages)
    }

    /// Fully encodes a resize request for sending over the Display Control Virtual Channel.
    ///
    /// If the Display Control Virtual Channel is not available, or not yet connected, this method
    /// will return `None`.
    ///
    /// Per [2.2.2.2.1]:
    /// - The `width` MUST be greater than or equal to 200 pixels and less than or equal to 8192 pixels, and MUST NOT be an odd value.
    /// - The `height` MUST be greater than or equal to 200 pixels and less than or equal to 8192 pixels.
    /// - The `scale_factor` MUST be ignored if it is less than 100 percent or greater than 500 percent.
    /// - The `physical_dims` (width, height) MUST be ignored if either is less than 10 mm or greater than 10,000 mm.
    ///
    /// Use [`ironrdp_displaycontrol::pdu::MonitorLayoutEntry::adjust_display_size`] to adjust `width` and `height` before calling this function
    /// to ensure the display size is within the valid range.
    ///
    /// [2.2.2.2.2]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpedisp/ea2de591-9203-42cd-9908-be7a55237d1c
    pub fn encode_resize(
        &mut self,
        width: u32,
        height: u32,
        scale_factor: Option<u32>,
        physical_dims: Option<(u32, u32)>,
    ) -> Option<SessionResult<Vec<u8>>> {
        if let Some(dvc) = self.get_dvc::<DisplayControlClient>() {
            if let Some(channel_id) = dvc.channel_id() {
                let display_control = dvc.channel_processor_downcast_ref::<DisplayControlClient>()?;
                let svc_messages = match display_control.encode_single_primary_monitor(
                    channel_id,
                    width,
                    height,
                    scale_factor,
                    physical_dims,
                ) {
                    Ok(messages) => messages,
                    Err(e) => return Some(Err(SessionError::encode(e))),
                };

                return Some(
                    self.process_svc_processor_messages(SvcProcessorMessages::<DrdynvcClient>::new(svc_messages)),
                );
            } else {
                debug!("Could not encode a resize: Display Control Virtual Channel is not yet connected");
            }
        } else {
            debug!("Could not encode a resize: Display Control Virtual Channel is not available");
        }

        None
    }

    pub fn encode_dvc_messages(&mut self, messages: Vec<SvcMessage>) -> SessionResult<Vec<u8>> {
        self.process_svc_processor_messages(SvcProcessorMessages::<DrdynvcClient>::new(messages))
    }
}

#[derive(Debug)]
pub enum ActiveStageOutput {
    ResponseFrame(Vec<u8>),
    GraphicsUpdate(InclusiveRectangle),
    PointerDefault,
    PointerHidden,
    PointerPosition {
        x: u16,
        y: u16,
    },
    PointerBitmap(Arc<DecodedPointer>),
    Terminate(GracefulDisconnectReason),
    DeactivateAll(Box<ConnectionActivationSequence>),
    /// Server Initiate Multitransport Request. The application should establish a
    /// sideband UDP transport using the provided request parameters.
    ///
    /// See [\[MS-RDPBCGR\] 2.2.15.1].
    ///
    /// [\[MS-RDPBCGR\] 2.2.15.1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/de783158-8b01-4818-8fb0-62523a5b3490
    MultitransportRequest(MultitransportRequestPdu),
    /// Server-reported network characteristics ([\[MS-RDPBCGR\] 2.2.14.1.5]).
    ///
    /// Contains an [`AutoDetectRequest::NetworkCharacteristicsResult`] with
    /// RTT and/or bandwidth measurements computed by the server.
    ///
    /// See [\[MS-RDPBCGR\] 2.2.14.1.5].
    ///
    /// [\[MS-RDPBCGR\] 2.2.14.1.5]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/228ffc5c-b60c-4d3e-9781-ac613f822fdf
    AutoDetect(AutoDetectRequest),
}

impl TryFrom<x224::ProcessorOutput> for ActiveStageOutput {
    type Error = SessionError;

    fn try_from(value: x224::ProcessorOutput) -> Result<Self, Self::Error> {
        match value {
            x224::ProcessorOutput::ResponseFrame(frame) => Ok(Self::ResponseFrame(frame)),
            x224::ProcessorOutput::Disconnect(desc) => {
                let desc = match desc {
                    x224::DisconnectDescription::McsDisconnect(reason) => match reason {
                        mcs::DisconnectReason::ProviderInitiated => GracefulDisconnectReason::ServerInitiated,
                        mcs::DisconnectReason::UserRequested => GracefulDisconnectReason::UserInitiated,
                        other => GracefulDisconnectReason::Other(other.description().to_owned()),
                    },
                    x224::DisconnectDescription::ErrorInfo(info) => GracefulDisconnectReason::Other(info.description()),
                };

                Ok(Self::Terminate(desc))
            }
            x224::ProcessorOutput::DeactivateAll(cas) => Ok(Self::DeactivateAll(cas)),
            x224::ProcessorOutput::MultitransportRequest(pdu) => Ok(Self::MultitransportRequest(pdu)),
            x224::ProcessorOutput::AutoDetect(request) => Ok(Self::AutoDetect(request)),
            // GraphicsUpdate and PointerUpdate are consumed in ActiveStage::process()
            // before reaching this conversion.
            x224::ProcessorOutput::GraphicsUpdate(_) | x224::ProcessorOutput::PointerUpdate(_) => Err(
                SessionError::general("slow-path graphics/pointer updates should be handled before this conversion"),
            ),
        }
    }
}

/// Reasons for graceful disconnect. This type provides GUI-friendly descriptions for
/// disconnect reasons.
#[derive(Debug, Clone)]
pub enum GracefulDisconnectReason {
    UserInitiated,
    ServerInitiated,
    Other(String),
}

impl GracefulDisconnectReason {
    pub fn description(&self) -> String {
        match self {
            GracefulDisconnectReason::UserInitiated => "user initiated disconnect".to_owned(),
            GracefulDisconnectReason::ServerInitiated => "server initiated disconnect".to_owned(),
            GracefulDisconnectReason::Other(description) => description.clone(),
        }
    }
}

impl core::fmt::Display for GracefulDisconnectReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.description())
    }
}

/// Parse and process a slow-path graphics update through the shared bitmap pipeline.
fn process_slow_path_graphics(
    fast_path_processor: &mut fast_path::Processor,
    image: &mut DecodedImage,
    data: &[u8],
) -> SessionResult<Vec<UpdateKind>> {
    let mut src = ReadCursor::new(data);
    let update_type = slow_path::read_graphics_update_type(&mut src).map_err(SessionError::decode)?;

    match update_type {
        GraphicsUpdateType::Bitmap => {
            let bitmap = slow_path::decode_slow_path_bitmap(&mut src).map_err(SessionError::decode)?;
            fast_path_processor.process_bitmap_update(image, bitmap)
        }
        GraphicsUpdateType::Orders => {
            warn!("Slow-path drawing orders not supported (MS-RDPEGDI)");
            Ok(Vec::new())
        }
        GraphicsUpdateType::Palette => {
            warn!("Slow-path palette update not supported (8bpp)");
            Ok(Vec::new())
        }
        // Synchronize is an artifact from the T.128 multipoint protocol
        // and carries no data. Safe to ignore.
        GraphicsUpdateType::Synchronize => {
            debug!("Ignoring slow-path synchronize update");
            Ok(Vec::new())
        }
    }
}

/// Parse and process a slow-path pointer update through the shared pointer pipeline.
fn process_slow_path_pointer(
    fast_path_processor: &mut fast_path::Processor,
    image: &mut DecodedImage,
    data: &[u8],
) -> SessionResult<Vec<UpdateKind>> {
    let mut src = ReadCursor::new(data);
    let pointer = slow_path::decode_slow_path_pointer(&mut src).map_err(SessionError::decode)?;
    fast_path_processor.process_pointer_update(image, pointer)
}
