use core::mem;

use ironrdp_pdu::rdp;
use ironrdp_pdu::rdp::capability_sets::{
    CapabilitySet, InputFlags, Rail, RailSupportLevel, WindowList, WindowSupportLevel,
};
use ironrdp_pdu::rdp::server_redirection::ServerRedirectionPdu;
use tracing::{debug, info, warn};

use crate::{
    Config, ConnectionFinalizationSequence, ConnectorError, ConnectorErrorExt as _, ConnectorResult, DesktopSize,
    MonotonicInstant, Sequence, State, Written, general_err, reason_err,
};

/// Represents the Capability Exchange and Connection Finalization phases
/// of the connection sequence (section [1.3.1.1]).
///
/// This is abstracted into its own struct to allow it to be used for the ordinary
/// RDP connection sequence [`ClientConnector`] that occurs for every RDP connection,
/// as well as the Deactivation-Reactivation Sequence ([1.3.1.3]) that occurs when
/// a [Server Deactivate All PDU] is received.
///
/// [1.3.1.1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/023f1e69-cfe8-4ee6-9ee0-7e759fb4e4ee
/// [1.3.1.3]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/dfc234ce-481a-4674-9a5d-2a7bafb14432
/// [`ClientConnector`]: crate::ClientConnector
/// [Server Deactivate All PDU]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/8a29971a-df3c-48da-add2-8ed9a05edc89
#[derive(Debug, Clone)]
pub struct ConnectionActivationSequence {
    state: ConnectionActivationState,
    monitor_layout: Option<rdp::finalization_messages::MonitorLayoutPdu>,
    config: Config,
    // The MCS channel IDs are invariant for the whole life of the sequence: they are negotiated
    // once and never change, even across a Deactivation-Reactivation Sequence. They are stored
    // here (rather than duplicated into every state variant).
    io_channel_id: u16,
    user_channel_id: u16,
}

impl ConnectionActivationSequence {
    pub fn new(config: Config, io_channel_id: u16, user_channel_id: u16) -> Self {
        // TODO/FIXME: Investigate whether we really need to carry around the whole `Config` struct.
        // RATIONALE(@CBenoit): Not very convenient when building in isolation.
        //   I doubt this type really needs every field there.
        Self {
            state: ConnectionActivationState::CapabilitiesExchange,
            monitor_layout: None,
            config,
            io_channel_id,
            user_channel_id,
        }
    }

    pub fn io_channel_id(&self) -> u16 {
        self.io_channel_id
    }

    pub fn user_channel_id(&self) -> u16 {
        self.user_channel_id
    }

    /// Returns the current state as a distinct type, rather than `&dyn State` provided by [`Self::state`].
    pub fn connection_activation_state(&self) -> ConnectionActivationState {
        self.state.clone()
    }

    /// Returns the server-reported monitor layout received during this activation.
    pub fn monitor_layout(&self) -> Option<rdp::finalization_messages::MonitorLayoutPdu> {
        self.monitor_layout.clone()
    }
}

/// Factory producing fresh [`ConnectionActivationSequence`] instances.
///
/// The [`Config`] and MCS channel IDs required to build a connection activation sequence are
/// invariant for the whole lifetime of the connection: they are negotiated once and never change,
/// even across a [Deactivation-Reactivation Sequence]. This factory captures them so that a fresh,
/// correctly-initialized sequence can be produced each time one is needed, driven until it is
/// finalized, then dropped.
///
/// [Deactivation-Reactivation Sequence]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/dfc234ce-481a-4674-9a5d-2a7bafb14432
#[derive(Debug, Clone)]
pub struct ConnectionActivationFactory {
    config: Config,
    io_channel_id: u16,
    user_channel_id: u16,
    multitransport_soft_sync: bool,
}

impl ConnectionActivationFactory {
    pub fn new(config: Config, io_channel_id: u16, user_channel_id: u16) -> Self {
        Self {
            config,
            io_channel_id,
            user_channel_id,
            multitransport_soft_sync: false,
        }
    }

    pub(crate) fn with_multitransport_soft_sync(mut self, multitransport_soft_sync: bool) -> Self {
        self.multitransport_soft_sync = multitransport_soft_sync;
        self
    }

    pub(crate) fn multitransport_soft_sync(&self) -> bool {
        self.multitransport_soft_sync
    }

    pub fn io_channel_id(&self) -> u16 {
        self.io_channel_id
    }

    pub fn user_channel_id(&self) -> u16 {
        self.user_channel_id
    }

    /// Produces a fresh [`ConnectionActivationSequence`] in the initial `CapabilitiesExchange` state.
    #[must_use]
    pub fn create(&self) -> ConnectionActivationSequence {
        ConnectionActivationSequence::new(self.config.clone(), self.io_channel_id, self.user_channel_id)
    }
}

impl Sequence for ConnectionActivationSequence {
    fn next_pdu_hint(&self) -> Option<&dyn ironrdp_pdu::PduHint> {
        match &self.state {
            ConnectionActivationState::Consumed => None,
            ConnectionActivationState::Finalized { .. } | ConnectionActivationState::Redirected { .. } => None,
            ConnectionActivationState::CapabilitiesExchange => Some(&ironrdp_pdu::X224_HINT),
            ConnectionActivationState::ConnectionFinalization {
                connection_finalization,
                ..
            } => connection_finalization.next_pdu_hint(),
        }
    }

    fn state(&self) -> &dyn State {
        &self.state
    }

    fn step(
        &mut self,
        input: &[u8],
        received_at: Option<MonotonicInstant>,
        output: &mut ironrdp_core::WriteBuf,
    ) -> ConnectorResult<Written> {
        // The server may redirect the client instead of, or in the middle of, activating it
        // ([MS-RDPBCGR] 3.2.5.13.1).
        if matches!(
            self.state,
            ConnectionActivationState::CapabilitiesExchange | ConnectionActivationState::ConnectionFinalization { .. }
        ) && let Some(redirection) = server_redirection(input)?
        {
            if redirection.is_informational() {
                debug!(?redirection, "Ignoring informational Server Redirection PDU");
            } else {
                info!(session_id = redirection.session_id, "Server requested a redirection");
                debug!(?redirection, "Received");
                self.state = ConnectionActivationState::Redirected {
                    redirection: Box::new(redirection),
                };
            }
            return Ok(Written::Nothing);
        }

        let (written, next_state) = match mem::take(&mut self.state) {
            ConnectionActivationState::Consumed
            | ConnectionActivationState::Finalized { .. }
            | ConnectionActivationState::Redirected { .. } => {
                return Err(general_err!(
                    "connector sequence state is finalized or consumed (this is a bug)"
                ));
            }
            ConnectionActivationState::CapabilitiesExchange => {
                debug!("Capabilities Exchange");

                let send_data_indication_ctx =
                    ironrdp_pdu::mcs::decode_send_data_indication(input).map_err(ConnectorError::decode)?;
                let share_control_ctx =
                    rdp::headers::decode_share_control(send_data_indication_ctx).map_err(ConnectorError::decode)?;

                debug!(message = ?share_control_ctx.pdu, "Received");

                if share_control_ctx.channel_id != self.io_channel_id {
                    warn!(
                        io_channel_id = self.io_channel_id,
                        share_control_ctx.channel_id, "Unexpected channel ID for received Share Control Pdu"
                    );
                }

                // Some servers (e.g. GNOME Remote Desktop) send a ServerDeactivateAll PDU
                // before ServerDemandActive as part of a Deactivation-Reactivation Sequence
                // (MS-RDPBCGR §1.3.1.3). Skip it and stay in the same state to wait for
                // the actual DemandActive PDU.
                //
                // The decoded PDU is intentionally discarded: the DeactivateAll body carries
                // no payload we need during initial activation.
                if matches!(
                    share_control_ctx.pdu,
                    rdp::headers::ShareControlPdu::ServerDeactivateAll(_)
                ) {
                    debug!(
                        "Skipping Server Deactivate All PDU received during Capabilities Exchange, awaiting Server Demand Active"
                    );
                    self.state = ConnectionActivationState::CapabilitiesExchange;
                    return Ok(Written::Nothing);
                }

                let capability_sets = if let rdp::headers::ShareControlPdu::ServerDemandActive(server_demand_active) =
                    share_control_ctx.pdu
                {
                    server_demand_active.pdu.capability_sets
                } else {
                    // Instead of reactivating after a Deactivate-All, a server may end the
                    // session (MS-RDPBCGR §1.3.1.3) by sending a Set Error Info PDU carrying the
                    // disconnect reason. FreeRDP-based servers such as GNOME Remote Desktop do
                    // this, for example when the backend screencast session cannot be created.
                    // Surface that reason so the disconnect is explained rather than reported as
                    // an unexpected PDU.
                    if let rdp::headers::ShareControlPdu::Data(rdp::headers::ShareDataHeader {
                        share_data_pdu:
                            rdp::headers::ShareDataPdu::ServerSetErrorInfo(rdp::server_error_info::ServerSetErrorInfoPdu(
                                error_info,
                            )),
                        ..
                    }) = share_control_ctx.pdu
                    {
                        // ERRINFO_NONE is informational (it clears a previously reported error),
                        // not a disconnect. Skip it and keep waiting for the Demand Active PDU,
                        // matching how the connection finalization sequence treats it.
                        if let rdp::server_error_info::ErrorInfo::ProtocolIndependentCode(
                            rdp::server_error_info::ProtocolIndependentCode::None,
                        ) = error_info
                        {
                            self.state = ConnectionActivationState::CapabilitiesExchange;
                            return Ok(Written::Nothing);
                        }

                        return Err(reason_err!(
                            "ConnectionActivation::CapabilitiesExchange",
                            "server ended the session with error info: {}",
                            error_info.description()
                        ));
                    }

                    return Err(reason_err!(
                        "ConnectionActivation::CapabilitiesExchange",
                        "unexpected Share Control PDU during capabilities exchange: got {} (expected Server Demand Active PDU)",
                        rdp::headers::describe_unexpected_share_control_pdu(&share_control_ctx.pdu),
                    ));
                };

                let window_list = server_window_list(&capability_sets);
                let window_support_level = negotiated_window_support_level(window_list.as_ref());

                let (refresh_rect_support, suppress_output_support) = capability_sets
                    .iter()
                    .find_map(|capability_set| {
                        let CapabilitySet::General(general) = capability_set else {
                            return None;
                        };
                        if general.protocol_version != rdp::capability_sets::PROTOCOL_VER {
                            warn!(version = general.protocol_version, "Unexpected protocol version");
                        }
                        Some((general.refresh_rect_support, general.suppress_output_support))
                    })
                    .unwrap_or((false, false));

                // Keep the server's Input capability flags so the session layer can tell whether
                // fast-path input was negotiated: per [MS-RDPBCGR] 2.2.8.1.2, the client MUST NOT
                // send fast-path input events unless the server advertised
                // `INPUT_FLAG_FASTPATH_INPUT` or `INPUT_FLAG_FASTPATH_INPUT2`. Servers that omit
                // both (e.g. VirtualBox VRDP) may reject fast-path input PDUs outright.
                let input_flags = capability_sets
                    .iter()
                    .find_map(|c| match c {
                        CapabilitySet::Input(i) => Some(i.input_flags),
                        _ => None,
                    })
                    .unwrap_or_else(InputFlags::empty);

                let static_channel_chunk_size = capability_sets
                    .iter()
                    .find_map(|c| match c {
                        CapabilitySet::VirtualChannel(channel) => channel
                            .chunk_size
                            .and_then(|chunk_size| usize::try_from(chunk_size).ok()),
                        _ => None,
                    })
                    .filter(|chunk_size| {
                        (ironrdp_svc::CHANNEL_CHUNK_LENGTH..=ironrdp_svc::MAX_CHANNEL_CHUNK_LENGTH).contains(chunk_size)
                    })
                    .unwrap_or(ironrdp_svc::CHANNEL_CHUNK_LENGTH);

                // At this point we have already sent a requested desktop size to the server -- either as a part of the
                // [`TS_UD_CS_CORE`] (on initial connection) or the [`DISPLAYCONTROL_MONITOR_LAYOUT`] (on resize event).
                //
                // The server is therefore responding with a desktop size here, which will be close to the requested size but
                // may be slightly different due to server-side constraints. We should use this negotiated size for the rest of
                // the session.
                //
                // [TS_UD_CS_CORE]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/00f1da4a-ee9c-421a-852f-c19f92343d73
                // [DISPLAYCONTROL_MONITOR_LAYOUT]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpedisp/ea2de591-9203-42cd-9908-be7a55237d1c
                let desktop_size = capability_sets
                    .iter()
                    .find_map(|c| match c {
                        CapabilitySet::Bitmap(b) => Some(DesktopSize {
                            width: b.desktop_width,
                            height: b.desktop_height,
                        }),
                        _ => None,
                    })
                    .unwrap_or(DesktopSize {
                        width: self.config.desktop_size.width,
                        height: self.config.desktop_size.height,
                    });

                let share_id = share_control_ctx.share_id;

                let client_confirm_active = rdp::headers::ShareControlPdu::ClientConfirmActive(
                    create_client_confirm_active(&self.config, capability_sets, desktop_size, window_list)?,
                );

                debug!(message = ?client_confirm_active, "Send");

                let written = rdp::headers::encode_share_control(
                    self.user_channel_id,
                    self.io_channel_id,
                    share_id,
                    client_confirm_active,
                    output,
                )
                .map_err(ConnectorError::encode)?;

                (
                    Written::from_size(written)?,
                    ConnectionActivationState::ConnectionFinalization {
                        desktop_size,
                        share_id,
                        input_flags,
                        static_channel_chunk_size,
                        refresh_rect_support,
                        suppress_output_support,
                        window_support_level,
                        connection_finalization: ConnectionFinalizationSequence::new(
                            self.io_channel_id,
                            self.user_channel_id,
                            share_id,
                        ),
                    },
                )
            }
            ConnectionActivationState::ConnectionFinalization {
                desktop_size,
                share_id,
                input_flags,
                static_channel_chunk_size,
                refresh_rect_support,
                suppress_output_support,
                window_support_level,
                mut connection_finalization,
            } => {
                debug!("Connection Finalization");

                let written = connection_finalization.step(input, received_at, output)?;

                let next_state = if !connection_finalization.state.is_terminal() {
                    ConnectionActivationState::ConnectionFinalization {
                        desktop_size,
                        share_id,
                        input_flags,
                        static_channel_chunk_size,
                        refresh_rect_support,
                        suppress_output_support,
                        window_support_level,
                        connection_finalization,
                    }
                } else {
                    self.monitor_layout = connection_finalization.monitor_layout;
                    ConnectionActivationState::Finalized {
                        desktop_size,
                        share_id,
                        input_flags,
                        static_channel_chunk_size,
                        enable_server_pointer: self.config.enable_server_pointer,
                        pointer_software_rendering: self.config.pointer_software_rendering,
                        refresh_rect_support,
                        suppress_output_support,
                        window_support_level,
                    }
                };

                (written, next_state)
            }
        };

        self.state = next_state;

        Ok(written)
    }
}

#[derive(Default, Debug, Clone)]
pub enum ConnectionActivationState {
    #[default]
    Consumed,
    CapabilitiesExchange,
    ConnectionFinalization {
        desktop_size: DesktopSize,
        share_id: u32,
        /// The server's Input capability flags from the Server Demand Active PDU.
        input_flags: InputFlags,
        /// The validated `VCChunkSize` from the server Virtual Channel Capability Set.
        static_channel_chunk_size: usize,
        refresh_rect_support: bool,
        suppress_output_support: bool,
        /// The server-negotiated Window List support level.
        window_support_level: Option<WindowSupportLevel>,
        connection_finalization: ConnectionFinalizationSequence,
    },
    Finalized {
        desktop_size: DesktopSize,
        share_id: u32,
        /// The server's Input capability flags from the Server Demand Active PDU.
        ///
        /// Per [MS-RDPBCGR] 2.2.8.1.2, fast-path input events may only be sent when
        /// `INPUT_FLAG_FASTPATH_INPUT` or `INPUT_FLAG_FASTPATH_INPUT2` is present.
        ///
        /// [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b8e7c588-51cb-455b-bb73-92d480903133
        input_flags: InputFlags,
        /// The validated `VCChunkSize` from the server Virtual Channel Capability Set.
        static_channel_chunk_size: usize,
        enable_server_pointer: bool,
        pointer_software_rendering: bool,
        /// Whether the server permits client Refresh Rect PDUs for visual recovery.
        refresh_rect_support: bool,
        /// Whether the server permits Suppress Output PDUs for visual recovery.
        suppress_output_support: bool,
        /// The server-negotiated Window List support level.
        window_support_level: Option<WindowSupportLevel>,
    },
    /// The server sent a Server Redirection PDU: the client must close this connection and connect to the target it
    /// describes ([MS-RDPBCGR] 3.2.5.13.1).
    ///
    /// [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/
    Redirected {
        redirection: Box<ServerRedirectionPdu>,
    },
}

impl State for ConnectionActivationState {
    fn name(&self) -> &'static str {
        match self {
            ConnectionActivationState::Consumed => "Consumed",
            ConnectionActivationState::CapabilitiesExchange => "CapabilitiesExchange",
            ConnectionActivationState::ConnectionFinalization { .. } => "ConnectionFinalization",
            ConnectionActivationState::Finalized { .. } => "Finalized",
            ConnectionActivationState::Redirected { .. } => "Redirected",
        }
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self,
            ConnectionActivationState::Finalized { .. } | ConnectionActivationState::Redirected { .. }
        )
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

const DEFAULT_POINTER_CACHE_SIZE: u16 = 32;

/// Decodes `input` as a Server Redirection PDU received on the I/O channel, if it is one.
///
/// Anything that is not an MCS Send Data Indication is left for the regular decoding path to report.
fn server_redirection(input: &[u8]) -> ConnectorResult<Option<ServerRedirectionPdu>> {
    let Ok(ctx) = ironrdp_pdu::mcs::decode_send_data_indication(input) else {
        return Ok(None);
    };
    rdp::server_redirection::decode_server_redirection(ctx.user_data).map_err(ConnectorError::decode)
}

fn server_window_list(capability_sets: &[CapabilitySet]) -> Option<WindowList> {
    capability_sets.iter().find_map(|capability_set| {
        if let CapabilitySet::WindowList(window_list) = capability_set {
            Some(window_list.clone())
        } else {
            None
        }
    })
}

fn negotiated_window_support_level(window_list: Option<&WindowList>) -> Option<WindowSupportLevel> {
    window_list.and_then(|window_list| {
        (window_list.support_level != WindowSupportLevel::NotSupported).then_some(window_list.support_level)
    })
}

fn remote_app_rail_capability(
    remote_application_mode: bool,
    rail_support_level: RailSupportLevel,
    server_capability_sets: &[CapabilitySet],
    window_list: Option<&WindowList>,
) -> ConnectorResult<Option<Rail>> {
    if !remote_application_mode {
        return Ok(None);
    }
    if !rail_support_level.contains(RailSupportLevel::SUPPORTED) {
        return Err(reason_err!(
            "Capabilities Exchange",
            "client RemoteApp configuration does not support remote programs"
        ));
    }

    let rail_supported = server_capability_sets.iter().any(|capability_set| {
        matches!(
            capability_set,
            CapabilitySet::Rail(rail) if rail.support_level.contains(RailSupportLevel::SUPPORTED)
        )
    });
    let window_list_supported =
        window_list.is_some_and(|window_list| window_list.support_level != WindowSupportLevel::NotSupported);
    if !rail_supported || !window_list_supported {
        return Err(reason_err!(
            "Capabilities Exchange",
            "server does not support required RemoteApp capabilities"
        ));
    }

    Ok(Some(Rail {
        support_level: rail_support_level,
    }))
}

/// Build Client Confirm Active from the connection config and server capabilities.
///
/// Legacy graphics mode skips enhanced surface capabilities when no bitmap codecs are advertised.
fn create_client_confirm_active(
    config: &Config,
    mut server_capability_sets: Vec<CapabilitySet>,
    desktop_size: DesktopSize,
    window_list: Option<WindowList>,
) -> ConnectorResult<rdp::capability_sets::ClientConfirmActive> {
    use ironrdp_pdu::rdp::capability_sets::{
        BITMAP_CACHE_ENTRIES_NUM, Bitmap, BitmapCache, BitmapDrawingFlags, Brush, CacheDefinition, CacheEntry,
        ClientConfirmActive, CmdFlags, DemandActive, FrameAcknowledge, GLYPH_CACHE_NUM, General, GeneralExtraFlags,
        GlyphCache, GlyphSupportLevel, Input, LargePointer, LargePointerSupportFlags, MultifragmentUpdate,
        OffscreenBitmapCache, Order, OrderFlags, OrderSupportExFlags, Pointer, SERVER_CHANNEL_ID, Sound, SoundFlags,
        SupportLevel, SurfaceCommands, VirtualChannel, VirtualChannelFlags,
    };

    let remote_app_rail_capability = remote_app_rail_capability(
        config.remote_application_mode,
        config.rail_support_level,
        &server_capability_sets,
        window_list.as_ref(),
    )?;

    server_capability_sets.retain(|capability_set| matches!(capability_set, CapabilitySet::MultiFragmentUpdate(_)));

    let lossy_bitmap_compression = config
        .bitmap
        .as_ref()
        .map(|bitmap| bitmap.lossy_compression)
        .unwrap_or(false);
    let pref_bits_per_pix = requested_bitmap_color_depth(config.bitmap.as_ref())?;

    let drawing_flags = if lossy_bitmap_compression {
        BitmapDrawingFlags::ALLOW_SKIP_ALPHA
            | BitmapDrawingFlags::ALLOW_DYNAMIC_COLOR_FIDELITY
            | BitmapDrawingFlags::ALLOW_COLOR_SUBSAMPLING
    } else {
        BitmapDrawingFlags::ALLOW_SKIP_ALPHA
    };

    let bitmap_codecs = config.bitmap.as_ref().map(|bitmap| bitmap.codecs.clone());
    let enable_surface_commands = bitmap_codecs.as_ref().is_some_and(|codecs| !codecs.0.is_empty());

    server_capability_sets.extend_from_slice(&[
        CapabilitySet::General(General {
            major_platform_type: config.platform,
            extra_flags: GeneralExtraFlags::FASTPATH_OUTPUT_SUPPORTED | GeneralExtraFlags::NO_BITMAP_COMPRESSION_HDR,
            ..Default::default()
        }),
        CapabilitySet::Bitmap(Bitmap {
            pref_bits_per_pix,
            desktop_width: desktop_size.width,
            desktop_height: desktop_size.height,
            // This is required to be true in order for the Microsoft::Windows::RDS::DisplayControl DVC to work.
            desktop_resize_flag: true,
            drawing_flags,
        }),
        CapabilitySet::Order(Order::new(
            OrderFlags::NEGOTIATE_ORDER_SUPPORT | OrderFlags::ZERO_BOUNDS_DELTAS_SUPPORT,
            OrderSupportExFlags::empty(),
            0,
            0,
        )),
        CapabilitySet::BitmapCache(BitmapCache {
            caches: [CacheEntry {
                entries: 0,
                max_cell_size: 0,
            }; BITMAP_CACHE_ENTRIES_NUM],
        }),
        CapabilitySet::Input(Input {
            input_flags: InputFlags::all(),
            keyboard_layout: 0,
            keyboard_type: Some(config.keyboard_type),
            keyboard_subtype: config.keyboard_subtype,
            keyboard_function_key: config.keyboard_functional_keys_count,
            keyboard_ime_filename: config.ime_file_name.clone(),
        }),
        CapabilitySet::Pointer(Pointer {
            // Pointer cache should be set to non-zero value to enable client-side pointer rendering.
            color_pointer_cache_size: DEFAULT_POINTER_CACHE_SIZE,
            pointer_cache_size: DEFAULT_POINTER_CACHE_SIZE,
        }),
        CapabilitySet::Brush(Brush {
            support_level: SupportLevel::Default,
        }),
        CapabilitySet::GlyphCache(GlyphCache {
            glyph_cache: [CacheDefinition {
                entries: 0,
                max_cell_size: 0,
            }; GLYPH_CACHE_NUM],
            frag_cache: CacheDefinition {
                entries: 0,
                max_cell_size: 0,
            },
            glyph_support_level: GlyphSupportLevel::None,
        }),
        CapabilitySet::OffscreenBitmapCache(OffscreenBitmapCache {
            is_supported: false,
            cache_size: 0,
            cache_entries: 0,
        }),
        CapabilitySet::VirtualChannel(VirtualChannel {
            flags: VirtualChannelFlags::NO_COMPRESSION,
            chunk_size: Some(0), // ignored
        }),
        CapabilitySet::Sound(Sound {
            flags: SoundFlags::empty(),
        }),
        CapabilitySet::LargePointer(LargePointer {
            // Setting `LargePointerSupportFlags::UP_TO_384X384_PIXELS` allows server to send
            // `TS_FP_LARGEPOINTERATTRIBUTE` update messages, which are required for client-side
            // rendering of pointers bigger than 96x96 pixels.
            // `LargePointerSupportFlags::UP_TO_96X96_PIXELS` is needed for proper cursor behavior
            // in Windows 2019 and older
            flags: LargePointerSupportFlags::UP_TO_96X96_PIXELS | LargePointerSupportFlags::UP_TO_384X384_PIXELS,
        }),
    ]);

    if enable_surface_commands {
        // Advertise Surface Commands, Bitmap Codecs, and Frame Acknowledge only when a concrete
        // bitmap codec is present; otherwise keep basic bitmap updates for legacy servers.
        server_capability_sets.extend_from_slice(&[
            CapabilitySet::SurfaceCommands(SurfaceCommands {
                flags: CmdFlags::SET_SURFACE_BITS | CmdFlags::STREAM_SURFACE_BITS | CmdFlags::FRAME_MARKER,
            }),
            CapabilitySet::BitmapCodecs(bitmap_codecs.expect("checked by enable_surface_commands")),
            CapabilitySet::FrameAcknowledge(FrameAcknowledge {
                // FIXME(#447): Revert this to 2 per FreeRDP.
                // This is a temporary hack to fix a resize bug, see:
                // https://github.com/Devolutions/IronRDP/issues/447
                max_unacknowledged_frame_count: 20,
            }),
        ]);
    }

    if !server_capability_sets
        .iter()
        .any(|c| matches!(&c, CapabilitySet::MultiFragmentUpdate(_)))
    {
        server_capability_sets.push(CapabilitySet::MultiFragmentUpdate(MultifragmentUpdate {
            max_request_size: 8 * 1024 * 1024, // 8 MB
        }));
    }
    if let Some(rail) = remote_app_rail_capability {
        server_capability_sets.push(CapabilitySet::Rail(rail));
    }
    if let Some(window_list) = window_list {
        server_capability_sets.push(CapabilitySet::WindowList(window_list));
    }

    Ok(ClientConfirmActive {
        originator_id: SERVER_CHANNEL_ID,
        pdu: DemandActive {
            source_descriptor: "IRONRDP".to_owned(),
            capability_sets: server_capability_sets,
        },
    })
}

/// Returns the color depth requested by the client configuration for the Bitmap Capability Set.
///
/// [MS-RDPBCGR] requires `preferredBitsPerPixel` to match the requested Client Core Data color
/// depth. Keeping these values aligned is particularly important for non-32-bpp clients: a 32-bpp
/// Bitmap Capability Set permits the server to select RDP 6.0 bitmap compression instead.
///
/// [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/49e7bcb9-a8d7-46f5-987e-46c63c44b2c4
fn requested_bitmap_color_depth(bitmap: Option<&crate::BitmapConfig>) -> ConnectorResult<u16> {
    match bitmap.map_or(32, |bitmap| bitmap.color_depth) {
        15 => Ok(15),
        16 => Ok(16),
        24 => Ok(24),
        32 => Ok(32),
        color_depth => Err(reason_err!(
            "create client confirm active",
            "unsupported bitmap color depth: {color_depth}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use ironrdp_pdu::gcc;
    use ironrdp_pdu::rdp::capability_sets::{
        BitmapCodecs, CapabilitySet, Codec, CodecProperty, FrameAcknowledge, Rail, RailSupportLevel, WindowList,
        WindowSupportLevel,
    };

    use super::{
        create_client_confirm_active, negotiated_window_support_level, remote_app_rail_capability,
        requested_bitmap_color_depth, server_window_list,
    };
    use crate::{BitmapConfig, Config, Credentials, DesktopSize};

    #[test]
    fn bitmap_capability_uses_requested_color_depth() {
        assert_eq!(requested_bitmap_color_depth(None).unwrap(), 32);
        for expected_color_depth in [15, 16, 24, 32] {
            let bitmap = BitmapConfig {
                color_depth: u32::from(expected_color_depth),
                lossy_compression: false,
                codecs: BitmapCodecs(Vec::new()),
            };

            assert_eq!(
                requested_bitmap_color_depth(Some(&bitmap)).unwrap(),
                expected_color_depth
            );
        }
    }

    #[test]
    fn window_list_capability_preserves_supported_level() {
        let window_list = WindowList {
            support_level: WindowSupportLevel::SupportedEx,
            num_icon_caches: 3,
            num_icon_cache_entries: 12,
        };
        let capabilities = vec![CapabilitySet::WindowList(window_list.clone())];

        assert_eq!(server_window_list(&capabilities), Some(window_list));
        assert_eq!(
            negotiated_window_support_level(server_window_list(&capabilities).as_ref()),
            Some(WindowSupportLevel::SupportedEx)
        );
        assert_eq!(negotiated_window_support_level(None), None);
        assert_eq!(
            negotiated_window_support_level(Some(&WindowList {
                support_level: WindowSupportLevel::NotSupported,
                num_icon_caches: 0,
                num_icon_cache_entries: 0,
            })),
            None
        );
    }

    #[test]
    fn remote_app_capabilities_require_server_rail_and_window_list() {
        let rail_support_level = RailSupportLevel::SUPPORTED;
        let window_list = WindowList {
            support_level: WindowSupportLevel::SupportedEx,
            num_icon_caches: 3,
            num_icon_cache_entries: 12,
        };
        let rail = CapabilitySet::Rail(Rail {
            support_level: RailSupportLevel::SUPPORTED,
        });

        assert_eq!(
            remote_app_rail_capability(
                true,
                rail_support_level,
                core::slice::from_ref(&rail),
                Some(&window_list)
            )
            .unwrap(),
            Some(Rail {
                support_level: rail_support_level,
            })
        );
        assert!(remote_app_rail_capability(true, rail_support_level, &[], Some(&window_list)).is_err());
        assert!(remote_app_rail_capability(true, rail_support_level, core::slice::from_ref(&rail), None).is_err());
    }

    #[test]
    fn remote_app_capabilities_require_client_rail_support() {
        let window_list = WindowList {
            support_level: WindowSupportLevel::Supported,
            num_icon_caches: 0,
            num_icon_cache_entries: 0,
        };
        let rail = CapabilitySet::Rail(Rail {
            support_level: RailSupportLevel::SUPPORTED,
        });

        assert!(
            remote_app_rail_capability(
                true,
                RailSupportLevel::empty(),
                core::slice::from_ref(&rail),
                Some(&window_list)
            )
            .is_err()
        );
    }

    #[test]
    fn confirm_active_omits_surface_capabilities_without_bitmap_codecs() {
        for bitmap in [
            None,
            Some(BitmapConfig {
                color_depth: 32,
                lossy_compression: false,
                codecs: BitmapCodecs(Vec::new()),
            }),
        ] {
            let confirm = create_client_confirm_active(
                &test_config(bitmap),
                Vec::new(),
                DesktopSize {
                    width: 1024,
                    height: 768,
                },
                None,
            )
            .unwrap();

            assert!(
                !confirm
                    .pdu
                    .capability_sets
                    .iter()
                    .any(|capability| matches!(capability, CapabilitySet::SurfaceCommands(_))),
                "legacy graphics must omit SurfaceCommands"
            );
            assert!(
                !confirm
                    .pdu
                    .capability_sets
                    .iter()
                    .any(|capability| matches!(capability, CapabilitySet::BitmapCodecs(_))),
                "legacy graphics must omit BitmapCodecs"
            );
            assert!(
                !confirm
                    .pdu
                    .capability_sets
                    .iter()
                    .any(|capability| matches!(capability, CapabilitySet::FrameAcknowledge(_))),
                "legacy graphics must omit FrameAcknowledge"
            );
        }
    }

    #[test]
    fn confirm_active_advertises_surface_capabilities_with_bitmap_codecs() {
        let codecs = BitmapCodecs(vec![Codec {
            id: 1,
            property: CodecProperty::Ignore,
        }]);
        let confirm = create_client_confirm_active(
            &test_config(Some(BitmapConfig {
                color_depth: 32,
                lossy_compression: false,
                codecs: codecs.clone(),
            })),
            Vec::new(),
            DesktopSize {
                width: 1024,
                height: 768,
            },
            None,
        )
        .unwrap();

        assert!(
            confirm
                .pdu
                .capability_sets
                .iter()
                .any(|capability| matches!(capability, CapabilitySet::SurfaceCommands(_)))
        );
        assert!(
            confirm
                .pdu
                .capability_sets
                .contains(&CapabilitySet::BitmapCodecs(codecs))
        );
        assert!(confirm.pdu.capability_sets.iter().any(|capability| matches!(
            capability,
            CapabilitySet::FrameAcknowledge(FrameAcknowledge {
                max_unacknowledged_frame_count: 20,
            })
        )));
    }

    fn test_config(bitmap: Option<BitmapConfig>) -> Config {
        Config {
            desktop_size: DesktopSize {
                width: 1024,
                height: 768,
            },
            monitor_layout: None,
            desktop_scale_factor: 0,
            desktop_physical_size: None,
            desktop_orientation: None,
            device_scale_factor: None,
            monitor_extended_layout: None,
            relative_mouse_input: false,
            enable_tls: true,
            enable_credssp: false,
            enable_standard_rdp_security: false,
            credentials: Credentials::UsernamePassword {
                username: "test".into(),
                password: "test".into(),
            },
            domain: None,
            client_build: 0,
            client_name: "test".into(),
            keyboard_type: gcc::KeyboardType::IBM_ENHANCED,
            keyboard_subtype: 0,
            keyboard_layout: 0,
            keyboard_functional_keys_count: 12,
            connection_type: gcc::ConnectionType::Lan,
            ime_file_name: String::new(),
            bitmap,
            dig_product_id: String::new(),
            client_dir: String::new(),
            platform: ironrdp_pdu::rdp::capability_sets::MajorPlatformType::UNIX,
            hardware_id: None,
            request_data: None,
            autologon: false,
            enable_audio_playback: false,
            enable_audio_capture: false,
            license_cache: None,
            compression_type: None,
            enable_server_pointer: false,
            pointer_software_rendering: false,
            multitransport_flags: None,
            support_dyn_vc_gfx_protocol: false,
            performance_flags: Default::default(),
            timezone_info: Default::default(),
            alternate_shell: String::new(),
            work_dir: String::new(),
            remote_application_mode: false,
            rail_support_level: RailSupportLevel::SUPPORTED,
        }
    }
}
