use core::any::TypeId;
use core::mem;
use core::net::SocketAddr;
use std::borrow::Cow;
use std::sync::Arc;

use ironrdp_core::{Encode, WriteBuf, decode, encode_vec};
use ironrdp_pdu::rdp::capability_sets::WindowSupportLevel;
use ironrdp_pdu::rdp::server_redirection::ServerRedirectionPdu;
use ironrdp_pdu::rdp::session_info::ServerAutoReconnect;
use ironrdp_pdu::x224::X224;
use ironrdp_pdu::{PduHint, gcc, mcs, nego, rdp};
use ironrdp_svc::{MAX_STATIC_CHANNELS, StaticChannelKey, StaticChannelSet, StaticVirtualChannel, SvcClientProcessor};
use tracing::{debug, error, info, warn};

use crate::channel_connection::{ChannelConnectionSequence, ChannelConnectionState};
use crate::connection_activation::{
    ConnectionActivationFactory, ConnectionActivationSequence, ConnectionActivationState,
};
use crate::license_exchange::{LicenseExchangeSequence, NoopLicenseCache};
use crate::{
    Config, ConnectorError, ConnectorErrorExt as _, ConnectorErrorKind, ConnectorResult, DesktopSize, MonotonicInstant,
    NegotiationFailure, Sequence, State, Written, encode_x224_packet, general_err, reason_err,
};

/// Maximum number of `Initiate Multitransport Request` PDUs the server is
/// permitted to send during bootstrapping, per MS-RDPBCGR 2.2.15.1 (one per
/// transport protocol: reliable + lossy UDP).
const MAX_MULTITRANSPORT_REQUESTS: usize = 2;

/// Size of the auto-detect header that precedes a Bandwidth Measure payload.
///
/// `headerLength` + `headerTypeId` + `sequenceNumber` + `requestType` +
/// `payloadLength`, which [MS-RDPBCGR] 2.2.14.1.3 pins by requiring
/// `headerLength` to be 0x08.
const AUTO_DETECT_HEADER_LEN: u32 = 8;

/// What one Bandwidth Measure message contributes to the Network Characteristics
/// Byte Count store, and the canonical source for the connect-time bandwidth
/// reasoning this file uses in several places (`UNMEASURABLE_INTERVAL_MS`, the
/// `BandwidthMeasureStop` arm below, [`Sequence::step`]'s doc). Those restate
/// only their own local decision plus a pointer here, so the reasoning behind
/// each one stays single-sourced instead of drifting across independent copies.
///
/// **What is counted.** [MS-RDPBCGR] 3.2.5.14 gives connect-time detection
/// exactly two accumulation steps, one on the Bandwidth Measure Payload and one
/// on the 0x002B Stop, both reading "increment ... by the value specified in
/// the **payloadLength** field plus the size of the header fields (8 bytes)".
/// The section's other accumulation rule, the one that counts every byte
/// received while the window is open, belongs to the 0x0014 and 0x0114 Starts,
/// the reliable and lossy UDP variants. Connect-time is 0x1014, whose step list
/// contains no such clause, so on this path the two per-message increments are
/// the whole of the byte count.
///
/// **Which request types are in scope.** Only the 0x002B Stop, encapsulated in
/// an Auto-Detect Request PDU during the connect-time phase, is handled here.
/// [MS-RDPBCGR] 2.2.14.1.4 scopes the Auto-Detect-Request-PDU form of 0x0429 to
/// *after* the RDP Connection Sequence has completed, so it cannot legitimately
/// arrive here; its other form, and 0x0629, are tunneled over a multitransport
/// channel this step never sees. The same 2.2.14.1.4 split sets `headerLength`
/// to 0x08 for 0x002B and 0x06 otherwise, which is what fixes `AUTO_DETECT_HEADER_LEN`
/// at 8 for this path specifically.
///
/// **Windows that could not be timed.** A driver whose `received_at` is always
/// `None` never opens a window (see [`Sequence::step`]'s doc), so its Results
/// report only the Stop's own payload against the untimed floor
/// (`UNMEASURABLE_INTERVAL_MS`) rather than a full count divided by a
/// `timeDelta` nobody measured. [MS-RDPBCGR] 3.2.5.14 states the Payload
/// increment unconditionally; gating it on the window being open is a
/// deliberate SHOULD-level deviation. It under-reports rather than over-reports
/// (a server acting on 3.3.5.14 picks conservative settings for such a client),
/// so it is not treated as a spec violation worth rejecting.
///
/// **This deliberately does not match FreeRDP.** FreeRDP counts the whole PDU
/// length at the framing layer, `bandwidthMeasureByteCount += length` in
/// `libfreerdp/core/rdp.c` after `rdp_read_header`, for any window including
/// connect-time, and then adds `payloadLength` again in
/// `libfreerdp/core/autodetect.c` for the Payload and the Stop. On the
/// connect-time path that counts the payload twice and adds framing bytes the
/// spec does not ask for. The figure is an informational QoS hint and the server
/// proceeds either way, so following the spec costs no interop and is easier to
/// justify than reproducing the reference's arithmetic. (This citation names
/// files and expressions in a project outside this tree; it may drift as
/// FreeRDP changes, and is not itself load-bearing for the decision above.)
fn counted_len(payload_len: usize) -> u32 {
    u32::try_from(payload_len)
        .unwrap_or(u32::MAX)
        .saturating_add(AUTO_DETECT_HEADER_LEN)
}

/// Reported as `timeDelta` when a connect-time bandwidth window was not timed.
/// See [`counted_len`]'s doc for why an untimed window is reported at all.
///
/// One millisecond rather than zero, because a server computing
/// `byteCount * 8 / timeDelta` divides by it ([MS-RDPBCGR] 3.3.5.14). It also
/// floors a window that was timed and elapsed in under a millisecond, where it is
/// a real bound rather than a stand-in.
const UNMEASURABLE_INTERVAL_MS: u32 = 1;

/// Outcome of a single multitransport bootstrapping request, passed to
/// [`ClientConnector::complete_multitransport()`].
///
/// The connector uses this to build the response PDU internally, carrying the
/// request ID from the server's original request. The request's 16-byte
/// security cookie is not echoed here: it binds the UDP transport itself, not
/// the main-channel response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultitransportResult {
    /// UDP transport was established successfully (`S_OK`).
    Success,
    /// UDP transport failed. The `u32` is the HRESULT error code (typically
    /// [`MultitransportResponsePdu::E_ABORT`](rdp::multitransport::MultitransportResponsePdu::E_ABORT)).
    Failure(u32),
}

impl MultitransportResult {
    const fn response_required(&self, soft_sync: bool) -> bool {
        soft_sync || matches!(self, Self::Failure(_))
    }

    /// Builds the required response PDU for this outcome and request.
    ///
    /// Successful initiation without Soft-Sync does not require a response.
    pub fn response_pdu(
        &self,
        request_id: u32,
        soft_sync: bool,
    ) -> Option<rdp::multitransport::MultitransportResponsePdu> {
        if !self.response_required(soft_sync) {
            return None;
        }

        Some(match self {
            Self::Success => rdp::multitransport::MultitransportResponsePdu::success(request_id),
            Self::Failure(hr) => multitransport_response(request_id, *hr),
        })
    }
}

/// Why a runtime-defined static virtual channel could not be registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicStaticChannelAttachError {
    /// The negotiated static-channel key space has no remaining entries.
    ChannelLimitReached,
    /// Another static channel already uses the requested channel name.
    DuplicateChannelName,
}

#[derive(Debug)]
pub struct ConnectionResult {
    pub io_channel_id: u16,
    pub user_channel_id: u16,
    /// MCS channel ID of the message channel, when one was negotiated.
    pub message_channel_id: Option<u16>,
    pub share_id: u32,
    pub static_channels: StaticChannelSet,
    pub desktop_size: DesktopSize,
    /// The server's Input capability flags from the Server Demand Active PDU.
    ///
    /// Per [MS-RDPBCGR] 2.2.8.1.2, fast-path input events may only be sent when
    /// `INPUT_FLAG_FASTPATH_INPUT` or `INPUT_FLAG_FASTPATH_INPUT2` is present; some
    /// servers (e.g. VirtualBox VRDP) close the connection on unsolicited fast-path
    /// input, so clients should fall back to slow-path input PDUs when neither flag
    /// is set.
    ///
    /// [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b8e7c588-51cb-455b-bb73-92d480903133
    pub input_flags: rdp::capability_sets::InputFlags,
    pub enable_server_pointer: bool,
    pub pointer_software_rendering: bool,
    /// Whether the server permits client Refresh Rect PDUs for visual recovery.
    pub refresh_rect_support: bool,
    /// Whether the server permits Suppress Output PDUs for visual recovery.
    pub suppress_output_support: bool,
    /// The Window List support level negotiated with the server.
    ///
    /// `None` means Window List was absent or disabled, so windowing orders
    /// retain ordinary desktop-session handling.
    pub window_support_level: Option<WindowSupportLevel>,
    /// The monitor layout reported by the server during connection finalization.
    pub monitor_layout: Option<rdp::finalization_messages::MonitorLayoutPdu>,
    /// Factory for producing connection activation sequences.
    ///
    /// Used to drive the [Deactivation-Reactivation Sequence] when a Server Deactivate All PDU is
    /// received: produce a fresh sequence, drive it to completion, then drop it.
    ///
    /// [Deactivation-Reactivation Sequence]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/dfc234ce-481a-4674-9a5d-2a7bafb14432
    pub activation_factory: ConnectionActivationFactory,
    /// The bulk compression type that was negotiated, if any.
    pub compression_type: Option<rdp::client_info::CompressionType>,
}

impl ConnectionResult {
    /// Whether both peers advertised Soft-Sync support for multitransport.
    pub fn multitransport_soft_sync(&self) -> bool {
        self.activation_factory.multitransport_soft_sync()
    }
}

/// How a client connection sequence ended.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "the outcome is produced once per connection and moved straight to its consumer"
)]
pub enum ConnectionOutcome {
    /// The connection is established and the session can start.
    Connected(ConnectionResult),
    /// The server sent a Server Redirection PDU ([MS-RDPBCGR] 3.2.5.13.1).
    ///
    /// The client must close this connection and connect to the target the PDU describes, sending its
    /// load-balancing information as the routing token and its session ID in the Client Cluster Data.
    ///
    /// [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/
    Redirected(Box<ServerRedirectionPdu>),
}

impl ConnectionOutcome {
    /// Returns the connection result, or an error for a client that does not follow redirections.
    pub fn into_connected(self) -> ConnectorResult<ConnectionResult> {
        match self {
            Self::Connected(result) => Ok(result),
            Self::Redirected(redirection) => Err(reason_err!(
                "Connect",
                "server requested a redirection to session {}, which this client does not follow",
                redirection.session_id
            )),
        }
    }
}

#[derive(Default, Debug)]
#[non_exhaustive]
pub enum ClientConnectorState {
    #[default]
    Consumed,

    ConnectionInitiationSendRequest,
    ConnectionInitiationWaitConfirm {
        requested_protocol: nego::SecurityProtocol,
    },
    EnhancedSecurityUpgrade {
        selected_protocol: nego::SecurityProtocol,
    },
    Credssp {
        selected_protocol: nego::SecurityProtocol,
    },
    /// Waiting for the server nonce over authenticated TLS.
    EntraAuthWaitNonce,
    /// Waiting for the caller to sign an RDP assertion bound to this nonce.
    EntraAuthPending {
        server_nonce: String,
    },
    /// Waiting for the server's authentication and authorization result.
    EntraAuthWaitResult,
    BasicSettingsExchangeSendInitial {
        selected_protocol: nego::SecurityProtocol,
    },
    BasicSettingsExchangeWaitResponse {
        connect_initial: mcs::ConnectInitial,
    },
    ChannelConnection {
        io_channel_id: u16,
        channel_connection: ChannelConnectionSequence,
    },
    SecureSettingsExchange {
        io_channel_id: u16,
        user_channel_id: u16,
    },
    ConnectTimeAutoDetection {
        io_channel_id: u16,
        user_channel_id: u16,
    },
    LicensingExchange {
        io_channel_id: u16,
        user_channel_id: u16,
        license_exchange: LicenseExchangeSequence,
    },
    /// Waiting for either an Initiate Multitransport Request or the Demand
    /// Active that ends the optional bootstrapping phase.
    ///
    /// The server may send 0, 1, or 2 requests, and there is no end marker for
    /// the set: it is not obliged to send Demand Active before the client acts
    /// on a request it has already sent. So each request is surfaced to the
    /// caller the moment it decodes, and the connector comes back here for the
    /// next PDU rather than trying to collect a batch it cannot know the size
    /// of. A PDU on the I/O channel is the Demand Active and ends the phase.
    MultitransportBootstrapping {
        io_channel_id: u16,
        user_channel_id: u16,
        /// MCS message channel negotiated during GCC, when the server offered
        /// one. Multitransport travels on it in both directions per
        /// MS-RDPBCGR 2.2.15.1 and 2.2.15.2, so it is both the channel inbound
        /// requests arrive on and the channel responses go out on. `None` means
        /// the server never offered one, in which case no request can be valid.
        message_channel_id: Option<u16>,
        /// How many requests have been surfaced so far, to enforce the cap in
        /// MS-RDPBCGR 2.2.15.1 now that they are handled one at a time.
        requests_seen: usize,
    },
    /// A single Initiate Multitransport Request has been surfaced and the
    /// connector is waiting for the caller to establish that UDP transport
    /// (RDPEUDP2 + TLS + RDPEMT) or decline it.
    ///
    /// Call [`ClientConnector::complete_multitransport()`] or
    /// [`ClientConnector::skip_multitransport()`] to advance. Either returns
    /// the connector to [`Self::MultitransportBootstrapping`] to read whatever
    /// the server sends next, which may be a second request or the Demand
    /// Active.
    ///
    /// On the wire, TCP and UDP negotiation happen in parallel: the UDP
    /// transport is established alongside the ongoing TCP handshake, and
    /// its completion is a signal to the dynamic-channel layer that
    /// subsequent channels may migrate to UDP. The connector's suspension
    /// here is a Rust-API affordance, not a spec-mandated TCP pause.
    MultitransportPending {
        io_channel_id: u16,
        user_channel_id: u16,
        /// MCS message channel the Initiate Multitransport Response must go out
        /// on; see the same field on [`Self::MultitransportBootstrapping`].
        message_channel_id: Option<u16>,
        /// The request awaiting the caller's outcome.
        request: rdp::multitransport::MultitransportRequestPdu,
        /// Carried through so the cap survives the round trip through the
        /// caller.
        requests_seen: usize,
        /// Whether both peers advertised Soft-Sync, captured when this state was
        /// entered. Combined with the reported outcome this decides whether the
        /// completion and skip paths emit an Initiate Multitransport Response:
        /// a failure is always reported, while success is withheld unless
        /// Soft-Sync was negotiated.
        soft_sync: bool,
    },
    CapabilitiesExchange {
        connection_activation: ConnectionActivationSequence,
    },
    ConnectionFinalization {
        connection_activation: ConnectionActivationSequence,
    },
    Connected {
        result: ConnectionResult,
    },
    /// The server sent a Server Redirection PDU instead of completing the connection.
    ///
    /// See [`ConnectionOutcome::Redirected`].
    Redirected {
        redirection: Box<ServerRedirectionPdu>,
    },
}

impl ClientConnectorState {
    /// Takes the outcome out of a terminal state, leaving [`Self::Consumed`].
    pub fn take_outcome(&mut self) -> Option<ConnectionOutcome> {
        match mem::take(self) {
            Self::Connected { result } => Some(ConnectionOutcome::Connected(result)),
            Self::Redirected { redirection } => Some(ConnectionOutcome::Redirected(redirection)),
            other => {
                *self = other;
                None
            }
        }
    }
}

impl State for ClientConnectorState {
    fn name(&self) -> &'static str {
        match self {
            Self::Consumed => "Consumed",
            Self::ConnectionInitiationSendRequest => "ConnectionInitiationSendRequest",
            Self::ConnectionInitiationWaitConfirm { .. } => "ConnectionInitiationWaitResponse",
            Self::EnhancedSecurityUpgrade { .. } => "EnhancedSecurityUpgrade",
            Self::Credssp { .. } => "Credssp",
            Self::EntraAuthWaitNonce => "EntraAuthWaitNonce",
            Self::EntraAuthPending { .. } => "EntraAuthPending",
            Self::EntraAuthWaitResult => "EntraAuthWaitResult",
            Self::BasicSettingsExchangeSendInitial { .. } => "BasicSettingsExchangeSendInitial",
            Self::BasicSettingsExchangeWaitResponse { .. } => "BasicSettingsExchangeWaitResponse",
            Self::ChannelConnection { .. } => "ChannelConnection",
            Self::SecureSettingsExchange { .. } => "SecureSettingsExchange",
            Self::ConnectTimeAutoDetection { .. } => "ConnectTimeAutoDetection",
            Self::LicensingExchange { .. } => "LicensingExchange",
            Self::MultitransportBootstrapping { .. } => "MultitransportBootstrapping",
            Self::MultitransportPending { .. } => "MultitransportPending",
            Self::CapabilitiesExchange {
                connection_activation, ..
            } => connection_activation.state().name(),
            Self::ConnectionFinalization {
                connection_activation, ..
            } => connection_activation.state().name(),
            Self::Connected { .. } => "Connected",
            Self::Redirected { .. } => "Redirected",
        }
    }

    fn is_terminal(&self) -> bool {
        matches!(self, Self::Connected { .. } | Self::Redirected { .. })
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

#[expect(
    clippy::partial_pub_fields,
    reason = "server response flags are negotiated internally and must not expand the public connector construction API; the connect-time bandwidth accumulators are likewise internal to the measurement, and exposing them would let a caller break the Start/Payload/Stop invariant"
)]
#[derive(Debug)]
pub struct ClientConnector {
    pub config: Config,
    pub state: ClientConnectorState,
    /// The client address to be used in the Client Info PDU.
    pub client_addr: SocketAddr,
    pub static_channels: StaticChannelSet,
    /// MCS message channel ID assigned by the server, once negotiated.
    pub message_channel_id: Option<u16>,
    cluster_data: Option<gcc::ClientClusterData>,
    load_balance_info: Option<String>,
    /// X.224 negotiation flags supplied by the server.
    response_flags: nego::ResponseFlags,
    entra_auth: bool,
    /// Multitransport flags the server advertised in its GCC
    /// `MultiTransportChannelData` block, if it sent one. Retained because
    /// MS-RDPBCGR 2.2.15.2 permits an `S_OK` response only to a server that
    /// advertised `SOFTSYNC_TCP_TO_UDP`, so the outcome reported back depends on
    /// what both peers advertised.
    pub server_multitransport_flags: Option<gcc::MultiTransportFlags>,
    /// Auto-reconnect cookie from a previous session, when reconnecting.
    ///
    /// Set via [`ClientConnector::with_auto_reconnect_cookie`].
    pub auto_reconnect_cookie: Option<ServerAutoReconnect>,
    /// Password cookie from a Server Redirection PDU, sent in the Client Info PDU.
    redirection_password_cookie: Option<Vec<u8>>,
    /// Start of the in-flight connect-time bandwidth measurement window.
    ///
    /// Set when the server's Bandwidth Measure Start arrives, and only when the
    /// driver reported an arrival time for it. Cleared when the matching Stop is
    /// answered. `None` therefore means no window is open, whether because no Start
    /// was seen or because this driver does not observe time at all.
    connect_time_bw_started_at: Option<MonotonicInstant>,
    /// Bytes seen in the open window, accumulated across Payload messages.
    ///
    /// Only accumulated while a window is open, since a total with no interval to
    /// divide it by is not a measurement of anything.
    connect_time_bw_bytes: u32,
}

impl ClientConnector {
    pub fn new(config: Config, client_addr: SocketAddr) -> Self {
        Self {
            config,
            state: ClientConnectorState::ConnectionInitiationSendRequest,
            client_addr,
            static_channels: StaticChannelSet::new(),
            message_channel_id: None,
            cluster_data: None,
            load_balance_info: None,
            response_flags: nego::ResponseFlags::empty(),
            entra_auth: false,
            server_multitransport_flags: None,
            auto_reconnect_cookie: None,
            redirection_password_cookie: None,
            connect_time_bw_started_at: None,
            connect_time_bw_bytes: 0,
        }
    }

    /// Require RDS AAD Auth instead of TLS-only logon or CredSSP.
    ///
    /// The caller must validate the target's TLS certificate and sign a nonce-bound RDP assertion with a PoP-bound RDP access token.
    /// See [MS-RDPBCGR] 5.4.5.4.1 for token and assertion requirements.
    /// This does not acquire tokens, invoke WAM, or permit fallback to another authentication method.
    /// Call this before starting negotiation.
    ///
    /// [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/
    #[must_use]
    pub fn with_entra_auth(mut self) -> Self {
        self.entra_auth = true;
        self
    }

    /// The server nonce to bind into the caller-signed RDP assertion.
    pub fn entra_server_nonce(&self) -> Option<&str> {
        match &self.state {
            ClientConnectorState::EntraAuthPending { server_nonce } => Some(server_nonce),
            _ => None,
        }
    }

    /// Write a signed compact JWS RDP assertion to the authenticated TLS transport.
    ///
    /// Supply an RDP assertion, not a bearer access token.
    /// The caller is responsible for its signature, claims, and binding to [`Self::entra_server_nonce`].
    /// The assertion is not retained or logged by the connector; the caller must send and clear `output`.
    pub fn submit_entra_assertion(&mut self, assertion: &str, output: &mut WriteBuf) -> ConnectorResult<Written> {
        if !matches!(self.state, ClientConnectorState::EntraAuthPending { .. }) {
            return Err(reason_err!("EntraAuth", "no server nonce is awaiting an assertion"));
        }
        let written = crate::entra::write_assertion(assertion, output)?;
        self.state = ClientConnectorState::EntraAuthWaitResult;
        Ok(written)
    }

    /// Attempt to resume a previous session using its auto-reconnect cookie.
    ///
    /// The cookie is handed to the client by the server in a Save Session Info
    /// PDU ([MS-RDPBCGR] 2.2.10.1) and is bound to one session. Supplying it here
    /// makes the connector send the derived Client Auto-Reconnect Packet
    /// ([MS-RDPBCGR] 2.2.4.3) in the Client Info PDU, which lets the server
    /// reattach the session without prompting for credentials again
    /// ([MS-RDPBCGR] 1.3.1.5).
    ///
    /// The server regenerates the cookie whenever a client connects and again at
    /// hourly intervals ([MS-RDPBCGR] 3.3.6.2), so pass the most recent one
    /// received. A stale or absent cookie is not an error: the server falls back
    /// to a normal logon.
    #[must_use]
    pub fn with_auto_reconnect_cookie(mut self, cookie: ServerAutoReconnect) -> Self {
        self.auto_reconnect_cookie = Some(cookie);
        self
    }

    /// Add GCC Client Cluster Data to advertise or request server-session redirection.
    #[must_use]
    pub fn with_cluster_data(mut self, cluster_data: gcc::ClientClusterData) -> Self {
        self.cluster_data = Some(cluster_data);
        self
    }

    /// Send the password cookie of a Server Redirection PDU in the Client Info PDU.
    ///
    /// [MS-RDPBCGR] 2.2.13.1 asks the client to pass the `Password` field of the Server Redirection Packet to the
    /// target server.
    /// The cookie replaces the configured password in the Client Info PDU only; the credentials still authenticate
    /// CredSSP.
    ///
    /// [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/
    #[must_use]
    pub fn with_redirection_password_cookie(mut self, cookie: Vec<u8>) -> Self {
        self.redirection_password_cookie = Some(cookie);
        self
    }

    /// Set opaque load-balancing data for the initial X.224 Connection Request.
    #[must_use]
    pub fn with_load_balance_info(mut self, load_balance_info: String) -> Self {
        self.load_balance_info = Some(load_balance_info);
        self
    }

    /// Send the initial X.224 request with an explicit security protocol set.
    pub fn initiate_with_security_protocol(
        &mut self,
        security_protocol: nego::SecurityProtocol,
        output: &mut WriteBuf,
    ) -> ConnectorResult<Written> {
        if !matches!(self.state, ClientConnectorState::ConnectionInitiationSendRequest) {
            return Err(reason_err!("Initiation", "connection initiation has already started"));
        }

        let enabled_protocols = self.enabled_security_protocols()?;
        if !enabled_protocols.contains(security_protocol)
            || (self.entra_auth && security_protocol != nego::SecurityProtocol::RDSAAD)
        {
            return Err(reason_err!(
                "Initiation",
                "requested security protocols {security_protocol} are not enabled by connector configuration",
            ));
        }

        self.state = ClientConnectorState::Consumed;
        self.encode_connection_request(security_protocol, output)
    }

    fn enabled_security_protocols(&self) -> ConnectorResult<nego::SecurityProtocol> {
        if self.entra_auth {
            return Ok(nego::SecurityProtocol::RDSAAD);
        }
        let mut security_protocol = nego::SecurityProtocol::empty();

        if self.config.enable_tls {
            security_protocol.insert(nego::SecurityProtocol::SSL);
        }
        if self.config.enable_credssp {
            // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/902b090b-9cb3-4efc-92bf-ee13373371e3
            // PROTOCOL_HYBRID "SHOULD" also set PROTOCOL_SSL, but it is not a MUST.
            // IronRDP intentionally omits SSL unless enable_tls is set so the server
            // cannot silently downgrade NLA to TLS-only.
            security_protocol.insert(nego::SecurityProtocol::HYBRID | nego::SecurityProtocol::HYBRID_EX);
        }

        // PROTOCOL_RDP (empty flags) is standard RDP security. IronRDP only supports the
        // ENCRYPTION_LEVEL_NONE variant (no RC4 Security Exchange). Keep it opt-in so
        // `enable_tls = false` + `enable_credssp = false` cannot silently open a plaintext
        // TCP session; local named-pipe transports set `enable_standard_rdp_security`.
        if security_protocol.is_standard_rdp_security() {
            if !self.config.enable_standard_rdp_security {
                return Err(reason_err!("Initiation", "standard RDP security is not supported"));
            }
            debug!("Advertising standard RDP security (PROTOCOL_RDP / no enhanced protocols)");
        }

        Ok(security_protocol)
    }

    fn encode_connection_request(
        &mut self,
        security_protocol: nego::SecurityProtocol,
        output: &mut WriteBuf,
    ) -> ConnectorResult<Written> {
        let connection_request = nego::ConnectionRequest {
            nego_data: if self.load_balance_info.is_none() {
                self.config.request_data.clone().or_else(|| {
                    self.config
                        .credentials
                        .username()
                        .map(|username| nego::NegoRequestData::cookie(username.to_owned()))
                })
            } else {
                None
            },
            flags: nego::RequestFlags::empty(),
            protocol: security_protocol,
            correlation_info: None,
        };

        debug!(message = ?connection_request, "Send");

        let written = if let Some(load_balance_info) = &self.load_balance_info {
            let request = nego::ConnectionRequestWithOpaqueRoutingToken {
                request: connection_request,
                routing_token: nego::OpaqueRoutingToken(load_balance_info.clone()),
            };
            ironrdp_core::encode_buf(&X224(request), output)
        } else {
            ironrdp_core::encode_buf(&X224(connection_request), output)
        }
        .map_err(ConnectorError::encode)?;
        self.state = ClientConnectorState::ConnectionInitiationWaitConfirm {
            requested_protocol: security_protocol,
        };
        Written::from_size(written)
    }

    /// Whether Soft-Sync (`SOFTSYNC_TCP_TO_UDP`) was mutually advertised, meaning
    /// both peers set the flag in their GCC `MultiTransportChannelData` block.
    ///
    /// This does not by itself decide whether a response is sent. It gates
    /// success only: per [\[MS-RDPBCGR\] 2.2.15.2] `S_OK` "MUST only be sent to a
    /// server that advertises the SOFTSYNC_TCP_TO_UDP flag", while a failure is
    /// reported either way. See [`Self::multitransport_response_channel`].
    ///
    /// [\[MS-RDPBCGR\] 2.2.15.2]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/44044233-e498-46f8-8e16-1ffa595a8e8b
    fn soft_sync_negotiated(&self) -> bool {
        fn advertised(flags: Option<gcc::MultiTransportFlags>) -> bool {
            flags.is_some_and(|flags| flags.contains(gcc::MultiTransportFlags::SOFT_SYNC_TCP_TO_UDP))
        }

        advertised(self.config.multitransport_flags) && advertised(self.server_multitransport_flags)
    }

    #[must_use]
    pub fn with_static_channel<T>(mut self, channel: T) -> Self
    where
        T: SvcClientProcessor + 'static,
    {
        self.attach_static_channel(channel);
        self
    }

    pub fn attach_static_channel<T>(&mut self, channel: T)
    where
        T: SvcClientProcessor + 'static,
    {
        let channel_name = channel.channel_name();
        let channel_key = StaticChannelKey::Typed(TypeId::of::<T>());
        if self.static_channels.get_by_type::<T>().is_none() && self.static_channels.len() >= MAX_STATIC_CHANNELS {
            warn!(max_channels = MAX_STATIC_CHANNELS, "Static channel limit reached");
            return;
        }
        if let Some((existing_key, _)) = self.static_channels.get_by_channel_name_key(&channel_name)
            && existing_key != channel_key
        {
            warn!(?channel_name, "Static channel name is already registered");
            return;
        }
        self.static_channels.insert(channel);
    }

    /// Attaches a runtime-defined static virtual channel.
    ///
    /// This permits multiple instances of the same processor type, each with its own negotiated
    /// channel name. `false` means the static-channel limit was reached or the name is already
    /// registered.
    pub fn attach_dynamic_static_channel<T>(&mut self, channel: T) -> bool
    where
        T: SvcClientProcessor + 'static,
    {
        self.try_attach_dynamic_static_channel(channel).is_ok()
    }

    /// Attaches a runtime-defined static virtual channel, returning the reason when it cannot be
    /// registered.
    pub fn try_attach_dynamic_static_channel<T>(&mut self, channel: T) -> Result<(), DynamicStaticChannelAttachError>
    where
        T: SvcClientProcessor + 'static,
    {
        let channel_name = channel.channel_name();
        if self.static_channels.len() >= MAX_STATIC_CHANNELS {
            return Err(DynamicStaticChannelAttachError::ChannelLimitReached);
        }
        if self.static_channels.get_by_channel_name_key(&channel_name).is_some() {
            return Err(DynamicStaticChannelAttachError::DuplicateChannelName);
        }
        self.static_channels
            .insert_dynamic(channel)
            .map(|_| ())
            .ok_or(DynamicStaticChannelAttachError::ChannelLimitReached)
    }

    pub fn get_static_channel_processor<T>(&mut self) -> Option<&T>
    where
        T: SvcClientProcessor + 'static,
    {
        self.static_channels
            .get_by_type::<T>()
            .and_then(|channel| channel.channel_processor_downcast_ref())
    }

    pub fn get_static_channel_processor_mut<T>(&mut self) -> Option<&mut T>
    where
        T: SvcClientProcessor + 'static,
    {
        self.static_channels
            .get_by_type_mut::<T>()
            .and_then(|channel| channel.channel_processor_downcast_mut())
    }

    pub fn should_perform_security_upgrade(&self) -> bool {
        matches!(self.state, ClientConnectorState::EnhancedSecurityUpgrade { .. })
    }

    /// Advance past [`ClientConnectorState::EnhancedSecurityUpgrade`] after TLS is already done.
    ///
    /// # Panics
    ///
    /// Panics if state is not [ClientConnectorState::EnhancedSecurityUpgrade].
    pub fn mark_security_upgrade_as_done(&mut self) {
        assert!(self.should_perform_security_upgrade());
        self.step(&[], None, &mut WriteBuf::new())
            .expect("transition to next state");
        debug_assert!(!self.should_perform_security_upgrade());
    }

    pub fn should_perform_credssp(&self) -> bool {
        matches!(self.state, ClientConnectorState::Credssp { .. })
    }

    /// Returns whether the connector is in the Entra RDS AAD authentication exchange.
    pub fn should_perform_entra_auth(&self) -> bool {
        matches!(
            self.state,
            ClientConnectorState::EntraAuthWaitNonce
                | ClientConnectorState::EntraAuthPending { .. }
                | ClientConnectorState::EntraAuthWaitResult
        )
    }

    /// Advance past [`ClientConnectorState::Credssp`] after NLA is already done.
    ///
    /// # Panics
    ///
    /// Panics if state is not [ClientConnectorState::Credssp].
    pub fn mark_credssp_as_done(&mut self) {
        assert!(self.should_perform_credssp());
        let res = self
            .step(&[], None, &mut WriteBuf::new())
            .expect("transition to next state");
        debug_assert!(!self.should_perform_credssp());
        assert_eq!(res, Written::Nothing);
    }

    /// Returns `true` when the server has sent an Initiate Multitransport
    /// Request and the connector is waiting for the application to either
    /// establish that UDP transport or decline it.
    ///
    /// The application should:
    ///
    /// 1. Call [`multitransport_request()`](Self::multitransport_request) to
    ///    get the server's request
    /// 2. Establish UDP transport (RDPEUDP2 + TLS + RDPEMT), or decide not to
    /// 3. Call [`complete_multitransport()`](Self::complete_multitransport) with
    ///    the [`MultitransportResult`], or
    ///    [`skip_multitransport()`](Self::skip_multitransport) to decline
    ///
    /// This can come round more than once. MS-RDPBCGR 2.2.15.1 permits two
    /// requests, one per transport protocol, and each is surfaced on its own
    /// as soon as it decodes rather than batched, because the server is not
    /// obliged to announce that it has finished sending them.
    pub fn should_perform_multitransport(&self) -> bool {
        matches!(self.state, ClientConnectorState::MultitransportPending { .. })
    }

    /// Returns the multitransport request PDU awaiting an outcome.
    ///
    /// `None` unless
    /// [`should_perform_multitransport()`](Self::should_perform_multitransport)
    /// returns `true`.
    pub fn multitransport_request(&self) -> Option<&rdp::multitransport::MultitransportRequestPdu> {
        match &self.state {
            ClientConnectorState::MultitransportPending { request, .. } => Some(request),
            _ => None,
        }
    }

    /// Returns whether both peers advertised Soft-Sync for the pending request.
    ///
    /// `None` means no multitransport request is pending.
    pub fn multitransport_soft_sync_negotiated(&self) -> Option<bool> {
        match &self.state {
            ClientConnectorState::MultitransportPending { soft_sync, .. } => Some(*soft_sync),
            _ => None,
        }
    }

    /// Report the outcome of the multitransport request currently surfaced by
    /// [`multitransport_request()`](Self::multitransport_request).
    ///
    /// The connector builds the response PDU internally from the stored request
    /// ID, sends it on the MCS message channel when one is owed for this outcome,
    /// and returns to reading. A failure is always reported; success is withheld
    /// unless Soft-Sync was negotiated, per MS-RDPBCGR 2.2.15.2. The next PDU may be a second request
    /// or the Demand Active that ends bootstrapping; either way the caller does
    /// not have to know which.
    ///
    /// Returns an error if the connector is not in `MultitransportPending`
    /// state.
    pub fn complete_multitransport(
        &mut self,
        result: MultitransportResult,
        output: &mut WriteBuf,
    ) -> ConnectorResult<Written> {
        self.respond_to_multitransport("complete_multitransport", result, output)
    }

    /// Decline the multitransport request currently surfaced.
    ///
    /// Use this when the application doesn't support or doesn't want UDP
    /// transport. This reports `E_ABORT`, which MS-RDPBCGR 3.2.5.15.1 asks for
    /// whenever the client cannot initiate the sideband channel, with no
    /// Soft-Sync condition attached; the server then continues TCP-only.
    ///
    /// Returns an error if the connector is not in `MultitransportPending`
    /// state.
    pub fn skip_multitransport(&mut self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        self.respond_to_multitransport(
            "skip_multitransport",
            MultitransportResult::Failure(rdp::multitransport::MultitransportResponsePdu::E_ABORT),
            output,
        )
    }

    /// The channel an Initiate Multitransport Response goes out on, or `None`
    /// when no response is owed.
    ///
    /// Which of the two applies is decided by the outcome as well as the mode.
    /// MS-RDPBCGR 3.2.5.15.1 asks for a response whenever the client could not
    /// initiate the sideband channel, with no Soft-Sync condition, and requires
    /// one either way once Soft-Sync is negotiated. 2.2.15.2 restricts only
    /// `S_OK`, which "MUST only be sent to a server that advertises the
    /// SOFTSYNC_TCP_TO_UDP flag". So a failure is reported whenever there is a
    /// channel to report it on, and only success is withheld.
    ///
    /// Under Soft-Sync the message channel is presupposed, and falling back to
    /// the I/O channel would put the response somewhere the server is not
    /// reading, so its absence is an error rather than a reason to improvise.
    ///
    /// Borrows rather than consuming, so the caller can resolve this while the
    /// connector is still in a state it can act on.
    fn multitransport_response_channel(&self, result: &MultitransportResult) -> ConnectorResult<Option<u16>> {
        let ClientConnectorState::MultitransportPending {
            message_channel_id,
            soft_sync,
            ..
        } = &self.state
        else {
            return Ok(None);
        };

        if !result.response_required(*soft_sync) {
            return Ok(None);
        }

        match *soft_sync {
            // Soft-Sync obliges a response either way, and presupposes the
            // message channel. Falling back to the I/O channel would put the
            // response somewhere the server is not reading, so its absence is an
            // error rather than a reason to improvise.
            true => message_channel_id
                .ok_or_else(|| {
                    general_err!("Soft-Sync was negotiated but the server never offered an MCS message channel")
                })
                .map(Some),
            // A failure is still reported: 3.2.5.15.1 asks for it whenever the
            // client could not initiate the channel, with no Soft-Sync condition.
            // It is a SHOULD, so a missing message channel means staying silent
            // rather than failing a connection over an optional report. In
            // practice one exists, since 2.2.15.1 puts the request on it.
            false => Ok(*message_channel_id),
        }
    }

    /// Shared body of [`Self::complete_multitransport`] and
    /// [`Self::skip_multitransport`]: declining is just an `E_ABORT` outcome,
    /// so the two differ only in the HRESULT they report.
    fn respond_to_multitransport(
        &mut self,
        caller: &str,
        result: MultitransportResult,
        output: &mut WriteBuf,
    ) -> ConnectorResult<Written> {
        // The state is read, never taken. Everything this needs is a scalar, so
        // nothing has to be moved out of `self.state`, and the transition at the
        // end is the only mutation. That makes state preservation structural: an
        // error anywhere above it leaves the connector exactly as it was, so the
        // caller can still see what failed and decline. Taking the state up front
        // and failing afterwards would leave it `Consumed`, with the error having
        // destroyed the state needed to act on it.
        let ClientConnectorState::MultitransportPending {
            io_channel_id,
            user_channel_id,
            message_channel_id,
            request,
            requests_seen,
            soft_sync,
        } = &self.state
        else {
            return Err(reason_err!(
                "MultitransportPending",
                "{caller} called outside MultitransportPending state",
            ));
        };
        let (io_channel_id, user_channel_id, message_channel_id, requests_seen, soft_sync) = (
            *io_channel_id,
            *user_channel_id,
            *message_channel_id,
            *requests_seen,
            *soft_sync,
        );
        let request_id = request.request_id;

        let response_channel = self.multitransport_response_channel(&result)?;

        // Whether a response is owed at all is decided by
        // `multitransport_response_channel`, which weighs the outcome against
        // Soft-Sync. Either way the outcome is consumed and the handshake
        // proceeds.
        let total_written = if let Some(response_channel) = response_channel {
            let response = result
                .response_pdu(request_id, soft_sync)
                .ok_or_else(|| general_err!("multitransport response channel selected without a required response"))?;

            encode_send_data_request(user_channel_id, response_channel, &response, output)?
        } else {
            0
        };

        // Back to reading. The server may send another request or the Demand
        // Active; nothing here needs to predict which.
        self.state = ClientConnectorState::MultitransportBootstrapping {
            io_channel_id,
            user_channel_id,
            message_channel_id,
            requests_seen,
        };

        // Nothing goes on the wire when no response is owed, and `from_size`
        // rejects a zero length.
        if total_written == 0 {
            Ok(Written::Nothing)
        } else {
            Written::from_size(total_written)
        }
    }

    fn respond_to_connect_time_autodetect(
        &mut self,
        request: rdp::autodetect::AutoDetectRequest,
        received_at: Option<MonotonicInstant>,
        message_channel_id: u16,
        user_channel_id: u16,
        output: &mut WriteBuf,
    ) -> ConnectorResult<Written> {
        use ironrdp_pdu::rdp::autodetect::{
            AutoDetectRequest, AutoDetectResponse, AutoDetectRspPdu, BW_RESULTS_CONNECT_TIME, BW_START_CONNECT_TIME,
            BW_STOP_CONNECT_TIME,
        };

        match request {
            AutoDetectRequest::RttRequest { sequence_number, .. } => {
                let response = AutoDetectRspPdu::new(AutoDetectResponse::RttResponse { sequence_number });
                let written = encode_send_data_request(user_channel_id, message_channel_id, &response, output)?;
                Written::from_size(written)
            }
            // Start opens the measurement window ([MS-RDPBCGR] 2.2.14.1.2). No reply is
            // due; we only note when it arrived.
            //
            // Only the connect-time variant belongs to this phase. [MS-RDPBCGR]
            // 3.2.5.14 gives 0x0014 and 0x0114, the reliable and lossy UDP Starts, a
            // different procedure: they accumulate every byte received rather than
            // just the Bandwidth Measure messages, and they are answered on a
            // multitransport channel. Opening a connect-time window for one would
            // measure the wrong thing and answer on the wrong channel, so they are
            // left alone here.
            //
            // A driver that reports no arrival time cannot time this window, so it does
            // not open one. That keeps the two unmeasurable situations distinct: a
            // window that was timed and turned out to be short is still a measurement,
            // while a driver with no clock never took one.
            AutoDetectRequest::BandwidthMeasureStart { request_type, .. } if request_type == BW_START_CONNECT_TIME => {
                self.connect_time_bw_started_at = received_at;
                self.connect_time_bw_bytes = 0;
                Ok(Written::Nothing)
            }
            // Payload carries the bytes whose transfer is being timed ([MS-RDPBCGR]
            // 2.2.14.1.3). No reply is due; accumulate so Stop can report the total.
            // With no window open there is nothing for the total to be divided by, so
            // there is nothing worth accumulating.
            //
            // [MS-RDPBCGR] 3.2.5.14 increments the Byte Count store by payloadLength
            // plus the size of the header fields (8 bytes: headerLength, headerTypeId,
            // sequenceNumber, requestType, and payloadLength itself), not by
            // payloadLength alone. `payload.len()` is exactly payloadLength, since
            // decode reads that many bytes into it after consuming the header fields.
            AutoDetectRequest::BandwidthMeasurePayload { payload, .. } => {
                if self.connect_time_bw_started_at.is_some() {
                    let len = counted_len(payload.len());
                    self.connect_time_bw_bytes = self.connect_time_bw_bytes.saturating_add(len);
                }
                Ok(Written::Nothing)
            }
            // A connect-time Bandwidth Measure Stop ([MS-RDPBCGR] 2.2.14.1.4) warrants a
            // Bandwidth Measure Results reply ([MS-RDPBCGR] 2.2.14.2.2), and only the
            // 0x002B form is handled here; see `counted_len`'s doc for why, and for the
            // byte-count and untimed-window reasoning this arm applies below.
            //
            // The reply is mandatory, not best-effort: FreeRDP-based servers (for
            // example GNOME Remote Desktop) block in their AWAIT_BW_RESULT state until
            // they receive it and never proceed to licensing without it, so omitting it
            // stalls the whole connection.
            AutoDetectRequest::BandwidthMeasureStop {
                sequence_number,
                request_type,
                payload,
            } if request_type == BW_STOP_CONNECT_TIME => {
                let stop_bytes = payload.as_ref().map_or(0, |p| counted_len(p.len()));

                // A window normally opens and closes on the same driver, so the same
                // driver stamps both Start and this Stop. Nothing enforces that: a
                // `Framed` rebuilt between the two (leftover bytes handed to a fresh
                // `Framed`, which starts with no arrival time of its own) would open a
                // window on one driver and close it on another with no reading, landing
                // in the `(Some, None)` arm below. That arm silently drops whatever this
                // window had accumulated; the debug log makes the drop visible instead of
                // leaving it indistinguishable from the ordinary no-window case.
                let (time_delta_ms, byte_count) = match (self.connect_time_bw_started_at, received_at) {
                    (Some(started_at), Some(stopped_at)) => {
                        let measured_ms =
                            u32::try_from(stopped_at.duration_since(started_at).as_millis()).unwrap_or(u32::MAX);
                        (
                            measured_ms.max(UNMEASURABLE_INTERVAL_MS),
                            self.connect_time_bw_bytes.saturating_add(stop_bytes),
                        )
                    }
                    (Some(_), None) => {
                        debug!(
                            dropped_bytes = self.connect_time_bw_bytes,
                            "Bandwidth Measure Stop arrived with no arrival time although its window was open; \
                             dropping the accumulated count"
                        );
                        (UNMEASURABLE_INTERVAL_MS, stop_bytes)
                    }
                    (None, _) => (UNMEASURABLE_INTERVAL_MS, stop_bytes),
                };

                self.connect_time_bw_started_at = None;
                self.connect_time_bw_bytes = 0;

                let response = AutoDetectRspPdu::new(AutoDetectResponse::BandwidthMeasureResults {
                    sequence_number,
                    response_type: BW_RESULTS_CONNECT_TIME,
                    time_delta_ms,
                    byte_count,
                });
                let written = encode_send_data_request(user_channel_id, message_channel_id, &response, output)?;
                Written::from_size(written)
            }
            // A Stop reaching here with any other requestType means a nonconformant
            // server. [MS-RDPBCGR] 2.2.14.1.4 scopes 0x0429-via-Auto-Detect-Request-PDU
            // to after the RDP Connection Sequence has completed, so during connect-time
            // detection the only legitimate form on this channel is 0x002B, matched
            // above; 0x0429 as a tunneled Sub-Header and 0x0629 both belong to a
            // multitransport channel this step never sees. No reply is owed here per
            // spec, but silently dropping it leaves nothing to debug a stalled
            // connection with, so it is noted rather than swallowed like the truly
            // expected continuous variants below.
            AutoDetectRequest::BandwidthMeasureStop {
                sequence_number,
                request_type,
                ..
            } => {
                warn!(
                    sequence_number,
                    request_type, "Unexpected Bandwidth Measure Stop requestType during connect-time auto-detection"
                );
                Ok(Written::Nothing)
            }
            // The Network Characteristics Result is informational; nothing to send.
            //
            // This also catches the continuous-detection Bandwidth Measure Start,
            // answered on a multitransport channel under a different procedure.
            // Reaching it here means a server sent a continuous request during
            // connect-time detection, which [MS-RDPBCGR] 3.2.5.14 does not provide for;
            // ignoring is the conservative response.
            _ => Ok(Written::Nothing),
        }
    }
}

/// Build an Initiate Multitransport Response carrying `hr_response`.
///
/// [`MultitransportResponsePdu::success`] covers `S_OK`; every other HRESULT,
/// whether a caller-supplied failure or the `E_ABORT` the skip path sends,
/// comes through here so the security-header framing lives in one place.
fn multitransport_response(request_id: u32, hr_response: u32) -> rdp::multitransport::MultitransportResponsePdu {
    rdp::multitransport::MultitransportResponsePdu {
        security_header: rdp::headers::BasicSecurityHeader {
            flags: rdp::headers::BasicSecurityHeaderFlags::TRANSPORT_RSP,
        },
        request_id,
        hr_response,
    }
}

fn advance_licensing_exchange(
    mut license_exchange: LicenseExchangeSequence,
    io_channel_id: u16,
    user_channel_id: u16,
    message_channel_id: Option<u16>,
    input: &[u8],
    received_at: Option<MonotonicInstant>,
    output: &mut WriteBuf,
) -> ConnectorResult<(Written, ClientConnectorState)> {
    let written = license_exchange.step(input, received_at, output)?;

    let next_state = if license_exchange.state.is_terminal() {
        ClientConnectorState::MultitransportBootstrapping {
            io_channel_id,
            user_channel_id,
            message_channel_id,
            requests_seen: 0,
        }
    } else {
        ClientConnectorState::LicensingExchange {
            io_channel_id,
            user_channel_id,
            license_exchange,
        }
    };

    Ok((written, next_state))
}

impl Sequence for ClientConnector {
    fn next_pdu_hint(&self) -> Option<&dyn PduHint> {
        match &self.state {
            ClientConnectorState::Consumed => None,
            ClientConnectorState::ConnectionInitiationSendRequest => None,
            ClientConnectorState::ConnectionInitiationWaitConfirm { .. } => Some(&ironrdp_pdu::X224_HINT),
            ClientConnectorState::EnhancedSecurityUpgrade { .. } => None,
            ClientConnectorState::Credssp { .. } => None,
            ClientConnectorState::EntraAuthWaitNonce | ClientConnectorState::EntraAuthWaitResult => {
                Some(&crate::entra::ENTRA_JSON_HINT)
            }
            ClientConnectorState::EntraAuthPending { .. } => None,
            ClientConnectorState::BasicSettingsExchangeSendInitial { .. } => None,
            ClientConnectorState::BasicSettingsExchangeWaitResponse { .. } if self.entra_auth => {
                Some(&crate::entra::ENTRA_POST_AUTH_X224_HINT)
            }
            ClientConnectorState::BasicSettingsExchangeWaitResponse { .. } => Some(&ironrdp_pdu::X224_HINT),
            ClientConnectorState::ChannelConnection { channel_connection, .. } => channel_connection.next_pdu_hint(),
            ClientConnectorState::SecureSettingsExchange { .. } => None,
            ClientConnectorState::ConnectTimeAutoDetection { .. } => {
                // Wait for input only when a message channel was negotiated, so
                // we can receive connect-time auto-detect requests there. With a
                // message channel the server always sends a PDU next in this phase
                // (a connect-time Auto-Detect Request on the message channel, or
                // the first licensing PDU on the I/O channel), so waiting here
                // cannot stall. Without one, this state reads nothing and
                // transitions straight to licensing.
                if self.message_channel_id.is_some() {
                    Some(&ironrdp_pdu::X224_HINT)
                } else {
                    None
                }
            }
            ClientConnectorState::LicensingExchange { license_exchange, .. } => license_exchange.next_pdu_hint(),
            ClientConnectorState::MultitransportBootstrapping { .. } => Some(&ironrdp_pdu::X224_HINT),
            ClientConnectorState::MultitransportPending { .. } => None,
            ClientConnectorState::CapabilitiesExchange {
                connection_activation, ..
            } => connection_activation.next_pdu_hint(),
            ClientConnectorState::ConnectionFinalization {
                connection_activation, ..
            } => connection_activation.next_pdu_hint(),
            ClientConnectorState::Connected { .. } | ClientConnectorState::Redirected { .. } => None,
        }
    }

    fn state(&self) -> &dyn State {
        &self.state
    }

    fn step(
        &mut self,
        input: &[u8],
        received_at: Option<MonotonicInstant>,
        output: &mut WriteBuf,
    ) -> ConnectorResult<Written> {
        let (written, next_state) = match mem::take(&mut self.state) {
            // Invalid state
            ClientConnectorState::Consumed => {
                return Err(general_err!("connector sequence state is consumed (this is a bug)",));
            }

            //== Connection Initiation ==//
            // Exchange supported security protocols and a few other connection flags.
            ClientConnectorState::ConnectionInitiationSendRequest => {
                debug!("Connection Initiation");
                let security_protocol = self.enabled_security_protocols()?;
                let written = self.encode_connection_request(security_protocol, output)?;
                (written, mem::take(&mut self.state))
            }
            ClientConnectorState::ConnectionInitiationWaitConfirm { requested_protocol } => {
                let connection_confirm = decode::<X224<nego::ConnectionConfirm>>(input)
                    .map_err(ConnectorError::decode)
                    .map(|p| p.0)?;

                debug!(message = ?connection_confirm, "Received");

                let (flags, selected_protocol) = match connection_confirm {
                    nego::ConnectionConfirm::Response { flags, protocol } => (flags, protocol),
                    nego::ConnectionConfirm::Failure { code } => {
                        error!(?code, "Received connection failure code");
                        return Err(ConnectorError::new(
                            "negotiation failure",
                            ConnectorErrorKind::Negotiation(NegotiationFailure::from(code)),
                        ));
                    }
                };

                info!(?selected_protocol, ?flags, "Server confirmed connection");

                // PROTOCOL_RDP is encoded as an empty bitset. `intersects` is false for two empty
                // sets, so treat standard RDP security as a special case.
                let protocol_ok = if selected_protocol.is_standard_rdp_security() {
                    requested_protocol.is_standard_rdp_security()
                } else if self.entra_auth {
                    selected_protocol == nego::SecurityProtocol::RDSAAD
                } else {
                    selected_protocol.intersects(requested_protocol)
                };
                if !protocol_ok {
                    return Err(reason_err!(
                        "Initiation",
                        "client advertised {requested_protocol}, but server selected {selected_protocol}",
                    ));
                }

                self.response_flags = flags;

                (
                    Written::Nothing,
                    ClientConnectorState::EnhancedSecurityUpgrade { selected_protocol },
                )
            }

            //== Upgrade to Enhanced RDP Security ==//
            // When PROTOCOL_RDP is selected there is no TLS/CredSSP front-end: the caller should
            // still invoke mark_security_upgrade_as_done() (a no-op upgrade) before continuing.
            // When SSL/HYBRID is selected, user code must perform the TLS handshake first.
            ClientConnectorState::EnhancedSecurityUpgrade { selected_protocol } => {
                let next_state = if selected_protocol.is_standard_rdp_security() {
                    debug!("Standard RDP security selected; skipping TLS and CredSSP");
                    ClientConnectorState::BasicSettingsExchangeSendInitial { selected_protocol }
                } else if selected_protocol
                    .intersects(nego::SecurityProtocol::HYBRID | nego::SecurityProtocol::HYBRID_EX)
                {
                    debug!("Begin NLA using CredSSP");
                    ClientConnectorState::Credssp { selected_protocol }
                } else if selected_protocol == nego::SecurityProtocol::RDSAAD {
                    ClientConnectorState::EntraAuthWaitNonce
                } else {
                    debug!("CredSSP is disabled, skipping NLA");
                    ClientConnectorState::BasicSettingsExchangeSendInitial { selected_protocol }
                };

                (Written::Nothing, next_state)
            }

            //== CredSSP ==//
            ClientConnectorState::Credssp { selected_protocol } => (
                Written::Nothing,
                ClientConnectorState::BasicSettingsExchangeSendInitial { selected_protocol },
            ),

            ClientConnectorState::EntraAuthWaitNonce => (
                Written::Nothing,
                ClientConnectorState::EntraAuthPending {
                    server_nonce: crate::entra::server_nonce(input)?,
                },
            ),
            ClientConnectorState::EntraAuthPending { server_nonce } => {
                self.state = ClientConnectorState::EntraAuthPending { server_nonce };
                return Err(reason_err!("EntraAuth", "a caller-signed RDP assertion is required"));
            }
            ClientConnectorState::EntraAuthWaitResult => {
                let code = crate::entra::authentication_result(input)?;
                if code != 0 {
                    return Err(ConnectorError::new("EntraAuth", ConnectorErrorKind::EntraAuth(code)));
                }
                (
                    Written::Nothing,
                    ClientConnectorState::BasicSettingsExchangeSendInitial {
                        selected_protocol: nego::SecurityProtocol::RDSAAD,
                    },
                )
            }

            //== Basic Settings Exchange ==//
            // Exchange basic settings including Core Data, Security Data and Network Data.
            ClientConnectorState::BasicSettingsExchangeSendInitial { selected_protocol } => {
                debug!("Basic Settings Exchange");

                let client_gcc_blocks = create_gcc_blocks(
                    &self.config,
                    self.cluster_data.as_ref(),
                    selected_protocol,
                    self.response_flags
                        .contains(nego::ResponseFlags::EXTENDED_CLIENT_DATA_SUPPORTED),
                    self.static_channels.values(),
                )?;

                let connect_initial =
                    mcs::ConnectInitial::with_gcc_blocks(client_gcc_blocks).map_err(ConnectorError::decode)?;

                debug!(message = ?connect_initial, "Send");

                let written = encode_x224_packet(&connect_initial, output)?;

                (
                    Written::from_size(written)?,
                    ClientConnectorState::BasicSettingsExchangeWaitResponse { connect_initial },
                )
            }
            ClientConnectorState::BasicSettingsExchangeWaitResponse { connect_initial } => {
                let input = if self.entra_auth {
                    crate::entra::skip_json_whitespace(input)
                } else {
                    input
                };
                let x224_payload = decode::<X224<crate::x224::X224Data<'_>>>(input)
                    .map_err(ConnectorError::decode)
                    .map(|p| p.0)?;
                let connect_response =
                    decode::<mcs::ConnectResponse>(x224_payload.data.as_ref()).map_err(ConnectorError::decode)?;

                debug!(message = ?connect_response, "Received");

                let client_gcc_blocks = connect_initial.conference_create_request.gcc_blocks();

                let server_gcc_blocks = connect_response.conference_create_response.into_gcc_blocks();

                if client_gcc_blocks.security == gcc::ClientSecurityData::no_security()
                    && server_gcc_blocks.security != gcc::ServerSecurityData::no_security()
                {
                    return Err(general_err!("can't satisfy server security settings"));
                }

                self.message_channel_id = server_gcc_blocks
                    .message_channel
                    .as_ref()
                    .map(|data| data.mcs_message_channel_id);

                self.server_multitransport_flags = server_gcc_blocks
                    .multi_transport_channel
                    .as_ref()
                    .map(|data| data.flags);

                let static_channel_ids = server_gcc_blocks.network.channel_ids;
                let io_channel_id = server_gcc_blocks.network.io_channel;

                debug!(?static_channel_ids, io_channel_id);

                let zipped: Vec<_> = self
                    .static_channels
                    .keys()
                    .zip(static_channel_ids.iter().copied())
                    .collect();

                zipped.into_iter().for_each(|(channel, channel_id)| {
                    self.static_channels.attach_channel_id_by_key(channel, channel_id);
                });

                let skip_channel_join = server_gcc_blocks
                    .core
                    .optional_data
                    .early_capability_flags
                    .is_some_and(|c| c.contains(gcc::ServerEarlyCapabilityFlags::SKIP_CHANNELJOIN_SUPPORTED));

                (
                    Written::Nothing,
                    ClientConnectorState::ChannelConnection {
                        io_channel_id,
                        channel_connection: if skip_channel_join {
                            ChannelConnectionSequence::skip_channel_join()
                        } else {
                            let mut join_channel_ids = static_channel_ids;
                            join_channel_ids.extend(self.message_channel_id);
                            ChannelConnectionSequence::new(io_channel_id, join_channel_ids)
                        },
                    },
                )
            }

            //== Channel Connection ==//
            // Connect every individual channel.
            ClientConnectorState::ChannelConnection {
                io_channel_id,
                mut channel_connection,
            } => {
                debug!("Channel Connection");
                let written = channel_connection.step(input, received_at, output)?;

                let next_state = if let ChannelConnectionState::AllJoined { user_channel_id } = channel_connection.state
                {
                    debug_assert!(channel_connection.state.is_terminal());

                    ClientConnectorState::SecureSettingsExchange {
                        io_channel_id,
                        user_channel_id,
                    }
                } else {
                    ClientConnectorState::ChannelConnection {
                        io_channel_id,
                        channel_connection,
                    }
                };

                (written, next_state)
            }

            //== RDP Security Commencement ==//
            // With standard RDP security and ENCRYPTION_LEVEL_NONE, no Security Exchange PDU is
            // sent (MS-RDPBCGR 5.3.2). IronRDP only supports that no-encryption path; RC4/FIPS
            // would require a Security Exchange here and is rejected earlier when the server's
            // SC_SECURITY block is not ServerSecurityData::no_security().
            //==============================//

            //== Secure Settings Exchange ==//
            // Send Client Info PDU (information about supported types of compression, username, password, etc).
            ClientConnectorState::SecureSettingsExchange {
                io_channel_id,
                user_channel_id,
            } => {
                debug!("Secure Settings Exchange");

                let client_info = create_client_info_pdu(
                    &self.config,
                    &self.client_addr,
                    self.auto_reconnect_cookie.as_ref(),
                    self.redirection_password_cookie.as_deref(),
                    self.entra_auth,
                );

                debug!(message = ?client_info, "Send");

                let written = encode_send_data_request(user_channel_id, io_channel_id, &client_info, output)?;

                (
                    Written::from_size(written)?,
                    ClientConnectorState::ConnectTimeAutoDetection {
                        io_channel_id,
                        user_channel_id,
                    },
                )
            }

            //== Optional Connect-Time Auto-Detection ==//
            // NOTE: IronRDP is not expecting the Auto-Detect Request PDU from server.
            ClientConnectorState::ConnectTimeAutoDetection {
                io_channel_id,
                user_channel_id,
            } => {
                // The server may run Optional Connect-Time Auto-Detection on the
                // message channel before licensing ([MS-RDPBCGR] 1.3.8). When a
                // message channel was negotiated we wait for a PDU here and demux
                // by MCS channel: a PDU on the message channel is never a licensing
                // PDU, so it must not be handed to the licensing sequence. An
                // auto-detect request is answered and we keep listening; any other
                // message-channel PDU is not ours to act on in this phase and is
                // ignored. The first PDU that is not on the message channel (the
                // licensing PDU on the I/O channel) ends the phase. Without a
                // message channel nothing is read and we go straight to licensing,
                // as before.
                // Decode the inbound PDU once and demux on the MCS channel.
                let message_channel_pdu = self.message_channel_id.and_then(|message_channel_id| {
                    let mcs = decode::<X224<mcs::McsMessage<'_>>>(input).ok()?;
                    match mcs.0 {
                        mcs::McsMessage::SendDataIndication(data) if data.channel_id == message_channel_id => {
                            Some((message_channel_id, data))
                        }
                        _ => None,
                    }
                });

                if let Some((message_channel_id, data)) = message_channel_pdu {
                    if let Ok(autodetect) = decode::<rdp::autodetect::AutoDetectReqPdu>(&data.user_data) {
                        let written = self.respond_to_connect_time_autodetect(
                            autodetect.request,
                            received_at,
                            message_channel_id,
                            user_channel_id,
                            output,
                        )?;
                        (
                            written,
                            ClientConnectorState::ConnectTimeAutoDetection {
                                io_channel_id,
                                user_channel_id,
                            },
                        )
                    } else {
                        // A message-channel PDU we do not handle in this phase (per the
                        // canonical sequence multitransport bootstrap is Phase 8 and
                        // heartbeat is post-connection, both after licensing). Ignore it
                        // and keep listening rather than decoding it as a licensing PDU.
                        (
                            Written::Nothing,
                            ClientConnectorState::ConnectTimeAutoDetection {
                                io_channel_id,
                                user_channel_id,
                            },
                        )
                    }
                } else {
                    let license_exchange = LicenseExchangeSequence::new(
                        io_channel_id,
                        self.config.credentials.username().unwrap_or("").to_owned(),
                        self.config.domain.clone(),
                        self.config.hardware_id.unwrap_or_default(),
                        self.config
                            .license_cache
                            .clone()
                            .unwrap_or_else(|| Arc::new(NoopLicenseCache)),
                    );
                    // If a PDU was read (message channel present) it is the first
                    // licensing PDU; advance the licensing sequence with it now,
                    // through the same helper the LicensingExchange state uses, so
                    // the terminal-state transition lives in one place. Otherwise
                    // nothing was read and the licensing sequence runs from its
                    // first step when the next PDU arrives.
                    if self.message_channel_id.is_some() {
                        advance_licensing_exchange(
                            license_exchange,
                            io_channel_id,
                            user_channel_id,
                            self.message_channel_id,
                            input,
                            received_at,
                            output,
                        )?
                    } else {
                        (
                            Written::Nothing,
                            ClientConnectorState::LicensingExchange {
                                io_channel_id,
                                user_channel_id,
                                license_exchange,
                            },
                        )
                    }
                }
            }

            //== Licensing ==//
            // Server is sending information regarding licensing.
            // Typically useful when support for more than two simultaneous connections is required (terminal server).
            ClientConnectorState::LicensingExchange {
                io_channel_id,
                user_channel_id,
                license_exchange,
            } => {
                debug!("Licensing Exchange");

                advance_licensing_exchange(
                    license_exchange,
                    io_channel_id,
                    user_channel_id,
                    self.message_channel_id,
                    input,
                    received_at,
                    output,
                )?
            }

            //== Optional Multitransport Bootstrapping ==//
            //
            // After licensing the server may send 0, 1, or 2 Initiate Multitransport
            // Request PDUs (MS-RDPBCGR 2.2.15.1), and it is under no obligation to
            // send the Demand Active before the client acts on one it has already
            // sent. There is therefore no end marker for the set, and waiting for a
            // following PDU to decide what to do with the current one can stall the
            // handshake outright. Each request is surfaced the moment it decodes,
            // per MS-RDPBCGR 3.2.5.15.1.
            //
            // Routing is by channel. Requests travel on the MCS message channel; the
            // Demand Active is on the I/O channel and ends the phase. The message
            // channel also carries auto-detect PDUs, so a decode still confirms what
            // arrived there, but the I/O channel is never speculatively decoded as
            // multitransport any more.
            ClientConnectorState::MultitransportBootstrapping {
                io_channel_id,
                user_channel_id,
                message_channel_id,
                requests_seen,
            } => {
                let ctx = mcs::decode_send_data_indication(input).map_err(ConnectorError::decode)?;

                if Some(ctx.channel_id) == message_channel_id {
                    let pdu = decode::<rdp::multitransport::MultitransportRequestPdu>(ctx.user_data)
                        .map_err(ConnectorError::decode)?;

                    if requests_seen >= MAX_MULTITRANSPORT_REQUESTS {
                        return Err(reason_err!(
                            "MultitransportBootstrapping",
                            "server sent more than {} multitransport requests (MS-RDPBCGR 2.2.15.1 caps the count at {})",
                            MAX_MULTITRANSPORT_REQUESTS,
                            MAX_MULTITRANSPORT_REQUESTS,
                        ));
                    }

                    debug!(
                        request_id = pdu.request_id,
                        protocol = ?pdu.requested_protocol,
                        "Received Initiate Multitransport Request"
                    );

                    // Captured on entry rather than read back at completion time: the
                    // GCC exchange carrying both peers' flags is long finished, and
                    // freezing it here keeps the response paths from depending on
                    // connector fields that could move in between.
                    let soft_sync = self.soft_sync_negotiated();

                    (
                        Written::Nothing,
                        ClientConnectorState::MultitransportPending {
                            io_channel_id,
                            user_channel_id,
                            message_channel_id,
                            request: pdu,
                            requests_seen: requests_seen + 1,
                            soft_sync,
                        },
                    )
                } else if ctx.channel_id == io_channel_id {
                    // Demand Active: bootstrapping is over, hand off to capabilities
                    // exchange with the PDU intact.
                    let mut connection_activation =
                        ConnectionActivationSequence::new(self.config.clone(), io_channel_id, user_channel_id);
                    let written = connection_activation.step(input, received_at, output)?;

                    (
                        written,
                        match connection_activation.connection_activation_state() {
                            ConnectionActivationState::ConnectionFinalization { .. } => {
                                ClientConnectorState::ConnectionFinalization { connection_activation }
                            }
                            ConnectionActivationState::Redirected { redirection } => {
                                ClientConnectorState::Redirected { redirection }
                            }
                            _ => ClientConnectorState::CapabilitiesExchange { connection_activation },
                        },
                    )
                } else {
                    return Err(reason_err!(
                        "MultitransportBootstrapping",
                        "PDU on unexpected channel {} (message channel is {}, I/O channel is {})",
                        ctx.channel_id,
                        message_channel_id
                            .map(|id| id.to_string())
                            .unwrap_or_else(|| "not negotiated".to_owned()),
                        io_channel_id,
                    ));
                }
            }

            // MultitransportPending: application should call complete_multitransport()
            // or skip_multitransport() instead of step()
            ClientConnectorState::MultitransportPending { .. } => {
                return Err(general_err!(
                    "multitransport pending: call complete_multitransport() or skip_multitransport()"
                ));
            }

            //== Capabilities Exchange ==/
            // The server sends the set of capabilities it supports to the client.
            ClientConnectorState::CapabilitiesExchange {
                mut connection_activation,
            } => {
                let written = connection_activation.step(input, received_at, output)?;
                match connection_activation.connection_activation_state() {
                    ConnectionActivationState::ConnectionFinalization { .. } => (
                        written,
                        ClientConnectorState::ConnectionFinalization { connection_activation },
                    ),
                    // The inner sequence stays in CapabilitiesExchange when it receives a
                    // Server Deactivate All PDU before the Server Demand Active PDU (sent
                    // by e.g. Windows Server and gnome-remote-desktop); mirror it here and
                    // wait for the next input.
                    ConnectionActivationState::CapabilitiesExchange => (
                        written,
                        ClientConnectorState::CapabilitiesExchange { connection_activation },
                    ),
                    ConnectionActivationState::Redirected { redirection } => {
                        (written, ClientConnectorState::Redirected { redirection })
                    }
                    _ => return Err(general_err!("invalid state (this is a bug)")),
                }
            }

            //== Connection Finalization ==//
            // Client and server exchange a few PDUs in order to finalize the connection.
            // Client may send PDUs one after the other without waiting for a response in order to speed up the process.
            ClientConnectorState::ConnectionFinalization {
                mut connection_activation,
            } => {
                let written = connection_activation.step(input, received_at, output)?;

                let next_state = if !connection_activation.connection_activation_state().is_terminal() {
                    ClientConnectorState::ConnectionFinalization { connection_activation }
                } else {
                    match connection_activation.connection_activation_state() {
                        ConnectionActivationState::Redirected { redirection } => {
                            ClientConnectorState::Redirected { redirection }
                        }
                        ConnectionActivationState::Finalized {
                            desktop_size,
                            share_id,
                            input_flags,
                            static_channel_chunk_size,
                            enable_server_pointer,
                            pointer_software_rendering,
                            refresh_rect_support,
                            suppress_output_support,
                            window_support_level,
                        } => {
                            let mut static_channels = mem::take(&mut self.static_channels);
                            if !static_channels.set_maximum_chunk_size(static_channel_chunk_size) {
                                return Err(general_err!("invalid static channel chunk size"));
                            }

                            ClientConnectorState::Connected {
                                result: ConnectionResult {
                                    io_channel_id: connection_activation.io_channel_id(),
                                    user_channel_id: connection_activation.user_channel_id(),
                                    message_channel_id: self.message_channel_id,
                                    share_id,
                                    static_channels,
                                    desktop_size,
                                    input_flags,
                                    enable_server_pointer,
                                    pointer_software_rendering,
                                    refresh_rect_support,
                                    suppress_output_support,
                                    window_support_level,
                                    monitor_layout: connection_activation.monitor_layout(),
                                    activation_factory: ConnectionActivationFactory::new(
                                        self.config.clone(),
                                        connection_activation.io_channel_id(),
                                        connection_activation.user_channel_id(),
                                    )
                                    .with_multitransport_soft_sync(self.soft_sync_negotiated()),
                                    compression_type: self.config.compression_type,
                                },
                            }
                        }
                        _ => return Err(general_err!("invalid state (this is a bug)")),
                    }
                };

                (written, next_state)
            }

            //== Connected ==//
            // The client connector job is done.
            ClientConnectorState::Connected { .. } => return Err(general_err!("already connected")),
            ClientConnectorState::Redirected { .. } => return Err(general_err!("already redirected")),
        };

        self.state = next_state;

        Ok(written)
    }
}

pub fn encode_send_data_request<T: Encode>(
    initiator_id: u16,
    channel_id: u16,
    user_msg: &T,
    buf: &mut WriteBuf,
) -> ConnectorResult<usize> {
    let user_data = encode_vec(user_msg).map_err(ConnectorError::encode)?;

    let pdu = mcs::SendDataRequest {
        initiator_id,
        channel_id,
        user_data: Cow::Owned(user_data),
    };

    let written = ironrdp_core::encode_buf(&X224(pdu), buf).map_err(ConnectorError::encode)?;

    Ok(written)
}

#[expect(single_use_lifetimes)] // anonymous lifetimes in `impl Trait` are unstable
fn create_gcc_blocks<'a>(
    config: &Config,
    cluster_data: Option<&gcc::ClientClusterData>,
    selected_protocol: nego::SecurityProtocol,
    extended_client_data_supported: bool,
    static_channels: impl Iterator<Item = &'a StaticVirtualChannel>,
) -> ConnectorResult<gcc::ClientGccBlocks> {
    use ironrdp_pdu::gcc::{
        ClientCoreData, ClientCoreOptionalData, ClientEarlyCapabilityFlags, ClientGccBlocks, ClientNetworkData,
        ClientSecurityData, ColorDepth, EncryptionMethod, HighColorDepth, MonitorOrientation, RdpVersion,
        SecureAccessSequence, SupportedColorDepths,
    };

    let max_color_depth = config.bitmap.as_ref().map(|bitmap| bitmap.color_depth).unwrap_or(32);

    // Derive the preferred depth indicator. 32bpp has no highColorDepth value; it is
    // expressed via WANT_32_BPP_SESSION in earlyCapabilityFlags instead.
    let high_color_depth = match max_color_depth {
        15 => HighColorDepth::Rgb555Bpp16,
        16 => HighColorDepth::Rgb565Bpp16,
        24 | 32 => HighColorDepth::Bpp24,
        _ => {
            return Err(reason_err!(
                "create gcc blocks",
                "unsupported color depth: {max_color_depth}"
            ));
        }
    };

    // Advertise all colour depth capabilities unconditionally. The preferred depth is
    // expressed via highColorDepth and WANT_32_BPP_SESSION, not by restricting this
    // bitmask. This lets servers negotiate down without resetting the connection.
    let supported_color_depths = SupportedColorDepths::BPP32
        | SupportedColorDepths::BPP24
        | SupportedColorDepths::BPP16
        | SupportedColorDepths::BPP15;

    let channels = static_channels
        .map(ironrdp_svc::make_channel_definition)
        .collect::<Vec<_>>();

    Ok(ClientGccBlocks {
        core: ClientCoreData {
            // Servers ignore the relative mouse capabilities below RDP 10.12 ([MS-RDPBCGR] 2.2.1.3.2,
            // 2.2.7.1.6), so only a client that sends relative input announces that version.
            version: if config.relative_mouse_input {
                RdpVersion::V10_12
            } else {
                RdpVersion::V5_PLUS
            },
            desktop_width: config.desktop_size.width,
            desktop_height: config.desktop_size.height,
            color_depth: ColorDepth::Bpp8, // ignored because we use the optional core data below
            sec_access_sequence: SecureAccessSequence::Del,
            keyboard_layout: config.keyboard_layout,
            client_build: config.client_build,
            client_name: config.client_name.clone(),
            keyboard_type: config.keyboard_type,
            keyboard_subtype: config.keyboard_subtype,
            keyboard_functional_keys_count: config.keyboard_functional_keys_count,
            ime_file_name: config.ime_file_name.clone(),
            optional_data: ClientCoreOptionalData {
                post_beta2_color_depth: Some(ColorDepth::Bpp8), // ignored because we set high_color_depth
                client_product_id: Some(1),
                serial_number: Some(0),
                high_color_depth: Some(high_color_depth),
                supported_color_depths: Some(supported_color_depths),
                early_capability_flags: {
                    let mut early_capability_flags = ClientEarlyCapabilityFlags::VALID_CONNECTION_TYPE
                        | ClientEarlyCapabilityFlags::SUPPORT_ERR_INFO_PDU
                        | ClientEarlyCapabilityFlags::STRONG_ASYMMETRIC_KEYS
                        | ClientEarlyCapabilityFlags::SUPPORT_NET_CHAR_AUTODETECT
                        | ClientEarlyCapabilityFlags::SUPPORT_SKIP_CHANNELJOIN;

                    // TODO(#136): support for ClientEarlyCapabilityFlags::SUPPORT_STATUS_INFO_PDU

                    if max_color_depth == 32 {
                        early_capability_flags |= ClientEarlyCapabilityFlags::WANT_32_BPP_SESSION;
                    }
                    if extended_client_data_supported {
                        early_capability_flags |= ClientEarlyCapabilityFlags::SUPPORT_MONITOR_LAYOUT_PDU;
                    }

                    if config.support_dyn_vc_gfx_protocol {
                        early_capability_flags |= ClientEarlyCapabilityFlags::SUPPORT_DYN_VC_GFX_PROTOCOL;
                    }
                    if config.relative_mouse_input {
                        early_capability_flags |= ClientEarlyCapabilityFlags::RELATIVE_MOUSE_INPUT;
                    }

                    Some(early_capability_flags)
                },
                dig_product_id: Some(config.dig_product_id.clone()),
                connection_type: Some(config.connection_type),
                server_selected_protocol: Some(selected_protocol),
                desktop_physical_width: Some(config.desktop_physical_size.map_or(0, |(width, _)| width)),
                desktop_physical_height: Some(config.desktop_physical_size.map_or(0, |(_, height)| height)),
                desktop_orientation: Some(
                    config
                        .desktop_orientation
                        .unwrap_or(if config.desktop_size.width > config.desktop_size.height {
                            MonitorOrientation::Landscape
                        } else {
                            MonitorOrientation::Portrait
                        })
                        .as_u16(),
                ),
                desktop_scale_factor: Some(config.desktop_scale_factor),
                device_scale_factor: if config.desktop_scale_factor >= 100 && config.desktop_scale_factor <= 500 {
                    Some(config.device_scale_factor.unwrap_or(100))
                } else {
                    Some(0)
                },
            },
        },
        security: ClientSecurityData {
            encryption_methods: EncryptionMethod::empty(),
            ext_encryption_methods: 0,
        },
        network: if channels.is_empty() {
            None
        } else {
            Some(ClientNetworkData { channels })
        },
        cluster: cluster_data.cloned(),
        monitor: extended_client_data_supported
            .then(|| config.monitor_layout.clone())
            .flatten(),
        // Request the MCS message channel, which carries network auto-detect
        // ([MS-RDPBCGR] 2.2.14) and the multitransport / heartbeat PDUs. The
        // server assigns its ID in Server Message Channel Data.
        message_channel: extended_client_data_supported.then_some(gcc::ClientMessageChannelData),
        multi_transport_channel: extended_client_data_supported
            .then(|| {
                config
                    .multitransport_flags
                    .map(|flags| gcc::MultiTransportChannelData { flags })
            })
            .flatten(),
        // Client Monitor Extended Data describes the monitors of Client Monitor Data, so it is
        // only sent alongside it, with the same monitor count ([MS-RDPBCGR] 2.2.1.3.10).
        monitor_extended: extended_client_data_supported
            .then(|| monitor_extended_layout(config))
            .flatten(),
    })
}

/// Returns the configured Client Monitor Extended Data when it describes every monitor of Client Monitor Data.
fn monitor_extended_layout(config: &Config) -> Option<gcc::ClientMonitorExtendedData> {
    let monitors = config.monitor_layout.as_ref()?.monitors.len();
    let extended = config.monitor_extended_layout.as_ref()?;
    if extended.extended_monitors_info.len() != monitors {
        warn!(
            monitors,
            extended_monitors = extended.extended_monitors_info.len(),
            "Omitting Client Monitor Extended Data whose monitor count differs from Client Monitor Data"
        );
        return None;
    }
    Some(extended.clone())
}

fn create_client_info_pdu(
    config: &Config,
    client_addr: &SocketAddr,
    auto_reconnect_cookie: Option<&ServerAutoReconnect>,
    password_cookie: Option<&[u8]>,
    entra_auth: bool,
) -> rdp::ClientInfoPdu {
    use ironrdp_pdu::rdp::ClientInfoPdu;
    use ironrdp_pdu::rdp::client_info::{
        AddressFamily, ClientAutoReconnect, ClientInfo, ClientInfoFlags, CompressionType, Credentials,
        ExtendedClientInfo, ExtendedClientOptionalInfo, PasswordCookie,
    };
    use ironrdp_pdu::rdp::headers::{BasicSecurityHeader, BasicSecurityHeaderFlags};

    let security_header = BasicSecurityHeader {
        flags: BasicSecurityHeaderFlags::INFO_PKT,
    };

    // Default flags for all sessions
    let mut flags = ClientInfoFlags::MOUSE
        | ClientInfoFlags::MOUSE_HAS_WHEEL
        | ClientInfoFlags::UNICODE
        | ClientInfoFlags::DISABLE_CTRL_ALT_DEL
        | ClientInfoFlags::LOGON_NOTIFY
        | ClientInfoFlags::LOGON_ERRORS
        | ClientInfoFlags::VIDEO_DISABLE
        | ClientInfoFlags::ENABLE_WINDOWS_KEY
        | ClientInfoFlags::MAXIMIZE_SHELL;

    if config.autologon && !entra_auth {
        flags |= ClientInfoFlags::AUTOLOGON;
    }

    if !entra_auth && matches!(config.credentials, crate::Credentials::SmartCard { .. }) {
        flags |= ClientInfoFlags::PASSWORD_IS_SC_PIN;
    }

    if !config.enable_audio_playback {
        flags |= ClientInfoFlags::NO_AUDIO_PLAYBACK;
    }

    if config.enable_audio_capture {
        flags |= ClientInfoFlags::AUDIO_CAPTURE;
    }

    if config.remote_application_mode {
        flags |= ClientInfoFlags::RAIL;
    }

    // Advertise bulk compression support if configured
    let compression_type = if let Some(ct) = config.compression_type {
        flags |= ClientInfoFlags::COMPRESSION;
        info!(compression_type = ?ct, "Advertising bulk compression in Client Info PDU");
        ct
    } else {
        CompressionType::K8 // ignored if ClientInfoFlags::COMPRESSION is not set
    };

    // MS-RDPERP requires RemoteApp launch data on the RAIL channel.
    let (alternate_shell, work_dir) = if config.remote_application_mode {
        (String::new(), String::new())
    } else {
        (config.alternate_shell.clone(), config.work_dir.clone())
    };

    let client_info = ClientInfo {
        credentials: Credentials {
            username: config.credentials.username().unwrap_or("").to_owned(),
            password: if entra_auth {
                String::new()
            } else {
                config.credentials.secret().to_owned()
            },
            domain: config.domain.clone(),
        },
        // A smart card logon sends its PIN, never a redirection cookie.
        password_cookie: password_cookie
            .filter(|_| !flags.contains(ClientInfoFlags::PASSWORD_IS_SC_PIN))
            .map(|cookie| PasswordCookie(cookie.to_vec())),
        code_page: 0, // ignored if the keyboardLayout field of the Client Core Data is set to zero
        flags,
        compression_type,
        alternate_shell,
        work_dir,
        extra_info: ExtendedClientInfo {
            address_family: match client_addr {
                SocketAddr::V4(_) => AddressFamily::INET,
                SocketAddr::V6(_) => AddressFamily::INET_6,
            },
            address: client_addr.ip().to_string(),
            dir: config.client_dir.clone(),
            optional_data: {
                let builder = ExtendedClientOptionalInfo::builder()
                    .timezone(config.timezone_info.clone())
                    .session_id(0)
                    .performance_flags(config.performance_flags);

                // Resuming a session: prove we held the cookie the server issued
                // for it ([MS-RDPBCGR] 2.2.4.3, derived per 5.5). Absent on a
                // fresh connection, which is an ordinary logon.
                match auto_reconnect_cookie {
                    Some(cookie) => builder
                        .reconnect_cookie(ClientAutoReconnect::from_server_cookie(cookie).to_bytes())
                        .build(),
                    None => builder.build(),
                }
            },
        },
    };

    ClientInfoPdu {
        security_header,
        client_info,
    }
}

#[cfg(test)]
mod tests {
    use ironrdp_pdu::rdp::capability_sets::{MajorPlatformType, RailSupportLevel};
    use ironrdp_pdu::rdp::client_info::ClientInfoFlags;
    use ironrdp_pdu::{gcc, nego};

    use super::{create_client_info_pdu, create_gcc_blocks};
    use crate::{Config, Credentials, DesktopSize};

    #[test]
    fn remote_application_client_info_uses_rail_launch_data() {
        let config = Config {
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
            keyboard_functional_keys_count: 12,
            keyboard_layout: 0,
            connection_type: gcc::ConnectionType::Lan,
            ime_file_name: String::new(),
            bitmap: None,
            dig_product_id: String::new(),
            client_dir: String::new(),
            alternate_shell: "app.exe".into(),
            work_dir: "C:\\apps".into(),
            remote_application_mode: true,
            rail_support_level: RailSupportLevel::SUPPORTED,
            platform: MajorPlatformType::UNIX,
            hardware_id: None,
            request_data: None,
            autologon: false,
            enable_audio_playback: false,
            enable_audio_capture: false,
            performance_flags: Default::default(),
            license_cache: None,
            timezone_info: Default::default(),
            compression_type: None,
            enable_server_pointer: false,
            pointer_software_rendering: false,
            multitransport_flags: None,
            support_dyn_vc_gfx_protocol: false,
        };

        let client_info =
            create_client_info_pdu(&config, &"127.0.0.1:3389".parse().unwrap(), None, None, false).client_info;

        assert!(client_info.flags.contains(ClientInfoFlags::RAIL));
        assert!(client_info.alternate_shell.is_empty());
        assert!(client_info.work_dir.is_empty());
        assert!(!client_info.flags.contains(ClientInfoFlags::AUDIO_CAPTURE));
    }

    #[test]
    fn audio_capture_flag_is_set_when_enabled() {
        let mut config = Config {
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
            keyboard_functional_keys_count: 12,
            keyboard_layout: 0,
            connection_type: gcc::ConnectionType::Lan,
            ime_file_name: String::new(),
            bitmap: None,
            dig_product_id: String::new(),
            client_dir: String::new(),
            alternate_shell: String::new(),
            work_dir: String::new(),
            remote_application_mode: false,
            rail_support_level: RailSupportLevel::empty(),
            platform: MajorPlatformType::UNIX,
            hardware_id: None,
            request_data: None,
            autologon: false,
            enable_audio_playback: true,
            enable_audio_capture: true,
            performance_flags: Default::default(),
            license_cache: None,
            timezone_info: Default::default(),
            compression_type: None,
            enable_server_pointer: false,
            pointer_software_rendering: false,
            multitransport_flags: None,
            support_dyn_vc_gfx_protocol: false,
        };

        let client_info =
            create_client_info_pdu(&config, &"127.0.0.1:3389".parse().unwrap(), None, None, false).client_info;
        assert!(client_info.flags.contains(ClientInfoFlags::AUDIO_CAPTURE));
        assert!(!client_info.flags.contains(ClientInfoFlags::NO_AUDIO_PLAYBACK));

        config.enable_audio_capture = false;
        let client_info =
            create_client_info_pdu(&config, &"127.0.0.1:3389".parse().unwrap(), None, None, false).client_info;
        assert!(!client_info.flags.contains(ClientInfoFlags::AUDIO_CAPTURE));
    }

    #[test]
    fn gcc_blocks_advertise_monitor_layout_when_supported() {
        let mut config = Config {
            desktop_size: DesktopSize {
                width: 1_920,
                height: 1_080,
            },
            monitor_layout: Some(gcc::ClientMonitorData {
                monitors: vec![gcc::Monitor {
                    left: 0,
                    top: 0,
                    right: 1_919,
                    bottom: 1_079,
                    flags: gcc::MonitorFlags::PRIMARY,
                }],
            }),
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
            keyboard_functional_keys_count: 12,
            keyboard_layout: 0,
            connection_type: gcc::ConnectionType::Lan,
            ime_file_name: String::new(),
            bitmap: None,
            dig_product_id: String::new(),
            client_dir: String::new(),
            alternate_shell: String::new(),
            work_dir: String::new(),
            remote_application_mode: false,
            rail_support_level: RailSupportLevel::empty(),
            platform: MajorPlatformType::UNIX,
            hardware_id: None,
            request_data: None,
            autologon: false,
            enable_audio_playback: false,
            enable_audio_capture: false,
            performance_flags: Default::default(),
            license_cache: None,
            timezone_info: Default::default(),
            compression_type: None,
            enable_server_pointer: false,
            pointer_software_rendering: false,
            multitransport_flags: None,
            support_dyn_vc_gfx_protocol: false,
        };

        let blocks = create_gcc_blocks(
            &config,
            None,
            nego::SecurityProtocol::empty(),
            true,
            core::iter::empty(),
        )
        .expect("valid GCC Client Monitor Data");

        assert_eq!(blocks.monitor, config.monitor_layout);
        assert!(blocks.monitor_extended.is_none());
        assert!(
            blocks
                .core
                .optional_data
                .early_capability_flags
                .expect("early capability flags are present")
                .contains(gcc::ClientEarlyCapabilityFlags::SUPPORT_MONITOR_LAYOUT_PDU)
        );

        let monitor_extended = gcc::ClientMonitorExtendedData {
            extended_monitors_info: vec![gcc::ExtendedMonitorInfo {
                physical_width: 0,
                physical_height: 0,
                orientation: gcc::MonitorOrientation::Portrait,
                desktop_scale_factor: 150,
                device_scale_factor: 140,
            }],
        };
        config.monitor_extended_layout = Some(monitor_extended.clone());
        let blocks = create_gcc_blocks(
            &config,
            None,
            nego::SecurityProtocol::empty(),
            true,
            core::iter::empty(),
        )
        .expect("valid GCC Client Monitor Extended Data");
        assert_eq!(blocks.monitor_extended, Some(monitor_extended.clone()));

        // A count that differs from Client Monitor Data would be a nonconformant block.
        let mut mismatched = monitor_extended;
        mismatched
            .extended_monitors_info
            .push(mismatched.extended_monitors_info[0].clone());
        config.monitor_extended_layout = Some(mismatched);
        let blocks = create_gcc_blocks(
            &config,
            None,
            nego::SecurityProtocol::empty(),
            true,
            core::iter::empty(),
        )
        .expect("valid GCC Client Monitor Data");
        assert!(blocks.monitor_extended.is_none());

        // Extended data describes the monitors of Client Monitor Data, so it is not sent alone.
        config.monitor_layout = None;
        let blocks = create_gcc_blocks(
            &config,
            None,
            nego::SecurityProtocol::empty(),
            true,
            core::iter::empty(),
        )
        .expect("valid GCC Client Monitor Data");

        assert!(blocks.monitor.is_none());
        assert!(blocks.monitor_extended.is_none());
        assert!(
            blocks
                .core
                .optional_data
                .early_capability_flags
                .expect("early capability flags are present")
                .contains(gcc::ClientEarlyCapabilityFlags::SUPPORT_MONITOR_LAYOUT_PDU)
        );

        let blocks = create_gcc_blocks(
            &config,
            None,
            nego::SecurityProtocol::empty(),
            false,
            core::iter::empty(),
        )
        .expect("valid GCC Client Monitor Data");

        assert!(blocks.monitor.is_none());
        assert!(blocks.message_channel.is_none());
        assert!(blocks.multi_transport_channel.is_none());
        assert!(
            !blocks
                .core
                .optional_data
                .early_capability_flags
                .expect("early capability flags are present")
                .contains(gcc::ClientEarlyCapabilityFlags::SUPPORT_MONITOR_LAYOUT_PDU)
        );

        let cluster_data = gcc::ClientClusterData {
            flags: gcc::RedirectionFlags::REDIRECTION_SUPPORTED | gcc::RedirectionFlags::REDIRECTED_SESSION_FIELD_VALID,
            redirection_version: gcc::RedirectionVersion::V6,
            redirected_session_id: 0,
        };
        let blocks = create_gcc_blocks(
            &config,
            Some(&cluster_data),
            nego::SecurityProtocol::empty(),
            true,
            core::iter::empty(),
        )
        .expect("valid GCC Client Cluster Data");
        assert_eq!(blocks.cluster, Some(cluster_data));
    }
}
