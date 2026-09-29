use core::fmt;
use core::net::SocketAddr;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use core::time::Duration;
use std::rc::Rc;
use std::sync::Arc;

use anyhow::{Context as _, Result, bail};
use ironrdp_acceptor::{Acceptor, AcceptorResult, BeginResult, DesktopSize};
use ironrdp_async::Framed;
use ironrdp_cliprdr::CliprdrServer;
use ironrdp_cliprdr::backend::ClipboardMessage;
use ironrdp_core::{decode, encode_vec, impl_as_any};
use ironrdp_displaycontrol::pdu::DisplayControlMonitorLayout;
use ironrdp_displaycontrol::server::{DisplayControlHandler, DisplayControlServer};
use ironrdp_dvc as dvc;
use ironrdp_pdu::input::InputEventPdu;
use ironrdp_pdu::input::fast_path::{FastPathInput, FastPathInputEvent};
use ironrdp_pdu::mcs::{SendDataIndication, SendDataRequest};
use ironrdp_pdu::rdp::capability_sets::{BitmapCodecs, CapabilitySet, CmdFlags, CodecProperty, GeneralExtraFlags};
pub use ironrdp_pdu::rdp::client_info::Credentials;
use ironrdp_pdu::rdp::headers::{ServerDeactivateAll, ShareControlPdu};
use ironrdp_pdu::rdp::server_error_info::{ErrorInfo, ProtocolIndependentCode, ServerSetErrorInfoPdu};
use ironrdp_pdu::x224::X224;
use ironrdp_pdu::{Action, PduResult, decode_err, mcs, nego, rdp};
use ironrdp_rdpsnd as rdpsnd;
use ironrdp_svc::{ChannelFlags, StaticChannelId, StaticChannelSet, SvcProcessor, server_encode_svc_messages};
use ironrdp_tokio::{FramedRead, FramedWrite, TokioFramed, split_tokio_framed, unsplit_tokio_framed};
use rdpsnd::server::{RdpsndServer, RdpsndServerMessage};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpSocket;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, trace, warn};

use crate::autodetect::{AutoDetectManager, RttSnapshot};
use crate::clipboard::CliprdrServerFactory;
use crate::display::{DisplayUpdate, RdpServerDisplay};
use crate::echo::{EchoDvcBridge, EchoServerHandle, EchoServerMessage, build_echo_request};
use crate::encoder::{UpdateEncoder, UpdateEncoderCodecs};
#[cfg(feature = "egfx")]
use crate::gfx::{EgfxServerMessage, GfxServerFactory};
use crate::handler::RdpServerInputHandler;
use crate::{SoundServerFactory, builder, capabilities};

/// TCP listen backlog size for the RDP server socket.
const LISTENER_BACKLOG: u32 = 1024;

/// Action to take after a client disconnects.
///
/// Returned by [`ConnectionHandler::on_disconnected`] to control whether
/// the server continues accepting new connections or shuts down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostConnectionAction {
    /// Continue accepting new connections.
    Continue,
    /// Stop the accept loop and return from [`RdpServer::run`].
    Stop,
}

/// Hooks for connection lifecycle events in [`RdpServer::run`].
///
/// Implement this trait to add pre-accept filtering (rate limiting,
/// IP allowlists) and post-disconnect logic (cleanup, session validity
/// checks, metrics).
///
/// All methods have default implementations that accept all connections
/// and continue unconditionally.
pub trait ConnectionHandler: Send {
    /// Called after `accept()` returns but before `run_connection()`.
    ///
    /// Return `false` to reject the connection (the TCP stream is dropped).
    fn on_accept(&mut self, peer: SocketAddr) -> bool {
        let _ = peer;
        true
    }

    /// Called after `run_connection()` completes (successfully or with error).
    ///
    /// `duration` is the wall-clock time the connection was active.
    /// `error` is `Some` if the connection ended with an error.
    fn on_disconnected(
        &mut self,
        peer: SocketAddr,
        duration: Duration,
        error: Option<&anyhow::Error>,
    ) -> PostConnectionAction {
        let _ = (peer, duration, error);
        PostConnectionAction::Continue
    }
}

/// Outcome of a successful [`CredentialValidator::validate`] call.
///
/// A rejection from a working validator is not an error: the validator did
/// its job and decided the credentials do not authenticate. Backend failures
/// (LDAP unreachable, PAM transport broken, database connection lost) are
/// reported via [`CredentialValidationError`] instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialDecision {
    /// Credentials accepted; the connection proceeds.
    Accept,
    /// Credentials rejected; the connection is closed.
    Reject,
}

/// Error returned by a [`CredentialValidator`] when the validator backend
/// itself fails (rather than the credentials being invalid).
///
/// Wraps any [`core::error::Error`] from the backend (LDAP/PAM/DB/etc.) so
/// the trait does not require a particular error library in implementors or
/// consumers.
#[derive(Debug)]
pub struct CredentialValidationError {
    source: Box<dyn core::error::Error + Send + Sync>,
}

impl CredentialValidationError {
    /// Wrap a backend error as a credential-validation failure.
    pub fn new<E>(source: E) -> Self
    where
        E: core::error::Error + Send + Sync + 'static,
    {
        Self {
            source: Box::new(source),
        }
    }
}

impl fmt::Display for CredentialValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("credential validator backend failure")
    }
}

impl core::error::Error for CredentialValidationError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&*self.source)
    }
}

/// Server-side credential validator for TLS-mode connections.
///
/// Called during connection setup when the server receives client credentials
/// via `ClientInfoPdu`. Not used for CredSSP/Hybrid connections (those use
/// pre-loaded credentials for NTLM challenge-response).
///
/// Implement this trait to validate credentials against external systems
/// (PAM, LDAP, database, etc.). For blocking backends, wrap the call in
/// `tokio::task::spawn_blocking` to avoid stalling the async runtime.
///
/// # Example
///
/// ```ignore
/// use ironrdp_server::{CredentialDecision, CredentialValidationError, CredentialValidator, Credentials};
///
/// struct StaticValidator {
///     expected_user: String,
///     expected_password: String,
/// }
///
/// #[async_trait::async_trait]
/// impl CredentialValidator for StaticValidator {
///     async fn validate(
///         &self,
///         creds: &Credentials,
///     ) -> Result<CredentialDecision, CredentialValidationError> {
///         if creds.username == self.expected_user && creds.password == self.expected_password {
///             Ok(CredentialDecision::Accept)
///         } else {
///             Ok(CredentialDecision::Reject)
///         }
///     }
/// }
/// ```
#[async_trait::async_trait]
pub trait CredentialValidator: Send + Sync {
    /// Validate credentials received from the client.
    ///
    /// Return `Ok(CredentialDecision::Accept)` to permit the connection,
    /// `Ok(CredentialDecision::Reject)` to refuse it. Return
    /// `Err(CredentialValidationError::new(_))` only when the validator
    /// itself could not produce a decision (backend system error).
    ///
    /// Implementors backed by blocking systems (PAM, libldap, a synchronous
    /// database driver) should offload the work, for example with
    /// `tokio::task::spawn_blocking`, so the returned future does not stall the
    /// caller's executor. Native-async backends can simply `.await`.
    async fn validate(&self, credentials: &Credentials) -> Result<CredentialDecision, CredentialValidationError>;
}

/// A built-in [`CredentialValidator`] that accepts exactly one fixed set of credentials.
///
/// This is the validation-policy equivalent of the acceptor's pre-loaded
/// exact-match: it keeps the common "one known account" case a one-liner while
/// going through the same hook as PAM, LDAP, or database-backed validators.
pub struct ExactMatchCredentialValidator {
    expected: Credentials,
}

impl ExactMatchCredentialValidator {
    /// Build a validator that accepts only `expected` and rejects everything else.
    pub fn new(expected: Credentials) -> Self {
        Self { expected }
    }
}

#[async_trait::async_trait]
impl CredentialValidator for ExactMatchCredentialValidator {
    async fn validate(&self, credentials: &Credentials) -> Result<CredentialDecision, CredentialValidationError> {
        if credentials == &self.expected {
            Ok(CredentialDecision::Accept)
        } else {
            Ok(CredentialDecision::Reject)
        }
    }
}

#[derive(Clone)]
#[non_exhaustive]
pub struct RdpServerOptions {
    pub addr: SocketAddr,
    pub security: RdpServerSecurity,
    pub codecs: BitmapCodecs,
    pub max_request_size: u32,
    /// When `true`, each connection's acceptor adopts the desktop size the
    /// client requests in its Client Core Data (instead of the size reported
    /// by the display handler), negotiating that size from the start without a
    /// Deactivation-Reactivation resize. Defaults to `false`. Set via
    /// [`RdpServerBuilder::with_honor_client_desktop_size`](crate::RdpServerBuilder::with_honor_client_desktop_size).
    pub honor_client_desktop_size: bool,
}

impl RdpServerOptions {
    /// Default [MultifragmentUpdate] max reassembly buffer size (8 MB).
    ///
    /// Advertised to the client during capability exchange as the largest
    /// reassembled Fast-Path Update the server can accept.
    /// Values that are too large cause certain clients (notably mstsc)
    /// to reject the connection.
    ///
    /// [MultifragmentUpdate]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/01717954-716a-424d-af35-28fb2b86df89
    pub(crate) const DEFAULT_MAX_REQUEST_SIZE: u32 = 8 * 1024 * 1024;

    fn has_image_remote_fx(&self) -> bool {
        self.codecs
            .0
            .iter()
            .any(|codec| matches!(codec.property, CodecProperty::ImageRemoteFx(_)))
    }

    fn has_remote_fx(&self) -> bool {
        self.codecs
            .0
            .iter()
            .any(|codec| matches!(codec.property, CodecProperty::RemoteFx(_)))
    }

    #[cfg(feature = "qoi")]
    fn has_qoi(&self) -> bool {
        self.codecs
            .0
            .iter()
            .any(|codec| matches!(codec.property, CodecProperty::Qoi))
    }

    #[cfg(feature = "qoiz")]
    fn has_qoiz(&self) -> bool {
        self.codecs
            .0
            .iter()
            .any(|codec| matches!(codec.property, CodecProperty::QoiZ))
    }

    #[cfg(feature = "nscodec")]
    fn has_nscodec(&self) -> bool {
        self.codecs
            .0
            .iter()
            .any(|codec| matches!(codec.property, CodecProperty::NsCodec(_)))
    }
}

#[derive(Clone)]
pub enum RdpServerSecurity {
    None,
    Tls(TlsAcceptor),
    /// Used for both hybrid + hybrid-ex.
    Hybrid((TlsAcceptor, Vec<u8>)),
}

impl RdpServerSecurity {
    pub fn flag(&self) -> nego::SecurityProtocol {
        match self {
            RdpServerSecurity::None => nego::SecurityProtocol::empty(),
            RdpServerSecurity::Tls(_) => nego::SecurityProtocol::SSL,
            RdpServerSecurity::Hybrid(_) => nego::SecurityProtocol::HYBRID | nego::SecurityProtocol::HYBRID_EX,
        }
    }
}

struct AInputHandler {
    handler: Arc<Mutex<Box<dyn RdpServerInputHandler>>>,
}

impl_as_any!(AInputHandler);

impl dvc::DvcProcessor for AInputHandler {
    fn channel_name(&self) -> &str {
        ironrdp_ainput::CHANNEL_NAME
    }

    fn start(&mut self, _channel_id: u32) -> PduResult<Vec<dvc::DvcMessage>> {
        use ironrdp_ainput::{ServerPdu, VersionPdu};

        let pdu = ServerPdu::Version(VersionPdu::default());

        Ok(vec![Box::new(pdu)])
    }

    fn close(&mut self, _channel_id: u32) {}

    fn process(&mut self, _channel_id: u32, payload: &[u8]) -> PduResult<Vec<dvc::DvcMessage>> {
        use ironrdp_ainput::ClientPdu;

        match decode(payload).map_err(|e| decode_err!(e))? {
            ClientPdu::Mouse(pdu) => {
                let handler = Arc::clone(&self.handler);
                task::spawn_blocking(move || {
                    handler.blocking_lock().mouse(pdu.into());
                });
            }
        }

        Ok(Vec::new())
    }
}

impl dvc::DvcServerProcessor for AInputHandler {}

struct DisplayControlBackend {
    display: Arc<Mutex<Box<dyn RdpServerDisplay>>>,
}

impl DisplayControlBackend {
    fn new(display: Arc<Mutex<Box<dyn RdpServerDisplay>>>) -> Self {
        Self { display }
    }
}

impl DisplayControlHandler for DisplayControlBackend {
    fn monitor_layout(&self, layout: DisplayControlMonitorLayout) {
        let display = Arc::clone(&self.display);
        task::spawn_blocking(move || display.blocking_lock().request_layout(layout));
    }
}

/// Selects who performs the TLS handshake for a connection accepted via
/// [`RdpServer::run_connection_with`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum TransportTls {
    /// IronRDP performs the TLS accept on the stream (standard TCP+TLS).
    Managed,
    /// The stream is already past TLS, terminated by a lower layer (e.g. a WSS
    /// terminator). IronRDP skips the TLS handshake. The caller MUST guarantee
    /// the transport is already encrypted; see the preconditions on
    /// [`RdpServer::run_connection_with`].
    AlreadyDone,
}

/// RDP Server
///
/// A server is created to listen for connections.
/// After the connection sequence is finalized using the provided security mechanism, the server can:
///  - receive display updates from a [`RdpServerDisplay`] and forward them to the client
///  - receive input events from a client and forward them to an [`RdpServerInputHandler`]
///
/// # Example
///
/// ```
/// use ironrdp_server::{RdpServer, RdpServerInputHandler, RdpServerDisplay, RdpServerDisplayUpdates};
///
///# use anyhow::Result;
///# use ironrdp_server::{DisplayUpdate, DesktopSize, KeyboardEvent, MouseEvent};
///# use tokio_rustls::TlsAcceptor;
///# struct NoopInputHandler;
///# impl RdpServerInputHandler for NoopInputHandler {
///#     fn keyboard(&mut self, _: KeyboardEvent) {}
///#     fn mouse(&mut self, _: MouseEvent) {}
///# }
///# struct NoopDisplay;
///# #[async_trait::async_trait]
///# impl RdpServerDisplay for NoopDisplay {
///#     async fn size(&mut self) -> DesktopSize {
///#         todo!()
///#     }
///#     async fn updates(&mut self) -> Result<Box<dyn RdpServerDisplayUpdates>> {
///#         todo!()
///#     }
///# }
///# async fn stub() -> Result<()> {
/// fn make_tls_acceptor() -> TlsAcceptor {
///    /* snip */
///#    todo!()
/// }
///
/// fn make_input_handler() -> impl RdpServerInputHandler {
///    /* snip */
///#    NoopInputHandler
/// }
///
/// fn make_display_handler() -> impl RdpServerDisplay {
///    /* snip */
///#    NoopDisplay
/// }
///
/// let tls_acceptor = make_tls_acceptor();
/// let input_handler = make_input_handler();
/// let display_handler = make_display_handler();
///
/// let mut server = RdpServer::builder()
///     .with_addr(([127, 0, 0, 1], 3389))
///     .with_tls(tls_acceptor)
///     .with_input_handler(input_handler)
///     .with_display_handler(display_handler)
///     .build();
///
/// server.run().await;
/// Ok(())
///# }
/// ```
pub struct RdpServer {
    opts: RdpServerOptions,
    // FIXME: replace with a channel and poll/process the handler?
    handler: Arc<Mutex<Box<dyn RdpServerInputHandler>>>,
    display: Arc<Mutex<Box<dyn RdpServerDisplay>>>,
    static_channels: StaticChannelSet,
    sound_factory: Option<Box<dyn SoundServerFactory>>,
    cliprdr_factory: Option<Box<dyn CliprdrServerFactory>>,
    echo_handle: EchoServerHandle,
    #[cfg(feature = "egfx")]
    gfx_factory: Option<Box<dyn GfxServerFactory>>,
    #[cfg(feature = "egfx")]
    gfx_handle: Option<crate::gfx::GfxServerHandle>,
    ev_sender: mpsc::UnboundedSender<ServerEvent>,
    ev_receiver: Arc<Mutex<mpsc::UnboundedReceiver<ServerEvent>>>,
    creds: Option<Credentials>,
    credential_validator: Option<Arc<dyn CredentialValidator>>,
    local_addr: Option<SocketAddr>,
    autodetect: Option<AutoDetectManager>,
    connection_handler: Option<Box<dyn ConnectionHandler>>,
    /// True while the client has sent `SuppressOutput { desktop_rect: None }`
    /// — the standard RDP "I don't need display updates right now" signal
    /// (mstsc raises it on window minimize). Cleared on
    /// `SuppressOutput { Some(rect) }` or `RefreshRectangle` (sent on
    /// refocus). Exposed via [`Self::display_suppressed_handle`] so display
    /// backends can hold a clone and skip frame emission while it's set —
    /// without this, a server keeps streaming high-bitrate
    /// EGFX/H.264 frames into a minimized client, which accumulates them
    /// and locks up its input dispatch for seconds on refocus while it
    /// chews through the backlog.
    display_suppressed: Arc<AtomicBool>,

    /// Latest NetworkAutoDetect round-trip time in milliseconds, or `u32::MAX`
    /// until the first measurement (and while auto-detect is disabled). Updated
    /// on each RTT Measure Response when auto-detect is enabled (see
    /// [`Self::enable_autodetect`]). Exposed via [`Self::autodetect_rtt_handle`]
    /// so display backends can read a fresh, frame-traffic-independent network
    /// RTT for flow control.
    autodetect_rtt: Arc<AtomicU32>,
}

#[derive(Debug)]
pub enum ServerEvent {
    Quit(String),
    Clipboard(ClipboardMessage),
    Rdpsnd(RdpsndServerMessage),
    Echo(EchoServerMessage),
    SetCredentials(Credentials),
    GetLocalAddr(oneshot::Sender<Option<SocketAddr>>),
    #[cfg(feature = "egfx")]
    Egfx(EgfxServerMessage),
    /// Trigger an RTT measurement probe (requires auto-detect enabled).
    AutoDetectRttRequest,
}

pub trait ServerEventSender {
    fn set_sender(&mut self, sender: mpsc::UnboundedSender<ServerEvent>);
}

impl ServerEvent {
    pub fn create_channel() -> (mpsc::UnboundedSender<Self>, mpsc::UnboundedReceiver<Self>) {
        mpsc::unbounded_channel()
    }
}

#[derive(Debug, PartialEq)]
enum RunState {
    Continue,
    Disconnect,
    DeactivationReactivation { desktop_size: DesktopSize },
}

impl RdpServer {
    #[expect(
        clippy::too_many_arguments,
        reason = "called via the builder; positional parameters are an internal detail"
    )]
    pub(crate) fn new(
        opts: RdpServerOptions,
        handler: Box<dyn RdpServerInputHandler>,
        display: Box<dyn RdpServerDisplay>,
        mut sound_factory: Option<Box<dyn SoundServerFactory>>,
        mut cliprdr_factory: Option<Box<dyn CliprdrServerFactory>>,
        connection_handler: Option<Box<dyn ConnectionHandler>>,
        #[cfg(feature = "egfx")] mut gfx_factory: Option<Box<dyn GfxServerFactory>>,
        display_suppressed: Option<Arc<AtomicBool>>,
        autodetect_rtt: Option<Arc<AtomicU32>>,
    ) -> Self {
        let (ev_sender, ev_receiver) = ServerEvent::create_channel();
        if let Some(cliprdr) = cliprdr_factory.as_mut() {
            cliprdr.set_sender(ev_sender.clone());
        }
        if let Some(snd) = sound_factory.as_mut() {
            snd.set_sender(ev_sender.clone());
        }
        #[cfg(feature = "egfx")]
        if let Some(gfx) = gfx_factory.as_mut() {
            gfx.set_sender(ev_sender.clone());
        }
        Self {
            opts,
            handler: Arc::new(Mutex::new(handler)),
            display: Arc::new(Mutex::new(display)),
            static_channels: StaticChannelSet::new(),
            sound_factory,
            cliprdr_factory,
            echo_handle: EchoServerHandle::new(ev_sender.clone()),
            #[cfg(feature = "egfx")]
            gfx_factory,
            #[cfg(feature = "egfx")]
            gfx_handle: None,
            ev_sender,
            ev_receiver: Arc::new(Mutex::new(ev_receiver)),
            creds: None,
            credential_validator: None,
            local_addr: None,
            autodetect: None,
            connection_handler,
            display_suppressed: display_suppressed.unwrap_or_else(|| Arc::new(AtomicBool::new(false))),
            autodetect_rtt: {
                // Reset to the sentinel: an injected handle must not expose a stale value before the first measurement.
                let handle = autodetect_rtt.unwrap_or_else(|| Arc::new(AtomicU32::new(u32::MAX)));
                handle.store(u32::MAX, Ordering::Relaxed);
                handle
            },
        }
    }

    pub fn builder() -> builder::RdpServerBuilder<builder::WantsAddr> {
        builder::RdpServerBuilder::new()
    }

    /// Set or clear the credential validator for TLS-mode connections.
    ///
    /// When set, credentials received from the client during
    /// `SecureSettingsExchange` are validated through this callback before
    /// the session is established. If the validator returns
    /// [`CredentialDecision::Reject`] (or a [`CredentialValidationError`]),
    /// the connection is rejected. Passing `None` clears any previously
    /// configured validator.
    ///
    /// Most callers should configure the validator at construction time via
    /// the builder's `with_credential_validator` method
    /// ([`RdpServer::builder`]); this setter exists for dynamic
    /// post-construction reconfiguration.
    ///
    /// Not used for CredSSP/Hybrid connections (those use pre-loaded credentials).
    pub fn set_credential_validator(&mut self, validator: Option<Arc<dyn CredentialValidator>>) {
        self.credential_validator = validator;
    }

    pub fn event_sender(&self) -> &mpsc::UnboundedSender<ServerEvent> {
        &self.ev_sender
    }

    /// Returns the shared "display suppressed" flag — `true` while the
    /// connected client has sent `SuppressOutput { desktop_rect: None }`
    /// (e.g., mstsc minimized).
    ///
    /// Display backends should hold a clone of this `Arc` and skip frame
    /// emission while it's set, so the client doesn't accumulate a backlog
    /// of frames it can't present until refocus. Cleared by the per-
    /// connection PDU handler on `SuppressOutput { Some(rect) }` or
    /// `RefreshRectangle`.
    ///
    /// **Caveat:** some clients (notably mstsc) send
    /// `SuppressOutput { desktop_rect: None }` during their connect
    /// handshake *before* their display surface is fully initialized; a
    /// backend that honors the flag blindly will block that first frame
    /// and leave the client with a half-initialized surface that doesn't
    /// recover on un-suppress (visible as a frozen desktop on first
    /// connect). Backends are advised to defer acting on the flag until
    /// after the first frame has been delivered to the client, and to
    /// debounce transient flaps (some clients pulse this PDU under wire
    /// pressure on heavy CPU/IO loads) — e.g., only engage the gate once
    /// the flag has been steady-`true` for ~1 s.
    ///
    /// The display backend typically needs to share this flag with the
    /// server before any client connects (so the same `Arc` is read by
    /// the backend's polling thread and written by the per-connection
    /// PDU handler). To inject the shared instance at construction time,
    /// use [`RdpServerBuilder::with_display_suppressed_handle`](crate::RdpServerBuilder::with_display_suppressed_handle).
    ///
    /// [crate::RdpServerBuilder]: crate::RdpServerBuilder
    pub fn display_suppressed_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.display_suppressed)
    }

    /// Returns a handle to the latest NetworkAutoDetect RTT in milliseconds
    /// (`u32::MAX` until the first measurement, and while auto-detect is
    /// disabled). The server updates it on each RTT Measure Response; backends
    /// clone the handle to read a fresh network RTT for flow control. Inject a
    /// shared instance at construction with
    /// [`RdpServerBuilder::with_autodetect_rtt_handle`](crate::RdpServerBuilder::with_autodetect_rtt_handle).
    pub fn autodetect_rtt_handle(&self) -> Arc<AtomicU32> {
        Arc::clone(&self.autodetect_rtt)
    }

    /// Returns the shared ECHO server handle for runtime probe requests and RTT measurements.
    pub fn echo_handle(&self) -> &EchoServerHandle {
        &self.echo_handle
    }

    /// Enable protocol-level auto-detect ([MS-RDPBCGR 2.2.14]).
    ///
    /// Auto-detect uses lightweight Share Data PDUs on the IO channel,
    /// separate from the ECHO DVC. It supports bandwidth measurement
    /// in addition to RTT and works even when DVC is unavailable.
    ///
    /// Send probes via [`ServerEvent::AutoDetectRttRequest`] and
    /// query results with [`rtt_snapshot()`](Self::rtt_snapshot).
    pub fn enable_autodetect(&mut self) {
        self.autodetect = Some(AutoDetectManager::new());
    }

    /// Get the latest auto-detect RTT snapshot.
    ///
    /// Returns `None` if auto-detect is not enabled or no measurements
    /// have been received yet.
    pub fn rtt_snapshot(&self) -> Option<RttSnapshot> {
        self.autodetect.as_ref().and_then(|ad| ad.snapshot())
    }

    /// Returns the shared EGFX server handle for proactive frame submission.
    ///
    /// Available after `build_server_with_handle()` returns `Some` during
    /// channel setup. Display handlers use this to call
    /// `send_avc420_frame()` / `send_avc444_frame()` and then signal the
    /// event loop via `ServerEvent::Egfx`.
    #[cfg(feature = "egfx")]
    pub fn gfx_handle(&self) -> Option<&crate::gfx::GfxServerHandle> {
        self.gfx_handle.as_ref()
    }

    fn attach_channels(&mut self, acceptor: &mut Acceptor) {
        if let Some(cliprdr_factory) = self.cliprdr_factory.as_deref() {
            let backend = cliprdr_factory.build_cliprdr_backend();

            let cliprdr = CliprdrServer::new(backend);

            acceptor.attach_static_channel(cliprdr);
        }

        if let Some(factory) = self.sound_factory.as_deref() {
            let backend = factory.build_backend();

            acceptor.attach_static_channel(RdpsndServer::new(backend));
        }

        let dcs_backend = DisplayControlBackend::new(Arc::clone(&self.display));
        let dvc = dvc::DrdynvcServer::new()
            .with_dynamic_channel(AInputHandler {
                handler: Arc::clone(&self.handler),
            })
            .with_dynamic_channel(DisplayControlServer::new(Box::new(dcs_backend)));

        let dvc = {
            let echo_handle = self.echo_handle.clone();
            dvc.with_dynamic_channel(EchoDvcBridge::new(echo_handle))
        };

        #[cfg(feature = "egfx")]
        let dvc = {
            let mut dvc = dvc;
            if let Some(gfx_factory) = self.gfx_factory.as_deref() {
                if let Some((bridge, handle)) = gfx_factory.build_server_with_handle() {
                    self.gfx_handle = Some(handle);
                    dvc = dvc.with_dynamic_channel(bridge);
                } else {
                    let handler = gfx_factory.build_gfx_handler();
                    let gfx_server = ironrdp_egfx::server::GraphicsPipelineServer::new(handler);
                    dvc = dvc.with_dynamic_channel(gfx_server);
                }
            }
            dvc
        };

        acceptor.attach_static_channel(dvc);
    }

    /// Run a single RDP connection over `stream`, performing the
    /// IronRDP-managed TLS handshake on `ShouldUpgrade` (standard TCP+TLS).
    ///
    /// Equivalent to [`run_connection_with`](Self::run_connection_with) with
    /// [`TransportTls::Managed`].
    pub async fn run_connection<S>(&mut self, stream: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Send + Sync + Unpin,
    {
        self.run_connection_with(stream, TransportTls::Managed).await
    }

    /// Run a single RDP connection over `stream`, choosing who performs the TLS
    /// handshake with `tls`.
    ///
    /// With [`TransportTls::Managed`], IronRDP performs the TLS accept on
    /// `ShouldUpgrade`, exactly as [`run_connection`](Self::run_connection).
    ///
    /// With [`TransportTls::AlreadyDone`], the caller's `stream` has ALREADY
    /// been transport-encrypted at a lower layer that the embedder owns
    /// (typically a WSS terminator in the same process, or a TLS stream the
    /// embedder accepted up front), so IronRDP skips the TLS handshake and
    /// advances the state machine via [`Acceptor::mark_security_upgrade_as_done`].
    /// Everything past the handshake, including the optional Hybrid CredSSP
    /// exchange and finalization, is identical to the managed path.
    ///
    /// # Use case for [`TransportTls::AlreadyDone`]
    ///
    /// This mode decouples transport encryption from the RDP security-upgrade
    /// step. It is for ironrdp-server endpoints that terminate transport
    /// encryption themselves before the RDP state machine runs — for example a
    /// server that accepts WSS directly, or one fronted by an in-process TLS
    /// terminator — and therefore must not perform a second, inner TLS
    /// handshake when the X.224 negotiation selects `PROTOCOL_SSL`.
    ///
    /// This is distinct from a [RDCleanPath] proxy deployment (e.g.
    /// Devolutions Gateway), where the proxy performs a real TLS handshake with
    /// a *separate* backend RDP server and relays that server's certificate
    /// chain to the client. In that topology the backend server owns its own
    /// TLS and uses [`TransportTls::Managed`]; this mode does not apply to it.
    /// RDCleanPath is relevant here only as one client-side mechanism (see
    /// precondition 2) for telling a client not to expect an inner handshake.
    ///
    /// # Preconditions for [`TransportTls::AlreadyDone`] (caller MUST guarantee)
    ///
    /// 1. The `stream` is already transport-encrypted by another layer
    ///    (WSS, in-process, etc.). Passing a plain TCP stream here exposes
    ///    RDP traffic in plaintext on the wire.
    ///
    /// 2. The connecting client must not expect an inner TLS handshake on this
    ///    stream. Vanilla RDP clients (mstsc, xfreerdp) negotiate TLS from the
    ///    X.224 `selectedProtocol` and have no concept of "TLS already done at a
    ///    lower layer": they will hang or fail, and must use
    ///    [`TransportTls::Managed`]. Arranging for a client to skip the inner
    ///    handshake is the embedder's responsibility; RDCleanPath is one such
    ///    mechanism, but this method does not depend on it.
    ///
    /// 3. If `self.opts.security` is [`RdpServerSecurity::Hybrid`], two things
    ///    must hold. First, the client must support CredSSP over this
    ///    transport; the SPNEGO exchange itself is transport-independent
    ///    (CredSSP carries its own crypto via TSRequest), so it runs the same
    ///    as on the managed path. Second, and less obvious: the CredSSP
    ///    server-public-key confirmation (`pubKeyAuth`, per MS-CSSP) binds to
    ///    the certificate the client validated at the lower transport layer,
    ///    not to anything IronRDP does here. So the public key configured in
    ///    [`RdpServerSecurity::Hybrid`] MUST be the public key of the
    ///    certificate that lower layer (e.g. the WSS terminator) presented to
    ///    the client, otherwise the client's `pubKeyAuth` check fails and
    ///    Hybrid is rejected. This is the embedder's responsibility; it does
    ///    not hold automatically. In practice it means terminating transport
    ///    TLS with the same certificate configured for Hybrid.
    ///
    /// [RDCleanPath]: https://docs.rs/ironrdp-rdcleanpath
    ///
    /// # Wire-level invariant
    ///
    /// This method does NOT alter the X.224 negotiation. The acceptor still
    /// advertises whatever `SecurityProtocol` it was constructed with, and the
    /// connecting client still negotiates as normal. The only behaviour change
    /// under [`TransportTls::AlreadyDone`] is that after the negotiation reaches
    /// the security-upgrade gate, no TLS handshake is performed on the byte
    /// stream, because the caller's stream is already past TLS at a lower layer.
    pub async fn run_connection_with<S>(&mut self, stream: S, tls: TransportTls) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Send + Sync + Unpin,
    {
        // Per-connection state must start fresh: if the previous client
        // disconnected while it had sent `SuppressOutput { None }` (e.g.,
        // closed the mstsc window while minimized so the matching resume
        // PDU never arrived), the flag would still read `true` here and the
        // display backend would silently drop frames for the entire new
        // session until/unless the new client happens to send a
        // `RefreshRectangle` or `SuppressOutput { Some(rect) }`. Resetting
        // here also covers backends that share an externally-created Arc via
        // `set_display_suppressed_handle()`.
        self.display_suppressed.store(false, Ordering::Relaxed);

        let framed = TokioFramed::new(stream);

        let size = self.display.lock().await.size().await;
        let capabilities = capabilities::capabilities(&self.opts, size);
        let mut acceptor = Acceptor::new(self.opts.security.flag(), size, capabilities, self.creds.clone());
        acceptor.set_honor_client_desktop_size(self.opts.honor_client_desktop_size);

        self.attach_channels(&mut acceptor);

        let res = ironrdp_acceptor::accept_begin(framed, &mut acceptor)
            .await
            .context("accept_begin failed")?;

        match res {
            // The only thing that varies between the two modes is who performs
            // the TLS handshake; everything past it is `finalize_after_upgrade`.
            BeginResult::ShouldUpgrade(stream) => match tls {
                TransportTls::Managed => {
                    let tls_acceptor = match &self.opts.security {
                        RdpServerSecurity::Tls(acceptor) => acceptor,
                        RdpServerSecurity::Hybrid((acceptor, _)) => acceptor,
                        RdpServerSecurity::None => unreachable!(),
                    };
                    let accept = match tls_acceptor.accept(stream).await {
                        Ok(accept) => accept,
                        Err(e) => {
                            warn!("Failed to TLS accept: {}", e);
                            return Ok(());
                        }
                    };
                    self.finalize_after_upgrade(TokioFramed::new(accept), acceptor, "TLS connection")
                        .await?;
                }
                TransportTls::AlreadyDone => {
                    // The stream is already past TLS (terminated at a lower
                    // layer, e.g. a WSS terminator); do NOT call
                    // tls_acceptor.accept on it.
                    self.finalize_after_upgrade(TokioFramed::new(stream), acceptor, "TLS-offloaded stream")
                        .await?;
                }
            },

            BeginResult::Continue(framed) => {
                self.accept_finalize(framed, acceptor).await?;
            }
        };

        Ok(())
    }

    /// Shared post-handshake tail for both [`TransportTls`] modes: mark the
    /// security upgrade complete, run the optional Hybrid CredSSP exchange,
    /// finalize, and shut the stream down. Single-sourcing this is what keeps
    /// the managed and TLS-offloaded paths structurally identical past the
    /// handshake, so per-connection state handling cannot drift between them.
    async fn finalize_after_upgrade<S>(
        &mut self,
        mut framed: TokioFramed<S>,
        mut acceptor: Acceptor,
        shutdown_label: &str,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Sync + Send + Unpin,
    {
        acceptor.mark_security_upgrade_as_done();

        if let RdpServerSecurity::Hybrid((_, pub_key)) = &self.opts.security {
            // Generic streams don't expose peer address. Use a neutral
            // placeholder; it's unclear whether CredSSP/NTLM actually
            // uses this value in practice.
            let client_name = "rdp-client".to_owned();

            ironrdp_acceptor::accept_credssp(
                &mut framed,
                &mut acceptor,
                &mut ironrdp_tokio::reqwest::ReqwestNetworkClient::new(),
                client_name.into(),
                pub_key.clone(),
                None,
            )
            .await?;
        }

        let framed = self.accept_finalize(framed, acceptor).await?;
        debug!("Shutting down {}", shutdown_label);
        let (mut inner, _) = framed.into_inner();
        if let Err(e) = inner.shutdown().await {
            debug!(?e, "{} shutdown error", shutdown_label);
        }

        Ok(())
    }

    pub async fn run(&mut self) -> Result<()> {
        // Create socket with control over options before binding.
        // Using TcpSocket instead of TcpListener::bind() allows setting
        // SO_REUSEADDR and IPv6 dual-stack mode.
        let socket = match self.opts.addr {
            SocketAddr::V4(_) => TcpSocket::new_v4().context("create IPv4 socket")?,
            SocketAddr::V6(_) => {
                // IPv6 socket: on Linux, dual-stack is the default
                // (net.ipv6.bindv6only=0), so IPv4 clients connect as
                // IPv4-mapped addresses (::ffff:x.x.x.x). On platforms
                // where IPV6_V6ONLY defaults to 1 (Windows, some BSDs),
                // only IPv6 clients will be accepted and a separate IPv4
                // listener would be needed.
                TcpSocket::new_v6().context("create IPv6 socket")?
            }
        };

        // SO_REUSEADDR prevents EADDRINUSE when restarting the server while
        // the previous socket is still in TIME_WAIT. Only set on Unix;
        // on Windows SO_REUSEADDR has different semantics that allow a
        // second process to bind the same port, which is a security risk.
        #[cfg(unix)]
        socket.set_reuseaddr(true).context("set SO_REUSEADDR")?;

        socket.bind(self.opts.addr).context("bind listen address")?;

        let listener = socket.listen(LISTENER_BACKLOG).context("start listener")?;
        let local_addr = listener.local_addr()?;

        debug!("Listening for connections on {local_addr}");
        self.local_addr = Some(local_addr);

        loop {
            let ev_receiver = Arc::clone(&self.ev_receiver);
            let mut ev_receiver = ev_receiver.lock().await;
            tokio::select! {
                Some(event) = ev_receiver.recv() => {
                    match event {
                        ServerEvent::Quit(reason) => {
                            debug!("Got quit event {reason}");
                            break;
                        }
                        ServerEvent::GetLocalAddr(tx) => {
                            let _ = tx.send(self.local_addr);
                        }
                        ServerEvent::SetCredentials(creds) => {
                            self.set_credentials(Some(creds));
                        }
                        ev => {
                            debug!("Unexpected event {:?}", ev);
                        }
                    }
                },
                Ok((stream, peer)) = listener.accept() => {
                    debug!(?peer, "Received connection");
                    drop(ev_receiver);

                    let accepted = self.connection_handler
                        .as_mut()
                        .is_none_or(|h| h.on_accept(peer));

                    if !accepted {
                        debug!(?peer, "Connection rejected by handler");
                        drop(stream);
                    } else {
                        let started = tokio::time::Instant::now();
                        let result = self.run_connection(stream).await;
                        let duration = started.elapsed();

                        if let Err(ref error) = result {
                            error!(?error, "Connection error");
                        }

                        self.static_channels = StaticChannelSet::new();

                        if let Some(ref mut handler) = self.connection_handler {
                            let action = handler.on_disconnected(
                                peer,
                                duration,
                                result.as_ref().err(),
                            );
                            if action == PostConnectionAction::Stop {
                                debug!(?peer, "Handler requested stop after disconnect");
                                break;
                            }
                        }
                    }
                }
                else => break,
            }
        }

        Ok(())
    }

    pub fn get_svc_processor<T: SvcProcessor + 'static>(&mut self) -> Option<&mut T> {
        self.static_channels
            .get_by_type_mut::<T>()
            .and_then(|svc| svc.channel_processor_downcast_mut())
    }

    pub fn get_channel_id_by_type<T: SvcProcessor + 'static>(&self) -> Option<StaticChannelId> {
        self.static_channels.get_channel_id_by_type::<T>()
    }

    async fn dispatch_pdu(
        &mut self,
        action: Action,
        bytes: bytes::BytesMut,
        writer: &mut impl FramedWrite,
        io_channel_id: u16,
        user_channel_id: u16,
        message_channel_id: Option<u16>,
    ) -> Result<RunState> {
        match action {
            Action::FastPath => {
                let input = decode(&bytes)?;
                self.handle_fastpath(input).await;
            }

            Action::X224 => {
                if self
                    .handle_x224(writer, io_channel_id, user_channel_id, message_channel_id, &bytes)
                    .await
                    .context("X224 input error")?
                {
                    debug!("Got disconnect request");
                    return Ok(RunState::Disconnect);
                }
            }
        }

        Ok(RunState::Continue)
    }

    async fn dispatch_display_update(
        update: DisplayUpdate,
        writer: &mut impl FramedWrite,
        user_channel_id: u16,
        io_channel_id: u16,
        buffer: &mut Vec<u8>,
        mut encoder: UpdateEncoder,
    ) -> Result<(RunState, UpdateEncoder)> {
        if let DisplayUpdate::Resize(desktop_size) = update {
            debug!(?desktop_size, "Display resize");
            encoder.set_desktop_size(desktop_size);
            deactivate_all(io_channel_id, user_channel_id, writer).await?;
            return Ok((RunState::DeactivationReactivation { desktop_size }, encoder));
        }

        let mut encoder_iter = encoder.update(update);
        loop {
            let Some(fragmenter) = encoder_iter.next().await else {
                break;
            };

            let mut fragmenter = fragmenter.context("error while encoding")?;
            if fragmenter.size_hint() > buffer.len() {
                buffer.resize(fragmenter.size_hint(), 0);
            }

            while let Some(len) = fragmenter.next(buffer) {
                writer
                    .write_all(&buffer[..len])
                    .await
                    .context("failed to write display update")?;
            }
        }

        Ok((RunState::Continue, encoder))
    }

    async fn dispatch_server_events(
        &mut self,
        events: &mut Vec<ServerEvent>,
        writer: &mut impl FramedWrite,
        user_channel_id: u16,
        message_channel_id: Option<u16>,
    ) -> Result<RunState> {
        // Avoid wave messages queuing up and causing extra delay. When a
        // batch carries more than `WAVE_KEEP` waves, drop the OLDEST ones
        // and keep the most recent — playing stale audio just bakes the
        // latency in permanently, so a one-time dispatch stall (e.g. a video
        // encode holding the server lock) would otherwise become a permanent
        // audio offset.
        //
        // This is still a naive solution; better long-term: compute the
        // actual delay, add IO priority, encode audio, use UDP, etc. 4 frames
        // is roughly low hundreds of ms in regular setups.
        const WAVE_KEEP: usize = 4;
        let wave_total = events
            .iter()
            .filter(|e| matches!(e, ServerEvent::Rdpsnd(RdpsndServerMessage::Wave(..))))
            .count();
        let mut wave_skip = wave_total.saturating_sub(WAVE_KEEP);
        for event in events.drain(..) {
            trace!(?event, "Dispatching");
            match event {
                ServerEvent::Quit(reason) => {
                    debug!("Got quit event: {reason}");
                    return Ok(RunState::Disconnect);
                }
                ServerEvent::GetLocalAddr(tx) => {
                    let _ = tx.send(self.local_addr);
                }
                ServerEvent::SetCredentials(creds) => {
                    self.set_credentials(Some(creds));
                }
                ServerEvent::Rdpsnd(s) => {
                    let Some(rdpsnd) = self.get_svc_processor::<RdpsndServer>() else {
                        warn!("No rdpsnd channel, dropping event");
                        continue;
                    };
                    let msgs = match s {
                        RdpsndServerMessage::Wave(data, ts) => {
                            if wave_skip > 0 {
                                wave_skip -= 1;
                                debug!("Dropping stale wave");
                                continue;
                            }
                            rdpsnd.wave(data, ts)
                        }
                        RdpsndServerMessage::SetVolume { left, right } => rdpsnd.set_volume(left, right),
                        RdpsndServerMessage::Close => rdpsnd.close(),
                        RdpsndServerMessage::Error(error) => {
                            error!(?error, "Handling rdpsnd event");
                            continue;
                        }
                    }
                    .context("failed to send rdpsnd event")?;
                    let channel_id = self
                        .get_channel_id_by_type::<RdpsndServer>()
                        .context("SVC channel not found")?;
                    let data = server_encode_svc_messages(msgs.into(), channel_id, user_channel_id)?;
                    writer.write_all(&data).await?;
                }
                ServerEvent::Clipboard(c) => {
                    let Some(cliprdr) = self.get_svc_processor::<CliprdrServer>() else {
                        warn!("No clipboard channel, dropping event");
                        continue;
                    };
                    let msgs = match c {
                        ClipboardMessage::SendInitiateCopy(formats) => cliprdr.initiate_copy(&formats),
                        ClipboardMessage::SendInitiateFileCopy(files) => cliprdr.initiate_file_copy(files),
                        ClipboardMessage::SendFormatData(data) => cliprdr.submit_format_data(data),
                        ClipboardMessage::SendInitiatePaste(format) => cliprdr.initiate_paste(format),
                        ClipboardMessage::SendFileContentsRequest(request) => cliprdr.request_file_contents(request),
                        ClipboardMessage::SendFileContentsResponse(response) => cliprdr.submit_file_contents(response),
                        ClipboardMessage::Error(error) => {
                            error!(?error, "Handling clipboard event");
                            continue;
                        }
                    }
                    .context("failed to send clipboard event")?;
                    let channel_id = self
                        .get_channel_id_by_type::<CliprdrServer>()
                        .context("SVC channel not found")?;
                    let data = server_encode_svc_messages(msgs.into(), channel_id, user_channel_id)?;
                    writer.write_all(&data).await?;
                }
                ServerEvent::Echo(msg) => match msg {
                    EchoServerMessage::SendRequest { payload } => {
                        let Some(drdynvc) = self.get_svc_processor::<dvc::DrdynvcServer>() else {
                            warn!("No drdynvc channel, dropping ECHO request");
                            continue;
                        };

                        let Some(echo_channel_id) = drdynvc.get_channel_id_by_type::<EchoDvcBridge>() else {
                            warn!("No ECHO dynamic channel, dropping ECHO request");
                            continue;
                        };

                        if !drdynvc.is_channel_opened(echo_channel_id) {
                            warn!("ECHO dynamic channel not yet opened, dropping ECHO request");
                            continue;
                        }

                        self.echo_handle.on_request_sent(&payload);

                        let request = build_echo_request(payload)?;
                        let messages =
                            dvc::encode_dvc_messages(echo_channel_id, vec![request], ChannelFlags::SHOW_PROTOCOL)?;

                        let drdynvc_channel_id = self
                            .get_channel_id_by_type::<dvc::DrdynvcServer>()
                            .context("DRDYNVC channel not found")?;

                        let data = server_encode_svc_messages(messages, drdynvc_channel_id, user_channel_id)?;
                        writer.write_all(&data).await?;
                    }
                },
                #[cfg(feature = "egfx")]
                ServerEvent::Egfx(msg) => match msg {
                    EgfxServerMessage::SendMessages { messages } => {
                        let drdynvc_channel_id = self
                            .get_channel_id_by_type::<dvc::DrdynvcServer>()
                            .context("DRDYNVC channel not found")?;
                        let data = server_encode_svc_messages(messages, drdynvc_channel_id, user_channel_id)?;
                        writer.write_all(&data).await?;
                    }
                },
                ServerEvent::AutoDetectRttRequest => {
                    // Auto-detect requests ride the MCS message channel
                    // ([MS-RDPBCGR] 2.2.14.3). With none negotiated (the client
                    // did not request it), there is nowhere to send them.
                    if let (Some(ad), Some(message_channel_id)) = (self.autodetect.as_mut(), message_channel_id) {
                        ad.expire_stale_probes(crate::autodetect::RTT_PROBE_MAX_AGE);
                        let request = ad.send_rtt_request();
                        let data = encode_autodetect_request(request, message_channel_id, user_channel_id)?;
                        writer.write_all(&data).await?;
                    }
                }
            }
        }

        Ok(RunState::Continue)
    }

    async fn client_loop<R, W>(
        &mut self,
        reader: &mut Framed<R>,
        writer: &mut Framed<W>,
        io_channel_id: u16,
        user_channel_id: u16,
        message_channel_id: Option<u16>,
        mut encoder: UpdateEncoder,
    ) -> Result<RunState>
    where
        R: FramedRead,
        W: FramedWrite,
    {
        debug!("Starting client loop");
        let mut display_updates = self.display.lock().await.updates().await?;
        let mut writer = SharedWriter::new(writer);
        let mut display_writer = writer.clone();
        let mut event_writer = writer.clone();
        let ev_receiver = Arc::clone(&self.ev_receiver);
        let s = Rc::new(Mutex::new(self));

        let this = Rc::clone(&s);
        let dispatch_pdu = async move {
            loop {
                let (action, bytes) = reader.read_pdu().await?;
                let mut this = this.lock().await;
                match this
                    .dispatch_pdu(
                        action,
                        bytes,
                        &mut writer,
                        io_channel_id,
                        user_channel_id,
                        message_channel_id,
                    )
                    .await?
                {
                    RunState::Continue => continue,
                    state => break Ok(state),
                }
            }
        };

        let dispatch_display = async move {
            let mut buffer = vec![0u8; 4096];

            loop {
                match display_updates.next_update().await {
                    Ok(Some(update)) => {
                        match Self::dispatch_display_update(
                            update,
                            &mut display_writer,
                            user_channel_id,
                            io_channel_id,
                            &mut buffer,
                            encoder,
                        )
                        .await?
                        {
                            (RunState::Continue, enc) => {
                                encoder = enc;
                                continue;
                            }
                            (state, _) => {
                                break Ok(state);
                            }
                        }
                    }
                    Ok(None) => {
                        break Ok(RunState::Disconnect);
                    }
                    Err(error) => {
                        warn!(error = format!("{error:#}"), "next_updated failed");
                    }
                }
            }
        };

        let this = Rc::clone(&s);
        let mut ev_receiver = ev_receiver.lock().await;
        let dispatch_events = async move {
            let mut events = Vec::with_capacity(100);
            loop {
                let nevents = ev_receiver.recv_many(&mut events, 100).await;
                if nevents == 0 {
                    debug!("No sever events.. stopping");
                    break Ok(RunState::Disconnect);
                }
                while let Ok(ev) = ev_receiver.try_recv() {
                    events.push(ev);
                }
                let mut this = this.lock().await;
                match this
                    .dispatch_server_events(&mut events, &mut event_writer, user_channel_id, message_channel_id)
                    .await?
                {
                    RunState::Continue => continue,
                    state => break Ok(state),
                }
            }
        };

        let state = tokio::select!(
            state = dispatch_pdu => state,
            state = dispatch_display => state,
            state = dispatch_events => state,
        );

        debug!("End of client loop: {state:?}");
        state
    }

    async fn client_accepted<R, W>(
        &mut self,
        reader: &mut Framed<R>,
        writer: &mut Framed<W>,
        result: AcceptorResult,
    ) -> Result<RunState>
    where
        R: FramedRead,
        W: FramedWrite,
    {
        debug!("Client accepted");

        // Validate credentials if a validator is configured. The validator runs here, in the
        // async server layer, rather than in the sans-I/O acceptor, because real validators
        // (PAM/LDAP/DB) are I/O-bound. On rejection, deny with a ServerSetErrorInfoPdu before
        // closing, matching the acceptor's exact-match denial path.
        if let Some(validator) = self.credential_validator.clone() {
            if let Some(creds) = &result.credentials {
                match validator.validate(creds).await {
                    Ok(CredentialDecision::Accept) => {
                        debug!("Credential validation accepted");
                    }
                    Ok(CredentialDecision::Reject) => {
                        warn!("Credential validation rejected");
                        send_access_denied(result.io_channel_id, result.user_channel_id, writer).await?;
                        bail!("credential validation rejected");
                    }
                    Err(e) => {
                        error!(error = %e, "Credential validator backend error");
                        send_access_denied(result.io_channel_id, result.user_channel_id, writer).await?;
                        bail!("credential validation backend error");
                    }
                }
            } else {
                debug!("Skipping credential validation (no credentials in AcceptorResult)");
            }
        }

        if !result.input_events.is_empty() {
            debug!("Handling input event backlog from acceptor sequence");
            self.handle_input_backlog(
                writer,
                result.io_channel_id,
                result.user_channel_id,
                result.message_channel_id,
                result.input_events,
            )
            .await?;
        }

        self.static_channels = result.static_channels;
        if !result.reactivation {
            for (_type_id, channel, channel_id) in self.static_channels.iter_mut() {
                debug!(?channel, ?channel_id, "Start");
                let Some(channel_id) = channel_id else {
                    continue;
                };
                let svc_responses = channel.start()?;
                let response = server_encode_svc_messages(svc_responses, channel_id, result.user_channel_id)?;
                writer.write_all(&response).await?;
            }
        }

        let mut update_codecs = UpdateEncoderCodecs::new();
        let mut surface_flags = CmdFlags::empty();
        for c in result.capabilities {
            match c {
                CapabilitySet::General(c) => {
                    let fastpath = c.extra_flags.contains(GeneralExtraFlags::FASTPATH_OUTPUT_SUPPORTED);
                    if !fastpath {
                        bail!("Fastpath output not supported!");
                    }
                }
                CapabilitySet::Bitmap(b) => {
                    if !b.desktop_resize_flag {
                        debug!("Desktop resize is not supported by the client");
                        continue;
                    }

                    let client_size = DesktopSize {
                        width: b.desktop_width,
                        height: b.desktop_height,
                    };
                    let display_size = self.display.lock().await.request_initial_size(client_size).await;

                    // It's problematic when the client didn't resize, as we send bitmap updates that don't fit.
                    // The client will likely drop the connection.
                    if client_size.width < display_size.width || client_size.height < display_size.height {
                        // TODO: we may have different behaviour instead, such as clipping or scaling?
                        warn!(
                            "Client size doesn't fit the server size: {:?} < {:?}",
                            client_size, display_size
                        );
                    }
                }
                CapabilitySet::SurfaceCommands(c) => {
                    surface_flags = c.flags;
                }
                CapabilitySet::BitmapCodecs(BitmapCodecs(codecs)) => {
                    for codec in codecs {
                        match codec.property {
                            // FIXME: The encoder operates in image mode only.
                            //
                            // See [MS-RDPRFX] 3.1.1.1 "State Machine" for
                            // implementation of the video mode. which allows to
                            // skip sending Header for each image.
                            //
                            // We should distinguish parameters for both modes,
                            // and somehow choose the "best", instead of picking
                            // the last parsed here.
                            CodecProperty::RemoteFx(rdp::capability_sets::RemoteFxContainer::ClientContainer(c))
                                if self.opts.has_remote_fx() =>
                            {
                                for caps in c.caps_data.0.0 {
                                    update_codecs.set_remotefx(Some((caps.entropy_bits, codec.id)));
                                }
                            }
                            CodecProperty::ImageRemoteFx(rdp::capability_sets::RemoteFxContainer::ClientContainer(
                                c,
                            )) if self.opts.has_image_remote_fx() => {
                                for caps in c.caps_data.0.0 {
                                    update_codecs.set_remotefx(Some((caps.entropy_bits, codec.id)));
                                }
                            }
                            #[cfg(feature = "nscodec")]
                            CodecProperty::NsCodec(client_ns) if self.opts.has_nscodec() => {
                                // Re-use the client's confirmed color-loss
                                // level so the server encodes at the same
                                // shift the client decodes against.
                                update_codecs.set_nscodec(Some((codec.id, client_ns.color_loss_level)));
                            }
                            CodecProperty::NsCodec(_) => (),
                            #[cfg(feature = "qoi")]
                            CodecProperty::Qoi if self.opts.has_qoi() => {
                                update_codecs.set_qoi(Some(codec.id));
                            }
                            #[cfg(feature = "qoiz")]
                            CodecProperty::QoiZ if self.opts.has_qoiz() => {
                                update_codecs.set_qoiz(Some(codec.id));
                            }
                            _ => (),
                        }
                    }
                }
                _ => {}
            }
        }

        let desktop_size = self.display.lock().await.size().await;
        let encoder = UpdateEncoder::new(desktop_size, surface_flags, update_codecs, self.opts.max_request_size)
            .context("failed to initialize update encoder")?;

        let state = self
            .client_loop(
                reader,
                writer,
                result.io_channel_id,
                result.user_channel_id,
                result.message_channel_id,
                encoder,
            )
            .await
            .context("client loop failure")?;

        Ok(state)
    }

    async fn handle_input_backlog(
        &mut self,
        writer: &mut impl FramedWrite,
        io_channel_id: u16,
        user_channel_id: u16,
        message_channel_id: Option<u16>,
        frames: Vec<Vec<u8>>,
    ) -> Result<()> {
        for frame in frames {
            match Action::from_fp_output_header(frame[0]) {
                Ok(Action::FastPath) => {
                    let input = decode(&frame)?;
                    self.handle_fastpath(input).await;
                }

                Ok(Action::X224) => {
                    let _ = self
                        .handle_x224(writer, io_channel_id, user_channel_id, message_channel_id, &frame)
                        .await;
                }

                // the frame here is always valid, because otherwise it would
                // have failed during the acceptor loop
                Err(_) => unreachable!(),
            }
        }

        Ok(())
    }

    async fn handle_fastpath(&mut self, input: FastPathInput) {
        for event in input.input_events().iter().copied() {
            let mut handler = self.handler.lock().await;
            match event {
                FastPathInputEvent::KeyboardEvent(flags, key) => {
                    handler.keyboard((key, flags).into());
                }

                FastPathInputEvent::UnicodeKeyboardEvent(flags, key) => {
                    handler.keyboard((key, flags).into());
                }

                FastPathInputEvent::SyncEvent(flags) => {
                    handler.keyboard(flags.into());
                }

                FastPathInputEvent::MouseEvent(mouse) => {
                    handler.mouse(mouse.into());
                }

                FastPathInputEvent::MouseEventEx(mouse) => {
                    handler.mouse(mouse.into());
                }

                FastPathInputEvent::MouseEventRel(mouse) => {
                    handler.mouse(mouse.into());
                }

                FastPathInputEvent::QoeEvent(quality) => {
                    warn!("Received QoE: {}", quality);
                }
            }
        }
    }

    async fn handle_io_channel_data(&mut self, data: SendDataRequest<'_>) -> Result<bool> {
        let control: rdp::headers::ShareControlHeader = decode(data.user_data.as_ref())?;

        match control.share_control_pdu {
            ShareControlPdu::Data(header) => match header.share_data_pdu {
                rdp::headers::ShareDataPdu::Input(pdu) => {
                    self.handle_input_event(pdu).await;
                }

                rdp::headers::ShareDataPdu::ShutdownRequest => {
                    return Ok(true);
                }

                // Client requests the server stop or resume sending display
                // updates. mstsc sends `desktop_rect: None` on minimize and
                // `desktop_rect: Some(rect)` on refocus. Without honoring
                // this, the server keeps streaming high-bitrate EGFX/H.264
                // frames into a minimized client; on refocus the client
                // must chew through the accumulated backlog before it can
                // present the current frame, locking up its input dispatch
                // for seconds. Flagging the shared `display_suppressed`
                // lets the display backend skip frame emission while it's
                // set.
                rdp::headers::ShareDataPdu::SuppressOutput(pdu) => {
                    let suppress = pdu.desktop_rect.is_none();
                    self.display_suppressed.store(suppress, Ordering::Relaxed);
                    debug!(suppress, "client suppress-output state changed");
                }

                // Client asks the server to redraw a rectangle — typical on
                // refocus after a minimize. Clear the suppress flag so the
                // backend resumes emission and treat this as "client wants
                // updates again." (The flag would also be cleared by the
                // `SuppressOutput { Some(rect) }` that usually accompanies
                // this; clearing here is belt-and-braces against clients
                // that send only one of the two.)
                rdp::headers::ShareDataPdu::RefreshRectangle(_) => {
                    if self.display_suppressed.swap(false, Ordering::Relaxed) {
                        debug!("client RefreshRectangle cleared suppress-output state");
                    }
                }

                unexpected => {
                    warn!(?unexpected, "Unexpected share data pdu");
                }
            },

            unexpected => {
                warn!(?unexpected, "Unexpected share control");
            }
        }

        Ok(false)
    }

    fn handle_message_channel_data(&mut self, data: SendDataRequest<'_>) {
        // The MCS message channel currently carries only the auto-detect
        // response. It is framed by a Basic Security Header (SEC_AUTODETECT_RSP),
        // not a Share Control header.
        match decode::<rdp::autodetect::AutoDetectRspPdu>(data.user_data.as_ref()) {
            Ok(pdu) => {
                if let Some(ref mut ad) = self.autodetect {
                    if let Some(rtt_ms) = ad.handle_response(&pdu.response) {
                        self.autodetect_rtt.store(rtt_ms, Ordering::Relaxed);
                        debug!(rtt_ms, seq = pdu.response.sequence_number(), "RTT measured");
                    } else {
                        trace!(seq = pdu.response.sequence_number(), "Unmatched auto-detect response");
                    }
                }
            }
            Err(error) => {
                warn!(error = format!("{error:#}"), "Unhandled MCS message channel PDU");
            }
        }
    }

    async fn handle_x224(
        &mut self,
        writer: &mut impl FramedWrite,
        io_channel_id: u16,
        user_channel_id: u16,
        message_channel_id: Option<u16>,
        frame: &[u8],
    ) -> Result<bool> {
        let message = decode::<X224<mcs::McsMessage<'_>>>(frame)?;
        match message.0 {
            mcs::McsMessage::SendDataRequest(data) => {
                debug!(
                    initiator_id = data.initiator_id,
                    channel_id = data.channel_id,
                    user_data_len = data.user_data.len(),
                    "McsMessage::SendDataRequest"
                );
                if data.channel_id == io_channel_id {
                    return self.handle_io_channel_data(data).await;
                }

                if message_channel_id == Some(data.channel_id) {
                    self.handle_message_channel_data(data);
                    return Ok(false);
                }

                if let Some(svc) = self.static_channels.get_by_channel_id_mut(data.channel_id) {
                    let response_pdus = svc.process(&data.user_data)?;
                    let response = server_encode_svc_messages(response_pdus, data.channel_id, user_channel_id)?;
                    writer.write_all(&response).await?;
                } else {
                    warn!(channel_id = data.channel_id, "Unexpected channel received: ID",);
                }
            }

            mcs::McsMessage::DisconnectProviderUltimatum(disconnect) => {
                if disconnect.reason == mcs::DisconnectReason::UserRequested {
                    return Ok(true);
                }
            }

            _ => {
                warn!(name = ironrdp_core::name(&message), "Unexpected mcs message");
            }
        }

        Ok(false)
    }

    async fn handle_input_event(&mut self, input: InputEventPdu) {
        for event in input.0 {
            let mut handler = self.handler.lock().await;
            match event {
                ironrdp_pdu::input::InputEvent::ScanCode(key) => {
                    handler.keyboard((key.key_code, key.flags).into());
                }

                ironrdp_pdu::input::InputEvent::Unicode(key) => {
                    handler.keyboard((key.unicode_code, key.flags).into());
                }

                ironrdp_pdu::input::InputEvent::Sync(sync) => {
                    handler.keyboard(sync.flags.into());
                }

                ironrdp_pdu::input::InputEvent::Mouse(mouse) => {
                    handler.mouse(mouse.into());
                }

                ironrdp_pdu::input::InputEvent::MouseX(mouse) => {
                    handler.mouse(mouse.into());
                }

                ironrdp_pdu::input::InputEvent::MouseRel(mouse) => {
                    handler.mouse(mouse.into());
                }

                ironrdp_pdu::input::InputEvent::Unused(_) => {}
            }
        }
    }

    async fn accept_finalize<S>(&mut self, mut framed: TokioFramed<S>, mut acceptor: Acceptor) -> Result<TokioFramed<S>>
    where
        S: AsyncRead + AsyncWrite + Sync + Send + Unpin,
    {
        loop {
            let (new_framed, result) = ironrdp_acceptor::accept_finalize(framed, &mut acceptor)
                .await
                .context("failed to accept client during finalize")?;

            let (mut reader, mut writer) = split_tokio_framed(new_framed);

            match self.client_accepted(&mut reader, &mut writer, result).await? {
                RunState::Continue => {
                    unreachable!();
                }
                RunState::DeactivationReactivation { desktop_size } => {
                    // No description of such behavior was found in the
                    // specification, but apparently, we must keep the channel
                    // state as they were during reactivation. This fixes
                    // various state issues during client resize.
                    acceptor = Acceptor::new_deactivation_reactivation(
                        acceptor,
                        core::mem::take(&mut self.static_channels),
                        desktop_size,
                    )?;
                    framed = unsplit_tokio_framed(reader, writer);
                    continue;
                }
                RunState::Disconnect => {
                    let final_framed = unsplit_tokio_framed(reader, writer);
                    return Ok(final_framed);
                }
            }
        }
    }

    pub fn set_credentials(&mut self, creds: Option<Credentials>) {
        debug!(?creds, "Changing credentials");
        self.creds = creds
    }
}

/// Encode a server-initiated Auto-Detect Request PDU for the MCS message channel.
///
/// The request is framed by a Basic Security Header (SEC_AUTODETECT_REQ) per
/// [MS-RDPBCGR] 2.2.14.3 and carried in an MCS Send Data Indication on the
/// negotiated message channel, not as a Share Data PDU on the I/O channel.
fn encode_autodetect_request(
    request: rdp::autodetect::AutoDetectRequest,
    message_channel_id: u16,
    user_channel_id: u16,
) -> Result<Vec<u8>> {
    // Auto-detect rides the MCS message channel framed by a Basic Security
    // Header (SEC_AUTODETECT_REQ), not a Share Control / Share Data header.
    let pdu = rdp::autodetect::AutoDetectReqPdu::new(request);
    let user_data = encode_vec(&pdu)?.into();
    let mcs_pdu = SendDataIndication {
        initiator_id: user_channel_id,
        channel_id: message_channel_id,
        user_data,
    };
    Ok(encode_vec(&X224(mcs_pdu))?)
}

async fn deactivate_all(
    io_channel_id: u16,
    user_channel_id: u16,
    writer: &mut impl FramedWrite,
) -> Result<(), anyhow::Error> {
    let pdu = ShareControlPdu::ServerDeactivateAll(ServerDeactivateAll);
    let pdu = rdp::headers::ShareControlHeader {
        share_id: 0,
        pdu_source: io_channel_id,
        share_control_pdu: pdu,
    };
    let user_data = encode_vec(&pdu)?.into();
    let pdu = SendDataIndication {
        initiator_id: user_channel_id,
        channel_id: io_channel_id,
        user_data,
    };
    let msg = encode_vec(&X224(pdu))?;
    writer.write_all(&msg).await?;
    Ok(())
}

/// Send a `ServerSetErrorInfoPdu(ServerDeniedConnection)` to the client, then return.
///
/// Used to deny a connection after credential validation rejects it, mirroring the
/// acceptor's exact-match denial so both paths refuse the same spec-defined way.
async fn send_access_denied(
    io_channel_id: u16,
    user_channel_id: u16,
    writer: &mut impl FramedWrite,
) -> Result<(), anyhow::Error> {
    let info = ServerSetErrorInfoPdu(ErrorInfo::ProtocolIndependentCode(
        ProtocolIndependentCode::ServerDeniedConnection,
    ));
    let user_data = encode_vec(&info)?.into();
    let pdu = SendDataIndication {
        initiator_id: user_channel_id,
        channel_id: io_channel_id,
        user_data,
    };
    let msg = encode_vec(&X224(pdu))?;
    writer.write_all(&msg).await?;
    Ok(())
}

struct SharedWriter<'w, W: FramedWrite> {
    writer: Rc<Mutex<&'w mut W>>,
}

impl<W: FramedWrite> Clone for SharedWriter<'_, W> {
    fn clone(&self) -> Self {
        Self {
            writer: Rc::clone(&self.writer),
        }
    }
}

impl<W> FramedWrite for SharedWriter<'_, W>
where
    W: FramedWrite,
{
    type WriteAllFut<'write>
        = core::pin::Pin<Box<dyn Future<Output = std::io::Result<()>> + 'write>>
    where
        Self: 'write;

    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> Self::WriteAllFut<'a> {
        Box::pin(async {
            let mut writer = self.writer.lock().await;

            writer.write_all(buf).await?;
            Ok(())
        })
    }
}

impl<'a, W: FramedWrite> SharedWriter<'a, W> {
    fn new(writer: &'a mut W) -> Self {
        Self {
            writer: Rc::new(Mutex::new(writer)),
        }
    }
}
