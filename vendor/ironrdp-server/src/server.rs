use core::cell::RefCell;
use core::fmt;
use core::net::{IpAddr, SocketAddr};
#[cfg(feature = "egfx")]
use core::num::NonZeroU32;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;
#[cfg(feature = "usb")]
use std::collections::HashMap;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::{Arc, LazyLock, Mutex as StdMutex};
use std::time::Instant;

use ironrdp_acceptor::{
    Acceptor, AcceptorResult, BeginResult, ConnectionSetupHandler, ConnectorError, ConnectorErrorExt as _,
    CredentialOrigin, DesktopSize, ReceivedCredentials,
};
use ironrdp_async::Framed;
use ironrdp_cliprdr::CliprdrServer;
use ironrdp_cliprdr::backend::ClipboardMessage;
use ironrdp_core::{WriteBuf, decode, encode_vec, impl_as_any};
use ironrdp_displaycontrol::pdu::{DisplayControlCapabilities, DisplayControlMonitorLayout};
use ironrdp_displaycontrol::server::{DisplayControlHandler, DisplayControlServer};
use ironrdp_dvc as dvc;
#[cfg(feature = "usb")]
use ironrdp_dvc::DynamicChannelId;
use ironrdp_error::ResultExt as _;
#[cfg(feature = "usb")]
use ironrdp_pdu::PduError;
use ironrdp_pdu::codecs::rfx::Quant;
use ironrdp_pdu::input::InputEventPdu;
use ironrdp_pdu::input::fast_path::{FastPathInput, FastPathInputEvent};
use ironrdp_pdu::mcs::{SendDataIndication, SendDataRequest};
use ironrdp_pdu::rdp::capability_sets::{
    BitmapCodecs, CapabilitySet, CmdFlags, Codec, CodecProperty, EntropyBits, GeneralExtraFlags,
    LargePointerSupportFlags, RemoteFxContainer,
};
pub use ironrdp_pdu::rdp::client_info::Credentials;
use ironrdp_pdu::rdp::headers::{ServerDeactivateAll, ShareControlPdu};
use ironrdp_pdu::rdp::server_error_info::{ErrorInfo, ProtocolIndependentCode, ServerSetErrorInfoPdu};
use ironrdp_pdu::rdp::server_redirection::ServerRedirectionPdu;
use ironrdp_pdu::x224::X224;
use ironrdp_pdu::{Action, PduResult, decode_err, mcs, nego, rdp};
use ironrdp_rdpdr as rdpdr;
use ironrdp_rdpeai as rdpeai;
use ironrdp_rdpsnd as rdpsnd;
use ironrdp_svc::{ChannelFlags, StaticChannelId, StaticChannelSet, SvcProcessor, server_encode_svc_messages};
use ironrdp_tokio::{FramedRead, FramedWrite, TokioFramed, split_tokio_framed, unsplit_tokio_framed};
use rand::RngCore as _;
use rdpdr::server::{RdpdrServer, RdpdrServerMessage};
use rdpeai::server::{RdpeaiServer, RdpeaiServerMessage};
use rdpsnd::server::{RdpsndServer, RdpsndServerMessage};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, trace, warn};

use crate::autodetect::{AutoDetectHandles, AutoDetectManager, AutoDetectOutcome};
use crate::clipboard::CliprdrServerFactory;
use crate::display::{DisplayContext, DisplayUpdate, RdpServerDisplay, RdpServerDisplayUpdates};
use crate::echo::{EchoDvcBridge, EchoServerHandle, EchoServerMessage, build_echo_request};
use crate::encoder::{RemoteFxCodec, UpdateEncoder, UpdateEncoderCodecs};
use crate::error::{ServerError, ServerErrorExt as _, ServerErrorKind, ServerResult};
#[cfg(feature = "egfx")]
use crate::gfx::{EgfxServerMessage, GfxContext, GfxServerFactory, GfxServerHandle};
use crate::handler::{KeyboardEvent, MouseEvent, RdpServerInputHandler};
use crate::heartbeat::HeartbeatConfig;
use crate::multitransport;
use crate::rdpeai::RdpeaiServerFactory;
use crate::rdpei::RdpeiServerFactory;
#[cfg(feature = "usb")]
use crate::urbdrc::{
    DeviceFactory, ServerDeviceIoReq, ServerUsbDevice, UrbdrcDeviceServerMessage, UrbdrcServerMessage,
    UsbControlHandle, UsbDeviceHandle,
};
use crate::{RdpdrServerFactory, SoundServerFactory, builder, capabilities};
#[cfg(feature = "usb")]
use ironrdp_rdpeusb::{InterfaceAlloc, server::UrbdrcControlServer, server::UrbdrcDeviceServer};

/// TCP listen backlog size for the RDP server socket.
const LISTENER_BACKLOG: u32 = 1024;

/// How long [`RdpServer::run`]'s TCP source waits after a failed accept before
/// it reports the failure, so a persistent one (no file descriptors left) is not
/// retried in a tight loop.
const TCP_ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

#[cfg(feature = "egfx")]
fn client_core_frame_ack_limit(capabilities: &[CapabilitySet]) -> Option<NonZeroU32> {
    capabilities.iter().find_map(|capability| match capability {
        CapabilitySet::FrameAcknowledge(capability) => NonZeroU32::new(capability.max_unacknowledged_frame_count),
        _ => None,
    })
}
const AUTO_RECONNECT_COOKIE_UPDATE_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// How often the server drives [`CliprdrServer::drive_timeouts`].
///
/// The clipboard channel tracks clipboard-data locks, in-flight file contents
/// requests and locked file list snapshots against wall-clock deadlines, but it
/// has no timer of its own: the docs on `drive_timeouts` require the embedder to
/// call it periodically. `ironrdp-client` and `ironrdp-web` already do; without
/// this the server role never sends `Unlock` PDUs, never expires locks and never
/// answers abandoned file contents requests.
///
/// Two of those sweeps reach the backend with no PDU from the peer behind them:
/// a file contents request left pending past the transfer timeout is answered
/// with a synthetic error through [`on_file_contents_response`], and a locked
/// file list snapshot left inactive for that same window is dropped with
/// [`on_unlock`]. Both already run for the client and web roles; a server
/// backend starts seeing them once this timer does.
///
/// [`on_file_contents_response`]: ironrdp_cliprdr::backend::CliprdrBackend::on_file_contents_response
/// [`on_unlock`]: ironrdp_cliprdr::backend::CliprdrBackend::on_unlock
const CLIPRDR_DRIVE_TIMEOUTS_INTERVAL: Duration = Duration::from_secs(5);

/// How long a single [`ironrdp_acceptor::accept_finalize`] pass may take before
/// the connection is dropped.
///
/// A client can complete the whole security handshake — X.224, TLS, and CredSSP
/// where applicable — and then stop producing PDUs, leaving the server blocked
/// on a socket read with no timeout. Because `RdpServer` serves one connection
/// at a time, that connection then holds the server indefinitely: the socket
/// stays ESTABLISHED with both TCP queues empty, and nothing tears it down.
/// This has been observed in the field against a real client, which completed
/// MCS Connect, Erect Domain, Attach User and every channel join and then never
/// sent its Client Info PDU; the connection sat there for 45 minutes.
///
/// Generous on purpose: a healthy finalize is sub-second, and even over a slow
/// mobile link with heavy retransmits the whole pass stays within a few
/// seconds. A false timeout is cheap — the connection is dropped and the client
/// reconnects (immediately, if it holds an auto-reconnect cookie).
const FINALIZE_TIMEOUT: Duration = Duration::from_secs(30);

/// Monotonic milliseconds since first use, for feeding the auto-detect state machine.
///
/// The clock lives here, in the I/O driver, rather than inside [`AutoDetectManager`]:
/// the state machine takes timestamps as arguments so it stays free of ambient time.
/// Only differences are meaningful, so the epoch is arbitrary.
fn monotonic_now_ms() -> u64 {
    static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);
    u64::try_from(EPOCH.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Action to take after a client disconnects.
///
/// Returned by [`ConnectionHandler::on_disconnected`] to control whether
/// the server continues accepting new connections or shuts down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostConnectionAction {
    /// Continue accepting new connections.
    Continue,
    /// Stop the accept loop and return from [`RdpServer::run`] or [`RdpServer::serve`].
    Stop,
}

/// Per-connection metadata captured during connection setup, made available to
/// [`ConnectionHandler::on_connection_info`] once the connection is established.
///
/// These are GCC Client Core Data fields (MS-RDPBCGR 2.2.1.3.2) and the Client
/// Monitor Data block (2.2.1.3.6) that the acceptor captures but has no use for
/// itself; embedders that want to act on them (for example, selecting a
/// server-side keyboard layout matching the client, or presenting as many
/// outputs as the client has monitors) can do so here without reaching into the
/// acceptor's internals.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ConnectionInfo {
    /// See [`ironrdp_acceptor::AcceptorResult::keyboard_layout`].
    pub keyboard_layout: u32,
    /// See [`ironrdp_acceptor::AcceptorResult::keyboard_type`].
    pub keyboard_type: ironrdp_pdu::gcc::KeyboardType,
    /// See [`ironrdp_acceptor::AcceptorResult::ime_file_name`].
    pub ime_file_name: String,
    /// The client came back with an auto-reconnect cookie the server
    /// verified, in place of its credentials.
    pub auto_reconnect: bool,
    /// See [`ironrdp_acceptor::AcceptorResult::client_monitors`]. Taken from the
    /// GCC Client Monitor Data (MS-RDPBCGR 2.2.1.3.6), not Client Core Data, and
    /// empty when the client sent none. It doesn't change the Monitor Layout PDU
    /// the acceptor sends, which still describes one monitor.
    pub client_monitors: Vec<ironrdp_pdu::gcc::Monitor>,
    /// See [`ironrdp_acceptor::AcceptorResult::routing_token`].
    pub routing_token: Option<String>,
    /// The session the client asked to reconnect to in its GCC Client Cluster Data (MS-RDPBCGR 2.2.1.3.5), as a
    /// client redirected by a Server Redirection PDU does.
    pub redirected_session_id: Option<u32>,
    /// See [`ironrdp_acceptor::AcceptorResult::password_cookie`].
    pub password_cookie: Option<rdp::client_info::PasswordCookie>,
}

impl ConnectionInfo {
    /// Builds a `ConnectionInfo` directly, for downstream `ConnectionHandler` implementations
    /// that want to exercise [`ConnectionHandler::on_connection_info`] in their own unit tests
    /// without going through a live connection. `#[non_exhaustive]` blocks struct-literal
    /// construction outside this crate, so a constructor is the only way to do that.
    pub fn new(keyboard_layout: u32, keyboard_type: ironrdp_pdu::gcc::KeyboardType, ime_file_name: String) -> Self {
        Self {
            keyboard_layout,
            keyboard_type,
            ime_file_name,
            auto_reconnect: false,
            client_monitors: Vec::new(),
            routing_token: None,
            redirected_session_id: None,
            password_cookie: None,
        }
    }
}

/// Hooks for connection lifecycle events.
///
/// Implement this trait to add pre-accept filtering (rate limiting,
/// IP allowlists), post-disconnect logic (cleanup, session validity
/// checks, metrics), and to observe per-connection metadata once a
/// connection is established.
///
/// All methods have default implementations that accept all connections
/// and continue unconditionally.
///
/// [`Self::on_accept`] and [`Self::on_disconnected`] are called only from
/// [`RdpServer::run`]'s accept loop and from [`RdpServer::serve`], which is the
/// same loop over an embedder's own [`ConnectionSource`]. Both take a
/// [`SocketAddr`], so a connection whose source reports no
/// [`peer`](IncomingConnection::peer) (a Unix socket, AF_VSOCK) is passed to
/// neither, and under [`ConnectionPolicy::Preempt`] nothing here gates it before
/// it may negotiate. [`Self::on_connection_info`]
/// is called from every code path that completes connection setup, including
/// [`RdpServer::run_connection`] and [`RdpServer::run_connection_with`], so it
/// is the hook to use for embedders that accept connections and call those
/// directly.
pub trait ConnectionHandler: Send {
    /// Called after `accept()` returns but before `run_connection()`.
    ///
    /// Return `false` to reject the connection (the TCP stream is dropped).
    fn on_accept(&mut self, peer: SocketAddr) -> bool {
        let _ = peer;
        true
    }

    /// Called once per connection, after credential and auto-reconnect
    /// validation succeed and before the session loop starts.
    fn on_connection_info(&mut self, info: &ConnectionInfo) {
        let _ = info;
    }

    /// Called after `run_connection()` completes (successfully or with error).
    ///
    /// `duration` is the wall-clock time the connection was active.
    /// `error` is `Some` if the connection ended with an error.
    fn on_disconnected(
        &mut self,
        peer: SocketAddr,
        duration: Duration,
        error: Option<&ServerError>,
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

/// Server-side credential validator for accepted client credentials.
///
/// Called during connection setup when the acceptor surfaces credentials from
/// either `ClientInfoPdu` or CredSSP delegated TSPasswordCreds. Use the
/// [`CredentialValidator::validate_received`] hook to distinguish unauthenticated
/// ClientInfo credentials from CredSSP-delegated credentials authenticated by the exchange.
///
/// Implement this trait to validate or authorize credentials against external systems
/// (PAM, LDAP, database, etc.). ClientInfo credentials require authentication;
/// CredSSP-delegated credentials may still require server-specific authorization.
/// For blocking backends, wrap the call in
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
    /// Validate or authorize credentials received from the client.
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

    /// Validate credentials with their transport/authentication provenance.
    ///
    /// Existing validators remain source-compatible through the default
    /// implementation. Validators that need different ClientInfo and CredSSP
    /// policies can override this method.
    async fn validate_received(
        &self,
        credentials: &Credentials,
        origin: CredentialOrigin,
    ) -> Result<CredentialDecision, CredentialValidationError> {
        let _ = origin;
        self.validate(credentials).await
    }
}

/// Display/input objects bound after the server authenticates a client.
///
/// Servers with per-user desktop/session isolation can start with placeholder
/// display and input handlers, authenticate the client's credentials, and then
/// replace those placeholders with handlers attached to the authenticated
/// user's session before the RDP client loop starts.
pub struct BoundConnection {
    pub display: Box<dyn RdpServerDisplay>,
    pub input: Box<dyn RdpServerInputHandler>,
}

/// Async post-auth connection binder for identity-bound display and input resources.
///
/// A multi-user server can keep protocol ownership inside IronRDP while keeping
/// account authorization and session lifecycle outside the RDP state machine.
/// It may start with placeholder handlers, authenticate or authorize the received
/// credentials, then use this hook to start or locate the user's session and
/// install the returned handlers before static channels, display updates, or
/// input dispatch begin.
///
/// The binder runs once for the initial acceptance of a TCP connection, after
/// the operational desktop size has been negotiated. `desktop_size` is the
/// exact size the returned display must expose. During Deactivation-Reactivation
/// (for example, a later client resize), the existing bound handlers remain
/// installed and the binder is not called again.
#[async_trait::async_trait]
pub trait ConnectionBinder: Send + Sync {
    async fn bind_connection(
        &self,
        credentials: &Credentials,
        desktop_size: DesktopSize,
    ) -> ServerResult<BoundConnection>;
}

struct BoundDisplaySlot {
    default: Box<dyn RdpServerDisplay>,
    // Async display methods lease the bound display from this slot. The lease
    // restores it on cancellation unless a newer connection binding replaced it.
    bound: Arc<StdMutex<BoundDisplayState>>,
}

#[derive(Default)]
struct BoundDisplayState {
    display: Option<Box<dyn RdpServerDisplay>>,
    generation: Arc<()>,
}

impl BoundDisplayState {
    fn clear(&mut self) {
        self.display.take();
        self.generation = Arc::new(());
    }
}

struct BoundDisplayLease {
    slot: Arc<StdMutex<BoundDisplayState>>,
    display: Option<Box<dyn RdpServerDisplay>>,
    generation: Arc<()>,
}

impl BoundDisplayLease {
    fn take(slot: &Arc<StdMutex<BoundDisplayState>>) -> Option<Self> {
        let mut state = slot.lock().expect("bound display lock poisoned");
        let display = state.display.take()?;
        Some(Self {
            slot: Arc::clone(slot),
            display: Some(display),
            generation: Arc::clone(&state.generation),
        })
    }

    fn display_mut(&mut self) -> &mut dyn RdpServerDisplay {
        self.display
            .as_deref_mut()
            .expect("bound display lease always owns a display")
    }
}

impl Drop for BoundDisplayLease {
    fn drop(&mut self) {
        let mut slot = self.slot.lock().expect("bound display lock poisoned");
        if Arc::ptr_eq(&slot.generation, &self.generation) && slot.display.is_none() {
            slot.display = self.display.take();
        }
    }
}

impl BoundDisplaySlot {
    fn new(default: Box<dyn RdpServerDisplay>, bound: Arc<StdMutex<BoundDisplayState>>) -> Self {
        Self { default, bound }
    }
}

#[async_trait::async_trait]
impl RdpServerDisplay for BoundDisplaySlot {
    async fn size(&mut self) -> DesktopSize {
        if let Some(mut lease) = BoundDisplayLease::take(&self.bound) {
            lease.display_mut().size().await
        } else {
            self.default.size().await
        }
    }

    async fn request_initial_size(&mut self, client_size: DesktopSize) -> DesktopSize {
        if let Some(mut lease) = BoundDisplayLease::take(&self.bound) {
            lease.display_mut().request_initial_size(client_size).await
        } else {
            self.default.request_initial_size(client_size).await
        }
    }

    async fn monitor_count(&mut self) -> u32 {
        if let Some(mut lease) = BoundDisplayLease::take(&self.bound) {
            lease.display_mut().monitor_count().await
        } else {
            self.default.monitor_count().await
        }
    }

    async fn offers_display_control(&mut self) -> bool {
        if let Some(mut lease) = BoundDisplayLease::take(&self.bound) {
            lease.display_mut().offers_display_control().await
        } else {
            self.default.offers_display_control().await
        }
    }

    async fn updates(&mut self, ctx: DisplayContext) -> ServerResult<Box<dyn RdpServerDisplayUpdates>> {
        if let Some(mut lease) = BoundDisplayLease::take(&self.bound) {
            lease.display_mut().updates(ctx).await
        } else {
            self.default.updates(ctx).await
        }
    }

    fn request_layout(&mut self, layout: DisplayControlMonitorLayout) {
        let mut bound = self.bound.lock().expect("bound display lock poisoned");
        if let Some(display) = bound.display.as_mut() {
            display.request_layout(layout);
        } else {
            drop(bound);
            self.default.request_layout(layout);
        }
    }
}

struct BoundInputSlot {
    default: Box<dyn RdpServerInputHandler>,
    // Kept parallel to BoundDisplaySlot. The outer tokio::Mutex around
    // RdpServer::handler serializes access before input dispatch reaches this slot.
    bound: Arc<StdMutex<Option<Box<dyn RdpServerInputHandler>>>>,
}

impl BoundInputSlot {
    fn new(
        default: Box<dyn RdpServerInputHandler>,
        bound: Arc<StdMutex<Option<Box<dyn RdpServerInputHandler>>>>,
    ) -> Self {
        Self { default, bound }
    }
}

impl RdpServerInputHandler for BoundInputSlot {
    fn keyboard(&mut self, event: KeyboardEvent) {
        let mut bound = self.bound.lock().expect("bound input lock poisoned");
        if let Some(handler) = bound.as_mut() {
            handler.keyboard(event);
        } else {
            drop(bound);
            self.default.keyboard(event);
        }
    }

    fn mouse(&mut self, event: MouseEvent) {
        let mut bound = self.bound.lock().expect("bound input lock poisoned");
        if let Some(handler) = bound.as_mut() {
            handler.mouse(event);
        } else {
            drop(bound);
            self.default.mouse(event);
        }
    }
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

/// What [`RdpServer::run`] and [`RdpServer::serve`] do with a second connection
/// that arrives while a session is already being served.
///
/// [`RdpServer`] serves one connection at a time, so a second connection
/// accepted while one is live has to go somewhere: left in the OS listen
/// backlog ([`Queue`](ConnectionPolicy::Queue)), closed at once
/// ([`Reject`](ConnectionPolicy::Reject)), or served in place of the running
/// session ([`Preempt`](ConnectionPolicy::Preempt)).
///
/// The default depends on the security mode -- see
/// [`ConnectionPolicy::default_for`]. There is deliberately no
/// mode-independent [`Default`]: whether takeover is safe out of the box is
/// decided by whether the client is authenticated before it could evict
/// anything, and only the security mode knows that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionPolicy {
    /// Leave the extra connection in the OS listen backlog until the running
    /// session ends. The pre-existing behaviour: the second client is not
    /// answered and appears to hang until the first leaves.
    Queue,
    /// Close the extra connection immediately. The running session is never
    /// interrupted; the new client fails fast and can retry rather than
    /// appearing to hang.
    ///
    /// A connection closed this way never reaches
    /// [`ConnectionHandler::on_accept`]: it is dropped before it enters the
    /// handler's lifecycle, just as a connection left in the backlog under
    /// `Queue` is not seen by the handler until it is served. The rejected
    /// peer is logged at `debug` level.
    Reject,
    /// Preempt the running session with a fully-authenticated newcomer: once it
    /// has **completed authentication**, the existing connection is told why it
    /// is going away and dropped, and the newcomer is served in its place.
    /// Suits a server backing a single specific session (e.g. mirroring one
    /// desktop), where a newly connecting client should replace a stale or
    /// abandoned one.
    ///
    /// # Security -- what a candidate must clear, per mode
    ///
    /// Evicting a live session is disruptive, so a candidate runs the FULL
    /// negotiation -- and, under [`RdpServerSecurity::Hybrid`], CredSSP/NLA --
    /// before the live session is touched at all. A candidate that fails at any
    /// step leaves the live session untouched.
    ///
    /// How strong that bar actually is depends entirely on the security mode,
    /// because only `Hybrid` authenticates the *client* before the point a
    /// candidate reaches. **Read this table before selecting this variant:**
    ///
    /// | Security mode | Bar to preempt | Guarantee |
    /// |---|---|---|
    /// | [`Hybrid`](RdpServerSecurity::Hybrid) | CredSSP/NLA succeeds | an unauthenticated peer can never evict |
    /// | [`Tls`](RdpServerSecurity::Tls) | a TLS handshake -- which authenticates the *server* to the client, not the reverse | **none against an unauthenticated peer**: any peer that can reach the port clears it, and a [`CredentialValidator`] does not run until finalization |
    /// | [`None`](RdpServerSecurity::None) | a well-formed X.224 Connection Request | **none**: this mode authenticates nothing |
    ///
    /// So under `Tls` and `None` an unauthenticated peer CAN evict an
    /// authenticated session, repeatedly -- the anti-storm cooldown bars the
    /// victim, never the attacker. A warning is logged at startup in that case.
    /// If you need takeover to be authentication-gated, use `Hybrid`; if you
    /// must select it under another mode, restrict who may attempt one with
    /// [`ConnectionHandler::on_accept`].
    ///
    /// Candidates are additionally gated through
    /// [`ConnectionHandler::on_accept`] *before* they are allowed to
    /// negotiate, so an IP allowlist or rate limiter bounds who may even
    /// attempt a takeover. It does NOT bound how long one admitted candidate
    /// can occupy the (single) negotiation slot before another is even
    /// considered -- see the limitation documented on
    /// `CANDIDATE_NEGOTIATION_TIMEOUT`.
    Preempt,
}

impl ConnectionPolicy {
    /// The policy [`RdpServerBuilder`](crate::RdpServerBuilder) starts from
    /// for a given security mode.
    ///
    /// Takeover is the least-surprising behaviour for the single-session
    /// servers `ironrdp-server` typically backs (one mirroring one desktop): a
    /// newly connecting client should replace a stale or abandoned one, not
    /// hang behind it. But takeover is only *safe* out of the box where the
    /// newcomer is authenticated before it could evict anything, and per the
    /// table on [`Preempt`](ConnectionPolicy::Preempt) that is
    /// [`RdpServerSecurity::Hybrid`] alone -- under `Tls` or `None` any peer
    /// able to complete the handshake clears the bar, and the anti-storm
    /// cooldown bars the victim rather than the attacker. So:
    ///
    /// | Security mode | Default |
    /// |---|---|
    /// | [`Hybrid`](RdpServerSecurity::Hybrid) | [`Preempt`](ConnectionPolicy::Preempt) -- CredSSP/NLA gates every takeover |
    /// | [`Tls`](RdpServerSecurity::Tls), [`None`](RdpServerSecurity::None) | [`Queue`](ConnectionPolicy::Queue) -- the pre-existing behaviour; an unauthenticated takeover is an explicit opt-in |
    ///
    /// Either can be overridden with
    /// [`RdpServerBuilder::with_connection_policy`](crate::RdpServerBuilder::with_connection_policy).
    #[must_use]
    pub fn default_for(security: &RdpServerSecurity) -> Self {
        if authenticates_before_eviction(security) {
            Self::Preempt
        } else {
            Self::Queue
        }
    }
}

/// Tunnel payloads held while a Soft-Sync response is pending; beyond this the
/// client is sending far more than the handful of messages the race allows.
const MAX_EARLY_TUNNEL_PAYLOADS: usize = 64;

#[derive(Clone)]
#[non_exhaustive]
pub struct RdpServerOptions {
    pub addr: SocketAddr,
    pub security: RdpServerSecurity,
    pub codecs: BitmapCodecs,
    pub max_request_size: u32,
    /// When `Some(max)`, each connection's acceptor adopts the desktop size the
    /// client requests in its Client Core Data (instead of the size reported by
    /// the display handler), negotiating that size from the start without a
    /// Deactivation-Reactivation resize. The request is clamped per dimension to
    /// `max` so an untrusted client can't drive the framebuffer/encoder
    /// allocation past that ceiling. `None` (the default) always enforces the
    /// server-provided size. Set via
    /// [`RdpServerBuilder::with_honor_client_desktop_size`](crate::RdpServerBuilder::with_honor_client_desktop_size).
    pub honor_client_desktop_size: Option<DesktopSize>,
    /// What to do with a second connection while a session is being served.
    /// Defaults to [`ConnectionPolicy::default_for`] the selected security
    /// mode. Set via
    /// [`RdpServerBuilder::with_connection_policy`](crate::RdpServerBuilder::with_connection_policy).
    pub connection_policy: ConnectionPolicy,
    /// Quantization values the RemoteFX encoder uses once selected. Defaults
    /// to [`Quant::default`], the same values Windows RDP servers send. Set
    /// via
    /// [`RdpServerBuilder::with_remotefx_quant`](crate::RdpServerBuilder::with_remotefx_quant).
    pub remotefx_quant: Quant,
    /// Preferred RemoteFX entropy coder. If the client's advertised
    /// TS_RFX_ICAP array includes it, the server uses it; otherwise the
    /// server falls back to whichever coder the client offered first.
    /// `None` (the default) always uses whichever coder is offered first,
    /// since [MS-RDPRFX] 3.1.5.1 has the server arbitrarily pick one
    /// supported TS_RFX_ICAP element rather than rank the array as a
    /// preference order. Set via
    /// [`RdpServerBuilder::with_remotefx_entropy_coder`](crate::RdpServerBuilder::with_remotefx_entropy_coder).
    ///
    /// [MS-RDPRFX]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdprfx/
    pub remotefx_entropy_coder: Option<EntropyBits>,
    /// UDP bind address for the sideband multitransport socket, when UDP
    /// multitransport is offered. `None` disables the feature entirely. Set
    /// via [`RdpServerBuilder::with_udp_transport`](crate::RdpServerBuilder::with_udp_transport).
    pub udp_bind_addr: Option<SocketAddr>,
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

/// Picks a RemoteFX entropy coder out of the client's advertised TS_RFX_ICAP
/// array. Returns `preferred` if the client offered it, otherwise the first
/// coder the client offered. Returns `None` if `offered` is empty.
pub fn pick_remotefx_entropy_coder(
    preferred: Option<EntropyBits>,
    offered: impl Iterator<Item = EntropyBits>,
) -> Option<EntropyBits> {
    let mut first = None;

    for entropy_bits in offered {
        if first.is_none() {
            first = Some(entropy_bits);
        }

        if preferred == Some(entropy_bits) {
            return Some(entropy_bits);
        }
    }

    first
}

/// Picks the RemoteFX codec, its codec id and entropy coder out of the client's
/// [2.2.7.2.10.1.1] Bitmap Codec (TS_BITMAPCODEC) list.
///
/// `CODEC_GUID_REMOTEFX` wins over `CODEC_GUID_IMAGE_REMOTEFX` whatever the order of the
/// client's list, so that the choice, and with it the surface command that carries the data,
/// does not depend on that order. Each codec is a candidate only when the server enables it.
///
/// [2.2.7.2.10.1.1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/86507fed-a0ee-4242-b802-237534a8f65e
#[cfg_attr(feature = "__test", visibility::make(pub))]
fn pick_remotefx_codec(
    preferred: Option<EntropyBits>,
    codecs: &[Codec],
    remote_fx: bool,
    image_remote_fx: bool,
) -> Option<(EntropyBits, u8, RemoteFxCodec)> {
    let pick = |wanted: RemoteFxCodec| {
        codecs.iter().find_map(|codec| {
            let caps = match (&codec.property, wanted) {
                (CodecProperty::RemoteFx(RemoteFxContainer::ClientContainer(c)), RemoteFxCodec::RemoteFx)
                | (CodecProperty::ImageRemoteFx(RemoteFxContainer::ClientContainer(c)), RemoteFxCodec::ImageRemoteFx) => {
                    c
                }
                _ => return None,
            };
            let offered = caps.caps_data.0.0.iter().map(|icap| icap.entropy_bits);
            pick_remotefx_entropy_coder(preferred, offered).map(|entropy_bits| (entropy_bits, codec.id, wanted))
        })
    };

    [
        (RemoteFxCodec::RemoteFx, remote_fx),
        (RemoteFxCodec::ImageRemoteFx, image_remote_fx),
    ]
    .into_iter()
    .filter(|&(_, enabled)| enabled)
    .find_map(|(codec, _)| pick(codec))
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

    /// The [`TlsAcceptor`] backing this security mode, if any.
    ///
    /// UDP multitransport reuses this connection's own TLS certificate for
    /// the sideband transport (`TlsAcceptor::config()`), rather than needing
    /// separate cert/key plumbing. `None` under [`RdpServerSecurity::None`],
    /// which has no certificate to reuse and cannot offer multitransport
    /// anyway (Enhanced Security only).
    fn tls_acceptor(&self) -> Option<&TlsAcceptor> {
        match self {
            RdpServerSecurity::None => None,
            RdpServerSecurity::Tls(acceptor) | RdpServerSecurity::Hybrid((acceptor, _)) => Some(acceptor),
        }
    }
}

struct AInputHandler {
    handler: Arc<Mutex<Box<dyn RdpServerInputHandler>>>,
    active: Arc<AtomicBool>,
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

    fn close(&mut self, _channel_id: u32) {
        self.active.store(false, Ordering::Release);
    }

    fn process(&mut self, _channel_id: u32, payload: &[u8]) -> PduResult<Vec<dvc::DvcMessage>> {
        use ironrdp_ainput::ClientPdu;

        match decode(payload).map_err(|e| decode_err!(e))? {
            ClientPdu::Mouse(pdu) => {
                self.active.store(true, Ordering::Release);
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
    monitor_count: u32,
}

impl DisplayControlBackend {
    fn new(display: Arc<Mutex<Box<dyn RdpServerDisplay>>>, monitor_count: u32) -> Self {
        Self { display, monitor_count }
    }
}

impl DisplayControlHandler for DisplayControlBackend {
    fn monitor_layout(&self, layout: DisplayControlMonitorLayout) {
        let display = Arc::clone(&self.display);
        task::spawn_blocking(move || display.blocking_lock().request_layout(layout));
    }

    fn capabilities(&self) -> PduResult<DisplayControlCapabilities> {
        // `DisplayControlCapabilities::new` only rejects `monitor_count > 1024`; 0 passes its
        // validation (0 * 3840 * 2400 does not overflow) but would advertise a server that
        // supports no monitors, so it is folded into the same out-of-range fallback below.
        let monitor_count = if self.monitor_count == 0 {
            warn!("RdpServerDisplay::monitor_count() returned 0, falling back to 1");
            1
        } else {
            self.monitor_count
        };
        let capabilities = DisplayControlCapabilities::new(monitor_count, 3840, 2400).unwrap_or_else(|e| {
            warn!(monitor_count, error = %e, "RdpServerDisplay::monitor_count() out of range, falling back to 1");
            DisplayControlCapabilities::single_monitor()
        });
        Ok(capabilities)
    }
}

#[cfg(feature = "usb")]
#[derive(Default)]
struct ServerUsbManager {
    comp_iface_alloc: InterfaceAlloc,
    router: HashMap<DynamicChannelId, Arc<ServerUsbDevice>>,
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

/// A connection an embedder accepted itself and hands to
/// [`RdpServer::serve`] through a [`ConnectionSource`].
#[derive(Debug)]
#[non_exhaustive]
pub struct IncomingConnection<S> {
    /// The accepted stream. Socket options are the source's to set; see
    /// [`RdpServer::run_connection`].
    pub stream: S,
    /// Who chooses the TLS handshake for this connection; see
    /// [`RdpServer::run_connection_with`].
    pub tls: TransportTls,
    /// The remote address, when the transport has one.
    ///
    /// A connection with an address is gated by [`ConnectionHandler::on_accept`],
    /// reported to [`ConnectionHandler::on_disconnected`], and a peer that was
    /// just replaced by a [`ConnectionPolicy::Preempt`] takeover is kept from
    /// retaking the session at once. A connection without one (a Unix socket,
    /// AF_VSOCK) gets none of those, since each takes a [`SocketAddr`].
    pub peer: Option<SocketAddr>,
    /// The local address the connection arrived on, when the transport has one.
    pub local_addr: Option<SocketAddr>,
    /// A value of the embedder's own, returned by
    /// [`AuthenticatedConnection::tag`] if this connection replaces a session.
    /// A connection can carry more than a [`SocketAddr`] says about it (which
    /// transport, a Unix path, a vsock port), and this lets the embedder find
    /// its record of it again. The server does not look at it.
    pub tag: u64,
}

impl<S> IncomingConnection<S> {
    /// A connection over `stream` whose TLS is handled as `tls` says, from
    /// `peer`, with no local address.
    ///
    /// Pass `None` only for a transport that has no [`SocketAddr`] to report,
    /// since [`Self::peer`] is what gates a connection with
    /// [`ConnectionHandler::on_accept`] and keeps a just-replaced peer from
    /// retaking the session at once.
    ///
    /// Under [`ConnectionPolicy::Preempt`], `None` therefore removes every
    /// server-side gate on a takeover, not only the hooks that take a
    /// [`SocketAddr`]: the connection skips `on_accept` and the re-preempt
    /// cooldown, and the only thing left between it and the live session is
    /// authentication. That is CredSSP under [`RdpServerSecurity::Hybrid`] and
    /// nothing under a mode that does not authenticate. An embedder with such
    /// a transport has to limit who may attempt a takeover itself, before its
    /// [`ConnectionSource`] returns the connection.
    pub fn new(stream: S, tls: TransportTls, peer: Option<SocketAddr>) -> Self {
        Self {
            stream,
            tls,
            peer,
            local_addr: None,
            tag: 0,
        }
    }

    /// Sets [`Self::local_addr`].
    #[must_use]
    pub fn with_local_addr(mut self, local_addr: SocketAddr) -> Self {
        self.local_addr = Some(local_addr);
        self
    }

    /// Sets [`Self::tag`].
    #[must_use]
    pub fn with_tag(mut self, tag: u64) -> Self {
        self.tag = tag;
        self
    }
}

/// A connection that negotiated and authenticated while another session was
/// live, and replaced it. [`RdpServer::serve_connection`] returns it in a
/// [`SessionOutcome`]; serving it next skips negotiation and the accept hooks it
/// already went through.
pub struct AuthenticatedConnection<S> {
    connection: Box<NegotiatedConnection<S>>,
    peer: Option<SocketAddr>,
    tag: u64,
}

impl<S> AuthenticatedConnection<S> {
    /// The remote address the connection came from, as its source reported it.
    pub fn peer(&self) -> Option<SocketAddr> {
        self.peer
    }

    /// The [`IncomingConnection::tag`] the source gave the connection.
    pub fn tag(&self) -> u64 {
        self.tag
    }
}

impl<S> fmt::Debug for AuthenticatedConnection<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticatedConnection")
            .field("peer", &self.peer)
            .field("tag", &self.tag)
            .finish_non_exhaustive()
    }
}

/// What [`RdpServer::serve_connection`] serves next.
#[derive(Debug)]
#[non_exhaustive]
pub enum NextConnection<S> {
    /// A connection from a [`ConnectionSource`].
    Incoming(IncomingConnection<S>),
    /// The connection that replaced the previous session.
    Authenticated(AuthenticatedConnection<S>),
}

impl<S> NextConnection<S> {
    /// The remote address of the connection, when it has one.
    pub fn peer(&self) -> Option<SocketAddr> {
        match self {
            Self::Incoming(incoming) => incoming.peer,
            Self::Authenticated(winner) => winner.peer,
        }
    }
}

/// How a session served by [`RdpServer::serve_connection`] ended.
#[derive(Debug)]
#[non_exhaustive]
pub struct SessionOutcome<S> {
    /// How the session ended.
    pub result: ServerResult<()>,
    /// The connection to serve next, when one replaced this session (or
    /// finished negotiating as it ended on its own).
    pub successor: Option<AuthenticatedConnection<S>>,
}

/// Where [`RdpServer::serve`] gets its connections.
///
/// [`RdpServer::run`] accepts on one TCP socket it binds itself. An embedder
/// that accepts elsewhere (several transports, a WebSocket terminator, sockets
/// handed over by the service manager) implements this trait and calls
/// [`RdpServer::serve`], so that [`ConnectionPolicy`] applies to its
/// connections exactly as it does to `run`'s: the race between a live session
/// and a newcomer, the authentication that gates a takeover, and the cooldown
/// that keeps an evicted client from retaking the session at once.
#[async_trait::async_trait]
pub trait ConnectionSource: Send {
    /// The stream type every connection from this source has. A source that
    /// accepts more than one kind of stream boxes them into one.
    type Stream: AsyncRead + AsyncWrite + Send + Sync + Unpin;

    /// Waits for the next connection.
    ///
    /// `Ok(None)` means the source is closed and will accept no more; the
    /// server then stops accepting but still finishes a session in progress.
    /// Once it has returned `Ok(None)` it must keep returning `Ok(None)`, since
    /// [`RdpServer::serve_connection`] asks a source again at the start of every
    /// session. An error is logged and accepting goes on, so return it only for a failure
    /// that can pass, and wait a moment first if it may repeat at once, such as
    /// running out of file descriptors.
    ///
    /// The server drops this future whenever a session ends, a connection is
    /// being negotiated or an event arrives, so it MUST be cancel safe: a
    /// connection that was accepted but not yet returned must not be lost.
    /// That rules out vetting a connection asynchronously inside this future,
    /// since a vet in progress is lost when the future is dropped. A source
    /// that needs to vet connections (a TLS probe, a check against another
    /// service) runs the vet in tasks it owns, or keeps the pending connection
    /// in its own state, and lets this method hand over only the results.
    async fn accept(&mut self) -> std::io::Result<Option<IncomingConnection<Self::Stream>>>;
}

/// The TCP socket [`RdpServer::run`] binds, as a [`ConnectionSource`].
struct TcpConnectionSource {
    listener: tokio::net::TcpListener,
}

#[async_trait::async_trait]
impl ConnectionSource for TcpConnectionSource {
    type Stream = TcpStream;

    async fn accept(&mut self) -> std::io::Result<Option<IncomingConnection<TcpStream>>> {
        let (stream, peer) = match self.listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                // A failure such as running out of file descriptors repeats on
                // the next call, which would turn the loop into a spin.
                tokio::time::sleep(TCP_ACCEPT_ERROR_BACKOFF).await;
                return Err(error);
            }
        };
        // RDP output is small writes the peer is waiting on: a frame, a pointer
        // update, a channel PDU. Nagle holds the trailing partial segment of
        // each until the previous is acknowledged, which against a peer using
        // delayed acknowledgements is dead time on every one. Not worth
        // refusing a connection over, though.
        if let Err(error) = stream.set_nodelay(true) {
            warn!(?peer, %error, "Failed to set TCP_NODELAY; interactive latency may suffer");
        }
        let mut incoming = IncomingConnection::new(stream, TransportTls::Managed, Some(peer));
        if let Ok(local_addr) = incoming.stream.local_addr() {
            incoming = incoming.with_local_addr(local_addr);
        }
        Ok(Some(incoming))
    }
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
///# use ironrdp_server::{DisplayContext, DisplayUpdate, DesktopSize, KeyboardEvent, MouseEvent, ServerResult};
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
///#     async fn updates(&mut self, _: DisplayContext) -> ServerResult<Box<dyn RdpServerDisplayUpdates>> {
///#         todo!()
///#     }
///# }
///# async fn stub() -> ServerResult<()> {
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
    static_channel_factories: Vec<Box<dyn StaticChannelFactory>>,
    /// Advanced Input owns mouse delivery while its DVC is active. Core mouse
    /// events from the overlapping FastPath path are then suppressed.
    advanced_input_active: Arc<AtomicBool>,
    // ConnectionBinder installs per-user handlers into these slots. The
    // default handler/display above stay stable for the server lifetime, while
    // the slots are cleared at connection entry and after each connection to
    // avoid cross-user reuse.
    bound_handler: Arc<StdMutex<Option<Box<dyn RdpServerInputHandler>>>>,
    bound_display: Arc<StdMutex<BoundDisplayState>>,
    sound_factory: Option<Box<dyn SoundServerFactory>>,
    cliprdr_factory: Option<Box<dyn CliprdrServerFactory>>,
    rdpei_factory: Option<Box<dyn RdpeiServerFactory>>,
    rdpdr_factory: Option<Box<dyn RdpdrServerFactory>>,
    rdpeai_factory: Option<Box<dyn RdpeaiServerFactory>>,
    echo_handle: EchoServerHandle,
    #[cfg(feature = "egfx")]
    gfx_factory: Option<Box<dyn GfxServerFactory>>,
    #[cfg(feature = "usb")]
    usb_factory: Option<Box<dyn DeviceFactory>>,
    ev_sender: mpsc::UnboundedSender<ServerEvent>,
    ev_receiver: Arc<Mutex<mpsc::UnboundedReceiver<ServerEvent>>>,
    creds: Option<Credentials>,
    credential_validator: Option<Arc<dyn CredentialValidator>>,
    connection_binder: Option<Arc<dyn ConnectionBinder>>,
    pending_authenticated_credentials: Arc<StdMutex<Option<Credentials>>>,
    local_addr: Option<SocketAddr>,
    /// The local address the current client reached. See
    /// [`Self::set_connection_local_addr`].
    connection_local_addr: Option<SocketAddr>,
    /// Whether each connection runs auto-detect; see [`Self::enable_autodetect`].
    autodetect_enabled: bool,
    heartbeat: Option<HeartbeatConfig>,
    /// Shared, not owned outright: under [`ConnectionPolicy::Preempt`] the live
    /// connection (which borrows `self` for the whole race) and a candidate's
    /// `on_accept` must both reach the handler. Reach it only through
    /// [`with_connection_handler`]. The server is `!Send`, so `Rc` costs
    /// embedders nothing.
    connection_handler: Option<SharedConnectionHandler>,
    /// Anti-storm net for [`ConnectionPolicy::Preempt`]: the
    /// peer most recently EVICTED by a takeover, and when it last tried to
    /// come back.
    ///
    /// Telling the loser why it was evicted (see
    /// [`ServerEvent::EvictedByOtherConnection`]) is the real fix for the
    /// eviction loop, but whether a client honours it is client-dependent.
    /// This bounds the damage if one doesn't: a just-evicted peer may not
    /// immediately re-preempt, and each refused attempt RE-ARMS the window, so
    /// an automatic reconnect storm can never win the session back, while a
    /// human who closes the client and reconnects still can. Keyed on source
    /// IP, since the source port changes on every reconnect. Cleared once a
    /// session ends on its own terms rather than being replaced.
    recently_evicted: Option<EvictedPeer>,

    /// Optional Server Auto-Reconnect Cookie (MS-RDPBCGR 2.2.4.2
    /// `ARC_SC_PRIVATE_PACKET`). When `Some`, the server validates a returning
    /// `ARC_CS_PRIVATE_PACKET`, replaces its random after every connection, and
    /// sends hourly updates to the active client. This requires TLS or Hybrid
    /// security, which provides the all-zero client random required for Enhanced
    /// RDP Security. `None` (the default) disables automatic reconnection.
    /// Configure it on the builder
    /// ([`RdpServer::builder`]) via `with_auto_reconnect_cookie`, or after
    /// construction via [`Self::set_auto_reconnect_cookie`].
    auto_reconnect_cookie: Option<rdp::session_info::ServerAutoReconnect>,
    /// The cookie replaced by the current one, accepted until the next rotation.
    ///
    /// A successful socket write does not prove the client received the
    /// replacement. Retaining one previous value lets a client that disconnects
    /// during that window reconnect with the last cookie it knows.
    previous_auto_reconnect_cookie: Option<rdp::session_info::ServerAutoReconnect>,
    /// Tracks whether the current cookie has reached a client. Subsequent
    /// connections and hourly updates replace it with a new random.
    auto_reconnect_sent: bool,
    /// Issue cookies only when asked (`SetAutoReconnectCookie`), or to a
    /// client that came back with a verified one; see
    /// [`Self::set_auto_reconnect_on_request`].
    auto_reconnect_on_request: bool,
    /// Whether the client's core Frame Acknowledge capability caps the EGFX
    /// frame window; see [`Self::set_egfx_core_frame_ack_limit`].
    #[cfg(feature = "egfx")]
    egfx_core_frame_ack_limit: bool,
}

/// Cloneable handle for updating the Server Auto-Reconnect Cookie while
/// [`RdpServer::run`] owns the server.
#[derive(Clone)]
pub struct AutoReconnectCookieHandle {
    sender: mpsc::UnboundedSender<ServerEvent>,
}

impl AutoReconnectCookieHandle {
    /// Queue a replacement cookie for the active client or the next connection.
    ///
    /// The change takes effect only after the server handles this event. `None`
    /// then disables auto-reconnect and invalidates every cookie currently held
    /// by the server.
    #[expect(
        clippy::result_large_err,
        reason = "SendError<ServerEvent> hands the whole event back on a closed channel; ServerEvent's size is \
                  driven by its largest per-channel payload (RdpdrServerMessage), not by anything this method does"
    )]
    pub fn set(
        &self,
        cookie: Option<rdp::session_info::ServerAutoReconnect>,
    ) -> Result<(), mpsc::error::SendError<ServerEvent>> {
        self.sender.send(ServerEvent::SetAutoReconnectCookie(cookie))
    }
}

/// Cloneable handle for gracefully disconnecting the active client with a
/// `ServerSetErrorInfo` PDU (MS-RDPBCGR 2.2.5.1) while [`RdpServer::run`]
/// owns the server.
#[derive(Clone)]
pub struct ErrorInfoDisconnectHandle {
    sender: mpsc::UnboundedSender<ServerEvent>,
}

impl ErrorInfoDisconnectHandle {
    /// Send `error` to the client via a `ServerSetErrorInfoPdu`, then close the
    /// connection.
    ///
    /// The disconnect takes effect only after the server handles this event.
    /// Unlike [`ServerEvent::Quit`], the client is told why: it decodes the
    /// PDU and can surface `error` to the user before the connection drops.
    ///
    /// The one exception is a client that did not set
    /// `RNS_UD_CS_SUPPORT_ERRINFO_PDU` in its Client Core Data: MS-RDPBCGR
    /// 3.3.5.7.1 forbids sending it the PDU, so it is disconnected without
    /// the reason.
    #[expect(
        clippy::result_large_err,
        reason = "SendError<ServerEvent> hands the whole event back on a closed channel; ServerEvent's size is \
                  driven by its largest per-channel payload (RdpdrServerMessage), not by anything this method does"
    )]
    pub fn disconnect(&self, error: ErrorInfo) -> Result<(), mpsc::error::SendError<ServerEvent>> {
        self.sender.send(ServerEvent::Disconnect(error))
    }
}

/// Cloneable handle for redirecting the active client to another server with a Server Redirection PDU
/// (MS-RDPBCGR 2.2.13.3.1) while [`RdpServer::run`] owns the server.
#[derive(Clone)]
pub struct ServerRedirectionHandle {
    sender: mpsc::UnboundedSender<ServerEvent>,
}

impl ServerRedirectionHandle {
    /// Send `redirection` to the client, then close the connection.
    ///
    /// The client reconnects to the target the PDU describes, as it would for an RD Connection Broker.
    #[expect(
        clippy::result_large_err,
        reason = "SendError<ServerEvent> hands the whole event back on a closed channel; ServerEvent's size is \
                  driven by its largest per-channel payload (RdpdrServerMessage), not by anything this method does"
    )]
    pub fn redirect(&self, redirection: ServerRedirectionPdu) -> Result<(), mpsc::error::SendError<ServerEvent>> {
        self.sender.send(ServerEvent::Redirect(Box::new(redirection)))
    }
}

pub enum ServerEvent {
    Quit(String),
    /// End this connection because an authenticated candidate is taking the
    /// session over — a preemption, not a plain quit.
    ///
    /// Unlike [`Self::Quit`], this sends a Server Set Error Info PDU carrying
    /// `ERRINFO_DISCONNECTED_BY_OTHERCONNECTION` (MS-RDPBCGR 2.2.5.1.1 — the
    /// code real Windows RDS uses for a session takeover) before
    /// disconnecting. That distinction is load-bearing rather than cosmetic
    /// whenever a Server Auto-Reconnect Cookie is in play: a client dropped
    /// with no explanation auto-reconnects a second later, re-preempts the
    /// client that replaced it, and the two ping-pong indefinitely. Telling
    /// the loser WHY it was disconnected is what makes it stay away.
    ///
    /// The PDU is only sent to a client that set
    /// `RNS_UD_CS_SUPPORT_ERRINFO_PDU` in its Client Core Data (MS-RDPBCGR
    /// 3.3.5.7.1 forbids it otherwise); one that did not is dropped without
    /// the reason, and the anti-storm cooldown on [`RdpServer::run`] is then
    /// the only thing standing between it and the ping-pong above. (mstsc and
    /// FreeRDP both set the flag.)
    ///
    /// A more general version of the same PDU/mechanism exists as
    /// [`Self::Disconnect`] (upstream, `ErrorInfoDisconnectHandle`) for an
    /// embedder-chosen [`ErrorInfo`]; this variant stays separate because its
    /// reason is fixed (always `DisconnectedByOtherconnection`) and it is
    /// wired specifically to the preemption race, not exposed as a public
    /// handle.
    EvictedByOtherConnection,
    /// Disconnect the active client with a `ServerSetErrorInfoPdu` carrying
    /// the given reason. See [`ErrorInfoDisconnectHandle::disconnect`].
    Disconnect(ErrorInfo),
    /// Redirect the active client with a Server Redirection PDU, then close the connection.
    /// See [`ServerRedirectionHandle::redirect`].
    Redirect(Box<ServerRedirectionPdu>),
    Clipboard(ClipboardMessage),
    Rdpsnd(RdpsndServerMessage),
    Rdpdr(RdpdrServerMessage),
    Rdpeai(RdpeaiServerMessage),
    Echo(EchoServerMessage),
    SetCredentials(Credentials),
    /// Replace or clear the Server Auto-Reconnect Cookie.
    SetAutoReconnectCookie(Option<rdp::session_info::ServerAutoReconnect>),
    GetLocalAddr(oneshot::Sender<Option<SocketAddr>>),
    #[cfg(feature = "egfx")]
    Egfx(EgfxServerMessage),
    /// Trigger an RTT measurement probe (requires auto-detect enabled).
    AutoDetectRttRequest,
    #[cfg(feature = "usb")]
    Usb(UrbdrcServerMessage),
}

/// Creates a fresh static-channel processor for each accepted RDP connection.
///
/// Factories are invoked before the Basic Settings Exchange so their channels
/// participate in GCC static-channel negotiation.
pub trait StaticChannelFactory: Send {
    /// Attaches the connection-local static-channel processor to `acceptor`.
    fn attach(&self, acceptor: &mut Acceptor);
}

impl fmt::Debug for ServerEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Quit(reason) => f.debug_tuple("Quit").field(reason).finish(),
            Self::EvictedByOtherConnection => f.write_str("EvictedByOtherConnection"),
            Self::Disconnect(error) => f.debug_tuple("Disconnect").field(error).finish(),
            Self::Redirect(redirection) => f.debug_tuple("Redirect").field(redirection).finish(),
            Self::Clipboard(..) => f.write_str("Clipboard(..)"),
            Self::Rdpsnd(..) => f.write_str("Rdpsnd(..)"),
            Self::Rdpdr(..) => f.write_str("Rdpdr(..)"),
            Self::Rdpeai(..) => f.write_str("Rdpeai(..)"),
            Self::Echo(..) => f.write_str("Echo(..)"),
            Self::SetCredentials(..) => f.write_str("SetCredentials(..)"),
            Self::SetAutoReconnectCookie(Some(..)) => f.write_str("SetAutoReconnectCookie(Some(..))"),
            Self::SetAutoReconnectCookie(None) => f.write_str("SetAutoReconnectCookie(None)"),
            Self::GetLocalAddr(..) => f.write_str("GetLocalAddr(..)"),
            #[cfg(feature = "egfx")]
            Self::Egfx(..) => f.write_str("Egfx(..)"),
            #[cfg(feature = "usb")]
            Self::Usb(..) => f.write_str("Usb(..)"),
            Self::AutoDetectRttRequest => f.write_str("AutoDetectRttRequest"),
        }
    }
}

pub trait ServerEventSender {
    fn set_sender(&mut self, sender: mpsc::UnboundedSender<ServerEvent>);
}

impl ServerEvent {
    pub fn create_channel() -> (mpsc::UnboundedSender<Self>, mpsc::UnboundedReceiver<Self>) {
        mpsc::unbounded_channel()
    }
}

/// The in-flight [`negotiate_candidate`] call for a candidate connection, or a
/// never-resolving placeholder while none is being negotiated. Borrows the
/// [`NegotiationContext`] the race built.
type PreemptProbe<'ctx, S> = core::pin::Pin<Box<dyn Future<Output = Option<AuthenticatedConnection<S>>> + 'ctx>>;

/// What resolved first while a session was live, under
/// [`ConnectionPolicy::Preempt`]: the session itself ending, a
/// new inbound connection, or the verdict on a [`PreemptProbe`] being
/// negotiated. The race's `select!` yields one of these and must not
/// otherwise mutate the probe slot, whose futures it still borrows.
enum PreemptRace<S> {
    Ended(ServerResult<()>),
    Accepted(std::io::Result<Option<IncomingConnection<S>>>),
    Probed(Option<AuthenticatedConnection<S>>),
}

/// How long a redirected client has to close the connection before the server closes it.
const REDIRECTION_CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, PartialEq)]
enum RunState {
    Continue,
    Disconnect,
    /// A Server Redirection PDU was sent: wait for the client to close the connection.
    Redirected,
    DeactivationReactivation {
        desktop_size: DesktopSize,
    },
}

/// Which transport a connection ended up on after
/// [`negotiate_and_authenticate`], carrying the framed stream in the shape the
/// finalize step needs. The three variants exist to preserve the three
/// pre-existing finalize behaviours exactly.
enum NegotiatedTransport<S> {
    /// Never upgraded ([`RdpServerSecurity::None`]): finalize without a
    /// stream shutdown, matching the old `BeginResult::Continue` arm.
    Continued(TokioFramed<S>),
    /// Upgraded in-band by us ([`TransportTls::Managed`]).
    Tls(Box<TokioFramed<tokio_rustls::server::TlsStream<S>>>),
    /// Already past TLS at a lower layer ([`TransportTls::AlreadyDone`]).
    Offloaded(TokioFramed<S>),
}

/// A freshly built [`Acceptor`], paired with the exact [`RdpServerSecurity`]
/// it was constructed from.
///
/// Negotiation needs both together: [`Acceptor::new`] takes `security.flag()`
/// up front, and the TLS-upgrade step later needs the full `security` value
/// again (for the [`TlsAcceptor`] and, under Hybrid, the CredSSP public key).
/// Threading `security` and `acceptor` as independent parameters — which an
/// earlier revision of this refactor did — turns that pairing into a
/// caller-enforced precondition: nothing stops a future caller from passing
/// an `Acceptor` built from a *different* `RdpServerSecurity`, and the
/// failure mode is a panic on a server connection path
/// (`RdpServerSecurity::None => unreachable!()`, below). The single
/// constructor here makes the pairing a construction-time guarantee instead:
/// there is no way to reach [`Self::negotiate_and_authenticate`] with a
/// mismatched pair, because there is no way to build a `PendingConnection`
/// without going through [`Self::new`], which ties them together atomically.
///
/// Owns a cloned `RdpServerSecurity` rather than borrowing `&self.opts.security`
/// — `RdpServerSecurity` is a cheap `Clone` (its `TlsAcceptor` is an `Arc`
/// underneath) — deliberately: a preempting candidate negotiates through
/// [`negotiate_candidate`] from a [`NegotiationContext`] snapshot, without
/// holding the server at all.
struct PendingConnection {
    security: RdpServerSecurity,
    acceptor: Acceptor,
    credentials_handler: ServerCredentialsHandler,
}

#[derive(Default)]
struct ServerCredentialsHandler {
    validator: Option<Arc<dyn CredentialValidator>>,
    require_authenticated: bool,
    authenticated_credentials: Option<Credentials>,
}

#[async_trait::async_trait(?Send)]
impl ConnectionSetupHandler for ServerCredentialsHandler {
    async fn handle_credentials(&mut self, credentials: Option<ReceivedCredentials>) -> Result<(), ConnectorError> {
        let authenticated = resolve_authenticated_credentials(self.validator.clone(), credentials.as_ref())
            .await
            .map_err(|error| ConnectorError::custom("credential validation failed", error))?;
        if self.validator.is_some() && authenticated.is_none() {
            return Err(ConnectorError::general("no credentials available for validation"));
        }
        if self.require_authenticated
            && self.validator.is_none()
            && credentials.as_ref().map(|received| received.origin) != Some(CredentialOrigin::CredSspDelegated)
        {
            return Err(ConnectorError::general(
                "connection binder requires authenticated credentials from a validator or CredSSP",
            ));
        }
        self.authenticated_credentials = authenticated.cloned();
        Ok(())
    }
}

struct BoundConnectionGuard {
    display: Arc<StdMutex<BoundDisplayState>>,
    input: Arc<StdMutex<Option<Box<dyn RdpServerInputHandler>>>>,
    credentials: Arc<StdMutex<Option<Credentials>>>,
}

impl Drop for BoundConnectionGuard {
    fn drop(&mut self) {
        self.display.lock().expect("bound display lock poisoned").clear();
        self.input.lock().expect("bound input lock poisoned").take();
        self.credentials
            .lock()
            .expect("authenticated credentials lock poisoned")
            .take();
    }
}

impl PendingConnection {
    fn new(
        security: RdpServerSecurity,
        desktop_size: DesktopSize,
        capabilities: Vec<CapabilitySet>,
        creds: Option<Credentials>,
        honor_client_desktop_size: Option<DesktopSize>,
        udp_bind_addr: Option<SocketAddr>,
        credentials_handler: ServerCredentialsHandler,
    ) -> Self {
        let mut acceptor = Acceptor::new(security.flag(), desktop_size, capabilities, creds);
        acceptor.set_honor_client_desktop_size(honor_client_desktop_size);
        // Multitransport requires Enhanced Security: `RdpServerSecurity::None`
        // has nothing to authenticate the sideband transport's TLS with, and
        // matches the reference client's own Enhanced-Security-only gate.
        if udp_bind_addr.is_some() && security.tls_acceptor().is_some() {
            // SOFT_SYNC_TCP_TO_UDP is included alongside the transport type
            // itself: Without it, Soft-Sync is never negotiated (MS-RDPEDYC
            // 3.1.5.3 requires both peers to advertise it), and
            // `dispatch_egfx_messages` gates the EGFX-over-tunnel migration
            // on `multitransport_flags` reflecting it.
            acceptor.set_multitransport_offer(Some(
                ironrdp_pdu::gcc::MultiTransportFlags::TRANSPORT_TYPE_UDP_FECR
                    | ironrdp_pdu::gcc::MultiTransportFlags::SOFT_SYNC_TCP_TO_UDP,
            ));
        }
        Self {
            security,
            acceptor,
            credentials_handler,
        }
    }

    /// Negotiate `stream` and, where the security mode provides it,
    /// AUTHENTICATE it — everything up to (but not including)
    /// `accept_finalize`.
    ///
    /// Consumes `self` rather than taking `&mut self`, so it can be driven
    /// without holding a mutable borrow of the whole server for the
    /// duration — a future caller (a preempting connection negotiating
    /// concurrently with the live one) needs exactly that.
    ///
    /// `Ok(None)` means the TLS handshake failed and was already logged — the
    /// caller should abandon the connection quietly rather than treat it as a
    /// connection error (preserving the pre-existing `return Ok(())` behaviour).
    async fn negotiate_and_authenticate<S>(
        self,
        stream: S,
        tls: TransportTls,
    ) -> ServerResult<Option<NegotiatedConnection<S>>>
    where
        S: AsyncRead + AsyncWrite + Send + Sync + Unpin,
    {
        let PendingConnection {
            security,
            mut acceptor,
            mut credentials_handler,
        } = self;
        let security = &security;
        let framed = TokioFramed::new(stream);

        let res = ironrdp_acceptor::accept_begin(framed, &mut acceptor)
            .await
            .map_err_kind("accept_begin failed", ServerErrorKind::Connector)?;

        match res {
            // The only thing that varies between the two modes is who performs
            // the TLS handshake; everything past it is `complete_security_upgrade`.
            BeginResult::ShouldUpgrade(stream) => match tls {
                TransportTls::Managed => {
                    // `RdpServerSecurity::None` can never reach this arm: `Self::new`
                    // built `acceptor` from THIS `security` via `security.flag()`,
                    // which is empty only for `None`, and `accept_begin` yields
                    // `ShouldUpgrade` only when the negotiated flags are non-empty
                    // -- `None` always yields `Continue` instead (the arm below).
                    let tls_acceptor = match security {
                        RdpServerSecurity::Tls(acceptor) => acceptor,
                        RdpServerSecurity::Hybrid((acceptor, _)) => acceptor,
                        RdpServerSecurity::None => unreachable!(),
                    };
                    let accept = match tls_acceptor.accept(stream).await {
                        Ok(accept) => accept,
                        Err(e) => {
                            warn!("Failed to TLS accept: {}", e);
                            return Ok(None);
                        }
                    };
                    let mut framed = TokioFramed::new(accept);
                    complete_security_upgrade(security, &mut framed, &mut acceptor, &mut credentials_handler).await?;
                    Ok(Some(NegotiatedConnection {
                        transport: NegotiatedTransport::Tls(Box::new(framed)),
                        acceptor,
                        local_addr: None,
                        authenticated_credentials: credentials_handler.authenticated_credentials,
                    }))
                }
                // The stream is already past TLS (terminated at a lower
                // layer, e.g. a WSS terminator); do NOT call
                // tls_acceptor.accept on it.
                TransportTls::AlreadyDone => {
                    let mut framed = TokioFramed::new(stream);
                    complete_security_upgrade(security, &mut framed, &mut acceptor, &mut credentials_handler).await?;
                    Ok(Some(NegotiatedConnection {
                        transport: NegotiatedTransport::Offloaded(framed),
                        acceptor,
                        local_addr: None,
                        authenticated_credentials: credentials_handler.authenticated_credentials,
                    }))
                }
            },

            BeginResult::Continue(framed) => Ok(Some(NegotiatedConnection {
                transport: NegotiatedTransport::Continued(framed),
                acceptor,
                local_addr: None,
                authenticated_credentials: credentials_handler.authenticated_credentials,
            })),
        }
    }
}

/// The result of [`PendingConnection::negotiate_and_authenticate`]: the
/// [`NegotiatedTransport`] it landed on, bundled with the same [`Acceptor`]
/// that negotiated it (rather than the caller tracking the two as separate
/// values, which is how this looked before `PendingConnection` existed).
struct NegotiatedConnection<S> {
    transport: NegotiatedTransport<S>,
    acceptor: Acceptor,
    /// The local address the client reached, when the stream is a socket
    /// the server accepted itself; see [`RdpServer::set_connection_local_addr`].
    local_addr: Option<SocketAddr>,
    authenticated_credentials: Option<Credentials>,
}

/// State that belongs to a single client connection.
///
/// Created when a [`NegotiatedConnection`] enters finalization and dropped
/// when that connection ends, on every path out of it. Nothing stored here can
/// outlive its connection or be observed by the next one, so it needs no
/// manual reset between connections.
#[derive(Default)]
struct ConnectionState {
    /// The static channels this connection negotiated.
    ///
    /// Empty until the acceptor hands them back after finalization. Handed to
    /// the acceptor again for each deactivation-reactivation, and returned
    /// once that finalization completes.
    static_channels: StaticChannelSet,
    /// Whether the client advertised `SUPPORT_HEART_BEAT_PDU` in its GCC
    /// Client Core Data.
    client_supports_heartbeat: bool,
    /// Whether the client advertised `SUPPORT_ERR_INFO_PDU` in its GCC Client
    /// Core Data. MS-RDPBCGR 3.3.5.7.1 forbids sending it a Server Set Error
    /// Info PDU unless it did.
    client_supports_errinfo: bool,
    /// Auto-detect state, present when the server has auto-detect enabled.
    ///
    /// Probes in flight, RTT samples and the session-lifetime lowest RTT all
    /// describe this connection's network path, so they start over with each
    /// connection.
    autodetect: Option<AutoDetectManager>,
    /// The latest auto-detect measurements, published to the display backend
    /// through [`DisplayContext::autodetect`].
    autodetect_handles: AutoDetectHandles,
    /// Whether the client asked the server to stop sending display updates
    /// (`SuppressOutput { desktop_rect: None }`), published to the display
    /// backend through [`DisplayContext::display_suppressed`]. Without it, a
    /// server keeps streaming high-bitrate EGFX/H.264 frames into a minimized
    /// client, which accumulates them and locks up its input dispatch for
    /// seconds on refocus while it chews through the backlog.
    display_suppressed: Arc<AtomicBool>,
    #[cfg(feature = "egfx")]
    gfx_handle: Option<GfxServerHandle>,
    #[cfg(feature = "usb")]
    usb_man: ServerUsbManager,
    /// Abort handle of this connection's pending UDP multitransport accept,
    /// if one is running. A client that could not establish the sideband
    /// transport answers with a failure Initiate Multitransport Response,
    /// often after finalization has completed; the message-channel handler
    /// uses this to stop the accept instead of letting it hold its socket
    /// until `multitransport::UDP_ACCEPT_TIMEOUT`.
    pending_udp_accept_abort: Option<task::AbortHandle>,
    /// Whether this connection negotiated SOFT_SYNC_TCP_TO_UDP, one of the two
    /// conditions for migrating a channel onto the sideband transport (see
    /// [`Self::udp_migration_allowed`]).
    soft_sync_negotiated: bool,
    /// Whether this connection may migrate EGFX onto the sideband transport.
    /// MS-RDPEDYC 3.1.5.3/3.3.5.3.1: Soft-Sync MUST NOT be used unless both
    /// peers negotiated SOFT_SYNC_TCP_TO_UDP and a successful Initiate
    /// Multitransport Response was received. Finalization sets it when the
    /// response came during finalization; the message-channel handler sets it
    /// when the response comes later, which is the usual case with mstsc,
    /// whose UDP bootstrap outlasts the TCP finalization.
    udp_migration_allowed: bool,
    /// Whether this connection's EGFX data has started going over the
    /// sideband transport, so the switch is logged once.
    egfx_on_udp: bool,
    /// Tunnel payloads that arrived while a Soft-Sync request was waiting for
    /// its response. The client writes on the tunnel right after sending the
    /// response over TCP, so its first tunnel data can overtake it; this holds
    /// that data until the response is in instead of dropping it.
    early_tunnel_payloads: VecDeque<Vec<u8>>,
    /// Whether this connection has been sent a cookie, which is what makes it
    /// eligible for the hourly update when cookies are on request (see
    /// [`RdpServer::set_auto_reconnect_on_request`]).
    auto_reconnect_issued: bool,
}

impl ConnectionState {
    /// The handles this connection hands to the display backend, cloned at
    /// each activation so every call to [`RdpServerDisplay::updates`] on the
    /// same connection gets the same ones.
    fn display_context(&self) -> DisplayContext {
        DisplayContext {
            display_suppressed: Arc::clone(&self.display_suppressed),
            autodetect: self.autodetect_handles.clone(),
            #[cfg(feature = "egfx")]
            gfx_handle: self.gfx_handle.clone(),
        }
    }

    fn get_svc_processor<T: SvcProcessor + 'static>(&mut self) -> Option<&mut T> {
        self.static_channels
            .get_by_type_mut::<T>()
            .and_then(|svc| svc.channel_processor_downcast_mut())
    }

    fn get_channel_id_by_type<T: SvcProcessor + 'static>(&self) -> Option<StaticChannelId> {
        self.static_channels.get_channel_id_by_type::<T>()
    }

    #[cfg(feature = "usb")]
    fn remove_usb_device(&mut self, dvc_id: DynamicChannelId) {
        let Some(device) = self.usb_man.router.remove(&dvc_id) else {
            trace!(dvc_id, "Closed USB device is absent from request router");
            return;
        };

        // Set the terminal state before failing waiters: a woken PendingRequest
        // must not enqueue CANCEL_REQUEST for a removed DVC. The pending map is
        // shared, so dropping the router entry no longer drops it.
        device.mark_closed();
        let pending_requests = device.drain_pending();
        debug!(
            dvc_id,
            pending_requests, "Removed closed USB device from request router"
        );
    }
}

/// Advance a stream that is now past the security upgrade: mark the acceptor
/// accordingly and, under [`RdpServerSecurity::Hybrid`], run the CredSSP
/// exchange.
///
/// Generic over the stream so both [`TransportTls`] modes can call this one
/// definition of the exchange (the two differ only in what the framed stream
/// wraps) — restoring, not introducing, the single-call-site property the
/// pre-existing `finalize_after_upgrade` already had for the same two arms
/// before this refactor split negotiation out of it. The actual reason this
/// exists as its own function is [`negotiate_and_authenticate`]'s: a future
/// caller (a preempting connection negotiating without holding `&mut self`)
/// needs the CredSSP step available from a plain function it can drive
/// itself, not bundled into a `&mut self` method.
async fn complete_security_upgrade<S>(
    security: &RdpServerSecurity,
    framed: &mut TokioFramed<S>,
    acceptor: &mut Acceptor,
    credentials_handler: &mut ServerCredentialsHandler,
) -> ServerResult<()>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin,
{
    acceptor.mark_security_upgrade_as_done();

    if let RdpServerSecurity::Hybrid((_, pub_key)) = security {
        // Generic streams don't expose peer address. Use a neutral
        // placeholder; it's unclear whether CredSSP/NTLM actually
        // uses this value in practice.
        let client_name = "rdp-client".to_owned();

        ironrdp_acceptor::accept_credssp_with(
            framed,
            acceptor,
            &mut ironrdp_tokio::reqwest::ReqwestNetworkClient::new(),
            client_name.into(),
            pub_key.clone(),
            None,
            credentials_handler,
        )
        .await
        .map_err_kind("accept_credssp", ServerErrorKind::Connector)?;
    }

    Ok(())
}

/// How long an evicted session gets to send its
/// `ERRINFO_DISCONNECTED_BY_OTHERCONNECTION` and wind down on its own before
/// it is cancelled outright. Short, because the preempting client is already
/// authenticated and waiting and a half-dead peer must not stall the takeover;
/// exceeding it is not an error, it just degrades to an abrupt drop.
const EVICTION_GRACE: Duration = Duration::from_millis(750);

/// How long a candidate gets to complete negotiation and authentication before
/// it is abandoned.
///
/// This bound is load-bearing, not a tidiness measure: `negotiate_candidate`
/// blocks on socket reads, so without it a peer that completes the TCP
/// handshake and then sends NOTHING parks the probe forever — which stalls
/// accepts for the rest of the session (the accept arm is gated on `!probing`)
/// and, once the live session ends, hangs the whole accept loop on the handoff
/// await with no way left to observe [`ServerEvent::Quit`]. Generous enough for
/// TLS + CredSSP over a slow link, which is sub-second on a healthy one.
///
/// # Known limitation: one candidate is negotiated at a time
///
/// `run()`'s race holds a SINGLE probe slot (`probe`/`probing`), so a peer
/// that has already cleared [`ConnectionHandler::on_accept`] and then merely
/// STALLS its handshake (a well-formed X.224 Connection Request, then
/// silence before TLS — `on_accept` cannot see this in advance, since it
/// already returned `true` for this peer) occupies the slot for up to this
/// whole timeout, during which the accept arm is gated off and no OTHER
/// candidate — including a legitimate one — can even begin negotiating. The
/// live session itself is unaffected either way (this only withholds
/// PREEMPTION, never breaks it), and it is not a regression against master's
/// queue-behind default. But it means `on_accept` bounds who may ATTEMPT a
/// takeover, not how long one attempt can hold up every other. Closing this
/// properly needs a small pool of concurrent probe slots rather than one;
/// not done here.
const CANDIDATE_NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the accept loop will wait, AFTER the live session has ended, for a
/// candidate that is still mid-negotiation.
///
/// Deliberately short and separate from [`CANDIDATE_NEGOTIATION_TIMEOUT`]:
/// while this wait is in progress the loop is servicing nothing — no accepts,
/// no [`ServerEvent`]s, not even [`ServerEvent::Quit`] — so it is the window in
/// which an unauthenticated peer can make the server look hung. A candidate
/// that cannot finish within it is dropped and simply reconnects; holding the
/// whole listener for it is the worse trade.
const CANDIDATE_HANDOFF_GRACE: Duration = Duration::from_millis(750);

/// How long a just-evicted peer is barred from preempting its way back in —
/// see [`RdpServer::recently_evicted`].
const REPREEMPT_COOLDOWN: Duration = Duration::from_secs(5);

/// Absolute cap on that bar, measured from the eviction itself.
///
/// [`refuse_reconnect_from_evicted`] re-arms its window on every refused
/// attempt, which is what stops an auto-reconnect storm from winning the
/// session back. Left uncapped that also permanently locks out the feature's
/// own headline case — a client whose link dropped, whose stale session is
/// still live, and which is auto-reconnecting to reclaim it. Past this cap the
/// bar lifts even under a continuing storm; by then the evicted peer has had
/// its `ERRINFO_DISCONNECTED_BY_OTHERCONNECTION` (the real fix for the loop),
/// and this heuristic has served its purpose as a backstop.
const REPREEMPT_MAX_LOCKOUT: Duration = Duration::from_secs(30);

/// Does this security mode authenticate the CLIENT before a candidate reaches
/// the point where it could evict the live session?
///
/// Only [`RdpServerSecurity::Hybrid`] does: CredSSP/NLA runs inside
/// [`negotiate_candidate`]. A `Tls` handshake authenticates the *server* to the
/// client, not the reverse, and any peer that can reach the port completes one;
/// `None` authenticates nothing. Under those two, preemption's bar is therefore
/// NOT authentication — see the security section on
/// [`ConnectionPolicy::Preempt`], and the startup warning in
/// [`RdpServer::run`].
fn authenticates_before_eviction(security: &RdpServerSecurity) -> bool {
    matches!(security, RdpServerSecurity::Hybrid(_))
}

/// A peer barred from preempting straight back after being evicted, and when
/// that bar started — see [`refuse_reconnect_from_evicted`].
#[derive(Debug, Clone, Copy)]
struct EvictedPeer {
    ip: IpAddr,
    /// When the eviction happened; bounds the lockout via [`REPREEMPT_MAX_LOCKOUT`].
    evicted_at: Instant,
    /// Most recent refused attempt; re-armed to throttle a reconnect storm.
    last_try: Instant,
}

/// Should this candidate be refused because it is the peer that was just
/// evicted, bouncing straight back to retake the session?
///
/// Each refused attempt RE-ARMS the window, so a client auto-reconnecting on a
/// ~1 s cadence keeps resetting its own cooldown and cannot immediately win the
/// session back, while a human who closes the client and reconnects — a gap
/// beyond `cooldown` — still can.
///
/// The re-arm is bounded by `max_lockout` from the eviction, so a peer that
/// keeps retrying is eventually let back in rather than barred forever. Without
/// that cap this locks out exactly the case the feature exists for: a client
/// whose network dropped, auto-reconnecting to reclaim its own stale session.
///
/// Keyed on source IP, because the source port changes on every reconnect. The
/// cost is that two clients behind one NAT briefly share a bar; the cap bounds
/// how long that lasts.
fn refuse_reconnect_from_evicted(
    recently_evicted: &mut Option<EvictedPeer>,
    peer: IpAddr,
    now: Instant,
    cooldown: Duration,
    max_lockout: Duration,
) -> bool {
    match recently_evicted {
        Some(evicted) if evicted.ip == peer => {
            let within_cooldown = now.duration_since(evicted.last_try) < cooldown;
            let within_cap = now.duration_since(evicted.evicted_at) < max_lockout;
            let refuse = within_cooldown && within_cap;
            if refuse {
                evicted.last_try = now;
            }
            refuse
        }
        _ => false,
    }
}

/// A cheap, cloned snapshot of everything a preempting candidate needs to
/// negotiate, so it can do so WITHOUT `&mut self` and therefore concurrently
/// with the live connection's borrow. Built per race via
/// [`RdpServer::negotiation_context`].
///
/// Deliberately does NOT carry the channel factories: a candidate builds no
/// backends, because it may never be served (see the note in
/// [`negotiate_candidate`]). Only the winner does, in
/// [`RdpServer::serve_negotiated`], from `self`.
struct NegotiationContext {
    opts: RdpServerOptions,
    creds: Option<Credentials>,
    display: Arc<Mutex<Box<dyn RdpServerDisplay>>>,
    credential_validator: Option<Arc<dyn CredentialValidator>>,
    requires_authenticated_credentials: bool,
}

/// Negotiate and authenticate a candidate connection against a cloned `ctx`,
/// touching no `&mut self` — which is what lets this run inside
/// [`RdpServer::run`]'s preemption race, concurrently with the live
/// connection.
///
/// Returns `Some` only once the candidate has genuinely earned the session:
/// negotiation completed and, where the security mode provides it,
/// authentication succeeded (see the table on
/// [`ConnectionPolicy::Preempt`]). On any failure — a
/// malformed or non-RDP handshake, TLS rejected, CredSSP rejected — returns
/// `None` and the live session is left completely undisturbed.
async fn negotiate_candidate<S>(
    ctx: &NegotiationContext,
    incoming: IncomingConnection<S>,
) -> Option<AuthenticatedConnection<S>>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin,
{
    let IncomingConnection {
        stream,
        tls,
        peer,
        local_addr,
        tag,
    } = incoming;
    let size = ctx.display.lock().await.size().await;
    let capabilities = capabilities::capabilities(&ctx.opts, size);
    let pending = PendingConnection::new(
        ctx.opts.security.clone(),
        size,
        capabilities,
        ctx.creds.clone(),
        ctx.opts.honor_client_desktop_size,
        ctx.opts.udp_bind_addr,
        ServerCredentialsHandler {
            validator: ctx.credential_validator.clone(),
            require_authenticated: ctx.requires_authenticated_credentials,
            ..ServerCredentialsHandler::default()
        },
    );

    // NOTE: deliberately NO channel attachment here. Building the cliprdr /
    // sound / gfx backends means running user-supplied factories for a peer
    // that has not authenticated yet — a port scan would construct and tear
    // down backends alongside the live session's, and those factories may claim
    // exclusive OS resources (an audio capture device, clipboard ownership).
    // The winner attaches its own channels in `RdpServer::serve_negotiated`,
    // which is still before `accept_finalize` — the acceptor does not consume
    // the static channel set until it processes the MCS Connect Initial, which
    // happens there, not in `accept_begin`.

    match pending.negotiate_and_authenticate(stream, tls).await {
        Ok(Some(mut negotiated)) => {
            debug!(?peer, "candidate authenticated -- eligible to preempt the live session");
            negotiated.local_addr = local_addr;
            Some(AuthenticatedConnection {
                connection: Box::new(negotiated),
                peer,
                tag,
            })
        }
        Ok(None) => {
            debug!(
                ?peer,
                "candidate TLS handshake failed -- not preempting the live session"
            );
            None
        }
        Err(error) => {
            debug!(
                ?peer,
                %error,
                "candidate did not negotiate/authenticate -- not preempting the live session"
            );
            None
        }
    }
}

/// [`negotiate_candidate`] under a hard deadline.
///
/// The negotiation blocks on socket reads from an as-yet-unauthenticated peer,
/// so it MUST NOT be awaited unbounded anywhere in the accept loop: a peer that
/// connects and then says nothing would otherwise stall accepts for the rest of
/// the session and hang the loop outright once the session ended. Timing out is
/// treated exactly like a failed negotiation — the candidate is dropped and the
/// live session is untouched.
async fn negotiate_candidate_bounded<S>(
    ctx: &NegotiationContext,
    incoming: IncomingConnection<S>,
) -> Option<AuthenticatedConnection<S>>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin,
{
    let peer = incoming.peer;
    match tokio::time::timeout(CANDIDATE_NEGOTIATION_TIMEOUT, negotiate_candidate(ctx, incoming)).await {
        Ok(candidate) => candidate,
        Err(_) => {
            debug!(
                ?peer,
                timeout = ?CANDIDATE_NEGOTIATION_TIMEOUT,
                "candidate did not finish negotiating in time -- abandoning it, the live session is untouched"
            );
            None
        }
    }
}

impl RdpServer {
    #[expect(
        clippy::too_many_arguments,
        reason = "called via the builder; positional parameters are an internal detail"
    )]
    #[expect(
        clippy::similar_names,
        reason = "rdpei (MS-RDPEI touch/pen) and rdpeai (MS-RDPEAI audio input) are distinct protocols \
                  whose names happen to be textually close; renaming either would be less accurate"
    )]
    pub(crate) fn new(
        opts: RdpServerOptions,
        handler: Box<dyn RdpServerInputHandler>,
        display: Box<dyn RdpServerDisplay>,
        static_channel_factories: Vec<Box<dyn StaticChannelFactory>>,
        mut sound_factory: Option<Box<dyn SoundServerFactory>>,
        mut cliprdr_factory: Option<Box<dyn CliprdrServerFactory>>,
        mut rdpei_factory: Option<Box<dyn RdpeiServerFactory>>,
        mut rdpdr_factory: Option<Box<dyn RdpdrServerFactory>>,
        mut rdpeai_factory: Option<Box<dyn RdpeaiServerFactory>>,
        connection_handler: Option<Box<dyn ConnectionHandler>>,
        #[cfg(feature = "egfx")] mut gfx_factory: Option<Box<dyn GfxServerFactory>>,
        #[cfg(feature = "usb")] usb_factory: Option<Box<dyn DeviceFactory>>,
    ) -> Self {
        let (ev_sender, ev_receiver) = ServerEvent::create_channel();
        if let Some(cliprdr) = cliprdr_factory.as_mut() {
            cliprdr.set_sender(ev_sender.clone());
        }
        if let Some(snd) = sound_factory.as_mut() {
            snd.set_sender(ev_sender.clone());
        }
        if let Some(rdpei) = rdpei_factory.as_mut() {
            rdpei.set_sender(ev_sender.clone());
        }
        if let Some(rdpdr) = rdpdr_factory.as_mut() {
            rdpdr.set_sender(ev_sender.clone());
        }
        if let Some(rdpeai) = rdpeai_factory.as_mut() {
            rdpeai.set_sender(ev_sender.clone());
        }
        #[cfg(feature = "egfx")]
        if let Some(gfx) = gfx_factory.as_mut() {
            gfx.set_sender(ev_sender.clone());
        }
        let bound_handler = Arc::new(StdMutex::new(None));
        let bound_display = Arc::new(StdMutex::new(BoundDisplayState::default()));

        Self {
            opts,
            handler: Arc::new(Mutex::new(Box::new(BoundInputSlot::new(
                handler,
                Arc::clone(&bound_handler),
            )))),
            display: Arc::new(Mutex::new(Box::new(BoundDisplaySlot::new(
                display,
                Arc::clone(&bound_display),
            )))),
            advanced_input_active: Arc::new(AtomicBool::new(false)),
            bound_handler,
            bound_display,
            static_channel_factories,
            sound_factory,
            cliprdr_factory,
            rdpei_factory,
            rdpdr_factory,
            rdpeai_factory,
            echo_handle: EchoServerHandle::new(ev_sender.clone()),
            #[cfg(feature = "egfx")]
            gfx_factory,
            #[cfg(feature = "usb")]
            usb_factory,
            ev_sender,
            ev_receiver: Arc::new(Mutex::new(ev_receiver)),
            creds: None,
            credential_validator: None,
            connection_binder: None,
            pending_authenticated_credentials: Arc::new(StdMutex::new(None)),
            local_addr: None,
            connection_local_addr: None,
            autodetect_enabled: false,
            heartbeat: None,
            connection_handler: connection_handler.map(|h| Rc::new(RefCell::new(h))),
            recently_evicted: None,
            auto_reconnect_cookie: None,
            previous_auto_reconnect_cookie: None,
            auto_reconnect_sent: false,
            auto_reconnect_on_request: false,
            #[cfg(feature = "egfx")]
            egfx_core_frame_ack_limit: false,
        }
    }

    pub fn builder() -> builder::RdpServerBuilder<builder::WantsAddr> {
        builder::RdpServerBuilder::new()
    }

    /// Set or clear the credential validator for accepted client credentials.
    ///
    /// When set, credentials surfaced by the acceptor are validated through
    /// this callback before the session is established. This includes
    /// `SecureSettingsExchange` (`ClientInfoPdu`) credentials and, when
    /// available, CredSSP/Hybrid delegated credentials. If the validator returns
    /// [`CredentialDecision::Reject`] (or a [`CredentialValidationError`]),
    /// the connection is rejected. Passing `None` clears any previously
    /// configured validator.
    ///
    /// A valid Server Auto-Reconnect Cookie bypasses this validator. Applications
    /// that must validate every connection should leave automatic reconnection
    /// disabled.
    ///
    /// Most callers should configure the validator at construction time via
    /// the builder's `with_credential_validator` method
    /// ([`RdpServer::builder`]); this setter exists for dynamic
    /// post-construction reconfiguration.
    pub fn set_credential_validator(&mut self, validator: Option<Arc<dyn CredentialValidator>>) {
        self.credential_validator = validator;
    }

    /// Set or clear the Server Auto-Reconnect Cookie (MS-RDPBCGR 2.2.4.2
    /// `ARC_SC_PRIVATE_PACKET`) handed to the client during logon.
    ///
    /// When set to `Some`, the server sends a Save Session Info PDU carrying the
    /// cookie right after activation. It verifies the returned
    /// `ARC_CS_PRIVATE_PACKET` using the HMAC-MD5 verifier required by
    /// MS-RDPBCGR 5.5, replaces the random after every accepted connection, and
    /// sends an update every hour. Automatic reconnection requires TLS or Hybrid
    /// security, which provides the all-zero client random required for Enhanced
    /// RDP Security. The [`ServerAutoReconnect`] `logon_id` identifies the
    /// session; the server generates replacement randoms with a CSPRNG.
    ///
    /// With [`Self::set_auto_reconnect_on_request`] the cookie is sent only on
    /// request, and the server regenerates it when the embedder vouches for a
    /// connection instead of after every accepted connection.
    ///
    /// Pass `None` (the default) to send no cookie.
    ///
    /// Most callers should configure this at construction time via the builder
    /// ([`RdpServer::builder`])'s `with_auto_reconnect_cookie`. To replace a
    /// cookie while [`Self::run`] owns the server, use
    /// [`Self::auto_reconnect_cookie_handle`].
    ///
    /// [`ServerAutoReconnect`]: ironrdp_pdu::rdp::session_info::ServerAutoReconnect
    pub fn set_auto_reconnect_cookie(&mut self, cookie: Option<rdp::session_info::ServerAutoReconnect>) {
        self.auto_reconnect_cookie = cookie;
        self.previous_auto_reconnect_cookie = None;
        self.auto_reconnect_sent = false;
    }

    /// Send a cookie only to a connection the embedder vouches for, by
    /// sending [`ServerEvent::SetAutoReconnectCookie`] (through
    /// [`Self::auto_reconnect_cookie_handle`]) once it has authenticated the
    /// user itself, or to a client that returned with a verified cookie.
    ///
    /// For embedders that accept a connection before the user has proved
    /// anything, for instance to draw their own logon screen after a
    /// credential validator hands off: by default the cookie goes to every
    /// connection at activation, and such a connection could present it on
    /// reconnecting and skip that screen.
    ///
    /// The regeneration on connect that MS-RDPBCGR 5.5 describes then happens
    /// when the embedder vouches for a connection: the cookie it sends replaces
    /// the current one and the previous one stops working at once, and a client
    /// that returns with a verified cookie is given a new one. A connection that
    /// is never vouched for changes nothing, so it can neither receive a cookie
    /// nor invalidate the one a legitimate user holds. An embedder that
    /// authenticates a different user must therefore vouch for that connection,
    /// or the previous user's cookie stays valid.
    ///
    /// A vouch belongs to the connection that was current when it was sent. If
    /// that connection is replaced before the server reads the vouch, the vouch
    /// is dropped and the replacement gets no cookie until the embedder vouches
    /// for it.
    ///
    /// A server with a connection binder (see [`Self::set_connection_binder`])
    /// refuses every auto-reconnect attempt, because a reconnect can't restore
    /// a credential-bound connection safely, so this option has no useful
    /// effect there.
    pub fn set_auto_reconnect_on_request(&mut self, on_request: bool) {
        self.auto_reconnect_on_request = on_request;
    }

    /// Choose whether the client's `maxUnacknowledgedFrameCount` caps the EGFX
    /// frame window. Off by default.
    ///
    /// The value comes from the [2.2.1.3] Frame Acknowledge Capability Set
    /// (TS_FRAME_ACKNOWLEDGE_CAPABILITYSET), which is defined for surface-command
    /// frames acknowledged with TS_FRAME_ACKNOWLEDGE_PDU. EGFX acknowledges its
    /// frames with its own [2.2.2.13] RDPGFX_FRAME_ACKNOWLEDGE_PDU, and Windows 10
    /// mstsc sends 1, which would allow one EGFX frame per round trip. When on,
    /// the value caps [`GraphicsPipelineServer::set_max_frames_in_flight`] for
    /// each capability exchange, including reactivation.
    ///
    /// [2.2.1.3]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdprfx/e4d498fd-822b-408d-b8b3-1c216f21265b
    /// [2.2.2.13]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/0241e258-77ef-4a58-b426-5039ed6296ce
    /// [`GraphicsPipelineServer::set_max_frames_in_flight`]: ironrdp_egfx::server::GraphicsPipelineServer::set_max_frames_in_flight
    #[cfg(feature = "egfx")]
    pub fn set_egfx_core_frame_ack_limit(&mut self, enabled: bool) {
        self.egfx_core_frame_ack_limit = enabled;
    }

    /// Returns a handle for replacing the cookie while [`Self::run`] owns this
    /// server.
    pub fn auto_reconnect_cookie_handle(&self) -> AutoReconnectCookieHandle {
        AutoReconnectCookieHandle {
            sender: self.ev_sender.clone(),
        }
    }

    /// Returns a handle for gracefully disconnecting the active client with a
    /// `ServerSetErrorInfo` PDU while [`Self::run`] owns this server.
    pub fn error_info_disconnect_handle(&self) -> ErrorInfoDisconnectHandle {
        ErrorInfoDisconnectHandle {
            sender: self.ev_sender.clone(),
        }
    }

    /// Returns a handle for redirecting the active client to another server while [`Self::run`] owns this server.
    pub fn server_redirection_handle(&self) -> ServerRedirectionHandle {
        ServerRedirectionHandle {
            sender: self.ev_sender.clone(),
        }
    }

    fn supports_auto_reconnect(&self) -> bool {
        matches!(
            &self.opts.security,
            RdpServerSecurity::Tls(_) | RdpServerSecurity::Hybrid(_)
        )
    }

    fn verify_auto_reconnect_cookie(&self, reconnect: &rdp::client_info::ClientAutoReconnect) -> bool {
        if !self.supports_auto_reconnect() {
            return false;
        }

        [&self.auto_reconnect_cookie, &self.previous_auto_reconnect_cookie]
            .into_iter()
            .flatten()
            .any(|cookie| reconnect.verify(cookie))
    }

    fn generate_auto_reconnect_cookie(logon_id: u32) -> rdp::session_info::ServerAutoReconnect {
        let mut random_bits = [0; 16];
        rand::rng().fill_bytes(&mut random_bits);

        rdp::session_info::ServerAutoReconnect { logon_id, random_bits }
    }

    fn next_auto_reconnect_cookie(&self) -> Option<rdp::session_info::ServerAutoReconnect> {
        if !self.supports_auto_reconnect() {
            return None;
        }

        let cookie = self.auto_reconnect_cookie.as_ref()?;

        if self.auto_reconnect_sent {
            Some(Self::generate_auto_reconnect_cookie(cookie.logon_id))
        } else {
            Some(cookie.clone())
        }
    }

    fn commit_auto_reconnect_rotation(&mut self, cookie: rdp::session_info::ServerAutoReconnect) {
        if self.auto_reconnect_sent {
            self.previous_auto_reconnect_cookie = self.auto_reconnect_cookie.replace(cookie);
        } else {
            self.auto_reconnect_cookie = Some(cookie);
        }
        self.auto_reconnect_sent = true;
    }

    /// (vendored, divergence 23) Invalidate whatever ARC cookie belongs to
    /// the session that is about to be EVICTED, without disabling
    /// auto-reconnect for the server going forward.
    ///
    /// MS-RDPBCGR 5.5 requires a session's auto-reconnect cookie to be
    /// invalidated once a different client's session begins. This crate
    /// already demotes the outgoing cookie into `previous_auto_reconnect_
    /// cookie` on every normal rotation (`commit_auto_reconnect_rotation`) --
    /// a network-timing tolerance for the common case of a lost Save Session
    /// Info PDU -- which means an EVICTED peer's cookie stays valid for one
    /// more rotation. Since `verify_auto_reconnect_cookie` accepts either
    /// slot, and a client presenting a valid ARC cookie skips
    /// `credential_validator` (see `client_accepted`), an evicted peer could
    /// silently resume without a real re-authorization check -- and, because
    /// re-authenticating via ARC needs no user interaction, do so reliably
    /// the moment `REPREEMPT_MAX_LOCKOUT` lifts.
    ///
    /// Rotates to a FRESH cookie under the SAME `logon_id` (so the server
    /// keeps issuing cookies to whoever connects next -- a normal rotation
    /// does the same) but with new random bits, which is what actually
    /// invalidates the old one: `ClientAutoReconnect::verify` HMACs against
    /// `random_bits`, not `logon_id` alone. `previous_auto_reconnect_cookie`
    /// is discarded outright here rather than demoted into, since the whole
    /// point is that the evicted party's cookie must not remain valid even
    /// for one more attempt.
    ///
    /// MUST NOT set `auto_reconnect_cookie` to `None`:
    /// `next_auto_reconnect_cookie` treats `None` as "auto-reconnect is not
    /// configured" and stops issuing cookies to EVERY future connection, not
    /// just this one -- silently disabling the feature server-wide for the
    /// rest of the process (see `next_auto_reconnect_cookie`'s early
    /// `self.auto_reconnect_cookie.as_ref()?`). No-op if auto-reconnect isn't
    /// configured at all.
    fn invalidate_auto_reconnect_cookie_on_eviction(&mut self) {
        if let Some(current) = self.auto_reconnect_cookie.as_ref() {
            self.auto_reconnect_cookie = Some(Self::generate_auto_reconnect_cookie(current.logon_id));
        }
        self.previous_auto_reconnect_cookie = None;
    }
    async fn send_auto_reconnect_cookie(
        cookie: rdp::session_info::ServerAutoReconnect,
        writer: &mut impl FramedWrite,
        io_channel_id: u16,
        user_channel_id: u16,
    ) -> ServerResult<()> {
        let pdu = rdp::headers::ShareDataPdu::SaveSessionInfo(rdp::session_info::SaveSessionInfoPdu {
            info_type: rdp::session_info::InfoType::LogonExtended,
            info_data: rdp::session_info::InfoData::LogonExtended(rdp::session_info::LogonInfoExtended {
                present_fields_flags: rdp::session_info::LogonExFlags::AUTO_RECONNECT_COOKIE,
                auto_reconnect: Some(cookie),
                errors_info: None,
            }),
        });
        let data = encode_share_data_pdu(pdu, user_channel_id, io_channel_id, user_channel_id)?;
        writer
            .write_all(&data)
            .await
            .map_err(|e| ServerError::io("send auto-reconnect cookie", e))?;
        debug!("Sent Server Auto-Reconnect Cookie (Save Session Info PDU)");

        Ok(())
    }

    async fn send_next_auto_reconnect_cookie(
        &mut self,
        conn: &mut ConnectionState,
        writer: &mut impl FramedWrite,
        io_channel_id: u16,
        user_channel_id: u16,
    ) -> ServerResult<()> {
        let Some(cookie) = self.next_auto_reconnect_cookie() else {
            return Ok(());
        };

        Self::send_auto_reconnect_cookie(cookie.clone(), writer, io_channel_id, user_channel_id).await?;
        self.commit_auto_reconnect_rotation(cookie);
        conn.auto_reconnect_issued = true;

        Ok(())
    }

    async fn rotate_auto_reconnect_cookie(
        &mut self,
        conn: &mut ConnectionState,
        writer: &mut impl FramedWrite,
        io_channel_id: u16,
        user_channel_id: u16,
    ) -> ServerResult<()> {
        // On request, the hourly update goes only to a connection that was issued a cookie.
        let may_rotate = !self.auto_reconnect_on_request || conn.auto_reconnect_issued;
        if !self.supports_auto_reconnect() || !may_rotate {
            return Ok(());
        }

        let Some(cookie) = self.auto_reconnect_cookie.as_ref() else {
            return Ok(());
        };
        let cookie = Self::generate_auto_reconnect_cookie(cookie.logon_id);

        Self::send_auto_reconnect_cookie(cookie.clone(), writer, io_channel_id, user_channel_id).await?;
        self.commit_auto_reconnect_rotation(cookie);

        Ok(())
    }

    /// Drives the clipboard channel's time-based cleanup.
    ///
    /// See [`CLIPRDR_DRIVE_TIMEOUTS_INTERVAL`]. A cleanup failure is logged and
    /// swallowed: the sweep is best-effort maintenance, and failing it must not
    /// disconnect an otherwise healthy session.
    async fn drive_cliprdr_timeouts(
        &mut self,
        conn: &mut ConnectionState,
        writer: &mut impl FramedWrite,
        user_channel_id: u16,
    ) -> ServerResult<()> {
        let Some(cliprdr) = conn.get_svc_processor::<CliprdrServer>() else {
            return Ok(());
        };

        let msgs = match cliprdr.drive_timeouts() {
            Ok(msgs) => Vec::from(msgs),
            Err(error) => {
                warn!(%error, "Clipboard timeout cleanup failed");
                return Ok(());
            }
        };

        if msgs.is_empty() {
            return Ok(());
        }

        // Unreachable today: locks and pending requests only accumulate through
        // a joined channel, so an unjoined one yields no messages above. Kept as
        // a non-fatal skip because a best-effort sweep must never end the session.
        let Some(channel_id) = conn.get_channel_id_by_type::<CliprdrServer>() else {
            warn!("Clipboard channel not joined, dropping timeout cleanup messages");
            return Ok(());
        };
        let data = server_encode_svc_messages(msgs, channel_id, user_channel_id).map_err(ServerError::encode)?;
        writer
            .write_all(&data)
            .await
            .map_err(|e| ServerError::io("write_all", e))?;

        Ok(())
    }

    async fn update_auto_reconnect_cookie(
        &mut self,
        conn: &mut ConnectionState,
        cookie: Option<rdp::session_info::ServerAutoReconnect>,
        writer: &mut impl FramedWrite,
        io_channel_id: u16,
        user_channel_id: u16,
    ) -> ServerResult<()> {
        let Some(cookie) = cookie else {
            self.set_auto_reconnect_cookie(None);
            return Ok(());
        };

        if !self.supports_auto_reconnect() {
            self.set_auto_reconnect_cookie(Some(cookie));
            return Ok(());
        }

        Self::send_auto_reconnect_cookie(cookie.clone(), writer, io_channel_id, user_channel_id).await?;
        self.auto_reconnect_cookie = Some(cookie);
        self.previous_auto_reconnect_cookie = None;
        conn.auto_reconnect_issued = true;
        self.auto_reconnect_sent = true;

        Ok(())
    }

    /// Set or clear a post-auth connection binder.
    ///
    /// When set, the binder is called only when authenticated credentials are
    /// available. The returned display/input handlers replace the server
    /// defaults for the accepted connection.
    pub fn set_connection_binder(&mut self, binder: Option<Arc<dyn ConnectionBinder>>) {
        self.connection_binder = binder;
    }

    fn install_bound_connection(&mut self, bound: BoundConnection) {
        let mut display = self.bound_display.lock().expect("bound display lock poisoned");
        display.clear();
        display.display = Some(bound.display);
        *self.bound_handler.lock().expect("bound input lock poisoned") = Some(bound.input);
    }

    fn clear_bound_connection(&mut self) {
        self.bound_display.lock().expect("bound display lock poisoned").clear();
        self.bound_handler.lock().expect("bound input lock poisoned").take();
        self.pending_authenticated_credentials
            .lock()
            .expect("authenticated credentials lock poisoned")
            .take();
        self.advanced_input_active.store(false, Ordering::Release);
    }

    pub fn event_sender(&self) -> &mpsc::UnboundedSender<ServerEvent> {
        &self.ev_sender
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
    /// Send probes via [`ServerEvent::AutoDetectRttRequest`]. The display
    /// backend reads the results through [`DisplayContext::autodetect`]. Each connection measures its own network
    /// path, starting from scratch.
    pub fn enable_autodetect(&mut self) {
        self.autodetect_enabled = true;
    }

    /// Enable periodic Server Heartbeat PDUs (MS-RDPBCGR 2.2.16.1).
    ///
    /// Heartbeats ride the MCS message channel, so they are only emitted
    /// when the client requested one AND advertised
    /// `RNS_UD_CS_SUPPORT_HEARTBEAT_PDU` in its early capability flags, and,
    /// per the spec's idle-only SHOULD, only when no other PDU went out
    /// during the previous heartbeat interval.
    pub fn enable_heartbeat(&mut self, config: HeartbeatConfig) {
        self.heartbeat = Some(config);
    }

    /// Builds this connection's channel backends into `acceptor` and returns the
    /// connection's state, holding the handles those backends were given.
    async fn attach_channels(&self, acceptor: &mut Acceptor) -> ConnectionState {
        let autodetect_handles = AutoDetectHandles::default();

        if let Some(cliprdr_factory) = self.cliprdr_factory.as_deref() {
            let backend = cliprdr_factory.build_cliprdr_backend();

            let cliprdr = CliprdrServer::new(backend);

            acceptor.attach_static_channel(cliprdr);
        }

        if let Some(factory) = self.sound_factory.as_deref() {
            let backend = factory.build_backend();

            acceptor.attach_static_channel(RdpsndServer::new(backend));
        }

        if let Some(factory) = self.rdpdr_factory.as_deref() {
            let backend = factory.build_backend();

            acceptor.attach_static_channel(RdpdrServer::new(backend));
        }

        let dvc = dvc::DrdynvcServer::new().with_dynamic_channel(AInputHandler {
            handler: Arc::clone(&self.handler),
            active: Arc::clone(&self.advanced_input_active),
        });

        // `monitor_count` is only asked when the channel is offered, since its
        // contract is tied to the channel opening. Both queries share one guard,
        // so no other task can interleave between them.
        let display_control_monitors = {
            let mut display = self.display.lock().await;
            if display.offers_display_control().await {
                Some(display.monitor_count().await)
            } else {
                None
            }
        };
        let dvc = if let Some(monitor_count) = display_control_monitors {
            let dcs_backend = DisplayControlBackend::new(Arc::clone(&self.display), monitor_count);
            dvc.with_dynamic_channel(DisplayControlServer::new(Box::new(dcs_backend)))
        } else {
            dvc
        };

        let dvc = {
            let echo_handle = self.echo_handle.clone();
            dvc.with_dynamic_channel(EchoDvcBridge::new(echo_handle))
        };

        let dvc = if let Some(factory) = self.rdpei_factory.as_deref() {
            dvc.with_dynamic_channel(factory.build_server())
        } else {
            dvc
        };

        let dvc = if let Some(factory) = self.rdpeai_factory.as_deref() {
            let backend = factory.build_backend();
            dvc.with_dynamic_channel(RdpeaiServer::new(backend))
        } else {
            dvc
        };

        #[cfg(feature = "egfx")]
        let (dvc, gfx_handle) = {
            let mut dvc = dvc;
            let mut gfx_handle = None;
            if let Some(gfx_factory) = self.gfx_factory.as_deref() {
                let gfx_context = GfxContext {
                    autodetect: autodetect_handles.clone(),
                };
                let (processor, handle) = crate::gfx::build_server_and_handle(gfx_factory, gfx_context);
                gfx_handle = Some(handle);
                dvc = dvc.with_dynamic_channel(processor);
            }
            (dvc, gfx_handle)
        };

        #[cfg(feature = "usb")]
        let dvc = {
            let mut dvc = dvc;
            if self.usb_factory.is_some() {
                dvc = dvc.with_dynamic_channel(UrbdrcControlServer::new(Box::new(UsbControlHandle::new(
                    self.ev_sender.clone(),
                ))));
            }
            dvc
        };

        acceptor.attach_static_channel(dvc);

        for factory in &self.static_channel_factories {
            factory.attach(acceptor);
        }

        ConnectionState {
            static_channels: StaticChannelSet::new(),
            client_supports_heartbeat: false,
            client_supports_errinfo: false,
            autodetect: self.autodetect_enabled.then(AutoDetectManager::new),
            autodetect_handles,
            display_suppressed: Arc::new(AtomicBool::new(false)),
            #[cfg(feature = "egfx")]
            gfx_handle,
            #[cfg(feature = "usb")]
            usb_man: ServerUsbManager::default(),
            pending_udp_accept_abort: None,
            soft_sync_negotiated: false,
            udp_migration_allowed: false,
            egfx_on_udp: false,
            early_tunnel_payloads: VecDeque::new(),
            auto_reconnect_issued: false,
        }
    }

    /// Drop every event still queued on the server-global channel that
    /// belongs to the SESSION just replaced, keeping only the small set of
    /// lifecycle/control events meant to survive across connections.
    ///
    /// Called before every connection starts negotiating, and immediately
    /// before serving a preemption winner. The channel is shared across every
    /// connection the server ever serves and is read by whichever connection
    /// drains it next -- so any event the outgoing session produced but never
    /// got around to consuming (its OWN eviction notice, a queued clipboard
    /// message, an RDPSND wave, an EGFX frame) would otherwise be delivered to
    /// its replacement. That is at best stale (an audio wave from a session
    /// that no longer exists), at worst a real leak (the previous peer's
    /// clipboard content, handed unprompted to the client that just replaced
    /// it) or a broken connection (an EGFX frame on a dynamic channel the new
    /// client has not opened yet).
    ///
    /// An ALLOWLIST of what to KEEP, not a denylist of `EvictedByOtherConnection`
    /// alone, and deliberately so: this mirrors what `run()`'s own top-level
    /// select already does when NOTHING is being served (only `Quit` /
    /// `GetLocalAddr` / `SetCredentials` / `SetAutoReconnectCookie` are
    /// meaningful there; everything else falls into its `ev => debug!("Unexpected
    /// event")` catch-all and is discarded). A new per-session `ServerEvent`
    /// variant is excluded here by default, instead of silently leaking across
    /// a takeover boundary until someone remembers to add it to a denylist.
    ///
    /// `SetAutoReconnectCookie` carries a cookie across the boundary only when
    /// the embedder is replacing the stored cookie on its own account. With
    /// [`RdpServer::set_auto_reconnect_on_request`] it is a vouch for one
    /// connection, so a vouch the replaced connection never consumed is dropped
    /// here instead of reaching the connection that replaced it.
    async fn discard_stale_session_events(&mut self) {
        let ev_receiver = Arc::clone(&self.ev_receiver);
        let mut ev_receiver = ev_receiver.lock().await;

        // Collect first, re-send after: re-sending during the drain would push
        // events onto the back of the same queue we are draining.
        let mut keep = Vec::new();
        let mut discarded = 0usize;
        while let Ok(event) = ev_receiver.try_recv() {
            let survives = match &event {
                ServerEvent::Quit(_)
                | ServerEvent::GetLocalAddr(_)
                | ServerEvent::SetCredentials(_)
                | ServerEvent::SetAutoReconnectCookie(None) => true,
                // On request, a cookie is a vouch that the connection that was
                // current when it was sent has authenticated its user. That
                // connection is gone, and the one replacing it has proved
                // nothing.
                ServerEvent::SetAutoReconnectCookie(Some(_)) => !self.auto_reconnect_on_request,
                _ => false,
            };
            if survives {
                keep.push(event);
            } else {
                discarded += 1;
            }
        }

        if discarded > 0 {
            debug!(
                discarded,
                "dropped per-session events the replaced session never consumed -- they must not reach its replacement"
            );
        }

        for event in keep {
            let _ = self.ev_sender.send(event);
        }
    }

    /// Build the cheap, cloned snapshot a preempting candidate negotiates
    /// against — see [`NegotiationContext`].
    fn negotiation_context(&self) -> NegotiationContext {
        NegotiationContext {
            opts: self.opts.clone(),
            creds: self.creds.clone(),
            display: Arc::clone(&self.display),
            credential_validator: self.credential_validator.clone(),
            requires_authenticated_credentials: self.connection_binder.is_some(),
        }
    }

    /// Serve a candidate that already won the preemption race: negotiation and
    /// authentication are done, so it hands off to the same finalization the
    /// normal path uses, which builds its channel backends. From here on, a
    /// preemption winner is indistinguishable from a normally-accepted
    /// connection.
    async fn serve_negotiated<S>(&mut self, candidate: Box<NegotiatedConnection<S>>) -> ServerResult<()>
    where
        S: AsyncRead + AsyncWrite + Send + Sync + Unpin,
    {
        self.finalize_negotiated(*candidate).await
    }

    /// Run a single RDP connection over `stream`, performing the
    /// IronRDP-managed TLS handshake on `ShouldUpgrade` (standard TCP+TLS).
    ///
    /// Socket options on `stream` are the caller's to set. In particular RDP
    /// is a stream of small, latency-sensitive writes, so a TCP stream should
    /// have `TCP_NODELAY` set; [`RdpServer::run`] does that for the
    /// connections it accepts itself.
    ///
    /// Equivalent to [`run_connection_with`](Self::run_connection_with) with
    /// [`TransportTls::Managed`], including the treatment of events queued
    /// before the call (see `Queued events` there).
    pub async fn run_connection<S>(&mut self, stream: S) -> ServerResult<()>
    where
        S: AsyncRead + AsyncWrite + Send + Sync + Unpin,
    {
        self.run_connection_with(stream, TransportTls::Managed).await
    }

    /// Run a single RDP connection over `stream`, choosing who performs the TLS
    /// handshake with `tls`.
    ///
    /// Socket options on `stream` are the caller's to set; see
    /// [`run_connection`](Self::run_connection).
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
    /// # Queued events
    ///
    /// Before negotiation starts, this method drops every event still waiting
    /// on the server-global channel, except `Quit`, `GetLocalAddr`,
    /// `SetCredentials` and `SetAutoReconnectCookie`. What a previous session
    /// queued but never consumed (EGFX frames, RDPSND waves, clipboard
    /// messages) would otherwise be written to this client before its
    /// channels exist. The same applies to anything an embedder queued through
    /// [`event_sender`](Self::event_sender) before calling this method:
    /// queue events for a connection only after this method has started.
    ///
    /// This is a drain, not a barrier: an event that a producer of the previous
    /// session sends after it has run still reaches this connection. The
    /// backends the server built for that session are dropped before this
    /// method returns, but a task the embedder runs with its own
    /// [`event_sender`](Self::event_sender) clone or one of the server's
    /// handles is not, so stop such producers before starting the next
    /// connection.
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
    pub async fn run_connection_with<S>(&mut self, stream: S, tls: TransportTls) -> ServerResult<()>
    where
        S: AsyncRead + AsyncWrite + Send + Sync + Unpin,
    {
        let result = self.run_connection_inner(stream, tls).await;
        // Given for this connection only; see `set_connection_local_addr`.
        self.connection_local_addr = None;
        result
    }

    async fn run_connection_inner<S>(&mut self, stream: S, tls: TransportTls) -> ServerResult<()>
    where
        S: AsyncRead + AsyncWrite + Send + Sync + Unpin,
    {
        self.clear_bound_connection();

        // Before negotiation, so nothing the previous session left queued can
        // reach this client ahead of its own channels. See
        // `discard_stale_session_events`.
        self.discard_stale_session_events().await;

        let size = self.display.lock().await.size().await;
        let capabilities = capabilities::capabilities(&self.opts, size);
        let pending = PendingConnection::new(
            self.opts.security.clone(),
            size,
            capabilities,
            self.creds.clone(),
            self.opts.honor_client_desktop_size,
            self.opts.udp_bind_addr,
            ServerCredentialsHandler {
                validator: self.credential_validator.clone(),
                require_authenticated: self.connection_binder.is_some(),
                ..ServerCredentialsHandler::default()
            },
        );

        let Some(negotiated) = pending.negotiate_and_authenticate(stream, tls).await? else {
            return Ok(());
        };

        self.finalize_negotiated(negotiated).await
    }

    /// Finalize a connection that has already negotiated (and, under Hybrid,
    /// authenticated) via [`PendingConnection::negotiate_and_authenticate`].
    /// Dispatches on which [`NegotiatedTransport`] variant it got: `Continued`
    /// (no security upgrade happened, [`RdpServerSecurity::None`]) goes
    /// straight to `accept_finalize` with no stream to shut down, while `Tls`
    /// / `Offloaded` route through [`Self::finalize_and_shutdown`] for the
    /// extra shutdown step — these three paths are NOT structurally identical
    /// past this point, only past the handshake `negotiate_and_authenticate`
    /// itself covers.
    async fn finalize_negotiated<S>(&mut self, negotiated: NegotiatedConnection<S>) -> ServerResult<()>
    where
        S: AsyncRead + AsyncWrite + Sync + Send + Unpin,
    {
        let NegotiatedConnection {
            transport,
            acceptor,
            local_addr,
            authenticated_credentials,
        } = negotiated;
        self.clear_bound_connection();
        let _binding = BoundConnectionGuard {
            display: Arc::clone(&self.bound_display),
            input: Arc::clone(&self.bound_handler),
            credentials: Arc::clone(&self.pending_authenticated_credentials),
        };
        *self
            .pending_authenticated_credentials
            .lock()
            .expect("authenticated credentials lock poisoned") = authenticated_credentials;
        if local_addr.is_some() {
            self.connection_local_addr = local_addr;
        }
        match transport {
            // No security upgrade happened, so there is no TLS session to shut
            // down — matches the pre-existing `BeginResult::Continue` arm.
            NegotiatedTransport::Continued(framed) => {
                self.accept_finalize(framed, acceptor).await?;
            }
            NegotiatedTransport::Tls(framed) => {
                self.finalize_and_shutdown(*framed, acceptor, "TLS connection").await?;
            }
            NegotiatedTransport::Offloaded(framed) => {
                self.finalize_and_shutdown(framed, acceptor, "TLS-offloaded stream")
                    .await?;
            }
        }

        Ok(())
    }

    /// Finalize an upgraded stream and shut it down afterwards. The
    /// negotiation and authentication that used to precede this now live in
    /// [`negotiate_and_authenticate`], which the preemption candidate path
    /// shares.
    async fn finalize_and_shutdown<S>(
        &mut self,
        framed: TokioFramed<S>,
        acceptor: Acceptor,
        shutdown_label: &str,
    ) -> ServerResult<()>
    where
        S: AsyncRead + AsyncWrite + Sync + Send + Unpin,
    {
        // No mark_security_upgrade_as_done / CredSSP here: this refactor moved
        // both into `complete_security_upgrade`, called from
        // `PendingConnection::negotiate_and_authenticate` before this function
        // ever runs -- upstream's un-refactored equivalent still does that
        // work at this point, since it has no separate negotiation step.
        let framed = self.accept_finalize(framed, acceptor).await?;
        debug!("Shutting down {}", shutdown_label);
        let (mut inner, _) = framed.into_inner();
        if let Err(e) = inner.shutdown().await {
            debug!(?e, "{} shutdown error", shutdown_label);
        }

        Ok(())
    }

    /// Bind the configured address and serve RDP connections until
    /// [`ServerEvent::Quit`] is received or the event channel closes.
    pub async fn run(&mut self) -> ServerResult<()> {
        // Create socket with control over options before binding.
        // Using TcpSocket instead of TcpListener::bind() allows setting
        // SO_REUSEADDR and IPv6 dual-stack mode.
        let socket = match self.opts.addr {
            SocketAddr::V4(_) => TcpSocket::new_v4().map_err(|e| ServerError::io("create IPv4 socket", e))?,
            SocketAddr::V6(_) => {
                // IPv6 socket: on Linux, dual-stack is the default
                // (net.ipv6.bindv6only=0), so IPv4 clients connect as
                // IPv4-mapped addresses (::ffff:x.x.x.x). On platforms
                // where IPV6_V6ONLY defaults to 1 (Windows, some BSDs),
                // only IPv6 clients will be accepted and a separate IPv4
                // listener would be needed.
                TcpSocket::new_v6().map_err(|e| ServerError::io("create IPv6 socket", e))?
            }
        };

        // SO_REUSEADDR prevents EADDRINUSE when restarting the server while
        // the previous socket is still in TIME_WAIT. Only set on Unix;
        // on Windows SO_REUSEADDR has different semantics that allow a
        // second process to bind the same port, which is a security risk.
        #[cfg(unix)]
        socket
            .set_reuseaddr(true)
            .map_err(|e| ServerError::io("set SO_REUSEADDR", e))?;

        socket
            .bind(self.opts.addr)
            .map_err(|e| ServerError::io("bind listen address", e))?;

        let listener = socket
            .listen(LISTENER_BACKLOG)
            .map_err(|e| ServerError::io("start listener", e))?;
        let local_addr = listener.local_addr().map_err(|e| ServerError::io("local_addr", e))?;

        debug!("Listening for connections on {local_addr}");
        self.local_addr = Some(local_addr);

        let mut source = TcpConnectionSource { listener };
        self.serve(&mut source).await
    }

    /// Serve RDP connections from `source` until [`ServerEvent::Quit`] is
    /// received or the event channel closes.
    ///
    /// This is [`run`](Self::run) for an embedder that accepts connections
    /// itself: several transports, a WebSocket terminator, sockets handed over
    /// by the service manager. `run` binds one TCP socket and calls this with
    /// it, so everything that depends on [`RdpServerOptions::connection_policy`]
    /// behaves the same here: a second connection that arrives mid-session is
    /// queued, refused, or, under [`ConnectionPolicy::Preempt`], negotiated and
    /// authenticated while the live session carries on, and takes it over only
    /// if it succeeds. [`ConnectionHandler::on_accept`] and
    /// [`ConnectionHandler::on_disconnected`] are called for connections that
    /// have a [`peer`](IncomingConnection::peer).
    ///
    /// An embedder that needs its own loop around the policy (its own hooks, its
    /// own shutdown) calls [`serve_connection`](Self::serve_connection) instead.
    ///
    /// Unlike `run`, this binds no socket, since the source owns them.
    /// [`ServerEvent::GetLocalAddr`] is answered with the address `run` bound
    /// earlier on this server, if it was ever called, and with `None` otherwise.
    pub async fn serve<C>(&mut self, source: &mut C) -> ServerResult<()>
    where
        C: ConnectionSource,
    {
        let mut source_open = true;

        // A candidate that wins a preemption race has ALREADY cleared
        // `on_accept` and fully authenticated by the time it lands here, so it
        // carries a negotiated candidate rather than a raw stream: the next
        // iteration resumes it at finalization, with no second `on_accept`
        // call (that hook is stateful for rate limiters) and no renegotiation.
        let mut pending: Option<AuthenticatedConnection<C::Stream>> = None;

        // Say so out loud: under these modes the bar to evict a live session is
        // NOT authentication, whatever the option's name suggests. Restrict who
        // may even attempt a takeover with `ConnectionHandler::on_accept`.
        if self.opts.connection_policy == ConnectionPolicy::Preempt
            && !authenticates_before_eviction(&self.opts.security)
        {
            warn!(
                "ConnectionPolicy::Preempt is selected under a security mode that does not authenticate the client \
                 before it could evict the live session: any peer able to complete the handshake can take the \
                 session over. Use RdpServerSecurity::Hybrid (CredSSP/NLA) for an authentication-gated takeover, or \
                 gate candidates with ConnectionHandler::on_accept."
            );
        }

        loop {
            let next = match pending.take() {
                Some(winner) => NextConnection::Authenticated(winner),
                None => {
                    let ev_receiver = Arc::clone(&self.ev_receiver);
                    let mut ev_receiver = ev_receiver.lock().await;
                    let accepted = tokio::select! {
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
                                ServerEvent::SetAutoReconnectCookie(cookie) => {
                                    self.set_auto_reconnect_cookie(cookie);
                                }
                                ev => {
                                    debug!("Unexpected event {:?}", ev);
                                }
                            }
                            continue;
                        },
                        accepted = source.accept(), if source_open => {
                            drop(ev_receiver);
                            match accepted {
                                Ok(Some(incoming)) => incoming,
                                Ok(None) => {
                                    debug!("The connection source is closed; no more connections will be accepted");
                                    source_open = false;
                                    continue;
                                }
                                Err(error) => {
                                    warn!(%error, "Accept failed");
                                    continue;
                                }
                            }
                        },
                        else => break,
                    };
                    NextConnection::Incoming(accepted)
                }
            };

            let peer = next.peer();
            debug!(?peer, "Received connection");

            // A `Negotiated` winner already passed `on_accept` as a candidate,
            // inside the race below — its negotiation would not even have
            // started otherwise. Re-running it here would double-count for a
            // stateful handler (a rate limiter's window, an audit record). A
            // connection with no peer address has nothing to pass to the hook.
            let accepted = matches!(next, NextConnection::Authenticated(_))
                || peer
                    .and_then(|peer| with_connection_handler(self.connection_handler.as_ref(), |h| h.on_accept(peer)))
                    .unwrap_or(true);

            if !accepted {
                debug!(?peer, "Connection rejected by handler");
                continue;
            }

            let started = tokio::time::Instant::now();

            let outcome = self.serve_connection(next, source).await;
            let duration = started.elapsed();
            let SessionOutcome { result, successor } = outcome;
            pending = successor;

            if let Err(ref error) = result {
                error!(?error, "Connection error");
            }

            if let Some(action) = peer.and_then(|peer| {
                with_connection_handler(self.connection_handler.as_ref(), |h| {
                    h.on_disconnected(peer, duration, result.as_ref().err())
                })
            }) {
                if action == PostConnectionAction::Stop {
                    debug!(?peer, "Handler requested stop after disconnect");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Serve one connection under [`RdpServerOptions::connection_policy`],
    /// accepting from `source` while it lasts, and return when it ends.
    ///
    /// This is the part of [`serve`](Self::serve) that applies the policy, for
    /// an embedder that wants its own accept loop around it: its own hooks, its
    /// own shutdown, work between sessions. Pass a connection from the source
    /// as [`NextConnection::Incoming`]; under [`ConnectionPolicy::Preempt`] the
    /// outcome may carry the connection that replaced it, and that goes to the
    /// next call as [`NextConnection::Authenticated`]. Nothing about it is
    /// negotiated or gated again, so the embedder must not run its own accept
    /// hooks for it a second time.
    ///
    /// A connection passed as `Incoming` is not gated here. [`serve`](Self::serve)
    /// calls [`ConnectionHandler::on_accept`] and
    /// [`ConnectionHandler::on_disconnected`] around this method, and an
    /// embedder with its own loop does the equivalent in it, which is what lets
    /// that gate be asynchronous. Only a newcomer that arrives while a session
    /// runs is gated inside, since the embedder has no other point at which to
    /// do it.
    ///
    /// While the session runs, a newcomer from `source` is, per the policy: left
    /// where it is until the session ends ([`Queue`](ConnectionPolicy::Queue)),
    /// closed ([`Reject`](ConnectionPolicy::Reject)), or negotiated and
    /// authenticated alongside the live session ([`Preempt`](ConnectionPolicy::Preempt)).
    /// Under `Preempt` the newcomer is gated by [`ConnectionHandler::on_accept`]
    /// before it may negotiate. A connection the embedder wants to vet in other
    /// ways, or asynchronously, has to be vetted by the source before
    /// [`ConnectionSource::accept`] returns it, within the cancel safety that
    /// method requires. Only one that gets through, and, under
    /// [`RdpServerSecurity::Hybrid`], completes CredSSP, ends the live session.
    ///
    /// The connection that replaced a session has already ended it, so serve the
    /// [`AuthenticatedConnection`] from the outcome; dropping it unserved
    /// disconnects that client without a session to show for it.
    ///
    /// The events that [`serve`](Self::serve) handles between connections
    /// ([`ServerEvent::Quit`] among them) are not read here, so the embedder's
    /// loop must read them, or stop the server by dropping this future. The live
    /// session reads its own events as it always has.
    ///
    /// `serve` warns once when `Preempt` is selected under a security mode that
    /// does not authenticate the client before it can evict a session. This
    /// method does not, since it runs once per session; an embedder choosing
    /// `Preempt` outside [`RdpServerSecurity::Hybrid`] is the one who knows that
    /// the only bar to a takeover is then what its source and
    /// [`ConnectionHandler::on_accept`] check.
    pub async fn serve_connection<C>(
        &mut self,
        connection: NextConnection<C::Stream>,
        source: &mut C,
    ) -> SessionOutcome<C::Stream>
    where
        C: ConnectionSource,
    {
        let peer = connection.peer();
        match &connection {
            NextConnection::Incoming(incoming) => self.connection_local_addr = incoming.local_addr,
            // The eviction event is queued on the server-global channel but
            // consumed by whichever connection happens to drain it. If the
            // incumbent was too wedged to take it within `EVICTION_GRACE`
            // (very plausibly the case, being wedged is why it was evicted), it
            // is still queued now, and the WINNER's `client_loop` would drain it
            // and disconnect itself, reporting a bogus
            // `ERRINFO_DISCONNECTED_BY_OTHERCONNECTION` to the client that just
            // took the session over. Discard any such leftover before serving
            // it; every other event is put back in order.
            NextConnection::Authenticated(_) => self.discard_stale_session_events().await,
        }
        self.clear_bound_connection();
        let mut source_open = true;

        let (result, successor) = match self.opts.connection_policy {
            ConnectionPolicy::Preempt => {
                // Serve this connection while still accepting: a newcomer that
                // clears `on_accept` AND fully authenticates
                // (`negotiate_candidate`) takes over, instead of queuing behind
                // the live session. Cancelling `conn` runs the same
                // per-connection teardown a client-side disconnect does.
                //
                // `conn` borrows `self` for the whole race, so the candidate's
                // `on_accept` and its negotiation work from clones taken here.
                // The handler is shared, not taken: the live connection's own
                // hooks (`on_connection_info`) must still reach it (#1969).
                let handler = self.connection_handler.clone();
                let ctx = self.negotiation_context();
                let ev_sender = self.ev_sender.clone();
                let mut recently_evicted = self.recently_evicted.take();
                // A candidate that finished negotiating just as the session ended on
                // its own, and so replaced nothing.
                let mut handoff: Option<AuthenticatedConnection<C::Stream>> = None;

                let outcome = {
                    // Uses the anyhow-returning inner method, not the public
                    // `run_connection` (`ServerResult`-returning as of
                    // upstream's typed-error migration, #1242): `conn`'s
                    // declared `Result<()>` (anyhow) must match
                    // `serve_negotiated`'s return type across both match
                    // arms, and `on_disconnected` below still expects
                    // `Option<&anyhow::Error>` -- the same reason upstream's
                    // own accept loop bypasses the public wrapper too.
                    let mut conn: core::pin::Pin<Box<dyn Future<Output = ServerResult<()>> + '_>> = match connection {
                        NextConnection::Incoming(incoming) => {
                            Box::pin(self.run_connection_inner(incoming.stream, incoming.tls))
                        }
                        NextConnection::Authenticated(winner) => Box::pin(self.serve_negotiated(winner.connection)),
                    };
                    let mut probe: PreemptProbe<'_, C::Stream> = Box::pin(core::future::pending());
                    let mut probing = false;

                    loop {
                        // This `select!` must only YIELD — never mutate
                        // `probe`, whose futures it still borrows.
                        let race = tokio::select! {
                            res = &mut conn => PreemptRace::Ended(res),
                            accepted = source.accept(), if !probing && source_open => PreemptRace::Accepted(accepted),
                            candidate = &mut probe => PreemptRace::Probed(candidate),
                        };

                        match race {
                            // The session ended on its own. A candidate still
                            // negotiating is NOT discarded — that would reset a
                            // legitimate client that happened to connect just
                            // as the old session ended; finish it and serve it
                            // next if it authenticates.
                            PreemptRace::Ended(res) => {
                                if probing {
                                    // BOUNDED: nothing else is being serviced
                                    // during this await, so a candidate that
                                    // is not nearly done is dropped rather
                                    // than allowed to stall the listener.
                                    handoff = match tokio::time::timeout(CANDIDATE_HANDOFF_GRACE, &mut probe).await {
                                        Ok(candidate) => candidate,
                                        Err(_) => {
                                            debug!(
                                                "a candidate was still negotiating when the session ended -- \
                                             dropping it rather than stalling the accept loop; it can reconnect"
                                            );
                                            None
                                        }
                                    };
                                }
                                break (res, None, recently_evicted);
                            }
                            PreemptRace::Accepted(Ok(Some(next))) => {
                                let next_peer = next.peer;
                                // A peer evicted moments ago may not bounce
                                // straight back and retake the session; each
                                // attempt re-arms the window, so a reconnect
                                // storm can never win. See `recently_evicted`.
                                // A connection without an address cannot be
                                // recognised, so it is never held to this.
                                let bounced_back = next_peer.is_some_and(|addr| {
                                    refuse_reconnect_from_evicted(
                                        &mut recently_evicted,
                                        addr.ip(),
                                        Instant::now(),
                                        REPREEMPT_COOLDOWN,
                                        REPREEMPT_MAX_LOCKOUT,
                                    )
                                });
                                // Gate the candidate through `on_accept` BEFORE
                                // it may negotiate, and so before it can
                                // preempt anything: otherwise a candidate the
                                // rate limiter would reject could still evict
                                // the live session and only be rejected
                                // afterwards, once the damage was done.
                                let candidate_accepted = !bounced_back
                                    && next_peer.is_none_or(|addr| {
                                        with_connection_handler(handler.as_ref(), |h| h.on_accept(addr)).unwrap_or(true)
                                    });

                                if candidate_accepted {
                                    probing = true;
                                    // BOUNDED: see `CANDIDATE_NEGOTIATION_TIMEOUT`.
                                    // An unbounded probe is a remote hang of
                                    // the whole accept loop.
                                    probe = Box::pin(negotiate_candidate_bounded(&ctx, next));
                                } else if bounced_back {
                                    info!(
                                        ?next_peer,
                                        "ignoring a reconnect from the peer just evicted -- it is \
                                     auto-reconnecting into the session that replaced it"
                                    );
                                } else {
                                    debug!(?next_peer, "candidate rejected by handler while a session was live");
                                }
                            }
                            PreemptRace::Accepted(Ok(None)) => {
                                debug!("The connection source is closed; no more connections will be accepted");
                                source_open = false;
                            }
                            PreemptRace::Accepted(Err(error)) => {
                                warn!(%error, "accept failed while a session was live");
                            }
                            PreemptRace::Probed(candidate) => {
                                probing = false;
                                probe = Box::pin(core::future::pending());
                                // `negotiate_candidate` already logged the
                                // reason when it declines, so there is nothing
                                // to do in the `None` case.
                                if let Some(winner) = candidate {
                                    info!(
                                        old_peer = ?peer,
                                        new_peer = ?winner.peer,
                                        "an authenticated client connected -- evicting the existing session"
                                    );
                                    let _ = ev_sender.send(ServerEvent::EvictedByOtherConnection);
                                    let now = Instant::now();
                                    recently_evicted = peer.map(|addr| EvictedPeer {
                                        ip: addr.ip(),
                                        evicted_at: now,
                                        last_try: now,
                                    });
                                    // Let the incumbent observe the event and
                                    // put the reason on the wire before it
                                    // goes; bounded, so a wedged peer cannot
                                    // stall the takeover.
                                    match tokio::time::timeout(EVICTION_GRACE, &mut conn).await {
                                        Ok(res) => {
                                            break (res, Some(winner), recently_evicted);
                                        }
                                        Err(_) => {
                                            debug!(old_peer = ?peer, "evicted session did not wind down in time");
                                            break (Ok(()), Some(winner), recently_evicted);
                                        }
                                    }
                                }
                            }
                        }
                    }
                };

                let (result, preempted_by, evicted) = outcome;
                // Only remember an eviction that actually replaced this
                // session; a session that ended on its own terms leaves nobody
                // barred from connecting.
                self.recently_evicted = if preempted_by.is_some() { evicted } else { None };
                if preempted_by.is_some() {
                    // Can't do this INSIDE the race above: `conn` (built from
                    // `self.run_connection`/`self.serve_negotiated`) borrows
                    // `self` mutably for the whole race, so no other &mut self
                    // call is possible there. `self` is free again here, and
                    // the ~750ms EVICTION_GRACE this waited through is
                    // immaterial to what this closes -- a real ARC reconnect
                    // takes far longer than that to occur.
                    self.invalidate_auto_reconnect_cookie_on_eviction();
                }
                let successor = preempted_by.or(handoff);
                (result, successor)
            }
            ConnectionPolicy::Reject => {
                // Serve while still accepting, but close any newcomer
                // instead of racing it (Preempt) or queuing it (Queue): the
                // extra connection fails fast rather than hanging in the
                // backlog (#1483). The session arm is polled first (biased),
                // so a client reconnecting the instant a session ends is
                // taken by the outer loop, not rejected here.
                let result = match connection {
                    NextConnection::Incoming(incoming) => {
                        let mut conn = Box::pin(self.run_connection_inner(incoming.stream, incoming.tls));
                        loop {
                            tokio::select! {
                                biased;
                                res = &mut conn => break res,
                                accepted = source.accept(), if source_open => match accepted {
                                    Ok(Some(extra)) => {
                                        debug!(extra_peer = ?extra.peer, "Session active; rejecting connection");
                                    }
                                    Ok(None) => {
                                        debug!("The connection source is closed; no more connections will be accepted");
                                        source_open = false;
                                    }
                                    Err(error) => warn!(%error, "accept failed while a session was live"),
                                },
                            }
                        }
                    }
                    // Unreachable: Reject never produces a Negotiated candidate.
                    NextConnection::Authenticated(winner) => Box::pin(self.serve_negotiated(winner.connection)).await,
                };
                (result, None)
            }
            ConnectionPolicy::Queue => {
                let result = match connection {
                    // Same anyhow-vs-ServerResult reasoning as the preemption
                    // branch above.
                    NextConnection::Incoming(incoming) => {
                        Box::pin(self.run_connection_inner(incoming.stream, incoming.tls)).await
                    }
                    // Unreachable in practice: `pending` is only ever populated
                    // by the preemption branch above.
                    NextConnection::Authenticated(winner) => Box::pin(self.serve_negotiated(winner.connection)).await,
                };
                (result, None)
            }
        };

        // Neither path above goes through `run_connection_with`, which clears
        // this for embedders.
        self.connection_local_addr = None;

        SessionOutcome { result, successor }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "private per-connection dispatch; the parameters are the connection's negotiated identifiers and transports"
    )]
    async fn dispatch_pdu(
        &mut self,
        conn: &mut ConnectionState,
        action: Action,
        bytes: bytes::BytesMut,
        writer: &mut impl FramedWrite,
        io_channel_id: u16,
        user_channel_id: u16,
        message_channel_id: Option<u16>,
        udp_transport: Option<&multitransport::UdpTransportHandle>,
    ) -> ServerResult<RunState> {
        match action {
            Action::FastPath => {
                let input = decode(&bytes).map_err(ServerError::decode)?;
                self.handle_fastpath(input).await;
            }

            Action::X224 => {
                if self
                    .handle_x224(
                        conn,
                        writer,
                        io_channel_id,
                        user_channel_id,
                        message_channel_id,
                        &bytes,
                        udp_transport,
                    )
                    .await?
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
    ) -> ServerResult<(RunState, UpdateEncoder)> {
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

            let mut fragmenter = fragmenter?;
            if fragmenter.size_hint() > buffer.len() {
                buffer.resize(fragmenter.size_hint(), 0);
            }

            while let Some(len) = fragmenter.next(buffer) {
                writer
                    .write_all(&buffer[..len])
                    .await
                    .map_err(|e| ServerError::io("failed to write display update", e))?;
            }
        }

        Ok((RunState::Continue, encoder))
    }

    /// `conn.client_supports_errinfo` is the client's `RNS_UD_CS_SUPPORT_ERRINFO_PDU`
    /// early-capability opt-in: MS-RDPBCGR 3.3.5.7.1 forbids sending a Server
    /// Set Error Info PDU to a client that did not set it, so the two arms below
    /// that carry a disconnect reason drop the PDU (and just disconnect) when it
    /// is `false`.
    #[expect(
        clippy::too_many_arguments,
        reason = "private per-connection dispatch; the parameters are the connection's negotiated identifiers and transports"
    )]
    async fn dispatch_server_events(
        &mut self,
        conn: &mut ConnectionState,
        events: &mut Vec<ServerEvent>,
        writer: &mut impl FramedWrite,
        io_channel_id: u16,
        user_channel_id: u16,
        message_channel_id: Option<u16>,
        udp_transport: Option<&multitransport::UdpTransportHandle>,
    ) -> ServerResult<RunState> {
        // Only referenced under `#[cfg(feature = "egfx")]` below (the only
        // channel this integration migrates); this keeps the parameter
        // itself unconditional so callers don't need their own `egfx` gate.
        #[cfg(not(feature = "egfx"))]
        let _ = &udp_transport;

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
                // Session takeover: tell the client WHY it is being
                // disconnected before dropping it, so it does not read this as
                // an unexpected drop and auto-reconnect (which ping-pongs
                // against the preempting client — see the variant's docs).
                ServerEvent::EvictedByOtherConnection => {
                    debug!("evicting this connection -- another client took the session over");
                    if !conn.client_supports_errinfo {
                        // MS-RDPBCGR 3.3.5.7.1: the client did not set
                        // RNS_UD_CS_SUPPORT_ERRINFO_PDU, so it MUST NOT be
                        // sent a Set Error Info PDU. Such a client cannot be
                        // told why it is going away; it just goes.
                        debug!("client did not opt into Set Error Info PDUs; dropping it without the eviction reason");
                        return Ok(RunState::Disconnect);
                    }
                    let pdu = rdp::headers::ShareDataPdu::ServerSetErrorInfo(ServerSetErrorInfoPdu(
                        ErrorInfo::ProtocolIndependentCode(ProtocolIndependentCode::DisconnectedByOtherconnection),
                    ));
                    // Best-effort: if the evicted peer's socket is already
                    // half-dead the write fails, which is fine — it is leaving
                    // either way, and the caller falls back to cancelling it.
                    // pduSource=0, not user_channel_id -- MS-RDPBCGR 2.2.5.1.1
                    // requires it for TS_SET_ERROR_INFO_PDU specifically.
                    match encode_share_data_pdu(pdu, 0, io_channel_id, user_channel_id) {
                        Ok(bytes) => {
                            if let Err(error) = writer.write_all(&bytes).await {
                                debug!(%error, "could not send the eviction reason; disconnecting anyway");
                            }
                        }
                        Err(error) => {
                            warn!(%error, "could not encode the eviction reason; disconnecting anyway");
                        }
                    }
                    return Ok(RunState::Disconnect);
                }
                ServerEvent::Disconnect(error) => {
                    debug!(?error, "Got disconnect event");
                    if !conn.client_supports_errinfo {
                        // Same MS-RDPBCGR 3.3.5.7.1 rule as the eviction arm.
                        debug!("client did not opt into Set Error Info PDUs; disconnecting without the reason");
                        return Ok(RunState::Disconnect);
                    }
                    let pdu = rdp::headers::ShareDataPdu::ServerSetErrorInfo(ServerSetErrorInfoPdu(error));
                    // pduSource=0, not user_channel_id -- same MS-RDPBCGR
                    // 2.2.5.1.1 requirement as the EvictedByOtherConnection
                    // arm above; upstream's original call here (before this
                    // merge) predated that parameter and used
                    // user_channel_id, which this fixes to match.
                    let data = encode_share_data_pdu(pdu, 0, io_channel_id, user_channel_id)?;
                    writer
                        .write_all(&data)
                        .await
                        .map_err(|e| ServerError::io("send server set error info", e))?;
                    return Ok(RunState::Disconnect);
                }
                ServerEvent::Redirect(redirection) => {
                    debug!(?redirection, "Got redirect event");
                    let pdu = rdp::headers::ShareControlHeader {
                        share_id: 0,
                        pdu_source: user_channel_id,
                        share_control_pdu: ShareControlPdu::ServerRedirect(*redirection),
                    };
                    let user_data = encode_vec(&pdu).map_err(ServerError::encode)?.into();
                    let data = encode_vec(&X224(SendDataIndication {
                        initiator_id: user_channel_id,
                        channel_id: io_channel_id,
                        user_data,
                    }))
                    .map_err(ServerError::encode)?;
                    writer
                        .write_all(&data)
                        .await
                        .map_err(|e| ServerError::io("send server redirection", e))?;
                    return Ok(RunState::Redirected);
                }
                ServerEvent::GetLocalAddr(tx) => {
                    let _ = tx.send(self.local_addr);
                }
                ServerEvent::SetCredentials(creds) => {
                    self.set_credentials(Some(creds));
                }
                ServerEvent::SetAutoReconnectCookie(cookie) => {
                    self.update_auto_reconnect_cookie(conn, cookie, writer, io_channel_id, user_channel_id)
                        .await?;
                }
                ServerEvent::Rdpsnd(s) => {
                    let Some(rdpsnd) = conn.get_svc_processor::<RdpsndServer>() else {
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
                            // The event channel outlives a single connection, so a
                            // wave queued by the previous client's sound handler can
                            // be the first event a new connection dispatches, before
                            // its own rdpsnd channel has negotiated a format. There is
                            // no channel to carry it yet; failing the whole connection
                            // over it would turn every audio-enabled disconnect into a
                            // failed next connect.
                            if !rdpsnd.is_ready() {
                                debug!("Dropping wave: rdpsnd channel not negotiated yet");
                                continue;
                            }
                            rdpsnd.wave(data, ts)
                        }
                        RdpsndServerMessage::SetVolume { left, right } => {
                            // Same stale-event case as a wave: set_volume needs the
                            // client's format flags, which a new connection does not
                            // have until its rdpsnd channel negotiates.
                            if !rdpsnd.is_ready() {
                                debug!("Dropping volume change: rdpsnd channel not negotiated yet");
                                continue;
                            }
                            rdpsnd.set_volume(left, right)
                        }
                        RdpsndServerMessage::Close => rdpsnd.close(),
                        RdpsndServerMessage::Error(error) => {
                            error!(?error, "Handling rdpsnd event");
                            continue;
                        }
                    }
                    .map_err_kind("failed to send rdpsnd event", ServerErrorKind::Pdu)?;
                    let channel_id = conn
                        .get_channel_id_by_type::<RdpsndServer>()
                        .ok_or_else(|| ServerError::channel("SVC channel not found"))?;
                    let data = server_encode_svc_messages(msgs.into(), channel_id, user_channel_id)
                        .map_err(ServerError::encode)?;
                    writer
                        .write_all(&data)
                        .await
                        .map_err(|e| ServerError::io("write_all", e))?;
                }
                ServerEvent::Rdpdr(msg) => {
                    let Some(rdpdr) = conn.get_svc_processor::<RdpdrServer>() else {
                        warn!("No rdpdr channel, dropping event");
                        continue;
                    };
                    let msgs = match msg {
                        RdpdrServerMessage::Create {
                            device_id,
                            path,
                            desired_access,
                            create_disposition,
                            create_options,
                        } => rdpdr.drive_create(device_id, path, desired_access, create_disposition, create_options),
                        RdpdrServerMessage::Read {
                            device_id,
                            file_id,
                            length,
                            offset,
                        } => rdpdr.drive_read(device_id, file_id, length, offset),
                        RdpdrServerMessage::Write {
                            device_id,
                            file_id,
                            data,
                            offset,
                        } => rdpdr.drive_write(device_id, file_id, data, offset),
                        RdpdrServerMessage::Close { device_id, file_id } => rdpdr.drive_close(device_id, file_id),
                        RdpdrServerMessage::FlushBuffers { device_id, file_id } => {
                            rdpdr.drive_flush_buffers(device_id, file_id)
                        }
                        RdpdrServerMessage::QueryInformation {
                            device_id,
                            file_id,
                            info_class,
                        } => rdpdr.drive_query_information(device_id, file_id, info_class),
                        RdpdrServerMessage::SetInformation {
                            device_id,
                            file_id,
                            set_buffer,
                        } => rdpdr.drive_set_information(device_id, file_id, set_buffer),
                        RdpdrServerMessage::QueryDirectory {
                            device_id,
                            file_id,
                            info_class,
                            path,
                            initial_query,
                        } => rdpdr.drive_query_directory(device_id, file_id, info_class, path, initial_query),
                        RdpdrServerMessage::NotifyChangeDirectory {
                            device_id,
                            file_id,
                            watch_tree,
                            completion_filter,
                        } => rdpdr.drive_notify_change_directory(device_id, file_id, watch_tree, completion_filter),
                        RdpdrServerMessage::QueryVolumeInformation {
                            device_id,
                            file_id,
                            fs_info_class,
                        } => rdpdr.drive_query_volume_information(device_id, file_id, fs_info_class),
                        RdpdrServerMessage::LockControl {
                            device_id,
                            file_id,
                            operation,
                            wait,
                            locks,
                        } => rdpdr.drive_lock_control(device_id, file_id, operation, wait, locks),
                        RdpdrServerMessage::QuerySecurity {
                            device_id,
                            file_id,
                            security_information,
                        } => rdpdr.drive_query_security(device_id, file_id, security_information),
                        RdpdrServerMessage::SetSecurity {
                            device_id,
                            file_id,
                            security_information,
                            security_descriptor,
                        } => rdpdr.drive_set_security(device_id, file_id, security_information, security_descriptor),
                        RdpdrServerMessage::DeviceControl {
                            device_id,
                            file_id,
                            io_control_code,
                            input_buffer,
                            output_buffer_length,
                        } => rdpdr.drive_device_control(
                            device_id,
                            file_id,
                            io_control_code,
                            input_buffer,
                            output_buffer_length,
                        ),
                    }
                    .map_err_kind("failed to send rdpdr event", ServerErrorKind::Pdu)?;
                    let channel_id = conn
                        .get_channel_id_by_type::<RdpdrServer>()
                        .ok_or_else(|| ServerError::channel("SVC channel not found"))?;
                    let data =
                        server_encode_svc_messages(msgs, channel_id, user_channel_id).map_err(ServerError::encode)?;
                    writer
                        .write_all(&data)
                        .await
                        .map_err(|e| ServerError::io("write_all", e))?;
                }
                ServerEvent::Rdpeai(msg) => {
                    let Some(drdynvc) = conn.get_svc_processor::<dvc::DrdynvcServer>() else {
                        warn!("No drdynvc channel, dropping AUDIO_INPUT event");
                        continue;
                    };
                    let Some(channel_id) = drdynvc.get_channel_id_by_type::<RdpeaiServer>() else {
                        warn!("No AUDIO_INPUT dynamic channel, dropping event");
                        continue;
                    };
                    // dvc_by_id_mut already returns None for a channel that isn't yet
                    // Opened, and that case is handled just below; a separate
                    // is_channel_opened check here would only duplicate it.
                    let Some(mut rdpeai) = drdynvc.dvc_by_id_mut::<RdpeaiServer>(channel_id) else {
                        warn!("AUDIO_INPUT channel not opened or not found by id, dropping event");
                        continue;
                    };
                    let result = match msg {
                        RdpeaiServerMessage::Open {
                            frames_per_packet,
                            initial_format,
                            capture_format,
                        } => rdpeai
                            .processor_mut()
                            .open(frames_per_packet, initial_format, capture_format),
                        RdpeaiServerMessage::ChangeFormat { new_format } => {
                            rdpeai.processor_mut().change_format(new_format)
                        }
                        RdpeaiServerMessage::Error(error) => {
                            error!(?error, "Handling AUDIO_INPUT event");
                            continue;
                        }
                    };
                    // open()/change_format() reject calls that race the channel's current
                    // state (e.g. Open before negotiation finishes); that is an expected,
                    // recoverable condition per their own doc comments, not a connection
                    // fault, so drop-and-warn like every other unavailability in this arm
                    // rather than tearing down the session.
                    let msgs = match result {
                        Ok(msgs) => msgs,
                        Err(error) => {
                            warn!(%error, "AUDIO_INPUT event rejected by current channel state, dropping");
                            continue;
                        }
                    };
                    let dvc_messages = dvc::encode_dvc_messages(channel_id, msgs, ChannelFlags::SHOW_PROTOCOL)
                        .map_err(ServerError::encode)?;
                    let drdynvc_channel_id = conn
                        .get_channel_id_by_type::<dvc::DrdynvcServer>()
                        .ok_or_else(|| ServerError::channel("DRDYNVC channel not found"))?;
                    let data = server_encode_svc_messages(dvc_messages, drdynvc_channel_id, user_channel_id)
                        .map_err(ServerError::encode)?;
                    writer
                        .write_all(&data)
                        .await
                        .map_err(|e| ServerError::io("write_all", e))?;
                }
                ServerEvent::Clipboard(c) => {
                    let Some(cliprdr) = conn.get_svc_processor::<CliprdrServer>() else {
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
                    };

                    // A clipboard failure is a per-request problem at worst: a
                    // stale or malformed request, a capability that was never
                    // negotiated, backpressure on pending transfers. None of
                    // that is a reason to disconnect a session whose display,
                    // audio and input are healthy. The `ClipboardMessage::Error`
                    // arm above already takes this view; propagating here made
                    // the two paths disagree.
                    let msgs = match msgs {
                        Ok(msgs) => msgs,
                        Err(error) => {
                            error!(?error, "Failed to send clipboard event");
                            continue;
                        }
                    };

                    let channel_id = conn
                        .get_channel_id_by_type::<CliprdrServer>()
                        .ok_or_else(|| ServerError::channel("SVC channel not found"))?;
                    let data = server_encode_svc_messages(msgs.into(), channel_id, user_channel_id)
                        .map_err(ServerError::encode)?;
                    writer
                        .write_all(&data)
                        .await
                        .map_err(|e| ServerError::io("write_all", e))?;
                }
                ServerEvent::Echo(msg) => match msg {
                    EchoServerMessage::SendRequest { payload } => {
                        let Some(drdynvc) = conn.get_svc_processor::<dvc::DrdynvcServer>() else {
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
                            dvc::encode_dvc_messages(echo_channel_id, vec![request], ChannelFlags::SHOW_PROTOCOL)
                                .map_err(ServerError::encode)?;

                        let drdynvc_channel_id = conn
                            .get_channel_id_by_type::<dvc::DrdynvcServer>()
                            .ok_or_else(|| ServerError::channel("DRDYNVC channel not found"))?;

                        let data = server_encode_svc_messages(messages, drdynvc_channel_id, user_channel_id)
                            .map_err(ServerError::encode)?;
                        writer
                            .write_all(&data)
                            .await
                            .map_err(|e| ServerError::io("write_all", e))?;
                    }
                },
                #[cfg(feature = "usb")]
                ServerEvent::Usb(msg) => match msg {
                    UrbdrcServerMessage::AddChan => {
                        let create_dvc_msg = {
                            use crate::urbdrc::UsbRedirServer;

                            let Some(usb_factory) = self.usb_factory.as_mut() else {
                                warn!("Missing USB device factory");
                                continue;
                            };
                            let Some(drdynvc) = conn
                                .static_channels
                                .get_by_type_mut::<dvc::DrdynvcServer>()
                                .and_then(|svc| svc.channel_processor_downcast_mut::<dvc::DrdynvcServer>())
                            else {
                                warn!("No drdynvc channel, dropping URBDRC request");
                                continue;
                            };

                            let Some(comp_iface) = conn.usb_man.comp_iface_alloc.alloc() else {
                                warn!("Run out of URBDRC interface IDs");
                                continue;
                            };

                            let Some(device_backend) = usb_factory.create_device() else {
                                warn!("Failed to create USB device backend");
                                continue;
                            };

                            drdynvc
                                .create_channel_with(|dvc_id| {
                                    let handle = UsbDeviceHandle::new(self.ev_sender.clone(), dvc_id);
                                    if conn.usb_man.router.insert(dvc_id, handle.device()).is_some() {
                                        warn!(dvc_id = dvc_id, "Replacing USB device pending-request map");
                                    }
                                    Ok::<_, PduError>(
                                        UrbdrcDeviceServer::new(
                                            Box::new(UsbRedirServer::new(device_backend, handle)),
                                            comp_iface,
                                        )
                                        .expect("interface ID allocated by InterfaceAlloc must be valid"),
                                    )
                                })
                                .map_err_kind("create URBDRC device channel", ServerErrorKind::Pdu)?
                        };

                        let drdynvc_channel_id = conn
                            .get_channel_id_by_type::<dvc::DrdynvcServer>()
                            .ok_or_else(|| ServerError::channel("DRDYNVC channel not found"))?;
                        let data =
                            server_encode_svc_messages(vec![create_dvc_msg], drdynvc_channel_id, user_channel_id)
                                .map_err(ServerError::encode)?;

                        writer
                            .write_all(&data)
                            .await
                            .map_err(|e| ServerError::io("write_all", e))?;
                    }
                    UrbdrcServerMessage::Device { dvc_id, dev_msg } => {
                        let Some(device) = conn.usb_man.router.get(&dvc_id).map(Arc::clone) else {
                            warn!(dvc_id, "Missing USB device state");
                            continue;
                        };

                        // Handle checks are an early rejection for callers. This event-loop check
                        // is authoritative because a request may already be queued when retract or
                        // channel close changes the shared lifecycle state.
                        if !device.is_open() {
                            trace!(dvc_id, "Dropping request for closing or closed USB device");
                            continue;
                        }

                        let Some(drdynvc) = conn.get_svc_processor::<dvc::DrdynvcServer>() else {
                            warn!("No drdynvc channel, dropping URBDRC request");
                            continue;
                        };

                        let Some(mut dvc) = drdynvc.dvc_by_id_mut::<UrbdrcDeviceServer>(dvc_id) else {
                            warn!(dvc_id, "USB dynamic channel ID mismatch");
                            continue;
                        };
                        let processor = dvc.processor_mut();

                        let (dvc_msgs, close_dev) = match dev_msg {
                            UrbdrcDeviceServerMessage::QueryDeviceText { text_type, locale_id } => {
                                let text = processor
                                    .query_device_text(text_type, locale_id)
                                    .map_err_kind("query USB device text", ServerErrorKind::Pdu)?;
                                (vec![text], false)
                            }
                            UrbdrcDeviceServerMessage::IoReq { data, tx } => {
                                if tx.is_closed() {
                                    continue;
                                }

                                let request = match data {
                                    ServerDeviceIoReq::IoControl(packet) => processor.io_control(packet),
                                    ServerDeviceIoReq::InternalIoControl(packet) => {
                                        processor.internal_io_control(packet)
                                    }
                                    ServerDeviceIoReq::TransferOut(packet) => processor.transfer_out(packet),
                                    ServerDeviceIoReq::TransferIn(packet) => processor.transfer_in(packet),
                                }
                                .map_err_kind("USB I/O request", ServerErrorKind::Pdu)?;

                                let pending = request
                                    .expects_completion
                                    .then(|| device.register_pending(request.request_id));

                                // Reply before the write so the caller owns cancel-on-drop as early
                                // as possible. A CANCEL_REQUEST it enqueues in response lands in a
                                // later batch, so it cannot overtake this request on the wire.
                                if tx.send(pending).is_err() && request.expects_completion {
                                    trace!(dvc_id, "USB I/O request receiver dropped");
                                    device.forget_pending(request.request_id);
                                    processor.abandon_unsent(request);
                                    (Vec::new(), false)
                                } else {
                                    (vec![request.message], false)
                                }
                            }
                            UrbdrcDeviceServerMessage::Retract(reason) => {
                                let request = processor
                                    .retract_device(reason)
                                    .map_err_kind("retract USB device", ServerErrorKind::Pdu)?;
                                device.mark_retracting();
                                (vec![request], true)
                            }
                            UrbdrcDeviceServerMessage::CancelRequest(request_id) => {
                                if !device.is_pending(request_id) {
                                    trace!(dvc_id, request_id, "USB I/O request is no longer pending");
                                    continue;
                                }

                                let request = processor
                                    .cancel_request(request_id)
                                    .map_err_kind("cancel USB I/O request", ServerErrorKind::Pdu)?;

                                (vec![request], false)
                            }
                        };

                        let mut messages = dvc::encode_dvc_messages(dvc_id, dvc_msgs, ChannelFlags::SHOW_PROTOCOL)
                            .map_err(ServerError::encode)?;

                        if close_dev {
                            let close_message = conn
                                .get_svc_processor::<dvc::DrdynvcServer>()
                                .and_then(|drdynvc| drdynvc.close_channel(dvc_id))
                                .ok_or_else(|| {
                                    ServerError::channel("URBDRC dynamic channel disappeared before close")
                                })?;
                            conn.remove_usb_device(dvc_id);
                            messages.push(close_message);
                        }

                        let drdynvc_channel_id = conn
                            .get_channel_id_by_type::<dvc::DrdynvcServer>()
                            .ok_or_else(|| ServerError::channel("DRDYNVC channel not found"))?;

                        let data = server_encode_svc_messages(messages, drdynvc_channel_id, user_channel_id)
                            .map_err(ServerError::encode)?;
                        writer
                            .write_all(&data)
                            .await
                            .map_err(|e| ServerError::io("write_all", e))?;
                    }
                    UrbdrcServerMessage::DeviceClosed { dvc_id } => {
                        conn.remove_usb_device(dvc_id);
                    }
                },
                #[cfg(feature = "egfx")]
                ServerEvent::Egfx(msg) => match msg {
                    EgfxServerMessage::SendMessages { messages } => {
                        self.dispatch_egfx_messages(
                            conn,
                            messages,
                            writer,
                            user_channel_id,
                            message_channel_id,
                            udp_transport,
                        )
                        .await?;
                    }
                },
                ServerEvent::AutoDetectRttRequest => {
                    // Auto-detect requests ride the MCS message channel
                    // ([MS-RDPBCGR] 2.2.14.3). With none negotiated (the client
                    // did not request it), there is nowhere to send them.
                    if let (Some(ad), Some(message_channel_id)) = (conn.autodetect.as_mut(), message_channel_id) {
                        let now_ms = monotonic_now_ms();
                        ad.expire_stale_probes(now_ms, crate::autodetect::RTT_PROBE_MAX_AGE_MS);
                        let request = ad.send_rtt_request(now_ms);
                        let data = encode_autodetect_request(request, message_channel_id, user_channel_id)?;
                        writer
                            .write_all(&data)
                            .await
                            .map_err(|e| ServerError::io("write_all", e))?;

                        // Report the measured characteristics to the client
                        // ([MS-RDPBCGR] 2.2.14.1.5). The client does not reply. Sent only
                        // once both RTT and bandwidth are known, and paced independently
                        // of this probe cadence, so a fast caller does not turn into a
                        // fast stream of unsolicited PDUs.
                        if let Some(result) = ad.build_netchar_result(now_ms) {
                            let data = encode_autodetect_request(result, message_channel_id, user_channel_id)?;
                            writer
                                .write_all(&data)
                                .await
                                .map_err(|e| ServerError::io("write_all", e))?;
                        }

                        // While no large graphics write has been bracketed recently (see
                        // `write_egfx_over_tcp` and `write_egfx_over_udp`), measure
                        // bandwidth over a window of ticks: Start on one, Stop several later,
                        // with ordinary traffic in between counted by the client, then a
                        // Bandwidth Measure Results PDU in reply. Until one has completed
                        // there is no characteristics result to send.
                        if let Some(pdu) = ad.build_bandwidth_measure() {
                            let data = encode_autodetect_request(pdu, message_channel_id, user_channel_id)?;
                            writer
                                .write_all(&data)
                                .await
                                .map_err(|e| ServerError::io("write_all", e))?;
                        }
                    }
                }
            }
        }

        Ok(RunState::Continue)
    }

    /// Routes EGFX graphics data over the sideband UDP transport when one is
    /// up and the channel has migrated, otherwise the normal TCP path.
    ///
    /// Opportunistically requests the migration (Soft-Sync,
    /// [`dvc::DrdynvcServer::request_reliable_udp`]) the first time EGFX has
    /// data to send after a transport exists: MS-RDPBCGR sequencing does not
    /// give an earlier point where EGFX's dynamic channel id is known to be
    /// open (dynamic channels open lazily, driven by the client, well after
    /// the transport could have already come up during multitransport
    /// bootstrapping). The request is made once per connection: A later attempt
    /// gets an "already requested" error from
    /// [`dvc::DrdynvcServer::request_reliable_udp`], which is expected and only
    /// traced. The request declares the TCP path flushed for the channel
    /// (SOFT_SYNC_TCP_FLUSHED, MS-RDPEDYC 2.2.5.1), so its data goes over the
    /// tunnel from then on (3.3.5.3.1), whatever the client's response lists.
    #[cfg(feature = "egfx")]
    async fn dispatch_egfx_messages(
        &mut self,
        conn: &mut ConnectionState,
        messages: Vec<ironrdp_svc::SvcMessage>,
        writer: &mut impl FramedWrite,
        user_channel_id: u16,
        message_channel_id: Option<u16>,
        udp_transport: Option<&multitransport::UdpTransportHandle>,
    ) -> ServerResult<()> {
        let drdynvc_channel_id = conn
            .get_channel_id_by_type::<dvc::DrdynvcServer>()
            .ok_or_else(|| ServerError::channel("DRDYNVC channel not found"))?;

        let mut udp_route = None;

        // `conn.udp_migration_allowed` gates the Soft-Sync Request itself
        // (`request_reliable_udp` below): MS-RDPEDYC 3.1.5.3/3.3.5.3.1 forbid
        // it unless both peers negotiated SOFT_SYNC_TCP_TO_UDP and a
        // successful Initiate Multitransport Response was actually received,
        // neither of which the sideband transport's own handshake succeeding
        // (`udp_transport.is_some()`) establishes on its own.
        let mut newly_on_udp = None;
        if conn.udp_migration_allowed
            && let Some(udp_transport) = udp_transport
            && let Some(drdynvc) = conn.get_svc_processor::<dvc::DrdynvcServer>()
        {
            let Some(egfx_dvc_id) = crate::gfx::egfx_channel_id(drdynvc) else {
                trace!("EGFX channel not open yet, staying on TCP");
                return self
                    .write_egfx_over_tcp(
                        conn,
                        messages,
                        writer,
                        drdynvc_channel_id,
                        user_channel_id,
                        message_channel_id,
                    )
                    .await;
            };

            // First time EGFX has data to send after the tunnel exists: ask
            // to migrate it. "Already requested" (a previous batch already
            // asked) and "channel not open" (raced with the client closing
            // it) are both expected steady-state outcomes here, not errors.
            match drdynvc.request_reliable_udp(vec![egfx_dvc_id]) {
                Ok(request) => {
                    let data = server_encode_svc_messages(vec![request], drdynvc_channel_id, user_channel_id)
                        .map_err(ServerError::encode)?;
                    writer
                        .write_all(&data)
                        .await
                        .map_err(|e| ServerError::io("write_all", e))?;
                    debug!(
                        egfx_dvc_id,
                        "Soft-Sync request sent, asking to move EGFX to reliable UDP"
                    );
                }
                Err(error) => trace!(%error, "No Soft-Sync request sent"),
            }

            // From the request on, not from the client's response: The request
            // carries SOFT_SYNC_TCP_FLUSHED, "no more data will be sent over
            // TCP for the specified DVCs" (MS-RDPEDYC 2.2.5.1), and the server
            // MUST keep using the tunnel it named immediately after sending it
            // (3.3.5.3.1). The client does not read the tunnel until the
            // request has arrived (3.2.5.3.1), so data that overtakes it waits.
            if drdynvc.tunnel_for_outgoing_channel(egfx_dvc_id) == Some(dvc::pdu::SoftSyncTunnelType::RELIABLE_UDP) {
                udp_route = Some(udp_transport);
                if !conn.egfx_on_udp {
                    newly_on_udp = Some(egfx_dvc_id);
                }
            }
        }
        if let Some(egfx_dvc_id) = newly_on_udp {
            conn.egfx_on_udp = true;
            debug!(egfx_dvc_id, "EGFX is now sent over the UDP transport");
        }

        if let Some(udp_transport) = udp_route {
            // Boxed to keep `run`'s future under `clippy::large_futures`.
            return Box::pin(self.write_egfx_over_udp(conn, messages, udp_transport)).await;
        }
        self.write_egfx_over_tcp(
            conn,
            messages,
            writer,
            drdynvc_channel_id,
            user_channel_id,
            message_channel_id,
        )
        .await
    }

    /// Sends EGFX messages over the UDP tunnel, one Tunnel Data PDU each.
    ///
    /// A batch large enough to measure is bracketed as on TCP (see
    /// [`Self::write_egfx_over_tcp`]), except that Start and Stop travel in
    /// RDP_TUNNEL_SUBHEADERs rather than on the MCS message channel
    /// ([MS-RDPBCGR] 1.3.9): The client counts the bytes that arrive on the
    /// transport carrying Start, and the graphics are no longer on TCP. Each
    /// goes in a PDU with no data of its own, so the count is exactly the
    /// graphics payloads between them whichever way the client orders a
    /// PDU's sub-headers and data.
    #[cfg(feature = "egfx")]
    async fn write_egfx_over_udp(
        &mut self,
        conn: &mut ConnectionState,
        messages: Vec<ironrdp_svc::SvcMessage>,
        udp_transport: &multitransport::UdpTransportHandle,
    ) -> ServerResult<()> {
        let payloads = messages
            .iter()
            .map(ironrdp_svc::SvcMessage::encode_unframed_pdu)
            .collect::<Result<Vec<_>, _>>()
            .map_err(ServerError::encode)?;
        let len = payloads.iter().map(Vec::len).sum();

        let start = conn
            .autodetect
            .as_mut()
            .and_then(|ad| ad.begin_bandwidth_measure(len, monotonic_now_ms()));
        let bracketed = start.is_some();
        if let Some(start) = start {
            trace!(len, "Bracketing a UDP graphics write for a bandwidth measurement");
            udp_transport.send_message(autodetect_sub_header(&start)?).await;
        }
        for payload in payloads {
            udp_transport.send(payload).await;
        }
        if bracketed
            && let Some(stop) = conn
                .autodetect
                .as_mut()
                .and_then(AutoDetectManager::end_bandwidth_measure)
        {
            udp_transport.send_message(autodetect_sub_header(&stop)?).await;
        }
        Ok(())
    }

    #[cfg(feature = "egfx")]
    async fn write_egfx_over_tcp(
        &mut self,
        conn: &mut ConnectionState,
        messages: Vec<ironrdp_svc::SvcMessage>,
        writer: &mut impl FramedWrite,
        drdynvc_channel_id: u16,
        user_channel_id: u16,
        message_channel_id: Option<u16>,
    ) -> ServerResult<()> {
        let data =
            server_encode_svc_messages(messages, drdynvc_channel_id, user_channel_id).map_err(ServerError::encode)?;

        // Measure bandwidth across this write when it is large enough to
        // say something about the link: Start, the graphics data and Stop
        // go out back to back on the same stream, so the client times a
        // burst rather than whatever idle stretch a fixed window happens
        // to span.
        if let (Some(ad), Some(message_channel_id)) = (conn.autodetect.as_mut(), message_channel_id)
            && let Some(start) = ad.begin_bandwidth_measure(data.len(), monotonic_now_ms())
        {
            let start = encode_autodetect_request(start, message_channel_id, user_channel_id)?;
            writer
                .write_all(&start)
                .await
                .map_err(|e| ServerError::io("write_all", e))?;
        }
        writer
            .write_all(&data)
            .await
            .map_err(|e| ServerError::io("write_all", e))?;
        // Only a bracket this write opened is still pending here, so the manager
        // returns a Stop for exactly that one, and `None` when no Start was sent.
        if let Some(message_channel_id) = message_channel_id
            && let Some(stop) = conn
                .autodetect
                .as_mut()
                .and_then(AutoDetectManager::end_bandwidth_measure)
        {
            let stop = encode_autodetect_request(stop, message_channel_id, user_channel_id)?;
            writer
                .write_all(&stop)
                .await
                .map_err(|e| ServerError::io("write_all", e))?;
        }
        Ok(())
    }

    /// Writes DRDYNVC output, sending the data of any channel the Soft-Sync
    /// request moved over the tunnel and everything else over TCP.
    ///
    /// Once the request is sent the server MUST keep using the tunnel it named
    /// for those channels (MS-RDPEDYC 3.3.5.3.1), and that covers a channel's
    /// replies to the client as well as data the server sends unprompted.
    /// Without a live tunnel everything goes over TCP.
    async fn write_drdynvc_output(
        &mut self,
        conn: &mut ConnectionState,
        messages: Vec<ironrdp_svc::SvcMessage>,
        writer: &mut impl FramedWrite,
        drdynvc_channel_id: u16,
        user_channel_id: u16,
        udp_transport: Option<&multitransport::UdpTransportHandle>,
    ) -> ServerResult<()> {
        let mut over_tcp = Vec::with_capacity(messages.len());
        match (udp_transport, conn.get_svc_processor::<dvc::DrdynvcServer>()) {
            (Some(udp_transport), Some(drdynvc)) => {
                for message in messages {
                    let payload = message.encode_unframed_pdu().map_err(ServerError::encode)?;
                    let tunneled = match decode::<dvc::pdu::DrdynvcServerPdu>(&payload) {
                        Ok(dvc::pdu::DrdynvcServerPdu::Data(data)) => {
                            drdynvc.tunnel_for_outgoing_channel(data.channel_id())
                                == Some(dvc::pdu::SoftSyncTunnelType::RELIABLE_UDP)
                        }
                        _ => false,
                    };
                    if tunneled {
                        udp_transport.send(payload).await;
                    } else {
                        over_tcp.push(message);
                    }
                }
            }
            _ => over_tcp = messages,
        }

        if over_tcp.is_empty() {
            return Ok(());
        }
        let data =
            server_encode_svc_messages(over_tcp, drdynvc_channel_id, user_channel_id).map_err(ServerError::encode)?;
        writer
            .write_all(&data)
            .await
            .map_err(|e| ServerError::io("write drdynvc output", e))?;
        Ok(())
    }

    /// Feeds tunnel payloads held back by [`Self::dispatch_udp_tunnel_payload`]
    /// through, in arrival order, once the Soft-Sync response they were
    /// waiting on has been processed.
    async fn replay_early_tunnel_payloads(
        &mut self,
        conn: &mut ConnectionState,
        writer: &mut impl FramedWrite,
        user_channel_id: u16,
        udp_transport: Option<&multitransport::UdpTransportHandle>,
    ) -> ServerResult<()> {
        if conn.early_tunnel_payloads.is_empty()
            || !conn
                .get_svc_processor::<dvc::DrdynvcServer>()
                .is_some_and(|drdynvc| drdynvc.soft_sync_response_received())
        {
            return Ok(());
        }
        debug!(
            count = conn.early_tunnel_payloads.len(),
            "Soft-Sync response received, processing the tunnel payloads held for it"
        );
        while let Some(payload) = conn.early_tunnel_payloads.pop_front() {
            self.dispatch_udp_tunnel_payload(conn, &payload, writer, user_channel_id, udp_transport)
                .await?;
        }
        Ok(())
    }

    /// Records the auto-detect responses carried in sub-headers on the UDP
    /// tunnel, where the client may return Bandwidth Measure Results for a
    /// measurement started there ([MS-RDPBCGR] 1.3.9). Results that come
    /// back on the message channel instead go through
    /// [`Self::handle_message_channel_data`].
    fn record_tunnel_sub_headers(conn: &mut ConnectionState, sub_headers: &[ironrdp_rdpemt::TunnelSubHeader]) {
        for response in sub_headers.iter().filter_map(autodetect_response_from_sub_header) {
            Self::record_autodetect_response(conn, &response);
        }
    }

    /// Decodes and dispatches one payload received over the sideband UDP
    /// transport (MS-RDPEMT TunnelData): raw DRDYNVC bytes, per
    /// [`dvc::DrdynvcServer::process_tunnel`]. Any resulting response
    /// messages go back over TCP; only outgoing EGFX frames are proactively
    /// routed onto the tunnel in this integration (see
    /// [`Self::dispatch_egfx_messages`]).
    ///
    /// A malformed or unexpected tunnel payload is logged and dropped rather
    /// than treated as a connection error: nothing about the primary TCP
    /// session depends on the sideband transport's correctness.
    async fn dispatch_udp_tunnel_payload(
        &mut self,
        conn: &mut ConnectionState,
        payload: &[u8],
        writer: &mut impl FramedWrite,
        user_channel_id: u16,
        udp_transport: Option<&multitransport::UdpTransportHandle>,
    ) -> ServerResult<RunState> {
        // A single guard: `get_channel_id_by_type` and `get_svc_processor`
        // both key off the same registered processor's `TypeId`, so one
        // succeeding without the other would mean `static_channels` itself
        // is inconsistent, not a case this function can meaningfully
        // distinguish from "no drdynvc channel".
        let (Some(drdynvc_channel_id), Some(drdynvc)) = (
            conn.get_channel_id_by_type::<dvc::DrdynvcServer>(),
            conn.get_svc_processor::<dvc::DrdynvcServer>(),
        ) else {
            warn!("No drdynvc channel, dropping UDP tunnel payload");
            return Ok(RunState::Continue);
        };

        // MS-RDPEDYC 3.3.5.3.2: the server MUST NOT begin to read tunnel data
        // until the Soft-Sync response has arrived. Hold it rather than drop
        // it; `replay_early_tunnel_payloads` feeds it through once the
        // response is in.
        if drdynvc.soft_sync_awaiting_response() {
            if conn.early_tunnel_payloads.len() < MAX_EARLY_TUNNEL_PAYLOADS {
                trace!(
                    len = payload.len(),
                    "Holding a tunnel payload until the Soft-Sync response arrives"
                );
                conn.early_tunnel_payloads.push_back(payload.to_vec());
            } else {
                warn!("Too many tunnel payloads ahead of the Soft-Sync response, dropping one");
            }
            return Ok(RunState::Continue);
        }

        let messages = match drdynvc.process_tunnel(payload) {
            Ok(messages) => messages,
            Err(error) => {
                warn!(%error, "Failed to process UDP tunnel payload, dropping it");
                return Ok(RunState::Continue);
            }
        };

        if messages.is_empty() {
            return Ok(RunState::Continue);
        }

        self.write_drdynvc_output(
            conn,
            messages,
            writer,
            drdynvc_channel_id,
            user_channel_id,
            udp_transport,
        )
        .await?;

        Ok(RunState::Continue)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "private per-connection entry point; the parameters are the connection's negotiated identifiers"
    )]
    async fn client_loop<R, W>(
        &mut self,
        conn: &mut ConnectionState,
        reader: &mut Framed<R>,
        writer: &mut Framed<W>,
        io_channel_id: u16,
        user_channel_id: u16,
        message_channel_id: Option<u16>,
        mut encoder: UpdateEncoder,
        udp_transport: Rc<RefCell<Option<multitransport::UdpTransportHandle>>>,
        pending_udp_accept: Option<task::JoinHandle<Option<multitransport::UdpTransportHandle>>>,
    ) -> ServerResult<RunState>
    where
        R: FramedRead,
        W: FramedWrite,
    {
        debug!("Starting client loop");
        let heartbeat = if conn.client_supports_heartbeat {
            self.heartbeat
        } else {
            None
        };
        let mut display_updates = self.display.lock().await.updates(conn.display_context()).await?;
        let mut writer = SharedWriter::new(writer);
        let mut display_writer = writer.clone();
        let mut event_writer = writer.clone();
        let mut auto_reconnect_writer = writer.clone();
        let mut heartbeat_writer = writer.clone();
        let mut udp_tunnel_writer = writer.clone();
        let udp_transport_for_events = Rc::clone(&udp_transport);
        let udp_transport_for_pdus = Rc::clone(&udp_transport);
        let mut cliprdr_writer = writer.clone();
        let write_counter = writer.write_counter();
        let ev_receiver = Arc::clone(&self.ev_receiver);
        let s = Rc::new(Mutex::new((self, conn)));

        let this = Rc::clone(&s);
        let dispatch_pdu = async move {
            loop {
                let (action, bytes) = reader.read_pdu().await.map_err(|e| ServerError::io("read pdu", e))?;
                // D8: per-PDU lock-acquisition + dispatch timing. The `this`
                // mutex is shared with dispatch_events; when an outbound
                // event batch is in flight, this lock wait is the latency
                // that a FrameAcknowledge sees before it reaches its
                // handler. Log when the dispatch itself or the lock wait
                // exceeds 50ms.
                let pdu_len = bytes.len();
                let lock_start = Instant::now();
                let mut this = this.lock().await;
                let lock_wait_ms = u64::try_from(lock_start.elapsed().as_millis()).unwrap_or(u64::MAX);

                let dispatch_start = Instant::now();
                let current_udp_transport = udp_transport_for_pdus.borrow().clone();
                let (server, conn) = &mut *this;
                let result = server
                    .dispatch_pdu(
                        conn,
                        action,
                        bytes,
                        &mut writer,
                        io_channel_id,
                        user_channel_id,
                        message_channel_id,
                        current_udp_transport.as_ref(),
                    )
                    .await?;
                let dispatch_ms = u64::try_from(dispatch_start.elapsed().as_millis()).unwrap_or(u64::MAX);

                if lock_wait_ms >= 50 {
                    tracing::warn!(
                        pdu_len,
                        lock_wait_ms,
                        dispatch_ms,
                        "dispatch_pdu delayed acquiring this.lock, contended with outbound batch (dispatch_events/dispatch_display)"
                    );
                } else if dispatch_ms >= 50 {
                    tracing::warn!(
                        pdu_len,
                        lock_wait_ms,
                        dispatch_ms,
                        "dispatch_pdu ran long after acquiring this.lock immediately, handler or runtime stall, not lock contention"
                    );
                } else {
                    tracing::debug!(pdu_len, lock_wait_ms, dispatch_ms, "dispatch_pdu");
                }

                match result {
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

                // D7: per-batch dispatch_events timing. The events Vec can
                // grow up to 100+ entries; dispatch_server_events holds the
                // `this` mutex AND the SharedWriter mutex for the full
                // batch. Log batch size + total dispatch time so operators
                // can see when an event batch ties up both locks.
                let batch_size = events.len();
                let lock_start = Instant::now();
                let mut this = this.lock().await;
                let lock_wait_ms = u64::try_from(lock_start.elapsed().as_millis()).unwrap_or(u64::MAX);

                let dispatch_start = Instant::now();
                // Cloned out of the cell before the call, since `dispatch_server_events`
                // is async and this must not hold the `RefCell` borrow across
                // an await point. `UdpTransportHandle` is cheap to clone (see
                // its own doc comment).
                let current_udp_transport = udp_transport_for_events.borrow().clone();
                let (server, conn) = &mut *this;
                let result = server
                    .dispatch_server_events(
                        conn,
                        &mut events,
                        &mut event_writer,
                        io_channel_id,
                        user_channel_id,
                        message_channel_id,
                        current_udp_transport.as_ref(),
                    )
                    .await?;
                let dispatch_ms = u64::try_from(dispatch_start.elapsed().as_millis()).unwrap_or(u64::MAX);

                if lock_wait_ms >= 50 || dispatch_ms >= 100 {
                    tracing::warn!(
                        batch_size,
                        lock_wait_ms,
                        dispatch_ms,
                        "dispatch_events batch stalled, long write or lock contention"
                    );
                } else if batch_size > 1 {
                    tracing::debug!(batch_size, lock_wait_ms, dispatch_ms, "dispatch_events batch");
                }

                match result {
                    RunState::Continue => continue,
                    state => break Ok(state),
                }
            }
        };

        let this = Rc::clone(&s);
        let refresh_auto_reconnect_cookie = async move {
            let mut interval = tokio::time::interval(AUTO_RECONNECT_COOKIE_UPDATE_INTERVAL);
            interval.tick().await;

            loop {
                interval.tick().await;
                let mut this = this.lock().await;
                let (server, conn) = &mut *this;
                server
                    .rotate_auto_reconnect_cookie(conn, &mut auto_reconnect_writer, io_channel_id, user_channel_id)
                    .await?;
            }
        };

        let send_heartbeats = async move {
            let (Some(config), Some(message_channel_id)) = (heartbeat, message_channel_id) else {
                return core::future::pending::<ServerResult<RunState>>().await;
            };
            // 2.2.16.1: `period` is in seconds. A zero period is meaningless
            // (and would panic tokio's interval), so it is bumped to one.
            let period = Duration::from_secs(u64::from(config.period_secs.max(1)));
            let mut interval = tokio::time::interval(period);
            // A stalled write (TCP back-pressure) can hold this future past
            // several tick deadlines; Burst (the default) would then fire the
            // missed ticks back-to-back and emit a run of consecutive
            // heartbeats on an otherwise idle link. Skip fires at the next
            // period boundary instead.
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await; // first tick completes immediately; real waits start below

            let mut writes_at_last_tick = write_counter.load(Ordering::Relaxed);
            loop {
                interval.tick().await;
                let writes_now = write_counter.load(Ordering::Relaxed);
                if writes_now != writes_at_last_tick {
                    // 2.2.16.1: heartbeats SHOULD only be sent when no other
                    // PDU went out in the interval; ordinary traffic doubles
                    // as the liveness signal.
                    writes_at_last_tick = writes_now;
                    continue;
                }
                let data = encode_heartbeat(&config, message_channel_id, user_channel_id)?;
                heartbeat_writer
                    .write_all(&data)
                    .await
                    .map_err(|e| ServerError::io("send heartbeat", e))?;
                // Re-read so the heartbeat's own write does not read as
                // foreign traffic on the next tick.
                writes_at_last_tick = write_counter.load(Ordering::Relaxed);
            }
        };

        let this = Rc::clone(&s);
        let dispatch_udp_tunnel = async move {
            // Only the pass of `client_loop` that received a fresh
            // `pending_udp_accept` waits on it; every other future in this
            // `select!` is already dispatching over TCP while this resolves,
            // so the session never stalls on it. The accepted transport (if
            // any) is stashed in the shared cell so `dispatch_events`, running
            // concurrently, can start using it as soon as it lands too.
            //
            // If a Deactivation-Reactivation cycle drops this future while
            // `handle` is still unresolved, the background accept task (and
            // whatever socket/handshake it is mid-negotiation on) is orphaned:
            // Its eventual result has nowhere left to be delivered, and this
            // session continues TCP-only for the rest of its lifetime. That is
            // an accepted narrow-window tradeoff; the alternative is
            // persisting in-flight `JoinHandle`s across reactivation, which
            // this integration does not attempt. The orphaned task also keeps
            // `udp_bind_addr` bound for up to `UDP_ACCEPT_TIMEOUT`, so a NEXT
            // connection's own bind attempt during that window can collide
            // with it too, not only a concurrently preempted session's (see
            // `multitransport::accept`'s own doc comment on that failure
            // mode); it degrades the same way, gracefully, to TCP-only.
            if let Some(handle) = pending_udp_accept {
                match handle.await {
                    Ok(Some(transport)) => {
                        *udp_transport.borrow_mut() = Some(transport);
                    }
                    Ok(None) => {
                        debug!("UDP transport did not come up, continuing TCP-only for the rest of the session");
                    }
                    Err(error) if error.is_cancelled() => {
                        debug!(
                            "UDP transport accept stopped after the client declined, continuing TCP-only for the rest of the session"
                        );
                    }
                    Err(error) => {
                        warn!(%error, "UDP transport accept task panicked, continuing TCP-only for the rest of the session");
                    }
                }
            }

            // This future is the cell's only writer, so the handle cannot
            // change under the loop below.
            let current = udp_transport.borrow().clone();
            let Some(transport) = current else {
                return core::future::pending::<ServerResult<RunState>>().await;
            };
            loop {
                let Some(message) = transport.recv().await else {
                    // Soft-Sync only moves channels onto a tunnel (MS-RDPEDYC
                    // 2.2.5.1 has no TCP tunnel type), its request promised
                    // no more of their data over TCP (SOFT_SYNC_TCP_FLUSHED),
                    // and the tunnel lasts as long as the connection
                    // (MS-RDPEMT 1.3.3). A client whose channels moved has
                    // nowhere left to read them, so end the connection and let
                    // it reconnect rather than keep a session it cannot draw.
                    let (_, conn) = &mut *this.lock().await;
                    if conn.egfx_on_udp {
                        warn!("UDP transport lost with EGFX on it, ending the connection");
                        return Err(ServerError::reason(
                            "UDP transport",
                            "lost with dynamic channels moved onto it",
                        ));
                    }
                    debug!("UDP transport closed, continuing TCP-only for the rest of the session");
                    // Without this, `dispatch_egfx_messages` would keep seeing
                    // `Some(dead_handle)` here and stay on the UDP branch,
                    // silently dropping every future EGFX batch instead of
                    // actually falling back to TCP as this log claims.
                    *udp_transport.borrow_mut() = None;
                    return core::future::pending::<ServerResult<RunState>>().await;
                };
                let mut this = this.lock().await;
                let (server, conn) = &mut *this;
                Self::record_tunnel_sub_headers(conn, &message.sub_headers);
                if message.data.is_empty() {
                    continue;
                }
                let result = server
                    .dispatch_udp_tunnel_payload(
                        conn,
                        &message.data,
                        &mut udp_tunnel_writer,
                        user_channel_id,
                        Some(&transport),
                    )
                    .await?;
                match result {
                    RunState::Continue => continue,
                    state => break Ok(state),
                }
            }
        };

        let this = Rc::clone(&s);
        let drive_cliprdr_timeouts = async move {
            let mut interval = tokio::time::interval(CLIPRDR_DRIVE_TIMEOUTS_INTERVAL);
            // A stalled write can hold this future past several tick deadlines;
            // Burst (the default) would then fire the missed ticks back-to-back
            // for a sweep that is idempotent anyway.
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await; // first tick completes immediately

            loop {
                interval.tick().await;
                let mut this = this.lock().await;
                let (server, conn) = &mut *this;
                server
                    .drive_cliprdr_timeouts(conn, &mut cliprdr_writer, user_channel_id)
                    .await?;
            }
        };

        let state = tokio::select!(
            state = dispatch_pdu => state,
            state = dispatch_display => state,
            state = dispatch_events => state,
            state = refresh_auto_reconnect_cookie => state,
            state = send_heartbeats => state,
            state = dispatch_udp_tunnel => state,
            state = drive_cliprdr_timeouts => state,
        );

        debug!("End of client loop: {state:?}");
        state
    }

    async fn prepare_authenticated_connection(
        &mut self,
        received_credentials: Option<ReceivedCredentials>,
    ) -> Result<(), ConnectorError> {
        let mut handler = ServerCredentialsHandler {
            validator: self.credential_validator.clone(),
            require_authenticated: self.connection_binder.is_some(),
            ..ServerCredentialsHandler::default()
        };
        handler.handle_credentials(received_credentials).await?;
        *self
            .pending_authenticated_credentials
            .lock()
            .expect("authenticated credentials lock poisoned") = handler.authenticated_credentials;
        Ok(())
    }

    async fn client_accepted<R, W>(
        &mut self,
        conn: &mut ConnectionState,
        reader: &mut Framed<R>,
        writer: &mut Framed<W>,
        (result, acceptor): (AcceptorResult, &Acceptor),
        udp_transport: Rc<RefCell<Option<multitransport::UdpTransportHandle>>>,
        pending_udp_accept: Option<task::JoinHandle<Option<multitransport::UdpTransportHandle>>>,
    ) -> ServerResult<RunState>
    where
        R: FramedRead,
        W: FramedWrite,
    {
        debug!("Client accepted");

        let is_auto_reconnect = if let Some(reconnect) = result.auto_reconnect.as_ref() {
            if !self.verify_auto_reconnect_cookie(reconnect) {
                warn!("Auto-reconnect cookie validation rejected");
                send_access_denied(acceptor, writer).await?;
                return Err(ServerError::reason("auto-reconnect validation", "cookie rejected"));
            }

            if self.connection_binder.is_some() {
                warn!("Auto-reconnect cannot restore a credential-bound connection safely");
                send_access_denied(acceptor, writer).await?;
                return Err(ServerError::reason(
                    "auto-reconnect validation",
                    "unsupported with a connection binder",
                ));
            }

            debug!("Auto-reconnect cookie validation accepted");
            true
        } else {
            false
        };

        if result.reactivation {
            debug!("Reactivation reuses the authenticated connection binding");
        } else if !is_auto_reconnect
            && (self.credential_validator.is_some() || self.connection_binder.is_some())
            && self
                .pending_authenticated_credentials
                .lock()
                .expect("authenticated credentials lock poisoned")
                .is_none()
        {
            warn!("Initial acceptance reached activation without prepared credentials");
            send_access_denied(acceptor, writer).await?;
            return Err(ServerError::reason(
                "credential validation",
                "credentials were not prepared before activation",
            ));
        }

        if !result.reactivation {
            with_connection_handler(self.connection_handler.as_ref(), |h| {
                h.on_connection_info(&ConnectionInfo {
                    keyboard_layout: result.keyboard_layout,
                    keyboard_type: result.keyboard_type,
                    ime_file_name: result.ime_file_name.clone(),
                    auto_reconnect: is_auto_reconnect,
                    client_monitors: result.client_monitors,
                    routing_token: result.routing_token.clone(),
                    redirected_session_id: result
                        .client_cluster_data
                        .as_ref()
                        .filter(|cluster| {
                            cluster
                                .flags
                                .contains(ironrdp_pdu::gcc::RedirectionFlags::REDIRECTED_SESSION_FIELD_VALID)
                        })
                        .map(|cluster| cluster.redirected_session_id),
                    password_cookie: result.password_cookie.clone(),
                });
            });
        }

        #[cfg(feature = "egfx")]
        if let Some(gfx_handle) = conn.gfx_handle.as_ref() {
            let mut server = gfx_handle
                .lock()
                .map_err(|_| ServerError::reason("graphics server", "GfxServerHandle mutex poisoned"))?;
            let core_limit = if self.egfx_core_frame_ack_limit {
                client_core_frame_ack_limit(&result.capabilities)
            } else {
                None
            };
            server.set_client_frame_ack_limit(core_limit);
        }
        conn.static_channels = result.static_channels;
        conn.client_supports_heartbeat = result
            .client_early_capability_flags
            .contains(ironrdp_pdu::gcc::ClientEarlyCapabilityFlags::SUPPORT_HEART_BEAT_PDU);
        conn.client_supports_errinfo = result
            .client_early_capability_flags
            .contains(ironrdp_pdu::gcc::ClientEarlyCapabilityFlags::SUPPORT_ERR_INFO_PDU);
        if !result.reactivation {
            for (_channel_key, channel, channel_id) in conn.static_channels.iter_by_key_mut() {
                debug!(?channel, ?channel_id, "Start");
                let Some(channel_id) = channel_id else {
                    continue;
                };
                let svc_responses = channel.start().map_err_kind("svc start", ServerErrorKind::Pdu)?;
                let response = server_encode_svc_messages(svc_responses, channel_id, result.user_channel_id)
                    .map_err(ServerError::encode)?;
                writer
                    .write_all(&response)
                    .await
                    .map_err(|e| ServerError::io("write svc response", e))?;
            }
        }

        let mut update_codecs = UpdateEncoderCodecs::new();
        let mut surface_flags = CmdFlags::empty();
        let mut pointer_cache_size: u16 = 0;
        // Absence means the client did not send a Large Pointer Capability Set at all,
        // which per MS-RDPBCGR 2.2.7.2.7 leaves the pointer size ceiling at 32x32 (the
        // base Color/New Pointer Update limit with no large-pointer flags set).
        let mut large_pointer_flags = LargePointerSupportFlags::empty();
        for c in result.capabilities {
            match c {
                CapabilitySet::General(c) => {
                    let fastpath = c.extra_flags.contains(GeneralExtraFlags::FASTPATH_OUTPUT_SUPPORTED);
                    if !fastpath {
                        return Err(ServerError::unsupported("Fastpath output"));
                    }
                }
                CapabilitySet::Bitmap(b) => {
                    if !b.desktop_resize_flag {
                        debug!("Desktop resize is not supported by the client");
                    }

                    let client_size = DesktopSize {
                        width: b.desktop_width,
                        height: b.desktop_height,
                    };
                    let display_size = self.display.lock().await.request_initial_size(client_size).await;

                    // It's problematic when the client didn't resize, as we send bitmap updates that don't fit.
                    // The client will likely drop the connection.
                    if (!b.desktop_resize_flag && client_size != display_size)
                        || client_size.width < display_size.width
                        || client_size.height < display_size.height
                    {
                        // TODO: we may have different behaviour instead, such as clipping or scaling?
                        warn!(?client_size, ?display_size, "Client size differs from the server size");
                    }
                }
                CapabilitySet::SurfaceCommands(c) => {
                    surface_flags = c.flags;
                }
                CapabilitySet::BitmapCodecs(BitmapCodecs(codecs)) => {
                    // FIXME: The encoder operates in image mode only.
                    //
                    // See [MS-RDPRFX] 3.1.1.1 "State Machine" for the
                    // implementation of the video mode, which allows
                    // skipping the header for each image.
                    //
                    // We should distinguish parameters for both modes.
                    if let Some(remotefx) = pick_remotefx_codec(
                        self.opts.remotefx_entropy_coder,
                        &codecs,
                        self.opts.has_remote_fx(),
                        self.opts.has_image_remote_fx(),
                    ) {
                        update_codecs.set_remotefx_codec(Some(remotefx));
                        update_codecs.set_remotefx_quant(self.opts.remotefx_quant.clone());
                    }

                    for codec in codecs {
                        match codec.property {
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
                CapabilitySet::Pointer(p) => {
                    // MS-RDPBCGR 2.2.7.1.5: pointerCacheSize is the client's advertised cache
                    // size for the New Pointer Update specifically (colorPointerCacheSize is
                    // the separate, always-supported Color Pointer Update cache). A zero or
                    // absent pointerCacheSize means the client did not advertise New Pointer
                    // Update support at all, so `UpdateEncoder` must not emit RGBAPointer, and
                    // must not reference a cache slot via CachedPointer either, since nothing
                    // else in this crate populates that cache via the Color Pointer Update.
                    pointer_cache_size = p.pointer_cache_size;
                }
                CapabilitySet::LargePointer(lp) => {
                    // MS-RDPBCGR 2.2.7.2.7: LARGE_POINTER_FLAG_96x96 raises the Color/New
                    // Pointer Update ceiling from 32x32 to 96x96; LARGE_POINTER_FLAG_384x384
                    // additionally unlocks the dedicated Fast-Path Large Pointer Update, up to
                    // 384x384. `UpdateEncoder` uses these flags to decide which pointer
                    // updates it can send at all, and at what size.
                    large_pointer_flags = lp.flags;
                }
                _ => {}
            }
        }

        if !result.input_events.is_empty() {
            debug!("Handling input event backlog from acceptor sequence");
            // Set on a reactivation pass, where EGFX may already be on the tunnel.
            let current_udp_transport = udp_transport.borrow().clone();
            self.handle_input_backlog(
                conn,
                writer,
                result.io_channel_id,
                result.user_channel_id,
                result.message_channel_id,
                result.input_events,
                current_udp_transport.as_ref(),
            )
            .await?;
        }

        let desktop_size = self.display.lock().await.size().await;
        let encoder = UpdateEncoder::new(
            desktop_size,
            surface_flags,
            update_codecs,
            self.opts.max_request_size,
            pointer_cache_size,
            large_pointer_flags,
        )?;

        // By default every connection gets a cookie at activation. On request, only one that came
        // back with a verified cookie does.
        if !self.auto_reconnect_on_request || is_auto_reconnect {
            self.send_next_auto_reconnect_cookie(conn, writer, result.io_channel_id, result.user_channel_id)
                .await?;
        }

        let pending_udp_accept =
            Self::drop_declined_udp_accept(pending_udp_accept, result.multitransport_response_success);
        conn.pending_udp_accept_abort = pending_udp_accept.as_ref().map(task::JoinHandle::abort_handle);

        // See `udp_migration_allowed`: a successful response that arrives
        // after this point enables migration from the message-channel handler.
        // Only ever raised here, never lowered: a deactivation-reactivation
        // pass lands here again without repeating the multitransport exchange,
        // and must not take back a migration the session may already be using.
        conn.soft_sync_negotiated |= result
            .multitransport_flags
            .contains(ironrdp_pdu::gcc::MultiTransportFlags::SOFT_SYNC_TCP_TO_UDP);
        conn.udp_migration_allowed |= conn.soft_sync_negotiated && result.multitransport_response_success == Some(true);

        let state = self
            .client_loop(
                conn,
                reader,
                writer,
                result.io_channel_id,
                result.user_channel_id,
                result.message_channel_id,
                encoder,
                udp_transport,
                pending_udp_accept,
            )
            .await?;

        Ok(state)
    }

    /// A failure hrResponse (E_ABORT) means the client could not establish
    /// the multitransport connection (MS-RDPBCGR 2.2.15.2), so no UDP
    /// handshake is coming. Stop the accept now instead of holding the
    /// socket until `multitransport::UDP_ACCEPT_TIMEOUT` and then reporting a
    /// timeout. No response at all leaves it running: the client may still be
    /// bringing UDP up.
    fn drop_declined_udp_accept<T>(
        pending_udp_accept: Option<task::JoinHandle<T>>,
        multitransport_response_success: Option<bool>,
    ) -> Option<task::JoinHandle<T>> {
        match pending_udp_accept {
            Some(handle) if multitransport_response_success == Some(false) => {
                handle.abort();
                debug!("Client could not establish the UDP multitransport connection, continuing TCP-only");
                None
            }
            other => other,
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "private per-connection dispatch; the parameters are the connection's negotiated identifiers and transports"
    )]
    async fn handle_input_backlog(
        &mut self,
        conn: &mut ConnectionState,
        writer: &mut impl FramedWrite,
        io_channel_id: u16,
        user_channel_id: u16,
        message_channel_id: Option<u16>,
        frames: Vec<Vec<u8>>,
        udp_transport: Option<&multitransport::UdpTransportHandle>,
    ) -> ServerResult<()> {
        for frame in frames {
            match Action::from_fp_output_header(frame[0]) {
                Ok(Action::FastPath) => {
                    let input = decode(&frame).map_err(ServerError::decode)?;
                    self.handle_fastpath(input).await;
                }

                Ok(Action::X224) => {
                    let _ = self
                        .handle_x224(
                            conn,
                            writer,
                            io_channel_id,
                            user_channel_id,
                            message_channel_id,
                            &frame,
                            udp_transport,
                        )
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
                    if !self.advanced_input_active.load(Ordering::Acquire) {
                        handler.mouse(mouse.into());
                    }
                }

                FastPathInputEvent::MouseEventEx(mouse) => {
                    if !self.advanced_input_active.load(Ordering::Acquire) {
                        handler.mouse(mouse.into());
                    }
                }

                FastPathInputEvent::MouseEventRel(mouse) => {
                    if !self.advanced_input_active.load(Ordering::Acquire) {
                        handler.mouse(mouse.into());
                    }
                }

                FastPathInputEvent::QoeEvent(quality) => {
                    warn!("Received QoE: {}", quality);
                }
            }
        }
    }

    async fn handle_io_channel_data(
        &mut self,
        conn: &mut ConnectionState,
        data: SendDataRequest<'_>,
    ) -> ServerResult<bool> {
        let control: rdp::headers::ShareControlHeader = decode(data.user_data.as_ref()).map_err(ServerError::decode)?;

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
                    conn.display_suppressed.store(suppress, Ordering::Relaxed);
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
                    if conn.display_suppressed.swap(false, Ordering::Relaxed) {
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

    /// Records a client Auto-Detect Response, whether it came on the MCS
    /// message channel or in a sub-header on the UDP tunnel.
    fn record_autodetect_response(conn: &mut ConnectionState, response: &rdp::autodetect::AutoDetectResponse) {
        let Some(ad) = conn.autodetect.as_mut() else {
            return;
        };
        match ad.handle_response(response, monotonic_now_ms()) {
            AutoDetectOutcome::Rtt(rtt_ms) => {
                conn.autodetect_handles.rtt.store(rtt_ms, Ordering::Relaxed);
                // A matched RTT sample always updates the session-lifetime low in the
                // same call (see `handle_response`'s RttResponse arm), so it is available
                // unconditionally here, not just on a new low.
                let baseline_rtt_ms = ad
                    .baseline_rtt_ms()
                    .expect("handle_response just recorded a sample above");
                conn.autodetect_handles
                    .baseline_rtt
                    .store(baseline_rtt_ms, Ordering::Relaxed);
                debug!(
                    rtt_ms,
                    baseline_rtt_ms,
                    seq = response.sequence_number(),
                    "RTT measured"
                );
            }
            AutoDetectOutcome::Bandwidth(Some(bandwidth_kbps)) => {
                conn.autodetect_handles
                    .bandwidth
                    .store(bandwidth_kbps, Ordering::Relaxed);
                conn.autodetect_handles
                    .bandwidth_generation
                    .fetch_add(1, Ordering::Release);
                // Logging the whole response, not just the computed figure: a
                // damage-driven video source makes any single measurement
                // window's byte count wildly bimodal (near-idle vs. a real
                // frame landing in it), so bandwidth_kbps alone reads as
                // noise without the response's time_delta_ms/byte_count
                // alongside it to show why.
                debug!(bandwidth_kbps, ?response, "Bandwidth measured");
            }
            AutoDetectOutcome::Bandwidth(None) => {
                // The manager just cleared its own figure rather than keep
                // reporting a stale one (see `handle_response`'s doc comment);
                // mirror that here so the exposed handle does not disagree.
                conn.autodetect_handles.bandwidth.store(u32::MAX, Ordering::Relaxed);
                conn.autodetect_handles
                    .bandwidth_generation
                    .fetch_add(1, Ordering::Release);
                trace!(
                    seq = response.sequence_number(),
                    "Bandwidth measurement completed without a usable figure"
                );
            }
            AutoDetectOutcome::Unmatched => {
                trace!(seq = response.sequence_number(), "Unmatched auto-detect response");
            }
        }
    }

    fn handle_message_channel_data(conn: &mut ConnectionState, data: SendDataRequest<'_>) {
        match decode::<rdp::message_channel::ClientMessageChannelPdu>(data.user_data.as_ref()) {
            Ok(rdp::message_channel::ClientMessageChannelPdu::AutoDetectResponse(pdu)) => {
                Self::record_autodetect_response(conn, &pdu.response);
            }
            Ok(rdp::message_channel::ClientMessageChannelPdu::MultitransportResponse(pdu)) => {
                // A failure code is not a decode error: the client is correctly reporting
                // that the sideband UDP attempt failed, and the session continues on the
                // main transport either way.
                debug!(
                    request_id = pdu.request_id,
                    success = pdu.is_success(),
                    hr_response = format!("{:#x}", pdu.hr_response),
                    "Received Initiate Multitransport Response"
                );
                // E_ABORT: the client could not establish the multitransport
                // connection (MS-RDPBCGR 2.2.15.2), so no UDP handshake is coming.
                if !pdu.is_success()
                    && let Some(abort) = conn.pending_udp_accept_abort.take()
                {
                    abort.abort();
                    debug!("Client could not establish the UDP multitransport connection, continuing TCP-only");
                }
                // A success after finalization, the usual order with mstsc,
                // completes the condition finalization could not see (see
                // `udp_migration_allowed`), so EGFX can migrate from here on.
                if pdu.is_success() && conn.soft_sync_negotiated && !conn.udp_migration_allowed {
                    conn.udp_migration_allowed = true;
                    debug!("Multitransport confirmed after finalization, EGFX may migrate to UDP");
                }
            }
            Err(error) => {
                warn!(error = format!("{error:#}"), "Unhandled MCS message channel PDU");
            }
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "private per-connection dispatch; the parameters are the connection's negotiated identifiers and transports"
    )]
    async fn handle_x224(
        &mut self,
        conn: &mut ConnectionState,
        writer: &mut impl FramedWrite,
        io_channel_id: u16,
        user_channel_id: u16,
        message_channel_id: Option<u16>,
        frame: &[u8],
        udp_transport: Option<&multitransport::UdpTransportHandle>,
    ) -> ServerResult<bool> {
        let message = decode::<X224<mcs::McsMessage<'_>>>(frame).map_err(ServerError::decode)?;
        match message.0 {
            mcs::McsMessage::SendDataRequest(data) => {
                debug!(
                    initiator_id = data.initiator_id,
                    channel_id = data.channel_id,
                    user_data_len = data.user_data.len(),
                    "McsMessage::SendDataRequest"
                );
                if data.channel_id == io_channel_id {
                    return self.handle_io_channel_data(conn, data).await;
                }

                if message_channel_id == Some(data.channel_id) {
                    Self::handle_message_channel_data(conn, data);
                    return Ok(false);
                }

                if let Some(svc) = conn.static_channels.get_by_channel_id_mut(data.channel_id) {
                    let response_pdus = svc
                        .process(&data.user_data)
                        .map_err_kind("svc process", ServerErrorKind::Pdu)?;
                    if conn.get_channel_id_by_type::<dvc::DrdynvcServer>() == Some(data.channel_id) {
                        self.write_drdynvc_output(
                            conn,
                            response_pdus,
                            writer,
                            data.channel_id,
                            user_channel_id,
                            udp_transport,
                        )
                        .await?;
                        self.replay_early_tunnel_payloads(conn, writer, user_channel_id, udp_transport)
                            .await?;
                    } else {
                        let response = server_encode_svc_messages(response_pdus, data.channel_id, user_channel_id)
                            .map_err(ServerError::encode)?;
                        writer
                            .write_all(&response)
                            .await
                            .map_err(|e| ServerError::io("write svc response", e))?;
                    }
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
                    if !self.advanced_input_active.load(Ordering::Acquire) {
                        handler.mouse(mouse.into());
                    }
                }

                ironrdp_pdu::input::InputEvent::MouseX(mouse) => {
                    if !self.advanced_input_active.load(Ordering::Acquire) {
                        handler.mouse(mouse.into());
                    }
                }

                ironrdp_pdu::input::InputEvent::MouseRel(mouse) => {
                    if !self.advanced_input_active.load(Ordering::Acquire) {
                        handler.mouse(mouse.into());
                    }
                }

                ironrdp_pdu::input::InputEvent::Unused(_) => {}
            }
        }
    }

    async fn accept_finalize<S>(
        &mut self,
        mut framed: TokioFramed<S>,
        mut acceptor: Acceptor,
    ) -> ServerResult<TokioFramed<S>>
    where
        S: AsyncRead + AsyncWrite + Sync + Send + Unpin,
    {
        let mut conn = self.attach_channels(&mut acceptor).await;
        let udp_bind_addr = self
            .opts
            .udp_bind_addr
            .map(|bind| multitransport::sideband_bind_addr(bind, self.connection_local_addr));
        let tls_config = self
            .opts
            .security
            .tls_acceptor()
            .map(|acceptor| Arc::clone(acceptor.config()));
        // Persists across a Deactivation-Reactivation pass of this loop: The
        // sideband transport, once established, is not torn down or
        // re-bootstrapped for a resize (see the acceptor's own doc comment
        // on `MultitransportBootstrapping` regarding reactivation). Shared
        // with `client_loop`, which populates it once `pending_udp_accept`
        // (below) resolves.
        let udp_transport: Rc<RefCell<Option<multitransport::UdpTransportHandle>>> = Rc::new(RefCell::new(None));
        // Set once, by the handler below, the first time the acceptor
        // actually sends a request. Taken (not cloned) when handed to
        // `client_loop`, which awaits it in its own select loop: The full
        // RDPEUDP2 + TLS + RDPEMT handshake this drives can take up to
        // `multitransport::UDP_ACCEPT_TIMEOUT`, and the handler below runs
        // synchronously as part of finalize, so establishing it must never
        // block the RDP handshake finalize itself is driving.
        let mut pending_udp_accept: Option<task::JoinHandle<Option<multitransport::UdpTransportHandle>>> = None;
        loop {
            // Bounded: see `FINALIZE_TIMEOUT`. The bound belongs on THIS call
            // and not on `accept_finalize` itself or its callers — the loop
            // below also runs `client_accepted`, which drives the entire live
            // session, so a timeout hoisted any higher would cap session
            // length. Applying it per pass also gives a
            // deactivation-reactivation its own budget rather than sharing one
            // with the initial handshake.
            //
            // Always the `_with_multitransport` driver rather than branching
            // on whether UDP is configured: when it is not, `acceptor` never
            // has a request to report (`set_multitransport_offer` was never
            // called, see `PendingConnection::new`), so the handler below
            // simply never runs and this is exactly `accept_finalize`'s own
            // behavior.
            let finalize = ironrdp_acceptor::accept_finalize_with_handlers(
                framed,
                &mut acceptor,
                self,
                async |request, _soft_sync| {
                    // Defensive only: reached only if the acceptor sent a
                    // request despite one of these being unset, which
                    // `PendingConnection::new`'s gate should prevent.
                    let (Some(udp_bind_addr), Some(tls_config)) = (udp_bind_addr, tls_config.clone()) else {
                        return;
                    };
                    // Spawned rather than awaited inline: See the comment on
                    // `pending_udp_accept`'s declaration above.
                    pending_udp_accept = Some(task::spawn(async move {
                        multitransport::accept(udp_bind_addr, tls_config, &request).await
                    }));
                },
            );
            let (new_framed, result) = match tokio::time::timeout(FINALIZE_TIMEOUT, finalize).await {
                Ok(res) => res.map_err_kind("failed to accept client during finalize", ServerErrorKind::Connector)?,
                Err(_) => {
                    warn!(
                        timeout = ?FINALIZE_TIMEOUT,
                        "Client stopped responding during the finalize handshake, dropping the connection"
                    );
                    return Err(ServerError::io(
                        "timed out waiting for the client during finalize",
                        std::io::Error::from(std::io::ErrorKind::TimedOut),
                    ));
                }
            };

            let (mut reader, mut writer) = split_tokio_framed(new_framed);

            match self
                .client_accepted(
                    &mut conn,
                    &mut reader,
                    &mut writer,
                    (result, &acceptor),
                    Rc::clone(&udp_transport),
                    pending_udp_accept.take(),
                )
                .await?
            {
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
                        core::mem::take(&mut conn.static_channels),
                        desktop_size,
                    )
                    .map_err_kind("deactivation-reactivation acceptor", ServerErrorKind::Connector)?;
                    framed = unsplit_tokio_framed(reader, writer);
                    continue;
                }
                RunState::Disconnect => {
                    let final_framed = unsplit_tokio_framed(reader, writer);
                    return Ok(final_framed);
                }
                RunState::Redirected => {
                    // The client terminates the connection once it has processed the Server Redirection PDU
                    // (MS-RDPBCGR 3.2.5.13.1). Closing it first can fail a write the client has in flight before it
                    // reads the PDU, so whatever it still sends is discarded until it disconnects.
                    let _ = Box::pin(tokio::time::timeout(REDIRECTION_CLOSE_TIMEOUT, async {
                        while reader.read_pdu().await.is_ok() {}
                    }))
                    .await;
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

    /// Tell the server which local address the next client reached, for
    /// connections driven through [`Self::run_connection`] or
    /// [`Self::run_connection_with`]. [`Self::run`] sets it itself.
    ///
    /// When the UDP transport address (see
    /// [`RdpServerBuilder::with_udp_transport`](crate::RdpServerBuilder::with_udp_transport))
    /// has an unspecified IP, the sideband socket binds to this address
    /// instead. A socket bound to the unspecified address replies from
    /// whichever local address the routing table picks, and on a host with
    /// several addresses (IPv6 temporary addresses, for example) that is not
    /// always the one the client sent to. The client then drops the replies
    /// and the UDP handshake never completes.
    ///
    /// Cleared when the connection ends.
    pub fn set_connection_local_addr(&mut self, addr: Option<SocketAddr>) {
        self.connection_local_addr = addr;
    }
}

fn validate_bound_display_size(negotiated_size: DesktopSize, bound_size: DesktopSize) -> Result<(), ConnectorError> {
    if bound_size == negotiated_size {
        Ok(())
    } else {
        Err(ConnectorError::reason(
            "bound display dimensions differ from negotiated dimensions",
            format!("negotiated {negotiated_size:?}, bound {bound_size:?}"),
        ))
    }
}

async fn resolve_authenticated_credentials(
    credential_validator: Option<Arc<dyn CredentialValidator>>,
    received_credentials: Option<&ReceivedCredentials>,
) -> ServerResult<Option<&Credentials>> {
    if let Some(received) = received_credentials {
        let creds = &received.credentials;
        if let Some(validator) = credential_validator {
            match validator.validate_received(creds, received.origin).await {
                Ok(CredentialDecision::Accept) => {
                    debug!("Credential validation accepted");
                    Ok(Some(creds))
                }
                Ok(CredentialDecision::Reject) => {
                    warn!("Credential validation rejected");
                    Err(ServerError::reason("credential validation", "rejected by validator"))
                }
                Err(e) => {
                    error!(error = %e, "Credential validator backend error");
                    Err(ServerError::custom("credential validation", e))
                }
            }
        } else {
            Ok(Some(creds))
        }
    } else {
        debug!("Skipping credential validation (no credentials in AcceptorResult)");
        Ok(None)
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
) -> ServerResult<Vec<u8>> {
    // Auto-detect rides the MCS message channel framed by a Basic Security
    // Header (SEC_AUTODETECT_REQ), not a Share Control / Share Data header.
    let pdu = rdp::autodetect::AutoDetectReqPdu::new(request);
    let user_data = encode_vec(&pdu).map_err(ServerError::encode)?.into();
    let mcs_pdu = SendDataIndication {
        initiator_id: user_channel_id,
        channel_id: message_channel_id,
        user_data,
    };
    encode_vec(&X224(mcs_pdu)).map_err(ServerError::encode)
}

/// headerLength and headerTypeId, common to every auto-detect structure
/// ([MS-RDPBCGR] 2.2.14.1).
#[cfg(feature = "egfx")]
const AUTODETECT_HEADER_SIZE: usize = 1 /* headerLength */ + 1 /* headerTypeId */;

/// Carries an auto-detect request as an RDP_TUNNEL_SUBHEADER, alone in a
/// Tunnel Data PDU of its own ([MS-RDPBCGR] 1.3.9, [MS-RDPEMT] 2.2.1.1.1).
///
/// The sub-header is the request itself, with none of the security header
/// [`encode_autodetect_request`] frames it with on the message channel: Its
/// SubHeaderLength and SubHeaderType are the request's headerLength and
/// headerTypeId, so SubHeaderData starts at the sequence number.
#[cfg(feature = "egfx")]
#[cfg_attr(feature = "__test", visibility::make(pub))]
fn autodetect_sub_header(
    request: &rdp::autodetect::AutoDetectRequest,
) -> ServerResult<ironrdp_rdpeudp_tokio::TunnelMessage> {
    let mut data = encode_vec(request).map_err(ServerError::encode)?;
    // Every auto-detect request starts with the two header bytes the
    // sub-header supplies itself.
    data.drain(..AUTODETECT_HEADER_SIZE);
    Ok(ironrdp_rdpeudp_tokio::TunnelMessage {
        sub_headers: vec![ironrdp_rdpemt::TunnelSubHeader {
            sub_header_type: ironrdp_rdpemt::SubHeaderType::AutoDetectRequest,
            data,
        }],
        data: Vec::new(),
    })
}

/// Reads the client's auto-detect response out of a tunnel sub-header
/// ([MS-RDPBCGR] 1.3.9), or `None` when the sub-header is not one or does not
/// decode.
///
/// A sub-header the client should not send, or a malformed one, is logged and
/// dropped rather than treated as an error: nothing about the primary TCP
/// session depends on the sideband transport's correctness.
#[cfg_attr(feature = "__test", visibility::make(pub))]
fn autodetect_response_from_sub_header(
    sub_header: &ironrdp_rdpemt::TunnelSubHeader,
) -> Option<rdp::autodetect::AutoDetectResponse> {
    if sub_header.sub_header_type != ironrdp_rdpemt::SubHeaderType::AutoDetectResponse {
        trace!(sub_header_type = ?sub_header.sub_header_type, "Ignoring a UDP tunnel sub-header the client does not send");
        return None;
    }
    // The sub-header's own two bytes are the response's headerLength and
    // headerTypeId ([MS-RDPEMT] 2.2.1.1.1), so the response is decoded from
    // the whole sub-header, not from its data alone.
    let bytes = match encode_vec(sub_header) {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!(%error, "Failed to re-encode a UDP tunnel sub-header, dropping it");
            return None;
        }
    };
    match decode::<rdp::autodetect::AutoDetectResponse>(&bytes) {
        Ok(response) => Some(response),
        Err(error) => {
            warn!(%error, "Failed to decode an auto-detect response from the UDP tunnel, dropping it");
            None
        }
    }
}

/// Encode a server-initiated Heartbeat PDU for the MCS message channel.
///
/// Like auto-detect (see [`encode_autodetect_request`]), heartbeats are framed
/// by a Basic Security Header (SEC_HEARTBEAT) and ride the message channel,
/// not a Share Control / Share Data header on the I/O channel
/// (MS-RDPBCGR 2.2.16.1).
fn encode_heartbeat(config: &HeartbeatConfig, message_channel_id: u16, user_channel_id: u16) -> ServerResult<Vec<u8>> {
    let pdu = rdp::heartbeat::HeartbeatPdu {
        security_header: rdp::headers::BasicSecurityHeader {
            flags: rdp::headers::BasicSecurityHeaderFlags::HEARTBEAT,
        },
        period: config.period_secs,
        count1: config.warning_count,
        count2: config.reconnect_count,
    };
    let user_data = encode_vec(&pdu).map_err(ServerError::encode)?.into();
    let mcs_pdu = SendDataIndication {
        initiator_id: user_channel_id,
        channel_id: message_channel_id,
        user_data,
    };
    encode_vec(&X224(mcs_pdu)).map_err(ServerError::encode)
}

/// Encode a Share Data PDU wrapped in a Share Control header and carried in an
/// MCS Send Data Indication on the I/O channel.
///
/// A general `encode_share_data_pdu` helper previously lived here for the
/// auto-detect path; #1348 rerouted auto-detect onto the message channel (see
/// [`encode_autodetect_request`]), leaving the Save Session Info sender as its
/// only user until the eviction notice (`ServerEvent::EvictedByOtherConnection`)
/// became a second one, so the encoder now lives with the former.
///
/// `pdu_source` is a parameter, not hardcoded, because the two callers
/// disagree: MS-RDPBCGR 2.2.1.19 has the server echo the client's own MCS user
/// channel ID here for a normal Share Data PDU (what Save Session Info sends),
/// but 2.2.5.1.1 requires `pduSource` to be zero specifically for
/// TS_SET_ERROR_INFO_PDU (what the eviction notice sends).
fn encode_share_data_pdu(
    share_data_pdu: rdp::headers::ShareDataPdu,
    pdu_source: u16,
    io_channel_id: u16,
    user_channel_id: u16,
) -> ServerResult<Vec<u8>> {
    let header = rdp::headers::ShareDataHeader {
        share_data_pdu,
        stream_priority: rdp::headers::StreamPriority::Medium,
        compression_flags: rdp::headers::CompressionFlags::empty(),
        compression_type: rdp::client_info::CompressionType::K8,
    };
    let pdu = rdp::headers::ShareControlHeader {
        share_id: 0,
        pdu_source,
        share_control_pdu: ShareControlPdu::Data(header),
    };
    let user_data = encode_vec(&pdu).map_err(ServerError::encode)?.into();
    let mcs_pdu = SendDataIndication {
        initiator_id: user_channel_id,
        channel_id: io_channel_id,
        user_data,
    };
    encode_vec(&X224(mcs_pdu)).map_err(ServerError::encode)
}

async fn deactivate_all(io_channel_id: u16, user_channel_id: u16, writer: &mut impl FramedWrite) -> ServerResult<()> {
    let pdu = ShareControlPdu::ServerDeactivateAll(ServerDeactivateAll);
    let pdu = rdp::headers::ShareControlHeader {
        share_id: 0,
        pdu_source: io_channel_id,
        share_control_pdu: pdu,
    };
    let user_data = encode_vec(&pdu).map_err(ServerError::encode)?.into();
    let pdu = SendDataIndication {
        initiator_id: user_channel_id,
        channel_id: io_channel_id,
        user_data,
    };
    let msg = encode_vec(&X224(pdu)).map_err(ServerError::encode)?;
    writer
        .write_all(&msg)
        .await
        .map_err(|e| ServerError::io("write deactivate_all", e))?;
    Ok(())
}

/// The [`ConnectionHandler`] shared between `run`'s live connection and a
/// [`ConnectionPolicy::Preempt`] candidate.
type SharedConnectionHandler = Rc<RefCell<Box<dyn ConnectionHandler>>>;

/// Call into the shared handler, if one is installed.
///
/// The only way the server reaches the handler. The borrow lives exactly as
/// long as `f`, and `f` is a synchronous closure, so it cannot be held across
/// an `.await` -- the compiler, not a convention, rules out the live
/// connection and a candidate holding it at the same time on this
/// single-threaded server.
fn with_connection_handler<R>(
    handler: Option<&SharedConnectionHandler>,
    f: impl FnOnce(&mut dyn ConnectionHandler) -> R,
) -> Option<R> {
    handler.map(|h| f(h.borrow_mut().as_mut()))
}

async fn send_access_denied(acceptor: &Acceptor, writer: &mut impl FramedWrite) -> ServerResult<()> {
    let mut buf = WriteBuf::new();
    let written = acceptor
        .encode_access_denied(&mut buf)
        .map_err_kind("encode access denied", ServerErrorKind::Connector)?;
    if written != 0 {
        writer
            .write_all(&buf[..written])
            .await
            .map_err(|e| ServerError::io("write access denied", e))?;
    }
    Ok(())
}

struct SharedWriter<'w, W: FramedWrite> {
    writer: Rc<Mutex<&'w mut W>>,
    /// Count of successful `write_all` calls across all clones. The heartbeat
    /// loop compares it across ticks to honor 2.2.16.1's idle-only SHOULD: a
    /// changed count means ordinary traffic already served as the liveness
    /// signal for that interval.
    writes: Arc<AtomicU64>,
}

impl<W: FramedWrite> Clone for SharedWriter<'_, W> {
    fn clone(&self) -> Self {
        Self {
            writer: Rc::clone(&self.writer),
            writes: Arc::clone(&self.writes),
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
        Box::pin(async move {
            // D1: time both the lock acquisition and the actual write.
            // Three concurrent tasks (dispatch_pdu, dispatch_display,
            // dispatch_events) share this Rc<Mutex<W>>. When the kernel TCP
            // send buffer fills (slow client), write_all blocks while still
            // holding the mutex — starving the other two tasks. Logging
            // both phases tells us whether a stall is "waiting in line for
            // the writer" (lock-wait) or "TLS write held up by TCP back-
            // pressure" (write-time).
            let len = buf.len();
            let wait_start = Instant::now();
            let mut writer = self.writer.lock().await;
            let wait_ms = u64::try_from(wait_start.elapsed().as_millis()).unwrap_or(u64::MAX);

            let write_start = Instant::now();
            let res = writer.write_all(buf).await;
            let write_ms = u64::try_from(write_start.elapsed().as_millis()).unwrap_or(u64::MAX);

            // Threshold: 50ms total budget for one write_all. Anything above
            // is operationally interesting on a healthy LAN. Logged at WARN
            // when stalled, DEBUG when fast (so wire-time samples are still
            // visible during routine debugging).
            if wait_ms + write_ms >= 50 {
                tracing::warn!(
                    bytes = len,
                    lock_wait_ms = wait_ms,
                    write_ms,
                    "SharedWriter.write_all stalled, possible TCP back-pressure or writer-mutex contention"
                );
            } else {
                tracing::debug!(bytes = len, lock_wait_ms = wait_ms, write_ms, "SharedWriter.write_all");
            }
            if res.is_ok() {
                self.writes.fetch_add(1, Ordering::Relaxed);
            }
            res
        })
    }
}

impl<'a, W: FramedWrite> SharedWriter<'a, W> {
    fn new(writer: &'a mut W) -> Self {
        Self {
            writer: Rc::new(Mutex::new(writer)),
            writes: Arc::new(AtomicU64::new(0)),
        }
    }

    fn write_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.writes)
    }
}

#[async_trait::async_trait(?Send)]
impl ConnectionSetupHandler for RdpServer {
    async fn handle_credentials(&mut self, credentials: Option<ReceivedCredentials>) -> Result<(), ConnectorError> {
        self.prepare_authenticated_connection(credentials).await
    }

    async fn prepare_capability_exchange(&mut self, desktop_size: DesktopSize) -> Result<(), ConnectorError> {
        if (self.credential_validator.is_some() || self.connection_binder.is_some())
            && self
                .pending_authenticated_credentials
                .lock()
                .expect("authenticated credentials lock poisoned")
                .is_none()
        {
            return Err(ConnectorError::general(
                "credentials were not prepared before capability exchange",
            ));
        }

        let Some(binder) = self.connection_binder.clone() else {
            return Ok(());
        };
        let credentials = self
            .pending_authenticated_credentials
            .lock()
            .expect("authenticated credentials lock poisoned")
            .clone()
            .ok_or_else(|| ConnectorError::general("no authenticated credentials for connection binding"))?;
        let bound = binder
            .bind_connection(&credentials, desktop_size)
            .await
            .map_err(|error| ConnectorError::custom("connection binder failed", error))?;

        let mut bound_display = bound.display;
        let bound_size = bound_display.size().await;
        validate_bound_display_size(desktop_size, bound_size)?;

        self.install_bound_connection(BoundConnection {
            display: bound_display,
            input: bound.input,
        });
        debug!(?bound_size, "Connection binder installed display/input handlers");
        Ok(())
    }
}

#[cfg(test)]
mod preempt_tests {
    use core::net::Ipv4Addr;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    use super::*;

    fn ctx_with_no_security() -> NegotiationContext {
        struct NoDisplay;
        #[async_trait::async_trait]
        impl RdpServerDisplay for NoDisplay {
            async fn size(&mut self) -> DesktopSize {
                DesktopSize {
                    width: 1024,
                    height: 768,
                }
            }
            async fn updates(&mut self, _: DisplayContext) -> ServerResult<Box<dyn RdpServerDisplayUpdates>> {
                unreachable!("negotiation never asks for updates")
            }
        }

        NegotiationContext {
            opts: RdpServerOptions {
                addr: (Ipv4Addr::LOCALHOST, 0).into(),
                security: RdpServerSecurity::None,
                codecs: BitmapCodecs(Vec::new()),
                max_request_size: 8 * 1024 * 1024,
                honor_client_desktop_size: None,
                connection_policy: ConnectionPolicy::Preempt,
                remotefx_quant: Quant::default(),
                remotefx_entropy_coder: None,
                udp_bind_addr: None,
            },
            creds: None,
            display: Arc::new(Mutex::new(Box::new(NoDisplay))),
            credential_validator: None,
            requires_authenticated_credentials: false,
        }
    }

    /// The invariant behind this feature: a connection that never completes a
    /// real RDP negotiation must NOT be treated as an eligible candidate, and
    /// so can never evict a live session. This is the case the earlier
    /// two-byte `03 00` peek got wrong — it accepted anything whose first
    /// bytes merely *looked* like a TPKT header.
    #[tokio::test]
    async fn a_candidate_sending_garbage_never_authenticates() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            // Starts with a plausible TPKT prefix — enough to fool a
            // header peek — but is not a valid X.224 Connection Request.
            stream.write_all(&[0x03, 0x00, 0xff, 0xff, 0x41, 0x41]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let (stream, peer) = listener.accept().await.unwrap();
        let ctx = ctx_with_no_security();
        assert!(
            negotiate_candidate(&ctx, IncomingConnection::new(stream, TransportTls::Managed, Some(peer)))
                .await
                .is_none(),
            "traffic that only looks like RDP must not become an eligible candidate"
        );

        client.await.unwrap();
    }

    /// The other half: a bare connect that sends nothing (a port scan, a
    /// half-open probe) must not qualify either.
    #[tokio::test]
    async fn a_candidate_that_closes_immediately_never_authenticates() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            drop(stream);
        });

        let (stream, peer) = listener.accept().await.unwrap();
        let ctx = ctx_with_no_security();
        assert!(
            negotiate_candidate(&ctx, IncomingConnection::new(stream, TransportTls::Managed, Some(peer)))
                .await
                .is_none(),
            "a connect-and-close must not become an eligible candidate"
        );

        client.await.unwrap();
    }

    /// The eviction notice must be a properly framed Share Data PDU carrying
    /// `ERRINFO_DISCONNECTED_BY_OTHERCONNECTION` (MS-RDPBCGR 2.2.5.1.1) — that
    /// exact code is what tells a client it was replaced rather than dropped,
    /// and so what stops it auto-reconnecting into a ping-pong. Round-trips
    /// the encoding a real eviction sends.
    #[test]
    fn the_eviction_notice_is_a_share_data_pdu_with_the_takeover_code() {
        let pdu = rdp::headers::ShareDataPdu::ServerSetErrorInfo(ServerSetErrorInfoPdu(
            ErrorInfo::ProtocolIndependentCode(ProtocolIndependentCode::DisconnectedByOtherconnection),
        ));
        // pdu_source=0 here: unlike the Save Session Info sender (which
        // echoes the client's own user_channel_id), MS-RDPBCGR 2.2.5.1.1
        // requires pduSource to be zero for TS_SET_ERROR_INFO_PDU.
        let bytes = encode_share_data_pdu(pdu, 0, 1003, 1002).expect("encode eviction notice");

        let x224: X224<mcs::McsMessage<'_>> = decode(&bytes).expect("decode X.224/MCS");
        let mcs::McsMessage::SendDataIndication(data) = x224.0 else {
            panic!("eviction notice must ride an MCS Send Data Indication");
        };
        let control: rdp::headers::ShareControlHeader =
            decode(data.user_data.as_ref()).expect("decode Share Control header");
        assert_eq!(
            control.pdu_source, 0,
            "MS-RDPBCGR 2.2.5.1.1 requires pduSource=0 for TS_SET_ERROR_INFO_PDU"
        );
        let ShareControlPdu::Data(header) = control.share_control_pdu else {
            panic!("eviction notice must be a Share Data PDU");
        };
        match header.share_data_pdu {
            rdp::headers::ShareDataPdu::ServerSetErrorInfo(ServerSetErrorInfoPdu(
                ErrorInfo::ProtocolIndependentCode(code),
            )) => {
                assert_eq!(code, ProtocolIndependentCode::DisconnectedByOtherconnection);
            }
            other => panic!("unexpected share data pdu: {other:?}"),
        }
    }

    /// The anti-storm net: a just-evicted peer may not bounce straight back,
    /// and every refused attempt RE-ARMS the window, so an automatic reconnect
    /// loop cannot immediately outlast it. A peer that goes quiet for the
    /// cooldown (a human closing the client and reconnecting) is let back in.
    #[test]
    fn a_just_evicted_peer_cannot_bounce_back_but_a_quiet_one_can() {
        let cooldown = Duration::from_secs(5);
        let max_lockout = Duration::from_secs(30);
        let evicted: IpAddr = Ipv4Addr::new(192, 168, 4, 46).into();
        let other: IpAddr = Ipv4Addr::new(192, 168, 4, 44).into();

        let t0 = Instant::now();
        let mut state = Some(EvictedPeer {
            ip: evicted,
            evicted_at: t0,
            last_try: t0,
        });

        // An unrelated peer is never affected by someone else's eviction.
        assert!(!refuse_reconnect_from_evicted(
            &mut state,
            other,
            t0 + Duration::from_millis(500),
            cooldown,
            max_lockout,
        ));

        // The evicted peer auto-reconnecting ~1 s later is refused, and each
        // attempt pushes the window out.
        let mut at = t0;
        for _ in 0..5 {
            at += Duration::from_secs(1);
            assert!(
                refuse_reconnect_from_evicted(&mut state, evicted, at, cooldown, max_lockout),
                "an auto-reconnect storm must not immediately win the session back"
            );
        }

        // ...but once it stops hammering for the full cooldown, a deliberate
        // reconnect is allowed through.
        let quiet = at + cooldown + Duration::from_millis(1);
        assert!(
            !refuse_reconnect_from_evicted(&mut state, evicted, quiet, cooldown, max_lockout),
            "a peer that waited out the cooldown must be able to connect again"
        );
    }

    /// The re-arming window MUST NOT lock a peer out forever, or it defeats
    /// the feature's own headline case: a client whose link dropped, whose
    /// stale session is still live, auto-reconnecting to reclaim it. Past
    /// `max_lockout` from the eviction the bar lifts even under a storm that
    /// never pauses.
    #[test]
    fn the_reconnect_bar_lifts_once_the_absolute_cap_passes() {
        let cooldown = Duration::from_secs(5);
        let max_lockout = Duration::from_secs(30);
        let evicted: IpAddr = Ipv4Addr::new(192, 168, 4, 46).into();

        let t0 = Instant::now();
        let mut state = Some(EvictedPeer {
            ip: evicted,
            evicted_at: t0,
            last_try: t0,
        });

        // A relentless 1 s auto-reconnect cadence: refused while inside the
        // cap, even though every attempt re-arms the cooldown...
        let mut at = t0;
        let mut refused_while_capped = 0;
        while at < t0 + max_lockout {
            at += Duration::from_secs(1);
            if at < t0 + max_lockout {
                assert!(
                    refuse_reconnect_from_evicted(&mut state, evicted, at, cooldown, max_lockout),
                    "still inside the cap, so the storm is throttled"
                );
                refused_while_capped += 1;
            }
        }
        assert!(refused_while_capped > 0, "the test must exercise the throttled window");

        // ...and let through the moment the cap passes, WITHOUT the peer ever
        // having paused. Before the cap was added this returned true forever.
        let past_cap = t0 + max_lockout + Duration::from_millis(1);
        assert!(
            !refuse_reconnect_from_evicted(&mut state, evicted, past_cap, cooldown, max_lockout),
            "a peer must not be barred forever just for retrying; that locks out the case the feature exists for"
        );
    }

    /// A silent candidate MUST NOT be able to hang the accept loop.
    ///
    /// `negotiate_candidate` blocks on socket reads from a peer that has not
    /// authenticated. Before `CANDIDATE_NEGOTIATION_TIMEOUT` the probe was
    /// awaited unbounded: a peer that connected and then sent NOTHING parked it
    /// forever, and once the live session ended `run()` blocked on the handoff
    /// await with no `select!` left — no further accepts, no event drain, so
    /// not even `ServerEvent::Quit` could stop the server. An unauthenticated
    /// remote could wedge the listener.
    ///
    /// Drive exactly that: a live session, a silent candidate, then end the
    /// session and require the server to still respond and still shut down.
    #[tokio::test]
    async fn a_declined_multitransport_response_stops_the_udp_accept() {
        let local = task::LocalSet::new();
        local
            .run_until(async {
                let pending = || Some(task::spawn_local(core::future::pending::<()>()));

                let declined = RdpServer::drop_declined_udp_accept(pending(), Some(false));
                assert!(declined.is_none());

                let kept = RdpServer::drop_declined_udp_accept(pending(), None).expect("no response keeps the accept");
                assert!(!kept.is_finished());
                kept.abort();

                let kept =
                    RdpServer::drop_declined_udp_accept(pending(), Some(true)).expect("success keeps the accept");
                assert!(!kept.is_finished());
                kept.abort();

                // The aborted task really stops, so its socket is released.
                let handle = task::spawn_local(core::future::pending::<()>());
                let probe = handle.abort_handle();
                assert!(RdpServer::drop_declined_udp_accept(Some(handle), Some(false)).is_none());
                task::yield_now().await;
                assert!(probe.is_finished());
            })
            .await;
    }

    #[test]
    fn a_late_multitransport_success_enables_migration_only_with_soft_sync() {
        use ironrdp_pdu::rdp::multitransport::MultitransportResponsePdu;

        let mut conn = ConnectionState::default();
        let response = |pdu: &MultitransportResponsePdu| SendDataRequest {
            initiator_id: 1007,
            channel_id: 1008,
            user_data: encode_vec(pdu).expect("encode response").into(),
        };

        // Soft-Sync not negotiated: MS-RDPEDYC forbids migration whatever the response.
        RdpServer::handle_message_channel_data(&mut conn, response(&MultitransportResponsePdu::success(1)));
        assert!(!conn.udp_migration_allowed);

        // Negotiated, but the client could not bring UDP up.
        conn.soft_sync_negotiated = true;
        RdpServer::handle_message_channel_data(&mut conn, response(&MultitransportResponsePdu::abort(1)));
        assert!(!conn.udp_migration_allowed);

        // Negotiated, and the success arrives after finalization.
        RdpServer::handle_message_channel_data(&mut conn, response(&MultitransportResponsePdu::success(1)));
        assert!(conn.udp_migration_allowed);
    }

    #[tokio::test]
    async fn a_late_multitransport_failure_stops_the_pending_udp_accept() {
        use ironrdp_pdu::rdp::multitransport::MultitransportResponsePdu;

        let local = task::LocalSet::new();
        local
            .run_until(async {
                let mut conn = ConnectionState::default();
                let response = |pdu: &MultitransportResponsePdu| SendDataRequest {
                    initiator_id: 1007,
                    channel_id: 1008,
                    user_data: encode_vec(pdu).expect("encode response").into(),
                };

                // No accept pending: a failure response is only logged.
                RdpServer::handle_message_channel_data(&mut conn, response(&MultitransportResponsePdu::abort(1)));

                let accept = task::spawn_local(core::future::pending::<()>());
                conn.pending_udp_accept_abort = Some(accept.abort_handle());

                // Success leaves the accept running.
                RdpServer::handle_message_channel_data(&mut conn, response(&MultitransportResponsePdu::success(1)));
                task::yield_now().await;
                assert!(!accept.is_finished());

                RdpServer::handle_message_channel_data(&mut conn, response(&MultitransportResponsePdu::abort(1)));
                task::yield_now().await;
                assert!(accept.is_finished());
                assert!(accept.await.expect_err("accept was aborted").is_cancelled());
                assert!(conn.pending_udp_accept_abort.is_none());
            })
            .await;
    }

    #[tokio::test]
    async fn a_silent_candidate_cannot_wedge_the_accept_loop() {
        let local = task::LocalSet::new();
        local
            .run_until(async move {
                let mut server = RdpServer::builder()
                    .with_addr((Ipv4Addr::LOCALHOST, 0))
                    .with_no_security()
                    .with_no_input()
                    .with_no_display()
                    .with_connection_policy(ConnectionPolicy::Preempt)
                    .build();

                let event_sender = server.event_sender().clone();
                let run_task = task::spawn_local(async move {
                    let _ = Box::pin(server.run()).await;
                });

                let addr = loop {
                    let (tx, rx) = oneshot::channel();
                    let _ = event_sender.send(ServerEvent::GetLocalAddr(tx));
                    if let Ok(Some(addr)) = rx.await {
                        break addr;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                };

                // Client A: the live session (connect, stay silent).
                let client_a = TcpStream::connect(addr).await.unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;

                // Client B: the candidate — completes the TCP handshake, then
                // says nothing at all, parking the probe mid-`accept_begin`.
                let _client_b = TcpStream::connect(addr).await.unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;

                // The live session ends. This is the branch that used to do a
                // bare `probe.await` and never come back.
                drop(client_a);

                // The server must still be answering its event channel. With
                // the unbounded await this never resolves.
                let responsive = tokio::time::timeout(Duration::from_secs(3), async {
                    loop {
                        let (tx, rx) = oneshot::channel();
                        if event_sender.send(ServerEvent::GetLocalAddr(tx)).is_err() {
                            return;
                        }
                        if rx.await.is_ok() {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                })
                .await;
                assert!(
                    responsive.is_ok(),
                    "the accept loop stopped servicing events while a silent candidate was in flight"
                );

                // ...and must still be stoppable.
                let _ = event_sender.send(ServerEvent::Quit("test over".to_owned()));
                let stopped = tokio::time::timeout(Duration::from_secs(3), run_task).await;
                assert!(
                    stopped.is_ok(),
                    "the server ignored Quit -- the accept loop was wedged by an unauthenticated silent peer"
                );
            })
            .await;
    }

    /// A `ConnectionHandler` that accepts the first connection and rejects
    /// every one after, recording every peer it was consulted about.
    struct RejectAfterFirst {
        seen: Arc<std::sync::Mutex<Vec<SocketAddr>>>,
        accepted_once: bool,
    }

    impl ConnectionHandler for RejectAfterFirst {
        fn on_accept(&mut self, peer: SocketAddr) -> bool {
            self.seen.lock().unwrap().push(peer);
            !core::mem::replace(&mut self.accepted_once, true)
        }
    }

    /// Drives a real `RdpServer::run()` accept loop over TCP with preemption
    /// on. A candidate must be gated through `ConnectionHandler::on_accept`
    /// *before* it is allowed to negotiate — so a rate limiter or IP allowlist
    /// can stop a takeover, rather than only learning about it after the live
    /// session was already evicted.
    #[tokio::test]
    async fn a_candidate_is_gated_through_on_accept_before_it_can_preempt() {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen_for_handler = Arc::clone(&seen);

        let local = task::LocalSet::new();
        local
            .run_until(async move {
                let mut server = RdpServer::builder()
                    .with_addr((Ipv4Addr::LOCALHOST, 0))
                    .with_no_security()
                    .with_no_input()
                    .with_no_display()
                    .with_connection_handler(Some(Box::new(RejectAfterFirst {
                        seen: seen_for_handler,
                        accepted_once: false,
                    })))
                    .with_connection_policy(ConnectionPolicy::Preempt)
                    .build();

                let event_sender = server.event_sender().clone();
                let run_task = task::spawn_local(async move {
                    let _ = Box::pin(server.run()).await;
                });

                // Learn the ephemeral port (retrying while `run()` binds).
                let addr = loop {
                    let (tx, rx) = oneshot::channel();
                    let _ = event_sender.send(ServerEvent::GetLocalAddr(tx));
                    if let Ok(Some(addr)) = rx.await {
                        break addr;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                };

                // Client A: connect and go silent. `run_connection` parks
                // reading the first PDU, which is all "a live session" needs
                // to be here.
                let mut client_a = TcpStream::connect(addr).await.unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;

                // Client B: the candidate. The handler rejects it, so it must
                // never reach negotiation, let alone evict client A.
                let mut client_b = TcpStream::connect(addr).await.unwrap();
                client_b.write_all(&[0x03, 0x00]).await.unwrap();

                let mut buf = [0u8; 1];
                let client_b_read = tokio::time::timeout(Duration::from_secs(2), client_b.read(&mut buf)).await;
                assert!(
                    matches!(client_b_read, Ok(Ok(0)) | Ok(Err(_))),
                    "the rejected candidate's connection should be closed, got {client_b_read:?}"
                );

                // Client A is untouched: a read TIMES OUT (no EOF, no data)
                // rather than showing the server dropped it for client B.
                let client_a_still_alive =
                    tokio::time::timeout(Duration::from_millis(300), client_a.read(&mut buf)).await;
                assert!(
                    client_a_still_alive.is_err(),
                    "the live session must survive a rejected preemption attempt, got {client_a_still_alive:?}"
                );

                // The handler was actually consulted about the candidate —
                // the gate ran on B, not merely on A.
                let seen = seen.lock().unwrap().clone();
                assert_eq!(
                    seen.len(),
                    2,
                    "on_accept should have been consulted for both peers: {seen:?}"
                );

                run_task.abort();
            })
            .await;
    }

    /// Regression guard for the blocking review finding: invalidating an
    /// evicted peer's ARC cookie must NOT permanently disable auto-reconnect
    /// for the server. `next_auto_reconnect_cookie` treats
    /// `self.auto_reconnect_cookie == None` as "unconfigured" and stops
    /// issuing cookies to EVERY future connection -- a naive
    /// `self.auto_reconnect_cookie = None` on eviction would have silently
    /// killed the feature server-wide the moment the first eviction ever
    /// happened.
    #[test]
    fn invalidating_the_evicted_peers_cookie_does_not_disable_auto_reconnect() {
        let mut server = RdpServer::builder()
            .with_addr((Ipv4Addr::LOCALHOST, 0))
            .with_no_security()
            .with_no_input()
            .with_no_display()
            .build();

        let seed = RdpServer::generate_auto_reconnect_cookie(4242);
        server.set_auto_reconnect_cookie(Some(seed.clone()));
        // A normal rotation would have run once by the time a real session
        // reaches an eviction; simulate that so `previous_auto_reconnect_
        // cookie` starts populated, which is the slot the fix must ALSO clear.
        server.commit_auto_reconnect_rotation(RdpServer::generate_auto_reconnect_cookie(seed.logon_id));

        server.invalidate_auto_reconnect_cookie_on_eviction();

        let after = server
            .auto_reconnect_cookie
            .as_ref()
            .expect("invalidation must not clear the cookie to None -- that permanently disables auto-reconnect");
        assert_eq!(after.logon_id, seed.logon_id, "the logon_id lineage must be preserved");
        assert_ne!(
            after.random_bits, seed.random_bits,
            "the random bits must actually change, or the evicted peer's OLD cookie would still verify"
        );
        assert!(
            server.previous_auto_reconnect_cookie.is_none(),
            "the outgoing cookie(s) must be discarded, not demoted into previous_ -- demoting would keep an \
             evicted peer's cookie valid for one more attempt, which is exactly the gap this closes"
        );
    }

    /// `discard_stale_session_events` must be an ALLOWLIST of lifecycle
    /// events, not a denylist of `EvictedByOtherConnection` alone -- otherwise
    /// a preemption winner is handed whatever per-session events (audio
    /// waves, clipboard messages, EGFX frames) the session it replaced left
    /// queued but never consumed.
    #[tokio::test]
    async fn stale_session_events_are_dropped_but_lifecycle_events_survive() {
        let mut server = RdpServer::builder()
            .with_addr((Ipv4Addr::LOCALHOST, 0))
            .with_no_security()
            .with_no_input()
            .with_no_display()
            .build();

        let sender = server.event_sender().clone();
        // A representative per-session event that must NOT survive a
        // takeover -- it belonged to the session just replaced.
        let _ = sender.send(ServerEvent::AutoDetectRttRequest);
        // A lifecycle event that MUST survive.
        let _ = sender.send(ServerEvent::Quit("keep me".to_owned()));

        server.discard_stale_session_events().await;

        let remaining = {
            let mut rx = server.ev_receiver.lock().await;
            let mut events = Vec::new();
            while let Ok(event) = rx.try_recv() {
                events.push(event);
            }
            events
        };

        assert_eq!(
            remaining.len(),
            1,
            "exactly the lifecycle event should have survived the drain: {remaining:?}"
        );
        assert!(
            matches!(&remaining[0], ServerEvent::Quit(reason) if reason == "keep me"),
            "the surviving event should be the Quit, not the discarded per-session event: {remaining:?}"
        );
    }

    /// Regression guard for the "no happy-path test" review finding, and the
    /// load-bearing claim it's actually worried about: that deferring
    /// `attach_channels` past negotiation (it runs in `accept_finalize`,
    /// which both connection entry paths reach) does NOT silently drop a
    /// preemption winner's channels. That claim rests entirely on
    /// `accept_begin` stopping at `AcceptorState::SecurityUpgrade` -- before
    /// `BasicSettingsWaitInitial` consumes `static_channels` -- for
    /// [`RdpServerSecurity::None`]. If a future `ironrdp-acceptor` change
    /// moved that stop point, a connection would negotiate ZERO static
    /// channels (no clipboard, no sound, no DVC) and every OTHER test in this
    /// module would still pass, since none of them drive a candidate all the
    /// way to `serve_negotiated`.
    ///
    /// Drives a REAL candidate through `negotiate_candidate` (a genuine X.224
    /// Connection Request, matching `RdpServerSecurity::None`'s empty
    /// protocol flags, is enough to reach `BeginResult::Continue` -- no TLS,
    /// no MCS needed) and then `serve_negotiated`, and asserts the sound
    /// factory's backend was actually built. `serve_negotiated` can't finish
    /// without a full MCS/GCC handshake this test doesn't drive, so it's
    /// bounded by a short timeout that is EXPECTED to fire -- the assertion
    /// that matters is the side effect that happens before that point.
    #[tokio::test]
    async fn a_winning_candidate_actually_gets_its_channels_attached() {
        let backend_built = Arc::new(AtomicBool::new(false));

        #[derive(Debug)]
        struct RecordingSoundHandler;
        impl ironrdp_rdpsnd::server::RdpsndServerHandler for RecordingSoundHandler {
            fn get_formats(&self) -> &[ironrdp_rdpsnd::pdu::AudioFormat] {
                &[]
            }
            fn choose_format<'a>(
                &mut self,
                _common: &'a [ironrdp_rdpsnd::server::NegotiatedFormat],
            ) -> Option<&'a ironrdp_rdpsnd::server::NegotiatedFormat> {
                None
            }
            fn start(
                &mut self,
                _format: &ironrdp_rdpsnd::server::NegotiatedFormat,
            ) -> Result<(), Box<dyn ironrdp_rdpsnd::server::RdpsndError>> {
                Ok(())
            }
            fn stop(&mut self) {}
        }

        #[derive(Debug)]
        struct RecordingSoundFactory(Arc<AtomicBool>);
        impl ServerEventSender for RecordingSoundFactory {
            fn set_sender(&mut self, _sender: mpsc::UnboundedSender<ServerEvent>) {}
        }
        impl SoundServerFactory for RecordingSoundFactory {
            fn build_backend(&self) -> Box<dyn ironrdp_rdpsnd::server::RdpsndServerHandler> {
                self.0.store(true, Ordering::SeqCst);
                Box::new(RecordingSoundHandler)
            }
        }

        let local = task::LocalSet::new();
        local
            .run_until(Box::pin(async move {
                let mut server = RdpServer::builder()
                    .with_addr((Ipv4Addr::LOCALHOST, 0))
                    .with_no_security()
                    .with_no_input()
                    .with_no_display()
                    .with_sound_factory(Some(Box::new(RecordingSoundFactory(Arc::clone(&backend_built)))))
                    .build();

                let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
                let addr = listener.local_addr().unwrap();

                let client = tokio::spawn(async move {
                    let mut stream = TcpStream::connect(addr).await.unwrap();
                    let cr = nego::ConnectionRequest {
                        nego_data: None,
                        flags: nego::RequestFlags::empty(),
                        // Matches `RdpServerSecurity::None`'s
                        // `RdpServerSecurity::flag()` exactly -- this is what
                        // makes `accept_begin` reach `BeginResult::Continue`.
                        protocol: nego::SecurityProtocol::empty(),
                        correlation_info: None,
                    };
                    let bytes = encode_vec(&X224(cr)).unwrap();
                    stream.write_all(&bytes).await.unwrap();
                    // Hold the connection open; `serve_negotiated` will try
                    // to read the next (MCS) PDU, which this test never
                    // sends, so the read simply blocks until the test ends.
                    tokio::time::sleep(Duration::from_secs(5)).await;
                });

                let (stream, peer) = listener.accept().await.unwrap();
                let candidate = negotiate_candidate(
                    &server.negotiation_context(),
                    IncomingConnection::new(stream, TransportTls::Managed, Some(peer)),
                )
                .await
                .expect("a well-formed X.224 Connection Request under RdpServerSecurity::None must authenticate");

                // Bounded: `serve_negotiated` cannot finish without a full
                // MCS/GCC handshake this test doesn't drive, so timing out is
                // the EXPECTED outcome here -- `attach_channels`'s
                // synchronous side effect (below) already happened before
                // `serve_negotiated` reached its first blocking read.
                let _ = tokio::time::timeout(
                    Duration::from_millis(300),
                    server.serve_negotiated(candidate.connection),
                )
                .await;

                assert!(
                    backend_built.load(Ordering::SeqCst),
                    "the winning candidate's sound backend was never built -- attach_channels was not called, \
                     meaning this preemption winner would have gotten NO static channels at all"
                );

                client.abort();
            }))
            .await;
    }
}

/// A failing clipboard event must not disconnect the session.
///
/// `dispatch_server_events` used to `?` the result of every `CliprdrServer`
/// call, so a single rejected clipboard message -- a stale file contents
/// request, a capability that was never negotiated, backpressure on pending
/// transfers -- ended `client_loop` and tore down a session whose display,
/// audio and input were healthy.
#[cfg(test)]
mod cliprdr_error_tests {
    use core::any::TypeId;
    use core::net::Ipv4Addr;

    use ironrdp_cliprdr::Cliprdr;
    use ironrdp_cliprdr::backend::CliprdrBackend;
    use ironrdp_cliprdr::pdu::{
        ClipboardFormat, ClipboardGeneralCapabilityFlags, FileContentsFlags, FileContentsRequest, FileContentsResponse,
        FormatDataRequest, FormatDataResponse, LockDataId,
    };
    use ironrdp_core::impl_as_any;

    use super::*;

    #[derive(Debug)]
    struct SilentBackend;

    impl_as_any!(SilentBackend);

    impl CliprdrBackend for SilentBackend {
        fn temporary_directory(&self) -> &str {
            "."
        }

        fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
            ClipboardGeneralCapabilityFlags::STREAM_FILECLIP_ENABLED
        }

        fn on_ready(&mut self) {}
        fn on_request_format_list(&mut self) {}
        fn on_process_negotiated_capabilities(&mut self, _: ClipboardGeneralCapabilityFlags) {}
        fn on_remote_copy(&mut self, _: &[ClipboardFormat]) {}
        fn on_format_data_request(&mut self, _: FormatDataRequest) {}
        fn on_format_data_response(&mut self, _: FormatDataResponse<'_>) {}
        fn on_file_contents_request(&mut self, _: FileContentsRequest) {}
        fn on_file_contents_response(&mut self, _: FileContentsResponse<'_>) {}
        fn on_lock(&mut self, _: LockDataId) {}
        fn on_unlock(&mut self, _: LockDataId) {}
    }

    #[derive(Default)]
    pub(super) struct CapturingWriter(pub(super) Vec<u8>);

    impl FramedWrite for CapturingWriter {
        type WriteAllFut<'write>
            = core::future::Ready<std::io::Result<()>>
        where
            Self: 'write;

        fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> Self::WriteAllFut<'a> {
            self.0.extend_from_slice(buf);
            core::future::ready(Ok(()))
        }
    }

    /// A clipboard message the channel refuses keeps the session alive.
    #[tokio::test]
    async fn a_refused_clipboard_message_does_not_end_the_client_loop() {
        let mut server = RdpServer::builder()
            .with_addr((Ipv4Addr::LOCALHOST, 0))
            .with_no_security()
            .with_no_input()
            .with_no_display()
            .build();

        // Left in its initial state, so `require_ready` refuses the request
        // below -- the cheapest reproduction of "the channel said no".
        let cliprdr: CliprdrServer = Cliprdr::new(Box::new(SilentBackend));
        let mut conn = ConnectionState {
            client_supports_errinfo: true,
            ..ConnectionState::default()
        };
        conn.static_channels.insert(cliprdr);
        conn.static_channels
            .attach_channel_id(TypeId::of::<CliprdrServer>(), 1004);

        let mut events = vec![ServerEvent::Clipboard(ClipboardMessage::SendFileContentsRequest(
            FileContentsRequest {
                stream_id: 1,
                index: 0,
                flags: FileContentsFlags::SIZE,
                position: 0,
                requested_size: 8,
                data_id: None,
            },
        ))];

        let mut writer = CapturingWriter::default();
        let state = server
            .dispatch_server_events(&mut conn, &mut events, &mut writer, 1003, 1002, None, None)
            .await
            .expect("a refused clipboard message must not surface as a session error");

        assert!(
            matches!(state, RunState::Continue),
            "the session must keep running after a refused clipboard message, got {state:?}"
        );
        assert!(writer.0.is_empty(), "a refused message has nothing to put on the wire");
    }
}

#[cfg(all(test, feature = "egfx"))]
mod frame_ack_limit_tests {
    use super::*;
    use ironrdp_pdu::rdp::capability_sets::FrameAcknowledge;
    #[test]
    fn absent_and_zero_core_limit_are_unconstrained() {
        assert_eq!(client_core_frame_ack_limit(&[]), None);
        assert_eq!(
            client_core_frame_ack_limit(&[CapabilitySet::FrameAcknowledge(FrameAcknowledge {
                max_unacknowledged_frame_count: 0
            })]),
            None
        );
    }
    #[test]
    fn nonzero_core_limit_is_preserved() {
        assert_eq!(
            client_core_frame_ack_limit(&[CapabilitySet::FrameAcknowledge(FrameAcknowledge {
                max_unacknowledged_frame_count: 1
            })])
            .map(NonZeroU32::get),
            Some(1)
        );
    }
}

#[cfg(test)]
mod credential_binding_tests {
    use super::*;

    struct FailingValidator;

    #[async_trait::async_trait]
    impl CredentialValidator for FailingValidator {
        async fn validate(&self, _credentials: &Credentials) -> Result<CredentialDecision, CredentialValidationError> {
            Err(CredentialValidationError::new(std::io::Error::other(
                "backend unavailable",
            )))
        }
    }

    fn creds(username: &str) -> Credentials {
        Credentials {
            username: username.to_owned(),
            password: "secret".to_owned(),
            domain: None,
        }
    }

    #[test]
    fn bound_display_size_must_match_negotiated_size() {
        let negotiated = DesktopSize {
            width: 1280,
            height: 720,
        };
        assert!(validate_bound_display_size(negotiated, negotiated).is_ok());

        let incompatible = DesktopSize {
            width: 1920,
            height: 1080,
        };
        assert!(validate_bound_display_size(negotiated, incompatible).is_err());
    }

    #[tokio::test]
    async fn credential_validator_backend_error_is_preserved() {
        let validator: Arc<dyn CredentialValidator> = Arc::new(FailingValidator);
        let received_credentials = ReceivedCredentials {
            credentials: creds("alice"),
            origin: CredentialOrigin::ClientInfo,
        };

        let error = resolve_authenticated_credentials(Some(validator), Some(&received_credentials))
            .await
            .expect_err("backend failure should be returned");
        let validation_error = core::error::Error::source(&error)
            .expect("validator source should be preserved")
            .downcast_ref::<CredentialValidationError>()
            .expect("credential validation error should remain downcastable");
        let source = core::error::Error::source(validation_error).expect("backend source should be preserved");
        assert_eq!(source.to_string(), "backend unavailable");
    }

    #[tokio::test]
    async fn candidate_credential_validation_does_not_change_the_active_identity() {
        let mut server = RdpServer::builder()
            .with_addr(([127, 0, 0, 1], 0))
            .with_no_security()
            .with_no_input()
            .with_no_display()
            .build();
        server.set_credential_validator(Some(Arc::new(ExactMatchCredentialValidator::new(creds("alice")))));
        *server.pending_authenticated_credentials.lock().unwrap() = Some(creds("bob"));
        let context = server.negotiation_context();
        let mut accepted = ServerCredentialsHandler {
            validator: context.credential_validator.clone(),
            ..ServerCredentialsHandler::default()
        };
        accepted
            .handle_credentials(Some(ReceivedCredentials {
                credentials: creds("alice"),
                origin: CredentialOrigin::CredSspDelegated,
            }))
            .await
            .unwrap();
        assert_eq!(accepted.authenticated_credentials, Some(creds("alice")));

        let mut rejected = ServerCredentialsHandler {
            validator: context.credential_validator,
            ..ServerCredentialsHandler::default()
        };
        assert!(
            rejected
                .handle_credentials(Some(ReceivedCredentials {
                    credentials: creds("mallory"),
                    origin: CredentialOrigin::CredSspDelegated,
                }))
                .await
                .is_err()
        );
        assert!(rejected.authenticated_credentials.is_none());
        assert_eq!(
            *server.pending_authenticated_credentials.lock().unwrap(),
            Some(creds("bob"))
        );
    }
}

#[cfg(test)]
mod tests {
    use core::future::pending;

    use ironrdp_core::{Encode as _, WriteCursor, impl_as_any};
    use ironrdp_dvc::DvcProcessor as _;
    use ironrdp_pdu::gcc::ChannelName;
    use ironrdp_svc::{SvcMessage, SvcServerProcessor};

    use super::*;

    /// A channel backend that owns a resource, released on drop the way
    /// `RdpsndServer` stops its handler.
    #[derive(Debug)]
    struct ResourceChannel(Arc<AtomicBool>);

    impl Drop for ResourceChannel {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    impl_as_any!(ResourceChannel);

    impl SvcProcessor for ResourceChannel {
        fn channel_name(&self) -> ChannelName {
            ChannelName::from_static(b"testchn\0")
        }

        fn process(&mut self, _payload: &[u8]) -> PduResult<Vec<SvcMessage>> {
            Ok(Vec::new())
        }
    }

    impl SvcServerProcessor for ResourceChannel {}

    struct NoopInput;

    impl RdpServerInputHandler for NoopInput {
        fn keyboard(&mut self, _event: KeyboardEvent) {}
        fn mouse(&mut self, _event: MouseEvent) {}
    }

    #[tokio::test]
    async fn advanced_input_owns_mouse_only_after_first_pdu() {
        use ironrdp_ainput::{ClientPdu, MouseEventFlags, MousePdu};

        let active = Arc::new(AtomicBool::new(false));
        let mut handler = AInputHandler {
            handler: Arc::new(Mutex::new(Box::new(NoopInput))),
            active: Arc::clone(&active),
        };

        handler.start(1).expect("AInput start failed");
        assert!(!active.load(Ordering::Acquire));

        let pdu = ClientPdu::Mouse(MousePdu {
            time: 0,
            flags: MouseEventFlags::MOVE,
            x: 1,
            y: 1,
        });
        let mut payload = vec![0; pdu.size()];
        pdu.encode(&mut WriteCursor::new(&mut payload))
            .expect("AInput encoding failed");
        handler.process(1, &payload).expect("AInput processing failed");
        assert!(active.load(Ordering::Acquire));

        handler.close(1);
        assert!(!active.load(Ordering::Acquire));
    }

    struct PendingDisplay;

    #[async_trait::async_trait]
    impl RdpServerDisplay for PendingDisplay {
        async fn size(&mut self) -> DesktopSize {
            pending().await
        }

        async fn updates(&mut self, _: DisplayContext) -> ServerResult<Box<dyn RdpServerDisplayUpdates>> {
            pending().await
        }
    }

    struct FixedDisplay(DesktopSize);

    #[async_trait::async_trait]
    impl RdpServerDisplay for FixedDisplay {
        async fn size(&mut self) -> DesktopSize {
            self.0
        }

        async fn updates(&mut self, _: DisplayContext) -> ServerResult<Box<dyn RdpServerDisplayUpdates>> {
            pending().await
        }

        async fn monitor_count(&mut self) -> u32 {
            2
        }
    }

    #[tokio::test]
    async fn cancelling_bound_display_call_restores_authenticated_display() {
        let expected = DesktopSize {
            width: 1280,
            height: 720,
        };
        let bound = Arc::new(StdMutex::new(BoundDisplayState {
            display: Some(Box::new(PendingDisplay)),
            ..BoundDisplayState::default()
        }));
        let mut slot = BoundDisplaySlot::new(Box::new(FixedDisplay(expected)), Arc::clone(&bound));

        assert!(tokio::time::timeout(Duration::ZERO, slot.size()).await.is_err());
        assert!(bound.lock().expect("bound display lock poisoned").display.is_some());
    }

    #[tokio::test]
    async fn bound_display_forwards_monitor_count() {
        let bound = Arc::new(StdMutex::new(BoundDisplayState {
            display: Some(Box::new(FixedDisplay(DesktopSize {
                width: 1280,
                height: 720,
            }))),
            ..BoundDisplayState::default()
        }));
        let mut slot = BoundDisplaySlot::new(Box::new(PendingDisplay), Arc::clone(&bound));
        assert_eq!(slot.monitor_count().await, 2);
        bound.lock().unwrap().clear();
        assert_eq!(slot.monitor_count().await, 1);
    }

    #[tokio::test]
    async fn cancelling_connection_drops_bound_resources_and_credentials() {
        let display = Arc::new(StdMutex::new(BoundDisplayState {
            display: Some(Box::new(PendingDisplay)),
            ..BoundDisplayState::default()
        }));
        let input: Arc<StdMutex<Option<Box<dyn RdpServerInputHandler>>>> =
            Arc::new(StdMutex::new(Some(Box::new(NoopInput))));
        let credentials = Arc::new(StdMutex::new(Some(Credentials {
            username: "alice".to_owned(),
            password: "secret".to_owned(),
            domain: None,
        })));
        let connection = async {
            let _binding = BoundConnectionGuard {
                display: Arc::clone(&display),
                input: Arc::clone(&input),
                credentials: Arc::clone(&credentials),
            };
            pending::<()>().await;
        };
        assert!(tokio::time::timeout(Duration::ZERO, connection).await.is_err());
        assert!(display.lock().unwrap().display.is_none());
        assert!(input.lock().unwrap().is_none());
        assert!(credentials.lock().unwrap().is_none());
    }

    #[test]
    fn a_cleared_connection_cannot_restore_an_old_display_lease() {
        let display = Arc::new(StdMutex::new(BoundDisplayState {
            display: Some(Box::new(PendingDisplay)),
            ..BoundDisplayState::default()
        }));
        let lease = BoundDisplayLease::take(&display).unwrap();
        display.lock().unwrap().clear();
        drop(lease);
        assert!(display.lock().unwrap().display.is_none());
    }

    #[tokio::test]
    async fn run_connection_releases_the_static_channels() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        struct ResourceFactory(Arc<AtomicBool>);
        impl StaticChannelFactory for ResourceFactory {
            fn attach(&self, acceptor: &mut Acceptor) {
                acceptor.attach_static_channel(ResourceChannel(Arc::clone(&self.0)));
            }
        }

        let released = Arc::new(AtomicBool::new(false));
        let mut server = RdpServer::builder()
            .with_addr(([127, 0, 0, 1], 0))
            .with_no_security()
            .with_no_input()
            .with_no_display()
            .with_static_channel_factory(Box::new(ResourceFactory(Arc::clone(&released))))
            .build();

        // The client negotiates and then vanishes, so the connection ends in
        // finalization, after its channel backends were built: the path an
        // embedder's accept loop sees when a client drops mid-handshake.
        let (mut client, server_side) = tokio::io::duplex(4096);
        let client = async move {
            let request = nego::ConnectionRequest {
                nego_data: None,
                flags: nego::RequestFlags::empty(),
                protocol: nego::SecurityProtocol::empty(),
                correlation_info: None,
            };
            let request = encode_vec(&X224(request)).expect("encode connection request");
            client.write_all(&request).await.expect("send connection request");
            let mut confirm = [0u8; 128];
            let read = client.read(&mut confirm).await.expect("read connection confirm");
            let _ = decode::<X224<nego::ConnectionConfirm>>(&confirm[..read]).expect("server answered the negotiation");
        };
        let _ = tokio::join!(server.run_connection(server_side), client);

        assert!(
            released.load(Ordering::Relaxed),
            "the channel backends of a finished connection must be released, not held until the next client"
        );
    }
}

/// The server role must drive [`CliprdrServer::drive_timeouts`] on a timer; see
/// [`CLIPRDR_DRIVE_TIMEOUTS_INTERVAL`].
#[cfg(test)]
mod cliprdr_timeout_tests {
    use core::any::TypeId;
    use core::net::Ipv4Addr;

    use ironrdp_cliprdr::Cliprdr;
    use ironrdp_cliprdr::backend::CliprdrBackend;
    use ironrdp_cliprdr::pdu::{
        Capabilities, ClipboardFormat, ClipboardFormatId, ClipboardFormatName, ClipboardGeneralCapabilityFlags,
        ClipboardPdu, ClipboardProtocolVersion, FileContentsRequest, FileContentsResponse, FormatDataRequest,
        FormatDataResponse, FormatList, LockDataId,
    };
    use ironrdp_core::{Encode as _, WriteCursor, impl_as_any};

    use super::cliprdr_error_tests::CapturingWriter;
    use super::*;

    /// The clipboard channel dates locks from [`CliprdrBackend::now_ms`], so the
    /// test owns the clock rather than sleeping.
    #[derive(Debug)]
    struct ClockBackend(Arc<AtomicU64>);

    impl_as_any!(ClockBackend);

    impl CliprdrBackend for ClockBackend {
        fn temporary_directory(&self) -> &str {
            "."
        }

        fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
            ClipboardGeneralCapabilityFlags::CAN_LOCK_CLIPDATA
                | ClipboardGeneralCapabilityFlags::STREAM_FILECLIP_ENABLED
                | ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
        }

        fn on_ready(&mut self) {}
        fn on_request_format_list(&mut self) {}
        fn on_process_negotiated_capabilities(&mut self, _: ClipboardGeneralCapabilityFlags) {}
        fn on_remote_copy(&mut self, _: &[ClipboardFormat]) {}
        fn on_format_data_request(&mut self, _: FormatDataRequest) {}
        fn on_format_data_response(&mut self, _: FormatDataResponse<'_>) {}
        fn on_file_contents_request(&mut self, _: FileContentsRequest) {}
        fn on_file_contents_response(&mut self, _: FileContentsResponse<'_>) {}
        fn on_lock(&mut self, _: LockDataId) {}
        fn on_unlock(&mut self, _: LockDataId) {}

        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn encode_pdu(pdu: &ClipboardPdu<'_>) -> Vec<u8> {
        let mut buf = vec![0u8; pdu.size()];
        pdu.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf
    }

    fn capabilities_buf() -> Vec<u8> {
        encode_pdu(&ClipboardPdu::Capabilities(Capabilities::new(
            ClipboardProtocolVersion::V2,
            ClipboardGeneralCapabilityFlags::CAN_LOCK_CLIPDATA
                | ClipboardGeneralCapabilityFlags::STREAM_FILECLIP_ENABLED
                | ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES,
        )))
    }

    fn format_list_buf(formats: &[ClipboardFormat]) -> Vec<u8> {
        encode_pdu(&ClipboardPdu::FormatList(
            FormatList::new_unicode(formats, true).unwrap(),
        ))
    }

    fn file_format_list_buf() -> Vec<u8> {
        format_list_buf(&[ClipboardFormat {
            id: ClipboardFormatId(49171),
            name: Some(ClipboardFormatName::new("FileGroupDescriptorW")),
        }])
    }

    fn text_format_list_buf() -> Vec<u8> {
        format_list_buf(&[ClipboardFormat {
            id: ClipboardFormatId::CF_UNICODETEXT,
            name: None,
        }])
    }

    fn server_with_cliprdr(clock: &Arc<AtomicU64>) -> (RdpServer, ConnectionState) {
        let cliprdr: CliprdrServer = Cliprdr::with_lock_timeouts(
            Box::new(ClockBackend(Arc::clone(clock))),
            Duration::from_millis(100),
            Duration::from_secs(60 * 60),
        );

        let server = RdpServer::builder()
            .with_addr((Ipv4Addr::LOCALHOST, 0))
            .with_no_security()
            .with_no_input()
            .with_no_display()
            .build();

        let mut conn = ConnectionState::default();
        conn.static_channels.insert(cliprdr);
        // Returns the *previous* id, so `None` is the expected first attach.
        conn.static_channels
            .attach_channel_id(TypeId::of::<CliprdrServer>(), 1004);

        (server, conn)
    }

    /// An expired lock is released once its inactivity timeout elapses -- but
    /// only because something drove the sweep.
    #[tokio::test]
    async fn an_expired_lock_is_released_when_the_sweep_is_driven() {
        let clock = Arc::new(AtomicU64::new(0));
        let (mut server, mut conn) = server_with_cliprdr(&clock);

        let cliprdr = conn.get_svc_processor::<CliprdrServer>().unwrap();
        cliprdr.process(&capabilities_buf()).unwrap();
        // Files on the remote clipboard make the channel lock it (2.2.4.1).
        let messages = cliprdr.process(&file_format_list_buf()).unwrap();
        assert!(
            messages.len() >= 2,
            "a file FormatList must answer FormatListResponse AND send LockData, got {} message(s)",
            messages.len()
        );

        // The remote clipboard changes: the lock expires but is deliberately
        // NOT released yet, because downloads from it may still be in flight.
        conn.get_svc_processor::<CliprdrServer>()
            .unwrap()
            .process(&text_format_list_buf())
            .unwrap();

        let mut writer = CapturingWriter::default();

        server
            .drive_cliprdr_timeouts(&mut conn, &mut writer, 1002)
            .await
            .unwrap();
        assert!(
            writer.0.is_empty(),
            "a lock that expired 0ms ago is still inside its inactivity window"
        );

        clock.store(500, Ordering::SeqCst);
        server
            .drive_cliprdr_timeouts(&mut conn, &mut writer, 1002)
            .await
            .unwrap();
        assert!(
            !writer.0.is_empty(),
            "past the inactivity timeout the sweep must emit an Unlock PDU; \
             an empty write means the server leaks the lock for the rest of the session"
        );
    }

    /// A session without a clipboard channel must not be an error path: the
    /// timer fires for every connection.
    #[tokio::test]
    async fn a_session_without_a_clipboard_channel_sweeps_quietly() {
        let mut server = RdpServer::builder()
            .with_addr((Ipv4Addr::LOCALHOST, 0))
            .with_no_security()
            .with_no_input()
            .with_no_display()
            .build();
        let mut conn = ConnectionState::default();

        let mut writer = CapturingWriter::default();
        server
            .drive_cliprdr_timeouts(&mut conn, &mut writer, 1002)
            .await
            .unwrap();
        assert!(writer.0.is_empty());
    }
}
