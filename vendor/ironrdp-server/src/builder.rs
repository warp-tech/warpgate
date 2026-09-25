use core::net::SocketAddr;
use core::sync::atomic::{AtomicBool, AtomicU32};
use std::sync::Arc;

use anyhow::Result;
use ironrdp_pdu::rdp::capability_sets::{BitmapCodecs, server_codecs_capabilities};
use tokio_rustls::TlsAcceptor;

use super::clipboard::CliprdrServerFactory;
use super::display::{DesktopSize, RdpServerDisplay};
#[cfg(feature = "egfx")]
use super::gfx::GfxServerFactory;
use super::handler::{KeyboardEvent, MouseEvent, RdpServerInputHandler};
use super::server::{ConnectionHandler, CredentialValidator, RdpServer, RdpServerOptions, RdpServerSecurity};
use crate::{DisplayUpdate, RdpServerDisplayUpdates, SoundServerFactory};

pub struct WantsAddr {}
pub struct WantsSecurity {
    addr: SocketAddr,
}
pub struct WantsHandler {
    addr: SocketAddr,
    security: RdpServerSecurity,
}
pub struct WantsDisplay {
    addr: SocketAddr,
    security: RdpServerSecurity,
    handler: Box<dyn RdpServerInputHandler>,
}
pub struct BuilderDone {
    addr: SocketAddr,
    security: RdpServerSecurity,
    codecs: BitmapCodecs,
    max_request_size: u32,
    handler: Box<dyn RdpServerInputHandler>,
    display: Box<dyn RdpServerDisplay>,
    cliprdr_factory: Option<Box<dyn CliprdrServerFactory>>,
    sound_factory: Option<Box<dyn SoundServerFactory>>,
    connection_handler: Option<Box<dyn ConnectionHandler>>,
    credential_validator: Option<Arc<dyn CredentialValidator>>,
    #[cfg(feature = "egfx")]
    gfx_factory: Option<Box<dyn GfxServerFactory>>,
    display_suppressed: Option<Arc<AtomicBool>>,
    autodetect_rtt: Option<Arc<AtomicU32>>,
    honor_client_desktop_size: bool,
}

pub struct RdpServerBuilder<State> {
    state: State,
}

impl RdpServerBuilder<WantsAddr> {
    pub fn new() -> Self {
        Self { state: WantsAddr {} }
    }

    #[expect(clippy::unused_self)] // ensuring state transition from WantsAddr
    pub fn with_addr(self, addr: impl Into<SocketAddr>) -> RdpServerBuilder<WantsSecurity> {
        RdpServerBuilder {
            state: WantsSecurity { addr: addr.into() },
        }
    }
}

impl Default for RdpServerBuilder<WantsAddr> {
    fn default() -> Self {
        Self::new()
    }
}

impl RdpServerBuilder<WantsSecurity> {
    pub fn with_no_security(self) -> RdpServerBuilder<WantsHandler> {
        RdpServerBuilder {
            state: WantsHandler {
                addr: self.state.addr,
                security: RdpServerSecurity::None,
            },
        }
    }

    pub fn with_tls(self, acceptor: impl Into<TlsAcceptor>) -> RdpServerBuilder<WantsHandler> {
        RdpServerBuilder {
            state: WantsHandler {
                addr: self.state.addr,
                security: RdpServerSecurity::Tls(acceptor.into()),
            },
        }
    }

    pub fn with_hybrid(self, acceptor: impl Into<TlsAcceptor>, pub_key: Vec<u8>) -> RdpServerBuilder<WantsHandler> {
        RdpServerBuilder {
            state: WantsHandler {
                addr: self.state.addr,
                security: RdpServerSecurity::Hybrid((acceptor.into(), pub_key)),
            },
        }
    }
}

impl RdpServerBuilder<WantsHandler> {
    pub fn with_input_handler<H>(self, handler: H) -> RdpServerBuilder<WantsDisplay>
    where
        H: RdpServerInputHandler + 'static,
    {
        RdpServerBuilder {
            state: WantsDisplay {
                addr: self.state.addr,
                security: self.state.security,
                handler: Box::new(handler),
            },
        }
    }

    pub fn with_no_input(self) -> RdpServerBuilder<WantsDisplay> {
        RdpServerBuilder {
            state: WantsDisplay {
                addr: self.state.addr,
                security: self.state.security,
                handler: Box::new(NoopInputHandler),
            },
        }
    }
}

impl RdpServerBuilder<WantsDisplay> {
    pub fn with_display_handler<D>(self, display: D) -> RdpServerBuilder<BuilderDone>
    where
        D: RdpServerDisplay + 'static,
    {
        RdpServerBuilder {
            state: BuilderDone {
                addr: self.state.addr,
                security: self.state.security,
                handler: self.state.handler,
                display: Box::new(display),
                sound_factory: None,
                cliprdr_factory: None,
                connection_handler: None,
                credential_validator: None,
                codecs: server_codecs_capabilities(&[]).expect("can't panic for &[]"),
                max_request_size: RdpServerOptions::DEFAULT_MAX_REQUEST_SIZE,
                #[cfg(feature = "egfx")]
                gfx_factory: None,
                display_suppressed: None,
                autodetect_rtt: None,
                honor_client_desktop_size: false,
            },
        }
    }

    pub fn with_no_display(self) -> RdpServerBuilder<BuilderDone> {
        RdpServerBuilder {
            state: BuilderDone {
                addr: self.state.addr,
                security: self.state.security,
                handler: self.state.handler,
                display: Box::new(NoopDisplay),
                sound_factory: None,
                cliprdr_factory: None,
                connection_handler: None,
                credential_validator: None,
                codecs: server_codecs_capabilities(&[]).expect("can't panic for &[]"),
                max_request_size: RdpServerOptions::DEFAULT_MAX_REQUEST_SIZE,
                #[cfg(feature = "egfx")]
                gfx_factory: None,
                display_suppressed: None,
                autodetect_rtt: None,
                honor_client_desktop_size: false,
            },
        }
    }
}

impl RdpServerBuilder<BuilderDone> {
    pub fn with_cliprdr_factory(mut self, cliprdr_factory: Option<Box<dyn CliprdrServerFactory>>) -> Self {
        self.state.cliprdr_factory = cliprdr_factory;
        self
    }

    pub fn with_sound_factory(mut self, sound: Option<Box<dyn SoundServerFactory>>) -> Self {
        self.state.sound_factory = sound;
        self
    }

    /// Configure EGFX (Graphics Pipeline Extension) for H.264 video streaming.
    #[cfg(feature = "egfx")]
    pub fn with_gfx_factory(mut self, gfx_factory: Option<Box<dyn GfxServerFactory>>) -> Self {
        self.state.gfx_factory = gfx_factory;
        self
    }

    pub fn with_bitmap_codecs(mut self, codecs: BitmapCodecs) -> Self {
        self.state.codecs = codecs;
        self
    }

    /// Sets the [MultifragmentUpdate] maximum reassembly buffer size advertised
    /// during capability exchange.
    ///
    /// Defaults to [`RdpServerOptions::DEFAULT_MAX_REQUEST_SIZE`] (8 MB).
    ///
    /// [MultifragmentUpdate]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/01717954-716a-424d-af35-28fb2b86df89
    pub fn with_max_request_size(mut self, max_request_size: u32) -> Self {
        self.state.max_request_size = max_request_size;
        self
    }

    /// Set a handler for connection lifecycle events (accept filtering,
    /// post-disconnect cleanup).
    pub fn with_connection_handler(mut self, handler: Option<Box<dyn ConnectionHandler>>) -> Self {
        self.state.connection_handler = handler;
        self
    }

    /// Share the server's "display suppressed" flag with the display
    /// backend before construction.
    ///
    /// The flag is `true` while the connected client has sent
    /// `SuppressOutput { desktop_rect: None }` (e.g., mstsc minimized).
    /// Display backends that want to skip frame emission while the
    /// client is minimized create one `Arc<AtomicBool>` in the
    /// application, hand a clone to the display, and pass the same
    /// `Arc` here so the server's per-connection PDU handler writes to
    /// the same instance the backend reads.
    ///
    /// When this is not called, the server allocates its own internal
    /// flag (still readable via [`RdpServer::display_suppressed_handle`])
    /// — useful when the backend can call `display_suppressed_handle()`
    /// after construction to obtain a handle, rather than sharing one in.
    pub fn with_display_suppressed_handle(mut self, handle: Arc<AtomicBool>) -> Self {
        self.state.display_suppressed = Some(handle);
        self
    }

    /// Negotiate each session at the desktop size the client requests in its
    /// Client Core Data, rather than the size reported by the display handler.
    ///
    /// The client's requested resolution is only carried in the GCC Client
    /// Core Data of the connection handshake; the size echoed back in the
    /// client's Confirm Active is the value it copied from the server's Demand
    /// Active (per [MS-RDPBCGR] 2.2.1.13.2) and so cannot reveal what the
    /// client asked for. With this enabled the acceptor adopts the requested
    /// size (when within the protocol-legal range) before Demand Active is
    /// sent, so the session starts at that size with no Deactivation-
    /// Reactivation resize. The display handler observes the negotiated size
    /// through [`RdpServerDisplay::request_initial_size`].
    ///
    /// Defaults to `false`, enforcing the size reported by the display handler.
    ///
    /// # Precondition
    ///
    /// Only enable this with a [`RdpServerDisplay`] whose
    /// [`request_initial_size`] actually adopts (or at least intersects) the
    /// size it is given: the acceptor negotiates the client's size, but the
    /// server still builds its framebuffer/encoder from the size the display
    /// handler reports. A fixed-size handler that ignores the requested size
    /// can produce a mismatch that drops the client. Leave this disabled when
    /// the display handler serves a fixed framebuffer.
    ///
    /// [`request_initial_size`]: crate::RdpServerDisplay::request_initial_size
    pub fn with_honor_client_desktop_size(mut self, honor: bool) -> Self {
        self.state.honor_client_desktop_size = honor;
        self
    }

    /// Set a credential validator for TLS-mode connections.
    ///
    /// When set, credentials received from the client during
    /// `SecureSettingsExchange` (`ClientInfoPdu`) are passed to this
    /// validator before the session is established. Rejection or a backend
    /// error closes the connection. Pass `None` (the default) to skip
    /// validation entirely.
    ///
    /// Not used for CredSSP/Hybrid connections (those use pre-loaded
    /// credentials for NTLM challenge-response).
    pub fn with_credential_validator(mut self, validator: Option<Arc<dyn CredentialValidator>>) -> Self {
        self.state.credential_validator = validator;
        self
    }

    /// Inject a shared NetworkAutoDetect RTT handle (milliseconds, `u32::MAX`
    /// until the first measurement). The server writes the latest measured RTT
    /// to the same instance the backend reads. When not called, the server
    /// allocates its own (still readable via
    /// [`RdpServer::autodetect_rtt_handle`]). The value stays `u32::MAX` unless
    /// auto-detect is enabled via [`RdpServer::enable_autodetect`].
    pub fn with_autodetect_rtt_handle(mut self, handle: Arc<AtomicU32>) -> Self {
        self.state.autodetect_rtt = Some(handle);
        self
    }

    pub fn build(self) -> RdpServer {
        let mut server = RdpServer::new(
            RdpServerOptions {
                addr: self.state.addr,
                security: self.state.security,
                codecs: self.state.codecs,
                max_request_size: self.state.max_request_size,
                honor_client_desktop_size: self.state.honor_client_desktop_size,
            },
            self.state.handler,
            self.state.display,
            self.state.sound_factory,
            self.state.cliprdr_factory,
            self.state.connection_handler,
            #[cfg(feature = "egfx")]
            self.state.gfx_factory,
            self.state.display_suppressed,
            self.state.autodetect_rtt,
        );
        server.set_credential_validator(self.state.credential_validator);
        server
    }
}

struct NoopInputHandler;

impl RdpServerInputHandler for NoopInputHandler {
    fn keyboard(&mut self, _: KeyboardEvent) {}
    fn mouse(&mut self, _: MouseEvent) {}
}

struct NoopDisplayUpdates;

#[async_trait::async_trait]
impl RdpServerDisplayUpdates for NoopDisplayUpdates {
    async fn next_update(&mut self) -> Result<Option<DisplayUpdate>> {
        let () = core::future::pending().await;
        unreachable!()
    }
}

struct NoopDisplay;

#[async_trait::async_trait]
impl RdpServerDisplay for NoopDisplay {
    async fn size(&mut self) -> DesktopSize {
        DesktopSize { width: 0, height: 0 }
    }

    async fn updates(&mut self) -> Result<Box<dyn RdpServerDisplayUpdates>> {
        Ok(Box::new(NoopDisplayUpdates {}))
    }
}
