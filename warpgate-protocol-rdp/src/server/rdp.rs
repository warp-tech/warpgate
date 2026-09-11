//! Viewer-facing RDP server: runs IronRDP's server state machine (including TLS) over
//! the accepted viewer socket, and bridges everything else to the owning Warpgate session
//! over [`Input`]/[`Event`] channels.
//!
//! Warpgate owns the listening socket, the session, authentication and recording; this
//! module owns only the RDP server protocol and its TLS.

use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroUsize};
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use ironrdp::displaycontrol::pdu::{DisplayControlMonitorLayout, MonitorLayoutEntry};
use ironrdp_server::tokio_rustls::TlsAcceptor;
use ironrdp_server::tokio_rustls::rustls::ServerConfig as TlsServerConfig;
use ironrdp_server::{
    BitmapUpdate, CredentialDecision, CredentialValidationError, CredentialValidator, Credentials,
    DesktopSize, DisplayUpdate, KeyboardEvent, MouseEvent, PixelFormat, RdpServer,
    RdpServerDisplay, RdpServerDisplayUpdates, RdpServerInputHandler,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, mpsc, oneshot};
use tracing::{Instrument as _, Span, debug, warn};
use warpgate_core::{DesktopInput, Scancode};
use warpgate_desktop_ui::DEFAULT_SIZE;

use super::clipboard::ViewerClipboard;
use super::protocol::{AuthVerdict, Event, Input};

/// Upper bound on a single framebuffer update, and so on the desktop size we will accept
/// from a viewer: a full-screen BGRA frame has to stay a sane allocation.
const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
/// Smallest desktop MS-RDPBCGR allows a client to ask for; also keeps the hold screen from
/// being asked to render into a degenerate framebuffer.
const MIN_DESKTOP_DIM: u16 = 200;
/// Largest desktop dimension we will honour.
const MAX_DESKTOP_DIM: u16 = 8192;

/// Run the RDP server on a dedicated thread, resolving to its result.
///
/// `RdpServer::run_connection` holds `Rc`s across await points, so its future is not
/// `Send` and cannot join the multi-threaded runtime. It gets a current-thread runtime of
/// its own instead; everything it exchanges with the session (the duplex transport and the
/// two channels) is `Send`, so only the state machine itself stays pinned here.
pub fn run_on_thread<S>(
    stream: S,
    cert_pem: String,
    key_pem: String,
    size: (u16, u16),
    out_tx: mpsc::UnboundedSender<Event>,
    in_rx: mpsc::Receiver<Input>,
) -> oneshot::Receiver<Result<()>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    let (done_tx, done_rx) = oneshot::channel();
    // The session span is thread-local, so it has to be carried over by hand: without it
    // nothing this server logs is attributed to the session.
    let span = Span::current();
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                let _ = done_tx.send(Err(anyhow::Error::new(error).context("RDP server runtime")));
                return;
            }
        };
        let result =
            runtime.block_on(run(stream, cert_pem, key_pem, size, out_tx, in_rx).instrument(span));
        let _ = done_tx.send(result);
    });
    done_rx
}

/// Run the RDP server state machine against an accepted viewer connection.
async fn run<S>(
    stream: S,
    cert_pem: String,
    key_pem: String,
    size: (u16, u16),
    out_tx: mpsc::UnboundedSender<Event>,
    in_rx: mpsc::Receiver<Input>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    // `ironrdp-server` pulls in tokio-rustls with the aws-lc-rs provider (its default);
    // install it as the process default so `ServerConfig::builder()` works.
    let _ = ironrdp_server::tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
        .install_default();

    let tls = build_tls_acceptor(&cert_pem, &key_pem)?;

    let (frame_tx, frame_rx) = mpsc::channel::<DisplayUpdate>(256);
    let size = Arc::new(Mutex::new(DesktopSize {
        width: size.0,
        height: size.1,
    }));

    let clipboard = ViewerClipboard::new(out_tx.clone());

    let router = tokio::spawn(
        route_input(
            in_rx,
            frame_tx,
            DisplayRouteState {
                size: Arc::clone(&size),
                out: out_tx.clone(),
            },
            clipboard.clone(),
        )
        .in_current_span(),
    );

    let display = DisplayHandler {
        size,
        initial_size_negotiated: false,
        updates: Arc::new(Mutex::new(frame_rx)),
        out: out_tx.clone(),
    };
    let input = InputHandler {
        out: out_tx.clone(),
        x: 0,
        y: 0,
        buttons: 0,
    };
    let validator: Arc<dyn CredentialValidator> = Arc::new(Validator {
        out: out_tx.clone(),
    });

    let mut server = RdpServer::builder()
        // `addr` is only used by `RdpServer::run()` (which binds a listener); we drive
        // `run_connection()` directly with the accepted stream, so it's a harmless
        // placeholder here.
        .with_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .with_tls(tls)
        .with_input_handler(input)
        .with_display_handler(display)
        // Opt in to calling `request_initial_size`; without it the acceptor ignores the
        // viewer's requested resolution and pins the session to `size()`'s seed.
        .with_honor_client_desktop_size(true)
        .with_credential_validator(Some(validator))
        .with_cliprdr_factory(Some(Box::new(clipboard)))
        .build();

    if let Err(error) = server.run_connection(stream).await {
        // A session-level error (e.g. viewer disconnect) is not a failure of the gateway:
        // report it and shut down cleanly.
        warn!(error = %format!("{error:#}"), "RDP session ended with error");
    }

    router.abort();
    Ok(())
}

/// Build a rustls `TlsAcceptor` from PEM cert + key.
fn build_tls_acceptor(cert_pem: &str, key_pem: &str) -> Result<TlsAcceptor> {
    let mut cert_reader = cert_pem.as_bytes();
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("parsing TLS certificate PEM")?;
    if certs.is_empty() {
        anyhow::bail!("no certificate found in TLS certificate PEM");
    }

    let mut key_reader = key_pem.as_bytes();
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("parsing TLS private key PEM")?
        .context("no private key found in TLS private key PEM")?;

    let config = TlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building rustls server config")?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Shared display state used while routing Warpgate framebuffer messages.
struct DisplayRouteState {
    size: Arc<Mutex<DesktopSize>>,
    out: mpsc::UnboundedSender<Event>,
}

/// Route Warpgate's messages to the display backend (framebuffer updates) and the
/// credential validator (auth decisions).
async fn route_input(
    mut rx: mpsc::Receiver<Input>,
    frame_tx: mpsc::Sender<DisplayUpdate>,
    display: DisplayRouteState,
    clipboard: ViewerClipboard,
) {
    while let Some(msg) = rx.recv().await {
        match msg {
            Input::Frame {
                x,
                y,
                width,
                height,
                data,
            } => {
                if let Some(update) = frame_to_update(x, y, width, height, data)
                    && frame_tx.send(update).await.is_err()
                {
                    break;
                }
            }
            Input::Resize { width, height } => {
                let new = DesktopSize { width, height };
                // A resize costs a deactivation-reactivation: the server tears the session
                // down to the acceptor and renegotiates capabilities with the viewer. Skip
                // it when the size is unchanged so an already-correct session is never
                // disturbed.
                let previous = core::mem::replace(&mut *display.size.lock().await, new);
                if previous == new {
                    continue;
                }
                debug!(?previous, ?new, "viewer surface resized");
                if frame_tx.send(DisplayUpdate::Resize(new)).await.is_err() {
                    break;
                }
                let _ = display.out.send(Event::Size {
                    width: new.width,
                    height: new.height,
                });
            }
            Input::Clipboard(text) => clipboard.offer(text),
            Input::Shutdown => break,
        }
    }
}

/// Convert a BGRA framebuffer rectangle into an IronRDP bitmap update. Returns `None` for
/// degenerate or short buffers rather than panicking downstream.
fn frame_to_update(x: u16, y: u16, width: u16, height: u16, data: Bytes) -> Option<DisplayUpdate> {
    let nz_width = NonZeroU16::new(width)?;
    let nz_height = NonZeroU16::new(height)?;
    let stride = NonZeroUsize::new(usize::from(width) * 4)?;
    if data.len() < usize::from(width) * usize::from(height) * 4 {
        warn!(width, height, len = data.len(), "ignoring undersized frame");
        return None;
    }
    Some(DisplayUpdate::Bitmap(BitmapUpdate {
        x,
        y,
        width: nz_width,
        height: nz_height,
        // The client emits bytes in B,G,R,A memory order (see its raw-image encoder),
        // which is exactly `PixelFormat::BgrA32`.
        format: PixelFormat::BgrA32,
        data,
        stride,
    }))
}

/// Bound a viewer-supplied desktop size. This arrives during the capability exchange,
/// before the credential validator has run, and drives full-screen framebuffer
/// allocations of `width * height * 4`, so it is untrusted input. Sizes whose full-screen
/// frame would exceed [`MAX_FRAME_BYTES`] fall back to the default rather than being
/// silently squashed to a different aspect ratio.
fn clamp_desktop_size(requested: DesktopSize) -> DesktopSize {
    let size = DesktopSize {
        width: requested.width.clamp(MIN_DESKTOP_DIM, MAX_DESKTOP_DIM),
        height: requested.height.clamp(MIN_DESKTOP_DIM, MAX_DESKTOP_DIM),
    };
    let frame_len = usize::from(size.width) * usize::from(size.height) * 4;
    if frame_len > MAX_FRAME_BYTES {
        warn!(
            width = size.width,
            height = size.height,
            "viewer requested a desktop too large to frame; using the default"
        );
        return DesktopSize {
            width: DEFAULT_SIZE.0,
            height: DEFAULT_SIZE.1,
        };
    }
    size
}

fn primary_monitor_size(layout: &DisplayControlMonitorLayout) -> Option<DesktopSize> {
    let monitor = layout
        .monitors()
        .iter()
        .find(|monitor| monitor.is_primary())?;
    let (width, height) = monitor.dimensions();
    let (width, height) = MonitorLayoutEntry::adjust_display_size(width, height);
    Some(clamp_desktop_size(DesktopSize {
        width: u16::try_from(width).ok()?,
        height: u16::try_from(height).ok()?,
    }))
}

/// Display backend: hands the IronRDP server a receiver of framebuffer updates fed by
/// Warpgate.
struct DisplayHandler {
    /// `size()` is re-queried on every deactivation-reactivation to build the new
    /// `UpdateEncoder`, so this has to track the size last renegotiated with the client,
    /// not the one the session started at.
    size: Arc<Mutex<DesktopSize>>,
    /// Whether the initial viewer-driven size has been adopted. Gates
    /// [`Self::request_initial_size`] so reactivations keep the committed size instead of
    /// re-adopting a stale one the viewer echoes.
    initial_size_negotiated: bool,
    // Shared, not `take()`n: ironrdp-server calls `updates()` again after every
    // deactivation-reactivation (e.g. an mstsc / MS Remote Desktop resize), so a
    // one-shot receiver would fail the second connection with "already taken".
    updates: Arc<Mutex<mpsc::Receiver<DisplayUpdate>>>,
    out: mpsc::UnboundedSender<Event>,
}

#[async_trait::async_trait]
impl RdpServerDisplay for DisplayHandler {
    async fn size(&mut self) -> DesktopSize {
        *self.size.lock().await
    }

    /// Whatever this returns is what the session runs at; RDP lets the server dictate, and
    /// the viewer resizes to match.
    ///
    /// ironrdp-server also calls this on every deactivation-reactivation, passing the size
    /// the viewer echoes in its Confirm Active. That echo can lag the resolution Warpgate
    /// just negotiated — mstsc, growing the window, still reports the smaller previous size —
    /// and adopting it would rebuild the encoder below the frames Warpgate is about to send,
    /// so every larger tile hits the "bitmap exceeds desktop size" drop (a grow paints black,
    /// while a shrink still fits and looks fine). So the viewer's size is honoured only for
    /// the initial negotiation; from then on the committed size — driven by the target after
    /// a Display Control resize — is authoritative and the viewer conforms to it.
    async fn request_initial_size(&mut self, client_size: DesktopSize) -> DesktopSize {
        if self.initial_size_negotiated {
            let committed = *self.size.lock().await;
            debug!(
                ?client_size,
                ?committed,
                "reactivation: keeping committed size, viewer echo ignored"
            );
            return committed;
        }
        self.initial_size_negotiated = true;
        let size = clamp_desktop_size(client_size);
        debug!(?client_size, adopted = ?size, "initial viewer size negotiated");
        *self.size.lock().await = size;
        let _ = self.out.send(Event::Size {
            width: size.width,
            height: size.height,
        });
        size
    }

    async fn updates(&mut self) -> Result<Box<dyn RdpServerDisplayUpdates>> {
        // Hand out a fresh view over the shared receiver. Only one is active at a time
        // (the previous is dropped when its client loop ends before reactivation).
        Ok(Box::new(DisplayUpdatesReceiver {
            rx: self.updates.clone(),
        }))
    }

    fn request_layout(&mut self, layout: DisplayControlMonitorLayout) {
        let Some(size) = primary_monitor_size(&layout) else {
            return;
        };
        // ironrdp-server calls this from `spawn_blocking`, never on the runtime thread, which
        // is what makes blocking on the lock legal here.
        if *self.size.blocking_lock() == size {
            return;
        }
        debug!(requested = ?size, "viewer requested a dynamic resize");
        let _ = self.out.send(Event::ResizeRequest {
            width: size.width,
            height: size.height,
        });
    }
}

struct DisplayUpdatesReceiver {
    rx: Arc<Mutex<mpsc::Receiver<DisplayUpdate>>>,
}

#[async_trait::async_trait]
impl RdpServerDisplayUpdates for DisplayUpdatesReceiver {
    async fn next_update(&mut self) -> Result<Option<DisplayUpdate>> {
        // `mpsc::Receiver::recv` is cancellation-safe, as this trait requires; the guard
        // is released on cancel and no message is lost. `Resize` and the frames that follow
        // it share this one ordered channel, so the encoder is always resized before it is
        // handed a frame at the new size.
        Ok(self.rx.lock().await.recv().await)
    }
}

/// Credential validator: forwards the viewer's credentials to Warpgate and awaits its
/// verdict on a per-request reply channel.
struct Validator {
    out: mpsc::UnboundedSender<Event>,
}

#[async_trait::async_trait]
impl CredentialValidator for Validator {
    async fn validate(
        &self,
        credentials: &Credentials,
    ) -> Result<CredentialDecision, CredentialValidationError> {
        let (reply, verdict) = oneshot::channel();
        if self
            .out
            .send(Event::AuthRequest {
                username: credentials.username.clone(),
                password: credentials.password.clone(),
                reply,
            })
            .is_err()
        {
            // Warpgate hung up before we could ask.
            return Ok(CredentialDecision::Reject);
        }
        match verdict.await {
            Ok(AuthVerdict::StartSession) => Ok(CredentialDecision::Accept),
            // Explicit denial, or the control loop dropped the reply without answering.
            Ok(AuthVerdict::Deny) | Err(_) => Ok(CredentialDecision::Reject),
        }
    }
}

/// Input handler: normalises IronRDP keyboard/mouse events onto the shared
/// `DesktopInput` stream.
struct InputHandler {
    out: mpsc::UnboundedSender<Event>,
    x: u16,
    y: u16,
    buttons: u8,
}

impl InputHandler {
    fn emit_pointer(&self) {
        let _ = self.out.send(Event::Input(DesktopInput::Pointer {
            x: self.x,
            y: self.y,
            buttons: self.buttons,
        }));
    }

    fn send_key(&self, keysym: Option<u32>, scancode: Option<Scancode>, down: bool) {
        let _ = self.out.send(Event::Input(DesktopInput::Key {
            keysym,
            scancode,
            down,
        }));
    }

    fn set_button(&mut self, bit: u8, down: bool) {
        if down {
            self.buttons |= 1 << bit;
        } else {
            self.buttons &= !(1 << bit);
        }
        self.emit_pointer();
    }
}

impl RdpServerInputHandler for InputHandler {
    fn keyboard(&mut self, event: KeyboardEvent) {
        match event {
            KeyboardEvent::Pressed { code, extended } => {
                self.send_key(None, Some(Scancode { code, extended }), true);
            }
            KeyboardEvent::Released { code, extended } => {
                self.send_key(None, Some(Scancode { code, extended }), false);
            }
            KeyboardEvent::UnicodePressed(unit) => {
                self.send_key(Some(u32::from(unit)), None, true);
            }
            KeyboardEvent::UnicodeReleased(unit) => {
                self.send_key(Some(u32::from(unit)), None, false);
            }
            // Lock-key (caps/num/scroll) sync state; not propagated to the target.
            KeyboardEvent::Synchronize(_) => {}
        }
    }

    fn mouse(&mut self, event: MouseEvent) {
        match event {
            MouseEvent::Move { x, y } => {
                self.x = x;
                self.y = y;
                self.emit_pointer();
            }
            MouseEvent::LeftPressed => self.set_button(0, true),
            MouseEvent::LeftReleased => self.set_button(0, false),
            MouseEvent::MiddlePressed => self.set_button(1, true),
            MouseEvent::MiddleReleased => self.set_button(1, false),
            MouseEvent::RightPressed => self.set_button(2, true),
            MouseEvent::RightReleased => self.set_button(2, false),
            MouseEvent::Button4Pressed => self.set_button(3, true),
            MouseEvent::Button4Released => self.set_button(3, false),
            MouseEvent::Button5Pressed => self.set_button(4, true),
            MouseEvent::Button5Released => self.set_button(4, false),
            MouseEvent::VerticalScroll { value } => {
                let _ = self.out.send(Event::Input(DesktopInput::Wheel {
                    x: self.x,
                    y: self.y,
                    vertical: true,
                    delta: wheel_notches(value),
                }));
            }
            MouseEvent::Scroll { x, y } => {
                // High-resolution (ainput) 2D scroll: prefer the vertical axis.
                let (vertical, magnitude) = if y != 0 { (true, y) } else { (false, x) };
                if magnitude != 0 {
                    let _ = self.out.send(Event::Input(DesktopInput::Wheel {
                        x: self.x,
                        y: self.y,
                        vertical,
                        delta: i16::try_from(magnitude.signum()).unwrap_or(0),
                    }));
                }
            }
            MouseEvent::RelMove { x, y } => {
                self.x = self.x.saturating_add_signed(clamp_to_i16(x));
                self.y = self.y.saturating_add_signed(clamp_to_i16(y));
                self.emit_pointer();
            }
        }
    }
}

/// RDP carries wheel rotation in units of 120 per detent; Warpgate's shared `Wheel` input
/// is a notch count (re-multiplied by 120 downstream), so divide, preserving sign for
/// sub-detent high-resolution wheels.
const fn wheel_notches(value: i16) -> i16 {
    let notches = value / 120;
    if notches == 0 {
        value.signum()
    } else {
        notches
    }
}

fn clamp_to_i16(value: i32) -> i16 {
    value.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16
}

#[cfg(test)]
mod desktop_size_tests {
    use std::sync::Arc;

    use ironrdp::displaycontrol::pdu::{DisplayControlMonitorLayout, MonitorLayoutEntry};
    use tokio::sync::{Mutex, mpsc};

    use super::{
        DEFAULT_SIZE, DesktopSize, DisplayHandler, MAX_DESKTOP_DIM, MAX_FRAME_BYTES,
        MIN_DESKTOP_DIM, RdpServerDisplay, clamp_desktop_size, primary_monitor_size,
    };
    use crate::server::protocol::Event;

    fn size(width: u16, height: u16) -> DesktopSize {
        DesktopSize { width, height }
    }

    fn single_primary_layout(width: u32, height: u32) -> DisplayControlMonitorLayout {
        DisplayControlMonitorLayout::new(&[MonitorLayoutEntry::new_primary(width, height).unwrap()])
            .unwrap()
    }

    #[test]
    fn honours_a_reasonable_request() {
        assert_eq!(clamp_desktop_size(size(2560, 1440)), size(2560, 1440));
    }

    #[test]
    fn clamps_degenerate_and_oversized_dimensions() {
        assert_eq!(
            clamp_desktop_size(size(0, 0)),
            size(MIN_DESKTOP_DIM, MIN_DESKTOP_DIM)
        );
        // Clamped per dimension, and the resulting area still has to fit one frame.
        let clamped = clamp_desktop_size(size(u16::MAX, 240));
        assert_eq!(clamped, size(MAX_DESKTOP_DIM, 240));
    }

    #[test]
    fn falls_back_when_a_full_frame_would_not_fit() {
        // 8192x8192 BGRA is 256 MB, past MAX_FRAME_BYTES, so neither dimension is trusted.
        let fallback = clamp_desktop_size(size(MAX_DESKTOP_DIM, MAX_DESKTOP_DIM));
        assert_eq!(fallback, size(DEFAULT_SIZE.0, DEFAULT_SIZE.1));
        let frame_len = usize::from(fallback.width) * usize::from(fallback.height) * 4;
        assert!(frame_len <= MAX_FRAME_BYTES);
    }

    #[test]
    fn uses_primary_monitor_for_dynamic_layout() {
        let layout = DisplayControlMonitorLayout::new(&[
            MonitorLayoutEntry::new_primary(1920, 1080).unwrap(),
            MonitorLayoutEntry::new_secondary(1280, 720)
                .unwrap()
                .with_position(1920, 0)
                .unwrap(),
        ])
        .unwrap();

        assert_eq!(primary_monitor_size(&layout), Some(size(1920, 1080)));
    }

    #[test]
    fn normalizes_dynamic_layout_size() {
        let layout = single_primary_layout(1921, 1080);

        assert_eq!(primary_monitor_size(&layout), Some(size(1920, 1080)));
    }

    fn display_handler(
        committed: DesktopSize,
        initial_size_negotiated: bool,
    ) -> (DisplayHandler, mpsc::UnboundedReceiver<Event>) {
        let (_tx, rx) = mpsc::channel(1);
        let (out, events) = mpsc::unbounded_channel();
        let display = DisplayHandler {
            size: Arc::new(Mutex::new(committed)),
            initial_size_negotiated,
            updates: Arc::new(Mutex::new(rx)),
            out,
        };
        (display, events)
    }

    /// A layout at the committed size is noise; a different one is a request for the target.
    #[test]
    fn dynamic_layout_request_is_forwarded_to_the_target() {
        let (mut display, mut events) = display_handler(size(800, 600), true);

        display.request_layout(single_primary_layout(800, 600));
        assert!(events.try_recv().is_err());

        display.request_layout(single_primary_layout(1024, 768));
        assert!(matches!(
            events.try_recv(),
            Ok(Event::ResizeRequest {
                width: 1024,
                height: 768,
            })
        ));
    }

    #[tokio::test]
    async fn initial_size_adopts_the_viewer_request() {
        let (mut display, mut events) =
            display_handler(size(DEFAULT_SIZE.0, DEFAULT_SIZE.1), false);

        assert_eq!(
            display.request_initial_size(size(1024, 768)).await,
            size(1024, 768)
        );
        assert_eq!(display.size().await, size(1024, 768));
        assert!(matches!(
            events.try_recv(),
            Ok(Event::Size {
                width: 1024,
                height: 768,
            })
        ));
    }

    /// On reactivation the viewer can echo a size that lags the freshly negotiated one; the
    /// committed (target-driven) size must win, or a grow would rebuild the encoder too small
    /// and drop every oversized tile.
    #[tokio::test]
    async fn reactivation_keeps_the_committed_size() {
        let (mut display, mut events) = display_handler(size(1920, 1080), true);

        assert_eq!(
            display.request_initial_size(size(1024, 768)).await,
            size(1920, 1080)
        );
        assert_eq!(display.size().await, size(1920, 1080));
        assert!(events.try_recv().is_err());
    }
}
