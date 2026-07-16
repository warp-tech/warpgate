//! Standalone RDP **server** (viewer-facing) helper for Warpgate.
//!
//! Like the client-side `warpgate-rdp-helper`, this binary lives **outside** the
//! Warpgate cargo workspace. `ironrdp-server`'s acceptor/CredSSP stack pins
//! `picky`/`sspi` pre-release crates that conflict with both `russh` (in the
//! workspace) and the client helper's own IronRDP generation, and these
//! pre-releases cannot coexist in a single lockfile. Building the RDP server as a
//! separate process with its own lockfile sidesteps the conflict — the same
//! design Apache Guacamole uses with `guacd`.
//!
//! This helper terminates the RDP protocol toward a native viewer (mstsc /
//! FreeRDP). Warpgate accepts the viewer's TCP connection, registers the session,
//! and shuttles the raw bytes to this helper over a loopback TCP socket; the
//! helper runs the IronRDP server state machine (including TLS) on that socket and
//! bridges everything else to Warpgate over line-delimited JSON on stdio:
//!
//! - first line on **stdin**: a [`ServeConfig`] (loopback port, TLS cert/key, size)
//! - subsequent lines on **stdin**: [`ControlIn`] messages (auth decisions, framebuffer updates)
//! - lines on **stdout**: [`ControlOut`] messages (auth requests, viewer input, lifecycle)
//!
//! Warpgate owns the listening socket, the Warpgate session, authentication and
//! recording; this helper owns only the RDP server protocol + TLS, keeping all
//! IronRDP (and its conflicting crypto pins) confined to this process.

use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroUsize};
use std::os::fd::{FromRawFd, RawFd};
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use ironrdp_server::tokio_rustls::TlsAcceptor;
use ironrdp_server::tokio_rustls::rustls::ServerConfig as TlsServerConfig;
use ironrdp_server::{
    BitmapUpdate, CredentialDecision, CredentialValidationError, CredentialValidator, Credentials,
    DesktopSize, DisplayUpdate, KeyboardEvent, MouseEvent, PixelFormat, RdpServer,
    RdpServerDisplay, RdpServerDisplayUpdates, RdpServerInputHandler,
};
use tokio::io::{Stdin, Stdout};
use tokio::net::UnixStream as TokioUnixStream;
use tokio::sync::{Mutex, mpsc};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use tracing::warn;
use warpgate_rdp_ipc::server::{Event as ControlOut, Input as ControlIn, ServeConfig};

pub async fn entry() {
    // Logs MUST go to stderr — stdout is the line-delimited control channel. Keep them
    // minimal: Warpgate reads each line and re-logs it with its own timestamp, so the
    // helper's timestamp (and target) would just be redundant noise.
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .without_time()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    if let Err(error) = run().await {
        // Setup-level failure (bad config / TLS / loopback). Surface and exit non-zero.
        eprintln!("warpgate-rdp-helper serve: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    // Warpgate hands us our end of the RDP-transport socketpair as an inherited fd, passed
    // as the second CLI argument (`serve <fd>`).
    let raw_fd: RawFd = std::env::args()
        .nth(2)
        .context("missing RDP transport fd argument")?
        .parse()
        .context("parsing RDP transport fd argument")?;

    // `ironrdp-server` pulls in tokio-rustls with the aws-lc-rs provider (its
    // default); install it as the process default so `ServerConfig::builder()` works.
    let _ = ironrdp_server::tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
        .install_default();

    // Length-delimited framing on stdio; read the config frame first, then the control
    // channel. Frames can be a full-screen BGRA rect, so raise the size limit.
    let codec = || {
        LengthDelimitedCodec::builder()
            .max_frame_length(warpgate_rdp_ipc::MAX_FRAME_LEN)
            .new_codec()
    };
    let mut stdin_frames = FramedRead::new(tokio::io::stdin(), codec());
    let first = stdin_frames
        .next()
        .await
        .context("missing config frame on stdin")?
        .context("reading config frame")?;
    let config: ServeConfig =
        warpgate_rdp_ipc::decode_json(&first).context("parsing config frame")?;

    let (out_tx, out_rx) = mpsc::unbounded_channel::<ControlOut>();
    let (frame_tx, frame_rx) = mpsc::channel::<DisplayUpdate>(256);
    let (auth_tx, auth_rx) = mpsc::channel::<bool>(1);

    let stdout_frames = FramedWrite::new(tokio::io::stdout(), codec());
    let writer_handle = tokio::spawn(stdout_writer(stdout_frames, out_rx));
    let router_handle = tokio::spawn(stdin_router(stdin_frames, frame_tx, auth_tx));

    let tls = build_tls_acceptor(&config.cert_pem, &config.key_pem)?;

    // The inherited fd is our end of the socketpair — the raw RDP byte stream the IronRDP
    // server speaks over (Warpgate relays it to the viewer). Safety: Warpgate dup2'd this
    // fd into place before exec and passed us its number; nothing else owns it.
    #[allow(unsafe_code)]
    let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(raw_fd) };
    std_stream
        .set_nonblocking(true)
        .context("making the RDP transport non-blocking")?;
    let stream = TokioUnixStream::from_std(std_stream).context("wrapping the RDP transport")?;

    let display = DisplayHandler {
        width: config.width,
        height: config.height,
        updates: Arc::new(Mutex::new(frame_rx)),
    };
    let input = InputHandler {
        out: out_tx.clone(),
        x: 0,
        y: 0,
        buttons: 0,
    };
    let validator: Arc<dyn CredentialValidator> = Arc::new(Validator {
        out: out_tx.clone(),
        resp: Mutex::new(auth_rx),
    });

    let mut server = RdpServer::builder()
        // `addr` is only used by `RdpServer::run()` (which binds a listener); we
        // drive `run_connection()` directly with the loopback stream, so it's a
        // harmless placeholder here.
        .with_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .with_tls(tls)
        .with_input_handler(input)
        .with_display_handler(display)
        .with_credential_validator(Some(validator))
        .build();

    match server.run_connection(stream).await {
        Ok(()) => {}
        Err(error) => {
            // A session-level error (e.g. viewer disconnect) is not a helper
            // failure: report it and shut down cleanly.
            warn!(error = %format!("{error:#}"), "RDP session ended with error");
            let _ = out_tx.send(ControlOut::Error {
                message: format!("{error:#}"),
            });
        }
    }
    let _ = out_tx.send(ControlOut::Disconnected);

    // Drop every `ControlOut` sender so the writer drains and exits, then wait for
    // the final flush so Warpgate sees `disconnected` before our stdout closes.
    drop(out_tx);
    drop(server);
    router_handle.abort();
    let _ = writer_handle.await;

    Ok(())
}

/// Build a rustls `TlsAcceptor` from PEM cert + key supplied by Warpgate.
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

/// Drains `ControlOut` messages to stdout as line-delimited JSON.
async fn stdout_writer(
    mut wr: FramedWrite<Stdout, LengthDelimitedCodec>,
    mut rx: mpsc::UnboundedReceiver<ControlOut>,
) {
    let mut buf = Vec::new();
    while let Some(msg) = rx.recv().await {
        msg.encode_into(&mut buf);
        if wr.send(Bytes::copy_from_slice(&buf)).await.is_err() {
            break;
        }
    }
}

/// Reads `ControlIn` messages from stdin and routes them to the display backend
/// (framebuffer updates) and the credential validator (auth decisions).
async fn stdin_router(
    mut rd: FramedRead<Stdin, LengthDelimitedCodec>,
    frame_tx: mpsc::Sender<DisplayUpdate>,
    auth_tx: mpsc::Sender<bool>,
) {
    while let Some(frame) = rd.next().await {
        let Ok(frame) = frame else {
            break;
        };
        // `freeze()` is zero-copy; a `Frame`'s pixels become a slice of this buffer.
        let Some(msg) = ControlIn::decode(&frame.freeze()) else {
            warn!("ignoring invalid control message");
            continue;
        };
        match msg {
            ControlIn::AuthResponse { accept } => {
                let _ = auth_tx.send(accept).await;
            }
            ControlIn::Frame {
                x,
                y,
                width,
                height,
                data,
            } => {
                // `data` is raw BGRA now (binary IMAGE frame) — no base64 decode.
                if let Some(update) = frame_to_update(x, y, width, height, data) {
                    if frame_tx.send(update).await.is_err() {
                        break;
                    }
                }
            }
            ControlIn::Resize { width, height } => {
                if frame_tx
                    .send(DisplayUpdate::Resize(DesktopSize { width, height }))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            ControlIn::Shutdown => break,
        }
    }
}

/// Convert a BGRA framebuffer rectangle from Warpgate into an IronRDP bitmap update.
/// Returns `None` for degenerate or short buffers rather than panicking downstream.
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
        // The client helper emits bytes in B,G,R,A memory order (see its raw-image
        // emitter), which is exactly `PixelFormat::BgrA32`.
        format: PixelFormat::BgrA32,
        data,
        stride,
    }))
}

/// Display backend: hands the IronRDP server a receiver of framebuffer updates
/// fed (via the stdin router) by Warpgate.
struct DisplayHandler {
    width: u16,
    height: u16,
    // Shared, not `take()`n: ironrdp-server calls `updates()` again after every
    // deactivation-reactivation (e.g. an mstsc / MS Remote Desktop resize), so a
    // one-shot receiver would fail the second connection with "already taken".
    updates: Arc<Mutex<mpsc::Receiver<DisplayUpdate>>>,
}

#[async_trait::async_trait]
impl RdpServerDisplay for DisplayHandler {
    async fn size(&mut self) -> DesktopSize {
        // Called before authentication / before the target connects, so we return
        // the configured default; a `Resize` update follows once the real size is known.
        DesktopSize {
            width: self.width,
            height: self.height,
        }
    }

    async fn updates(&mut self) -> Result<Box<dyn RdpServerDisplayUpdates>> {
        // Hand out a fresh view over the shared receiver. Only one is active at a time
        // (the previous is dropped when its client loop ends before reactivation).
        Ok(Box::new(DisplayUpdatesReceiver {
            rx: self.updates.clone(),
        }))
    }
}

struct DisplayUpdatesReceiver {
    rx: Arc<Mutex<mpsc::Receiver<DisplayUpdate>>>,
}

#[async_trait::async_trait]
impl RdpServerDisplayUpdates for DisplayUpdatesReceiver {
    async fn next_update(&mut self) -> Result<Option<DisplayUpdate>> {
        // `mpsc::Receiver::recv` is cancellation-safe, as this trait requires; the guard
        // is released on cancel and no message is lost.
        Ok(self.rx.lock().await.recv().await)
    }
}

/// Credential validator: forwards the viewer's credentials to Warpgate and awaits
/// its accept/reject verdict.
struct Validator {
    out: mpsc::UnboundedSender<ControlOut>,
    resp: Mutex<mpsc::Receiver<bool>>,
}

#[async_trait::async_trait]
impl CredentialValidator for Validator {
    async fn validate(
        &self,
        credentials: &Credentials,
    ) -> Result<CredentialDecision, CredentialValidationError> {
        let _ = self.out.send(ControlOut::AuthRequest {
            username: credentials.username.clone(),
            password: credentials.password.clone(),
            domain: credentials.domain.clone(),
        });
        let mut resp = self.resp.lock().await;
        match resp.recv().await {
            Some(true) => Ok(CredentialDecision::Accept),
            // Reject on explicit denial or if Warpgate hung up before answering.
            _ => Ok(CredentialDecision::Reject),
        }
    }
}

/// Input handler: normalises IronRDP keyboard/mouse events into [`ControlOut`]
/// messages that Warpgate maps onto its shared `DesktopInput` stream.
struct InputHandler {
    out: mpsc::UnboundedSender<ControlOut>,
    x: u16,
    y: u16,
    buttons: u8,
}

impl InputHandler {
    fn emit_pointer(&self) {
        let _ = self.out.send(ControlOut::Pointer {
            x: self.x,
            y: self.y,
            buttons: self.buttons,
        });
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
                let _ = self.out.send(ControlOut::Scancode {
                    code,
                    extended,
                    down: true,
                });
            }
            KeyboardEvent::Released { code, extended } => {
                let _ = self.out.send(ControlOut::Scancode {
                    code,
                    extended,
                    down: false,
                });
            }
            KeyboardEvent::UnicodePressed(unit) => {
                let _ = self.out.send(ControlOut::Key {
                    keysym: u32::from(unit),
                    down: true,
                });
            }
            KeyboardEvent::UnicodeReleased(unit) => {
                let _ = self.out.send(ControlOut::Key {
                    keysym: u32::from(unit),
                    down: false,
                });
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
                let _ = self.out.send(ControlOut::Wheel {
                    x: self.x,
                    y: self.y,
                    vertical: true,
                    delta: wheel_notches(value),
                });
            }
            MouseEvent::Scroll { x, y } => {
                // High-resolution (ainput) 2D scroll: prefer the vertical axis.
                let (vertical, magnitude) = if y != 0 { (true, y) } else { (false, x) };
                if magnitude != 0 {
                    let _ = self.out.send(ControlOut::Wheel {
                        x: self.x,
                        y: self.y,
                        vertical,
                        delta: i16::try_from(magnitude.signum()).unwrap_or(0),
                    });
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

/// RDP carries wheel rotation in units of 120 per detent; Warpgate's shared
/// `Wheel` input is a notch count (re-multiplied by 120 downstream), so divide,
/// preserving sign for sub-detent high-resolution wheels.
fn wheel_notches(value: i16) -> i16 {
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
