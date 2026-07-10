use anyhow::Context;
use bytes::Bytes;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{
    Receiver, Sender, UnboundedReceiver, UnboundedSender, channel, unbounded_channel,
};
use tracing::{Instrument, debug, error, info_span, warn};
use vnc::{ClientKeyEvent, PixelFormat, VncConnector, VncEncoding, VncEvent, X11Event};
use warpgate_common::{SecretBackendRef, TargetVncOptions, VncTargetAuth};
use warpgate_core::{
    DESKTOP_INPUT_CHANNEL_CAPACITY, DesktopEvent, DesktopInput, DesktopRect, DesktopState,
};

/// Handles for driving a backend VNC client running on its own task.
pub struct VncClientHandles {
    /// Normalised desktop events produced by the backend.
    pub event_rx: Receiver<DesktopEvent>,
    /// Inputs to forward to the backend.
    pub input_tx: Sender<DesktopInput>,
    /// Signal the backend task to disconnect and stop.
    pub abort_tx: UnboundedSender<()>,
}

const fn rect_from(r: vnc::Rect) -> DesktopRect {
    DesktopRect {
        x: r.x,
        y: r.y,
        width: r.width,
        height: r.height,
    }
}

/// Map one desktop input to the VNC events it produces. Most inputs map to a single
/// event; a wheel scroll maps to a press+release of the relevant RFB scroll button
/// (4-7), repeated per notch.
fn map_input(input: DesktopInput) -> Vec<X11Event> {
    match input {
        DesktopInput::Pointer { x, y, buttons } => {
            vec![X11Event::PointerEvent((x, y, buttons).into())]
        }
        DesktopInput::Key { keysym, down } => vec![X11Event::KeyEvent(ClientKeyEvent {
            keycode: keysym,
            down,
        })],
        DesktopInput::Wheel {
            x,
            y,
            vertical,
            delta,
        } => {
            // RFB scroll buttons: 4=up (0x08), 5=down (0x10), 6=left (0x20), 7=right (0x40).
            let button: u8 = match (vertical, delta >= 0) {
                (true, true) => 0x08,
                (true, false) => 0x10,
                (false, true) => 0x40,
                (false, false) => 0x20,
            };
            let count = (delta.unsigned_abs() as usize).clamp(1, 10);
            let mut events = Vec::with_capacity(count * 2);
            for _ in 0..count {
                events.push(X11Event::PointerEvent((x, y, button).into()));
                events.push(X11Event::PointerEvent((x, y, 0).into()));
            }
            events
        }
        DesktopInput::Clipboard(text) => vec![X11Event::CopyText(text)],
        DesktopInput::Refresh => vec![X11Event::FullRefresh],
        // RFB has no raw-scancode input; native-RDP scancodes are meaningless to a
        // VNC target, so drop them (keysym input is used for VNC instead).
        DesktopInput::Scancode { .. } => vec![],
    }
}

/// Encodings for the in-browser path. Tight (including its JPEG sub-encoding) and
/// the cursor pseudo-encoding are decoded and rendered by the browser canvas.
const BROWSER_ENCODINGS: &[VncEncoding] = &[
    VncEncoding::Tight,
    VncEncoding::Zrle,
    VncEncoding::CopyRect,
    VncEncoding::Raw,
    VncEncoding::CursorPseudo,
    VncEncoding::DesktopSizePseudo,
];

/// Encodings for the native decode-and-re-encode proxy (the single path every native
/// VNC session takes, recorded or not). Tight is included so the backend can compress
/// with its JPEG sub-encoding (bandwidth-efficient over the target link); we decode the
/// JPEG and re-encode toward the viewer. CopyRect is omitted so re-encoding needs no
/// server-side framebuffer, and the cursor pseudo-encoding is omitted so the backend
/// bakes the cursor into the framebuffer. What remains decodes to `RawImage`/`JpegImage`/
/// `Resize` events that re-encode to the viewer as RFB Raw rectangles.
const PROXY_ENCODINGS: &[VncEncoding] = &[
    VncEncoding::Tight,
    VncEncoding::Zrle,
    VncEncoding::Raw,
    VncEncoding::DesktopSizePseudo,
];

/// Connect to a VNC target and spawn a task that proxies it as normalised
/// [`DesktopEvent`]/[`DesktopInput`] streams.
pub fn connect(options: TargetVncOptions, secret_backend: SecretBackendRef) -> VncClientHandles {
    spawn_client(options, secret_backend, BROWSER_ENCODINGS)
}

/// Like [`connect`], but negotiates the encodings ([`PROXY_ENCODINGS`]) used by the
/// native VNC proxy's single decode-and-re-encode path, where every backend update is
/// decoded (Tight/JPEG included) and re-encoded through a minimal RFB server encoder
/// toward the viewer, and optionally recorded.
pub fn connect_for_proxy(
    options: TargetVncOptions,
    secret_backend: SecretBackendRef,
) -> VncClientHandles {
    spawn_client(options, secret_backend, PROXY_ENCODINGS)
}

fn spawn_client(
    options: TargetVncOptions,
    secret_backend: SecretBackendRef,
    encodings: &'static [VncEncoding],
) -> VncClientHandles {
    let (event_tx, event_rx) = channel::<DesktopEvent>(1024);
    let (input_tx, input_rx) = channel::<DesktopInput>(DESKTOP_INPUT_CHANNEL_CAPACITY);
    let (abort_tx, abort_rx) = unbounded_channel::<()>();

    let span = info_span!("VNC-client", host = %options.host, port = options.port);
    tokio::spawn(
        async move {
            if let Err(error) = run(
                options,
                secret_backend,
                encodings,
                event_tx.clone(),
                input_rx,
                abort_rx,
            )
            .await
            {
                error!(%error, "VNC backend client failed");
                let _ = event_tx.send(DesktopEvent::Error(error.to_string())).await;
            }
            let _ = event_tx
                .send(DesktopEvent::State(DesktopState::Disconnected))
                .await;
        }
        .instrument(span),
    );

    VncClientHandles {
        event_rx,
        input_tx,
        abort_tx,
    }
}

async fn run(
    options: TargetVncOptions,
    secret_backend: SecretBackendRef,
    encodings: &'static [VncEncoding],
    event_tx: tokio::sync::mpsc::Sender<DesktopEvent>,
    mut input_rx: Receiver<DesktopInput>,
    mut abort_rx: UnboundedReceiver<()>,
) -> anyhow::Result<()> {
    event_tx
        .send(DesktopEvent::State(DesktopState::Connecting))
        .await
        .ok();

    let stream = TcpStream::connect((options.host.clone(), options.port))
        .await
        .context("connecting to VNC target")?;

    let password = match &options.auth {
        VncTargetAuth::Password(auth) => auth
            .password
            .resolve(&*secret_backend)
            .await
            .context("resolving VNC password")?
            .expose_secret()
            .clone(),
        VncTargetAuth::None(_) => String::new(),
    };

    let mut connector =
        VncConnector::new(stream).set_auth_method(async move { Ok::<_, vnc::VncError>(password) });
    for encoding in encodings {
        connector = connector.add_encoding(*encoding);
    }
    let client = connector
        .allow_shared(true)
        .set_pixel_format(PixelFormat::bgra())
        .build()
        .context("building VNC connector")?
        .try_start()
        .await
        .context("starting VNC session")?
        .finish()
        .context("finishing VNC handshake")?;

    event_tx
        .send(DesktopEvent::State(DesktopState::Connected))
        .await
        .ok();

    // Ask for an initial full frame.
    client.input(X11Event::FullRefresh).await.ok();

    loop {
        tokio::select! {
            event = client.poll_event() => {
                match event {
                    Ok(Some(event)) => {
                        if let Some(mapped) = map_event(event)
                            && event_tx.send(mapped).await.is_err()
                        {
                            break;
                        }
                        // Keep the framebuffer flowing.
                        client.input(X11Event::Refresh).await.ok();
                    }
                    Ok(None) => {}
                    Err(error) => {
                        warn!(%error, "VNC poll error");
                        break;
                    }
                }
            }
            input = input_rx.recv() => {
                match input {
                    Some(input) => {
                        for event in map_input(input) {
                            if let Err(error) = client.input(event).await {
                                warn!(%error, "VNC input error");
                                break;
                            }
                        }
                    }
                    None => break,
                }
            }
            _ = abort_rx.recv() => {
                debug!("VNC client aborted");
                break;
            }
        }
    }

    client.close().await.ok();
    Ok(())
}

fn map_event(event: VncEvent) -> Option<DesktopEvent> {
    Some(match event {
        VncEvent::SetResolution(screen) => DesktopEvent::Resize {
            width: screen.width,
            height: screen.height,
        },
        VncEvent::RawImage(rect, data) => DesktopEvent::RawImage {
            rect: rect_from(rect),
            data: Bytes::from(data),
        },
        VncEvent::JpegImage(rect, data) => DesktopEvent::JpegImage {
            rect: rect_from(rect),
            data: Bytes::from(data),
        },
        VncEvent::Copy(dst, src) => DesktopEvent::CopyRect {
            dst: rect_from(dst),
            src_x: src.x,
            src_y: src.y,
        },
        VncEvent::SetCursor(rect, data) => DesktopEvent::Cursor {
            rect: rect_from(rect),
            data: Bytes::from(data),
        },
        VncEvent::Text(text) => DesktopEvent::Clipboard(text),
        VncEvent::Bell => DesktopEvent::Bell,
        VncEvent::Error(message) => DesktopEvent::Error(message),
        // Everything else (including the server's pixel-format echo — we fix our own)
        // is not surfaced.
        _ => return None,
    })
}
