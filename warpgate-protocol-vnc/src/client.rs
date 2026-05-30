use anyhow::Context;
use bytes::Bytes;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{
    Receiver, UnboundedReceiver, UnboundedSender, channel, unbounded_channel,
};
use tracing::{Instrument, debug, error, info_span, warn};
use vnc::{
    ClientKeyEvent, ClientMouseEvent, PixelFormat, VncConnector, VncEncoding, VncEvent, X11Event,
};
use warpgate_common::{TargetVncOptions, VncTargetAuth};
use warpgate_core::{DesktopEvent, DesktopInput, DesktopRect, DesktopState};

/// Handles for driving a backend VNC client running on its own task.
pub struct VncClientHandles {
    /// Normalised desktop events produced by the backend.
    pub event_rx: Receiver<DesktopEvent>,
    /// Inputs to forward to the backend.
    pub input_tx: UnboundedSender<DesktopInput>,
    /// Signal the backend task to disconnect and stop.
    pub abort_tx: UnboundedSender<()>,
}

fn rect_from(r: vnc::Rect) -> DesktopRect {
    DesktopRect {
        x: r.x,
        y: r.y,
        width: r.width,
        height: r.height,
    }
}

fn map_input(input: DesktopInput) -> X11Event {
    match input {
        DesktopInput::Pointer { x, y, buttons } => X11Event::PointerEvent(ClientMouseEvent {
            position_x: x,
            position_y: y,
            bottons: buttons,
        }),
        DesktopInput::Key { keysym, down } => X11Event::KeyEvent(ClientKeyEvent {
            keycode: keysym,
            down,
        }),
        DesktopInput::Clipboard(text) => X11Event::CopyText(text),
        DesktopInput::Refresh => X11Event::FullRefresh,
    }
}

/// Connect to a VNC target and spawn a task that proxies it as normalised
/// [`DesktopEvent`]/[`DesktopInput`] streams.
pub fn connect(options: TargetVncOptions) -> VncClientHandles {
    let (event_tx, event_rx) = channel::<DesktopEvent>(1024);
    let (input_tx, input_rx) = unbounded_channel::<DesktopInput>();
    let (abort_tx, abort_rx) = unbounded_channel::<()>();

    let span = info_span!("VNC-client", host = %options.host, port = options.port);
    tokio::spawn(
        async move {
            if let Err(error) = run(options, event_tx.clone(), input_rx, abort_rx).await {
                error!(%error, "VNC backend client failed");
                let _ = event_tx
                    .send(DesktopEvent::Error(error.to_string()))
                    .await;
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
    event_tx: tokio::sync::mpsc::Sender<DesktopEvent>,
    mut input_rx: UnboundedReceiver<DesktopInput>,
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
        VncTargetAuth::Password(auth) => auth.password.expose_secret().clone(),
        VncTargetAuth::None(_) => String::new(),
    };

    let client = VncConnector::new(stream)
        .set_auth_method(async move { Ok::<_, vnc::VncError>(password) })
        .add_encoding(VncEncoding::Tight)
        .add_encoding(VncEncoding::Zrle)
        .add_encoding(VncEncoding::CopyRect)
        .add_encoding(VncEncoding::Raw)
        .add_encoding(VncEncoding::CursorPseudo)
        .add_encoding(VncEncoding::DesktopSizePseudo)
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
                        if let Some(mapped) = map_event(event) {
                            if event_tx.send(mapped).await.is_err() {
                                break;
                            }
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
                        if let Err(error) = client.input(map_input(input)).await {
                            warn!(%error, "VNC input error");
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
        // We fix our own pixel format, so ignore the server's echo.
        VncEvent::SetPixelFormat(_) => return None,
        _ => return None,
    })
}
