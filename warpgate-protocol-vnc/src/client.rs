use std::sync::Arc;

use bytes::Bytes;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{Receiver, Sender, UnboundedReceiver, channel, unbounded_channel};
use tracing::{Instrument, debug, error, info_span, warn};
use vnc::{
    ClientKeyEvent, PixelFormat, VncClient, VncConnector, VncEncoding, VncError, VncEvent, X11Event,
};
use warpgate_common::helpers::port_knock;
use warpgate_common::{SecretResolver, TargetVncOptions, VncTargetAuth, WarpgateError};
use warpgate_core::{
    AdmittedTarget, DESKTOP_CONNECT_TIMEOUT, DESKTOP_HANDSHAKE_TIMEOUT,
    DESKTOP_INPUT_CHANNEL_CAPACITY, DesktopClientHandles, DesktopConnectionError, DesktopEvent,
    DesktopInput, DesktopRect, DesktopState, LogonState, check_desktop_size, within_deadline,
};

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
        // RFB has no scancode input, so a viewer that only reports key positions
        // (a native RDP viewer) has nothing a VNC target can use.
        DesktopInput::Key { keysym, down, .. } => keysym
            .map(|keycode| X11Event::KeyEvent(ClientKeyEvent { keycode, down }))
            .into_iter()
            .collect(),
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
        // Dynamic resize toward a VNC target is not supported.
        DesktopInput::Resize { .. } => vec![],
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
pub fn connect(
    admitted: AdmittedTarget<TargetVncOptions>,
    secrets: Arc<dyn SecretResolver>,
) -> Result<DesktopClientHandles, WarpgateError> {
    spawn_approved_client(admitted, BROWSER_ENCODINGS, secrets)
}

/// Like [`connect`], but negotiates the encodings ([`PROXY_ENCODINGS`]) used by the
/// native VNC proxy's single decode-and-re-encode path, where every backend update is
/// decoded (Tight/JPEG included) and re-encoded through a minimal RFB server encoder
/// toward the viewer, and optionally recorded.
pub fn connect_for_proxy(
    admitted: AdmittedTarget<TargetVncOptions>,
    secrets: Arc<dyn SecretResolver>,
) -> Result<DesktopClientHandles, WarpgateError> {
    spawn_approved_client(admitted, PROXY_ENCODINGS, secrets)
}

fn spawn_approved_client(
    admitted: AdmittedTarget<TargetVncOptions>,
    encodings: &'static [VncEncoding],
    secrets: Arc<dyn SecretResolver>,
) -> Result<DesktopClientHandles, WarpgateError> {
    let options = admitted.specific_target().options().clone();
    Ok(spawn_client(options, encodings, secrets))
}

fn spawn_client(
    options: TargetVncOptions,
    encodings: &'static [VncEncoding],
    secrets: Arc<dyn SecretResolver>,
) -> DesktopClientHandles {
    let (event_tx, event_rx) = channel::<DesktopEvent>(1024);
    let (input_tx, input_rx) = channel::<DesktopInput>(DESKTOP_INPUT_CHANNEL_CAPACITY);
    let (abort_tx, abort_rx) = unbounded_channel::<()>();

    let span = info_span!("VNC-client", host = %options.host, port = options.port);
    tokio::spawn(
        async move {
            if let Err(error) = run(
                options,
                encodings,
                event_tx.clone(),
                input_rx,
                abort_rx,
                secrets,
            )
            .await
            {
                let error = Arc::new(error);
                let _ = event_tx.send(DesktopEvent::Error(error.clone())).await;
                error!(
                    "VNC backend client failed: {:#}",
                    anyhow::Error::from(error)
                );
            }
            let _ = event_tx
                .send(DesktopEvent::State(DesktopState::Disconnected))
                .await;
        }
        .instrument(span),
    );

    DesktopClientHandles {
        event_rx,
        input_tx,
        abort_tx,
        // placeholder
        logon_state: LogonState::logged_on(),
    }
}

async fn run(
    options: TargetVncOptions,
    encodings: &'static [VncEncoding],
    event_tx: tokio::sync::mpsc::Sender<DesktopEvent>,
    mut input_rx: Receiver<DesktopInput>,
    mut abort_rx: UnboundedReceiver<()>,
    secrets: Arc<dyn SecretResolver>,
) -> Result<(), DesktopConnectionError> {
    event_tx
        .send(DesktopEvent::State(DesktopState::Connecting))
        .await
        .ok();

    // Outside the connect deadline: the sequence's own pauses can exceed it.
    if let Some(port_knocking) = &options.port_knocking {
        port_knock::knock(&options.host, port_knocking)
            .await
            .map_err(DesktopConnectionError::Io)?;
    }

    let stream = within_deadline(DESKTOP_CONNECT_TIMEOUT, async {
        TcpStream::connect((options.host.clone(), options.port))
            .await
            .map_err(DesktopConnectionError::Io)
    })
    .await?;

    let password = match &options.auth {
        VncTargetAuth::Password(auth) => auth
            .password
            .resolve(&*secrets)
            .await?
            .expose_secret()
            .clone(),
        VncTargetAuth::None(_) => String::new(),
    };

    let mut connector =
        VncConnector::new(stream).set_auth_method(async move { Ok::<_, vnc::VncError>(password) });
    for encoding in encodings {
        connector = connector.add_encoding(*encoding);
    }
    let client = within_deadline(DESKTOP_HANDSHAKE_TIMEOUT, async {
        connector
            .allow_shared(true)
            .set_pixel_format(PixelFormat::bgra())
            .build()
            .map_err(vnc_error)?
            .try_start()
            .await
            .map_err(vnc_error)?
            .finish()
            .map_err(vnc_error)
    })
    .await?;

    event_tx
        .send(DesktopEvent::State(DesktopState::Connected))
        .await
        .ok();

    let result = pump(&client, &event_tx, &mut input_rx, &mut abort_rx).await;
    client.close().await.ok();
    result
}

async fn pump(
    client: &VncClient,
    event_tx: &Sender<DesktopEvent>,
    input_rx: &mut Receiver<DesktopInput>,
    abort_rx: &mut UnboundedReceiver<()>,
) -> Result<(), DesktopConnectionError> {
    // Awaiting the send inline would stall input while the viewer is slow. The decoder
    // is not read while an event waits here, so backpressure still reaches the target
    let mut outgoing: Option<DesktopEvent> = None;

    loop {
        tokio::select! {
            permit = event_tx.reserve(), if outgoing.is_some() => {
                let Ok(permit) = permit else { break };
                if let Some(event) = outgoing.take() {
                    permit.send(event);
                }
            }
            event = client.recv_event(), if outgoing.is_none() => {
                let event = match event {
                    Ok(event) => event,
                    Err(error) => {
                        warn!(%error, "VNC poll error");
                        break;
                    }
                };
                // RFB flow control: the target sends one update per request
                if matches!(event, VncEvent::FramebufferUpdateEnd) {
                    client.input(X11Event::Refresh).await.ok();
                }
                outgoing = map_event(event);
                if let Some(DesktopEvent::Resize { width, height }) = outgoing {
                    check_desktop_size(width, height)?;
                }
            }
            input = input_rx.recv() => {
                let Some(input) = input else { break };
                for event in map_input(input) {
                    if let Err(error) = client.input(event).await {
                        warn!(%error, "VNC input error");
                        return Ok(());
                    }
                }
            }
            _ = abort_rx.recv() => {
                debug!("VNC client aborted");
                break;
            }
        }
    }
    Ok(())
}

fn vnc_error(error: VncError) -> DesktopConnectionError {
    match error {
        VncError::WrongPassword | VncError::NoPassword => {
            DesktopConnectionError::TargetRejectedCredentials(error.into())
        }
        VncError::IoError(error) => DesktopConnectionError::Io(error),
        error => DesktopConnectionError::Handshake(error.into()),
    }
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
        VncEvent::Error(message) => {
            error!(%message, "VNC backend reported an error");
            DesktopEvent::Error(Arc::new(DesktopConnectionError::Session(anyhow::anyhow!(
                message
            ))))
        }
        // Everything else (including the server's pixel-format echo — we fix our own)
        // is not surfaced.
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::sync::mpsc::{channel, unbounded_channel};
    use vnc::{PixelFormat, VncConnector, VncEncoding, VncError, VncEvent};
    use warpgate_common::UserFacingReason;
    use warpgate_core::{DesktopEvent, DesktopInput};

    use super::{map_event, pump};

    #[test]
    fn a_decoder_error_is_not_shown_verbatim() {
        let shown = match map_event(VncEvent::Error(
            "Connection reset by peer (os error 54)".into(),
        )) {
            Some(DesktopEvent::Error(error)) => error.user_facing_reason(),
            other => format!("{other:?}"),
        };
        assert_eq!(shown, "The target session failed");
    }

    const RECTS: u16 = 8;

    /// No-auth RFB 3.8 server. Sends one update of `RECTS` raw rectangles and returns
    /// the (full, incremental) request counts seen before the first pointer event
    async fn fake_server(mut s: DuplexStream) -> (usize, usize) {
        let mut buf = [0u8; 64];
        s.write_all(b"RFB 003.008\n").await.unwrap();
        s.read_exact(&mut buf[..12]).await.unwrap();
        s.write_all(&[1, 1]).await.unwrap();
        s.read_exact(&mut buf[..1]).await.unwrap();
        s.write_all(&[0; 4]).await.unwrap();
        s.read_exact(&mut buf[..1]).await.unwrap();
        // 16x16, a 16-byte pixel format the client overrides, empty name
        let mut init = vec![0, 16, 0, 16];
        init.extend([32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]);
        init.extend([0; 4]);
        s.write_all(&init).await.unwrap();

        let mut update = vec![0, 0];
        update.extend(RECTS.to_be_bytes());
        for _ in 0..RECTS {
            update.extend([0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 2, 3, 4]);
        }
        s.write_all(&update).await.unwrap();

        let (mut full, mut incremental) = (0, 0);
        loop {
            match s.read_u8().await.unwrap() {
                0 => drop(s.read_exact(&mut buf[..19]).await.unwrap()),
                2 => {
                    s.read_u8().await.unwrap();
                    for _ in 0..s.read_u16().await.unwrap() {
                        s.read_u32().await.unwrap();
                    }
                }
                3 => {
                    s.read_exact(&mut buf[..9]).await.unwrap();
                    if buf[0] == 0 {
                        full += 1;
                    } else {
                        incremental += 1;
                    }
                }
                5 => return (full, incremental),
                // An unknown message type fails the count assertions
                _ => return (usize::MAX, usize::MAX),
            }
        }
    }

    /// (full, incremental) request counts from [`fake_server`]
    async fn request_counts(viewer_reads: bool) -> (usize, usize) {
        let (ours, theirs) = tokio::io::duplex(1 << 16);
        let server = tokio::spawn(fake_server(theirs));

        let client = VncConnector::new(ours)
            .set_auth_method(async { Ok::<_, VncError>(String::new()) })
            .add_encoding(VncEncoding::Raw)
            .set_pixel_format(PixelFormat::bgra())
            .build()
            .unwrap()
            .try_start()
            .await
            .unwrap()
            .finish()
            .unwrap();

        let (event_tx, mut event_rx) = channel(1);
        let (input_tx, mut input_rx) = channel(1);
        let (_abort_tx, mut abort_rx) = unbounded_channel();
        let session =
            tokio::spawn(
                async move { pump(&client, &event_tx, &mut input_rx, &mut abort_rx).await },
            );
        let viewer = tokio::spawn(async move {
            if viewer_reads {
                while event_rx.recv().await.is_some() {}
            } else {
                // A dropped receiver would end the session
                std::future::pending::<()>().await;
                drop(event_rx);
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        input_tx
            .send(DesktopInput::Pointer {
                x: 1,
                y: 1,
                buttons: 0,
            })
            .await
            .unwrap();

        // Times out if input is stuck behind undelivered frames
        let counts = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        session.abort();
        viewer.abort();
        counts
    }

    #[tokio::test(start_paused = true)]
    async fn input_reaches_the_target_while_the_viewer_is_stalled() {
        assert_eq!(request_counts(false).await, (1, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn one_request_follows_each_complete_update() {
        assert_eq!(request_counts(true).await, (1, 1));
    }
}
