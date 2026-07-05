//! The authorized VNC proxy session: the single decode-and-re-encode loop that pumps
//! backend framebuffer updates to the viewer as RFB, forwards viewer input to the backend,
//! and records both. Recording is transparent — recorded and unrecorded sessions share this
//! path.

use std::collections::VecDeque;

use anyhow::{Result, anyhow, bail};
use tokio::io::AsyncWrite;
use tokio::sync::mpsc;
use tracing::warn;
use warpgate_core::recordings::DesktopRecorder;
use warpgate_core::{DesktopEvent, DesktopInput, DesktopState};

use super::protocol::{
    ClientEvent, pack_bgra, write_desktop_size, write_raw_rect, write_server_cut_text,
    write_tight_jpeg_rect,
};
use super::{ProxySession, RenderState};

/// Record an event, logging (but not failing on) recorder write errors. No-op when
/// recording is disabled (`None`).
async fn record_event(recorder: &Option<DesktopRecorder>, event: &DesktopEvent) {
    if let Some(recorder) = recorder
        && let Err(error) = recorder.write_event(event).await
    {
        warn!(%error, "Failed to record VNC desktop event");
    }
}

/// Record a viewer input, logging (but not failing on) recorder write errors. No-op when
/// recording is disabled (`None`).
async fn record_input(recorder: &Option<DesktopRecorder>, input: &DesktopInput) {
    if let Some(recorder) = recorder
        && let Err(error) = recorder.write_input(input).await
    {
        warn!(%error, "Failed to record VNC viewer input");
    }
}

/// Drain backend events until the first [`DesktopEvent::Resize`] reveals the framebuffer
/// geometry, recording each consumed event. The backend client always emits `Resize`
/// before any `RawImage`, so nothing visible is consumed here.
pub(super) async fn wait_for_backend_size(
    event_rx: &mut mpsc::Receiver<DesktopEvent>,
    recorder: &Option<DesktopRecorder>,
) -> Result<(u16, u16)> {
    while let Some(event) = event_rx.recv().await {
        record_event(recorder, &event).await;
        match event {
            DesktopEvent::Resize { width, height } => return Ok((width, height)),
            DesktopEvent::Error(message) => bail!("backend error before first frame: {message}"),
            DesktopEvent::State(DesktopState::Disconnected) => {
                bail!("backend disconnected before first frame")
            }
            _ => {}
        }
    }
    bail!("backend channel closed before first frame")
}

/// Re-encode one queued backend frame toward the viewer in response to an outstanding
/// `FramebufferUpdateRequest`. Clears `pending_request` once a frame is actually sent.
async fn flush_frame<W>(
    viewer_wr: &mut W,
    render: &mut RenderState,
    event: DesktopEvent,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    match event {
        DesktopEvent::RawImage { rect, data } => {
            let pixels = pack_bgra(&render.pixel_format, &data);
            write_raw_rect(viewer_wr, rect.x, rect.y, rect.width, rect.height, &pixels).await?;
            render.pending_request = false;
        }
        // The backend compressed this rect with Tight's JPEG sub-encoding. The viewer
        // negotiated Tight, so it decodes JPEG itself — forward the bytes straight through
        // as a Tight/JPEG rect rather than decoding and re-encoding as (much larger) Raw.
        DesktopEvent::JpegImage { rect, data } if render.viewer_supports_tight => {
            write_tight_jpeg_rect(viewer_wr, rect.x, rect.y, rect.width, rect.height, &data)
                .await?;
            render.pending_request = false;
        }
        // A viewer that requested Tight is universal; if one somehow didn't, we can't
        // proxy the backend's JPEG without a decoder, so skip the rect (it stays stale
        // until the next full frame) rather than carrying a JPEG decoder for this.
        DesktopEvent::JpegImage { .. } => {
            warn!("viewer did not negotiate Tight; dropping backend JPEG rect");
            render.pending_request = false;
        }
        DesktopEvent::Resize { width, height } if render.supports_desktop_size => {
            write_desktop_size(viewer_wr, width, height).await?;
            render.pending_request = false;
        }
        // A resize the viewer can't be told about: drop it but keep the request pending
        // so the next real frame still satisfies it. Other variants never reach the queue.
        _ => {}
    }
    Ok(())
}

/// The decode-and-re-encode loop: pump backend `DesktopEvent`s to the viewer as RFB
/// (recording each), and forward viewer input back to the backend. Lockstep — at most
/// one rect per `FramebufferUpdateRequest` — with a bounded queue providing end-to-end
/// backpressure when the viewer is slow. Dropping the recorder finalises the recording.
pub(super) async fn run_proxy_session(session: ProxySession) -> Result<()> {
    /// Bound on queued-but-unflushed backend frames before we stop draining the backend.
    const QUEUE_CAP: usize = 256;

    let ProxySession {
        mut viewer_wr,
        mut viewer_events,
        reader,
        stop_tx,
        mut render,
        backend,
        recorder,
    } = session;
    let crate::client::VncClientHandles {
        mut event_rx,
        input_tx,
        abort_tx,
    } = backend;

    let mut queue: VecDeque<DesktopEvent> = VecDeque::new();

    let result = loop {
        // Satisfy an outstanding request with one queued frame before blocking again.
        if render.pending_request
            && let Some(event) = queue.pop_front()
        {
            if let Err(error) = flush_frame(&mut viewer_wr, &mut render, event).await {
                break Err(error);
            }
            continue;
        }

        tokio::select! {
            biased;

            // Viewer → us: input to forward, plus pixel-format/encoding/refresh updates.
            event = viewer_events.recv() => {
                match event {
                    Some(ClientEvent::WantsFrame) => render.pending_request = true,
                    Some(ClientEvent::PixelFormat(pf)) => render.pixel_format = pf,
                    Some(ClientEvent::Encodings {
                        desktop_size,
                        tight,
                    }) => {
                        render.supports_desktop_size = desktop_size;
                        render.viewer_supports_tight = tight;
                    }
                    Some(ClientEvent::Key { down, keysym }) => {
                        let input = DesktopInput::Key { keysym, down };
                        record_input(&recorder, &input).await;
                        if input_tx.send(input).await.is_err() {
                            break Ok(());
                        }
                    }
                    Some(ClientEvent::Pointer { x, y, buttons }) => {
                        let input = DesktopInput::Pointer { x, y, buttons };
                        record_input(&recorder, &input).await;
                        if input_tx.send(input).await.is_err() {
                            break Ok(());
                        }
                    }
                    Some(ClientEvent::Clipboard(text)) => {
                        let input = DesktopInput::Clipboard(text);
                        record_input(&recorder, &input).await;
                        let _ = input_tx.send(input).await;
                    }
                    None => break Ok(()), // viewer disconnected
                }
            }

            // Backend → us: record every event, queue frames, mirror clipboard. Gated so
            // a slow viewer back-pressures the backend instead of growing the queue.
            event = event_rx.recv(), if queue.len() < QUEUE_CAP => {
                match event {
                    Some(event) => {
                        record_event(&recorder, &event).await;
                        match event {
                            DesktopEvent::RawImage { .. }
                            | DesktopEvent::JpegImage { .. }
                            | DesktopEvent::Resize { .. } => {
                                queue.push_back(event);
                            }
                            DesktopEvent::Clipboard(text) => {
                                if let Err(error) = write_server_cut_text(&mut viewer_wr, &text).await {
                                    break Err(error);
                                }
                            }
                            DesktopEvent::State(DesktopState::Disconnected) => break Ok(()),
                            DesktopEvent::Error(message) => break Err(anyhow!("backend error: {message}")),
                            // PROXY_ENCODINGS rules out CopyRect/Cursor; Bell/Cursor ignored.
                            _ => {}
                        }
                    }
                    None => break Ok(()), // backend ended
                }
            }
        }
    };

    // Teardown: stop the viewer reader and the backend client. Dropping `recorder`
    // (held until here) finalises the recording.
    let _ = stop_tx.send(());
    let _ = abort_tx.send(());
    reader.abort();
    drop(recorder);

    result
}
