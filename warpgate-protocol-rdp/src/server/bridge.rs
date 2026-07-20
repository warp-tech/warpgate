//! Target-side bridging: once auth succeeds, dial the target, pump its framebuffer to the
//! viewer-facing RDP server, and record the session. Owns the single feed into that server,
//! shedding stale frames so a slow viewer can't grow the queue without limit.

use std::collections::VecDeque;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::Mutex;
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{Target, TargetRdpOptions};
use warpgate_core::recordings::DesktopRecorder;
use warpgate_core::{DesktopEvent, DesktopState, Services, WarpgateServerHandle};

use super::BackendBridge;
use super::protocol::Input as ServerInput;

/// How many framebuffer updates may be queued toward the RDP server before we shed the
/// oldest. Queued `Frame`s are cheap (ref-counted `Bytes`), but if the viewer falls behind
/// an unbounded queue would lag the screen far behind live. Small on purpose so we deliver
/// the live edge.
const MAX_PENDING_FRAMES: usize = 8;

/// Bridge target-side desktop events to the viewer-facing RDP server, batching each burst
/// so the oldest frames can be dropped before delivery. Recording runs on its own task so
/// its (serialising) `write_event` never gates live frame delivery — `DesktopEvent` clones
/// are cheap (`RawImage` holds ref-counted `Bytes`). The recorder is also shared with
/// `control_loop` (viewer input); the recording finalises once every handle drops.
async fn frame_bridge(
    mut event_rx: tokio::sync::mpsc::Receiver<DesktopEvent>,
    server_in: Sender<ServerInput>,
    recorder: Option<Arc<DesktopRecorder>>,
) {
    let record_tx = recorder.map(|recorder| {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<DesktopEvent>(256);
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if let Err(error) = recorder.write_event(&event).await {
                    warn!(%error, "Failed to record RDP desktop event");
                }
            }
        });
        tx
    });

    let mut batch: VecDeque<ServerInput> = VecDeque::new();
    loop {
        // Block for one event, then drain the rest of the burst so we can shed across the
        // whole batch before doing any delivery.
        let Some(first) = event_rx.recv().await else {
            return;
        };
        let mut shutdown = push_event(first, &record_tx, &mut batch);
        while let Ok(event) = event_rx.try_recv() {
            shutdown |= push_event(event, &record_tx, &mut batch);
        }

        // Drop the oldest framebuffer updates beyond the cap; never drop control messages
        // (resize / shutdown), whose loss would desync the viewer.
        let is_frame = |m: &ServerInput| matches!(m, ServerInput::Frame { .. });
        let mut frames = batch.iter().filter(|m| is_frame(m)).count();
        while frames > MAX_PENDING_FRAMES {
            if let Some(pos) = batch.iter().position(is_frame) {
                batch.remove(pos);
                frames -= 1;
            } else {
                break;
            }
        }

        for msg in batch.drain(..) {
            if server_in.send(msg).await.is_err() {
                return;
            }
        }
        if shutdown {
            let _ = server_in.send(ServerInput::Shutdown).await;
            return;
        }
    }
}

/// Record `event`, map it to a [`ServerInput`], and queue it. Returns `true` when the
/// target has disconnected and the session should be torn down after the batch drains.
fn push_event(
    event: DesktopEvent,
    record_tx: &Option<tokio::sync::mpsc::Sender<DesktopEvent>>,
    batch: &mut VecDeque<ServerInput>,
) -> bool {
    if let Some(record_tx) = record_tx {
        // Best-effort: recording must never stall the live path, so drop under overload.
        let _ = record_tx.try_send(event.clone());
    }

    match event {
        DesktopEvent::Resize { width, height } => {
            batch.push_back(ServerInput::Resize { width, height });
        }
        DesktopEvent::RawImage { rect, data } => batch.push_back(ServerInput::Frame {
            x: rect.x,
            y: rect.y,
            width: rect.width,
            height: rect.height,
            // `data` is ref-counted `Bytes` — moved into the frame, no framebuffer copy.
            data,
        }),
        DesktopEvent::State(DesktopState::Disconnected) => return true,
        DesktopEvent::Error(message) => warn!(%message, "RDP target reported an error"),
        DesktopEvent::State(state @ (DesktopState::Connecting | DesktopState::Connected)) => {
            info!(?state, "RDP target");
        }
        // The client only emits Connecting/Connected/Resize/RawImage/Error/Disconnected;
        // the remaining framebuffer variants never occur on this path.
        _ => {}
    }
    false
}

/// Connect to the target and start bridging its framebuffer, once auth is complete.
pub(super) async fn connect_backend(
    services: &Services,
    server_handle: &Arc<Mutex<WarpgateServerHandle>>,
    server_in_tx: &Sender<ServerInput>,
    user_info: AuthStateUserInfo,
    target: Target,
    options: TargetRdpOptions,
    screen: warpgate_desktop_ui::Screen,
) -> Result<BackendBridge> {
    {
        let handle = server_handle.lock().await;
        handle.set_user_info(user_info).await?;
        handle.set_target(&target).await?;
    }
    info!(target=%target.name, "Authorized");

    let session_id = server_handle.lock().await.id();
    let recorder = warpgate_desktop_auth::start_recording(services, &session_id, "rdp")
        .await
        .map(Arc::new);

    let crate::RdpClientHandles {
        event_rx,
        input_tx,
        abort_tx,
    } = crate::connect(options, (screen.width, screen.height));
    let frame_bridge = tokio::spawn(frame_bridge(
        event_rx,
        server_in_tx.clone(),
        recorder.clone(),
    ));
    Ok(BackendBridge {
        input_tx,
        abort_tx,
        frame_bridge,
        recorder,
    })
}
