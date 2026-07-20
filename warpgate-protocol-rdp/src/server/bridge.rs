//! Target-side bridging: once auth succeeds, dial the target (via the client helper),
//! pump its framebuffer to the serve helper, and record the session. Also owns the single
//! serve-helper stdin writer (with drop-oldest frame shedding).

use std::collections::VecDeque;
use std::sync::Arc;

use anyhow::Result;
use futures::SinkExt;
use tokio::sync::Mutex;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing::{info, warn};
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{Target, TargetRdpOptions};
use warpgate_core::recordings::DesktopRecorder;
use warpgate_core::{DesktopEvent, DesktopState, Services, WarpgateServerHandle};
use warpgate_rdp_ipc::server::Input as ServerHelperInput;

use super::{BackendBridge, HelperWriter};

/// Bridge target-side desktop events to the serve helper. Recording runs on its own task
/// so its (serialising) `write_event` never gates live frame delivery — `DesktopEvent`
/// clones are cheap (`RawImage` holds ref-counted `Bytes`). The recorder is also shared
/// with `control_loop` (viewer input); the recording finalises once every handle drops.
async fn frame_bridge(
    mut event_rx: tokio::sync::mpsc::Receiver<DesktopEvent>,
    helper_in_tx: UnboundedSender<ServerHelperInput>,
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

    while let Some(event) = event_rx.recv().await {
        if let Some(record_tx) = &record_tx {
            // Best-effort: recording must never stall the live path, so drop under overload.
            let _ = record_tx.try_send(event.clone());
        }

        let message = match event {
            DesktopEvent::Resize { width, height } => ServerHelperInput::Resize { width, height },
            DesktopEvent::RawImage { rect, data } => ServerHelperInput::Frame {
                x: rect.x,
                y: rect.y,
                width: rect.width,
                height: rect.height,
                // `data` is ref-counted `Bytes` — moved into the frame, no framebuffer copy.
                data,
            },
            DesktopEvent::State(DesktopState::Disconnected) => {
                let _ = helper_in_tx.send(ServerHelperInput::Shutdown);
                break;
            }
            DesktopEvent::Error(message) => {
                warn!(%message, "RDP target reported an error");
                continue;
            }
            DesktopEvent::State(state @ (DesktopState::Connecting | DesktopState::Connected)) => {
                info!(?state, "RDP target");
                continue;
            }
            // The client helper only emits Connecting/Connected/Resize/RawImage/Error/
            // Disconnected; the remaining framebuffer variants never occur on this path.
            _ => continue,
        };

        if helper_in_tx.send(message).is_err() {
            break;
        }
    }
}

/// How many framebuffer updates may be queued toward the serve helper before we start
/// shedding the oldest. Queued `Frame`s are cheap (ref-counted `Bytes`), but each still
/// costs a copy at the framed write; if the viewer/helper falls behind, an unbounded queue
/// would lag the screen far behind live. Small on purpose so we deliver the live edge.
const MAX_PENDING_HELPER_FRAMES: usize = 8;

pub(super) async fn helper_stdin_writer(
    mut stdin: HelperWriter,
    mut rx: UnboundedReceiver<ServerHelperInput>,
) {
    let mut batch: VecDeque<ServerHelperInput> = VecDeque::new();
    let mut body = Vec::new();
    loop {
        // Block for at least one message, then drain everything else already queued so we
        // can shed staleness across the whole burst before doing any expensive work.
        match rx.recv().await {
            Some(msg) => batch.push_back(msg),
            None => return,
        }
        while let Ok(msg) = rx.try_recv() {
            batch.push_back(msg);
        }

        // Drop the oldest framebuffer updates beyond the cap; never drop control messages
        // (auth verdicts / resize / shutdown), whose loss would desync the viewer.
        let is_frame = |m: &ServerHelperInput| matches!(m, ServerHelperInput::Frame { .. });
        let mut frames = batch.iter().filter(|m| is_frame(m)).count();
        while frames > MAX_PENDING_HELPER_FRAMES {
            if let Some(pos) = batch.iter().position(is_frame) {
                batch.remove(pos);
                frames -= 1;
            } else {
                break;
            }
        }

        for msg in batch.drain(..) {
            msg.encode_into(&mut body);
            // `feed` (not `send`) to avoid a flush per message; flush once after the batch.
            if stdin
                .feed(bytes::Bytes::copy_from_slice(&body))
                .await
                .is_err()
            {
                return;
            }
        }
        let _ = stdin.flush().await;
    }
}

/// Connect to the target and start bridging its framebuffer, once auth is complete.
pub(super) async fn connect_backend(
    services: &Services,
    server_handle: &Arc<Mutex<WarpgateServerHandle>>,
    helper_in_tx: &UnboundedSender<ServerHelperInput>,
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
        helper_in_tx.clone(),
        recorder.clone(),
    ));
    Ok(BackendBridge {
        input_tx,
        abort_tx,
        frame_bridge,
        recorder,
    })
}
