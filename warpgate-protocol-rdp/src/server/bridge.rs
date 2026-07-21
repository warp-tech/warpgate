//! Target-side bridging: once auth succeeds, dial the target, pump its framebuffer to the
//! viewer-facing RDP server, and record the session.

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

/// Bridge target-side desktop events to the viewer-facing RDP server. Every framebuffer
/// update is a delta rectangle, so none may be dropped — a lost tile leaves that region
/// stale until it next changes. `server_in` is bounded, so a slow viewer applies
/// backpressure here, which propagates to the target via IronRDP's frame acknowledgements
/// (the target paces to the slowest consumer instead of us discarding pixels).
///
/// Recording runs on its own task so its (serialising) `write_event` never gates live frame
/// delivery — `DesktopEvent` clones are cheap (`RawImage` holds ref-counted `Bytes`). The
/// recorder is also shared with `control_loop` (viewer input); the recording finalises once
/// every handle drops.
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

    while let Some(event) = event_rx.recv().await {
        if let Some(record_tx) = &record_tx {
            // Best-effort: recording must never stall the live path, so drop under overload.
            let _ = record_tx.try_send(event.clone());
        }

        let message = match event {
            DesktopEvent::Resize { width, height } => ServerInput::Resize { width, height },
            DesktopEvent::RawImage { rect, data } => ServerInput::Frame {
                x: rect.x,
                y: rect.y,
                width: rect.width,
                height: rect.height,
                // `data` is ref-counted `Bytes` — moved into the frame, no framebuffer copy.
                data,
            },
            DesktopEvent::State(DesktopState::Disconnected) => {
                let _ = server_in.send(ServerInput::Shutdown).await;
                return;
            }
            DesktopEvent::Error(message) => {
                warn!(%message, "RDP target reported an error");
                continue;
            }
            DesktopEvent::State(state @ (DesktopState::Connecting | DesktopState::Connected)) => {
                info!(?state, "RDP target");
                continue;
            }
            // The client only emits Connecting/Connected/Resize/RawImage/Error/Disconnected;
            // the remaining framebuffer variants never occur on this path.
            _ => continue,
        };

        if server_in.send(message).await.is_err() {
            return;
        }
    }
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
