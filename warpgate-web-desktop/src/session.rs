use std::sync::Arc;

use tokio::sync::mpsc::Sender;
use tracing::warn;
use uuid::Uuid;
use warpgate_core::DesktopInput;
use warpgate_core::recordings::DesktopRecorder;
use warpgate_web_clients_common::{ManagedSession, Sheddable, WebSession};

use crate::protocol::ServerMessage;

/// Initial output-buffer allocation. Not a hard cap: incremental frames are bounded by
/// [`MAX_BUFFERED_INCREMENTAL`] and structural messages are rare, so the buffer stays small.
const OUTPUT_BUFFER_CAPACITY: usize = 128;

/// How many incremental (droppable) framebuffer frames to keep buffered for a slow or
/// briefly-disconnected client. Small on purpose: a client that falls behind should get
/// the recent live edge, not a huge stale backlog to grind through (which is what froze
/// the browser on high-frequency updates). Structural messages are never counted or dropped.
const MAX_BUFFERED_INCREMENTAL: usize = 64;

impl Sheddable for ServerMessage {
    fn is_droppable(&self) -> bool {
        self.is_incremental()
    }
}

pub struct WebDesktopSession {
    core: WebSession<ServerMessage>,
    input_tx: Sender<DesktopInput>,
    // shared with the manager's event loop; records viewer input for audit
    recorder: Option<Arc<DesktopRecorder>>,
}

impl WebDesktopSession {
    pub fn new(
        id: Uuid,
        user_id: Uuid,
        target_name: String,
        target_kind: warpgate_db_entities::Target::TargetKind,
        server_handle: Arc<tokio::sync::Mutex<warpgate_core::WarpgateServerHandle>>,
        input_tx: Sender<DesktopInput>,
        abort_tx: tokio::sync::mpsc::UnboundedSender<()>,
        recorder: Option<Arc<DesktopRecorder>>,
    ) -> Self {
        Self {
            core: WebSession::new(
                id,
                user_id,
                target_name,
                target_kind,
                server_handle,
                abort_tx,
                OUTPUT_BUFFER_CAPACITY,
                MAX_BUFFERED_INCREMENTAL,
            ),
            input_tx,
            recorder,
        }
    }

    pub async fn send_input(&self, input: DesktopInput) {
        // Record the viewer's input for audit before forwarding (like native RDP/VNC).
        if let Some(recorder) = &self.recorder
            && let Err(error) = recorder.write_input(&input).await
        {
            warn!(%error, "Failed to record web-desktop viewer input");
        }
        // let inputs drop under backpressure
        let _ = self.input_tx.try_send(input);
    }
}

impl std::ops::Deref for WebDesktopSession {
    type Target = WebSession<ServerMessage>;
    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl ManagedSession for WebDesktopSession {
    fn id(&self) -> Uuid {
        self.core.id()
    }

    fn user_id(&self) -> Uuid {
        self.core.user_id()
    }

    fn on_removed(&self) {
        self.core.abort();
        self.core.close();
    }
}
