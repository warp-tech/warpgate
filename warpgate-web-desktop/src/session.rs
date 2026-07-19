use std::sync::Arc;

use tokio::sync::Mutex;
use tokio::sync::mpsc::Sender;
use tracing::warn;
use uuid::Uuid;
use warpgate_core::recordings::DesktopRecorder;
use warpgate_core::{DesktopEvent, DesktopInput, Framebuffer};
use warpgate_web_clients_common::{ManagedSession, Sheddable, WebSession};

use crate::protocol::{ServerMessage, WsRect};

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
    /// Composited surface, kept so a viewer attaching mid-session gets a base image.
    /// Separate from the recorder's: that one must only see events it actually wrote.
    framebuffer: Mutex<Framebuffer>,
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
            framebuffer: Mutex::new(Framebuffer::default()),
        }
    }

    /// Composite an event into the session's surface. Driven from the manager's event loop
    /// on the *pre-JPEG* stream, so this stays a plain blit with no decode round-trip.
    pub async fn composite(&self, event: &DesktopEvent) {
        self.framebuffer.lock().await.apply(event);
    }

    /// A full-canvas snapshot for a viewer that just attached. `None` before the first
    /// resize, when the backend hasn't reported a size yet.
    ///
    /// Encodes under the lock: it runs once per attach, and copying the surface out to
    /// offload it would cost more than the encode saves.
    pub async fn keyframe(&self) -> Option<ServerMessage> {
        let (width, height, data) = self.framebuffer.lock().await.snapshot_png()?;
        Some(ServerMessage::Keyframe {
            rect: WsRect {
                x: 0,
                y: 0,
                width,
                height,
            },
            data: data.into(),
        })
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
