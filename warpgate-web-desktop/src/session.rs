use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::futures::Notified;
use tokio::sync::mpsc::{Sender, UnboundedSender};
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use tracing::warn;
use uuid::Uuid;
use warpgate_core::recordings::DesktopRecorder;
use warpgate_core::{DesktopInput, SessionHandle, WarpgateServerHandle};
use warpgate_db_entities::Target::TargetKind;

use crate::WebDesktopClientManager;
use crate::protocol::ServerMessage;

pub const OUTPUT_BUFFER_CAPACITY: usize = 4096;

pub struct WebDesktopSessionHandle {
    abort_tx: UnboundedSender<()>,
}

impl WebDesktopSessionHandle {
    pub fn new(abort_tx: UnboundedSender<()>) -> Self {
        Self { abort_tx }
    }
}

impl SessionHandle for WebDesktopSessionHandle {
    fn close(&mut self) {
        let _ = self.abort_tx.send(());
    }
}

pub struct WebDesktopSession {
    id: Uuid,
    user_id: Uuid,
    target_name: String,
    target_kind: TargetKind,

    // prevents the handle from getting dropped too early
    _server_handle: Arc<Mutex<WarpgateServerHandle>>,

    input_tx: Sender<DesktopInput>,
    abort_tx: UnboundedSender<()>,

    // shared with the manager's event loop; records viewer input for audit
    recorder: Option<Arc<DesktopRecorder>>,

    // events are buffered so that we can queue and replay them
    // if the WS stream reconnects
    output_buffer: Arc<Mutex<VecDeque<ServerMessage>>>,
    output_notify: Arc<Notify>,

    is_dead: Arc<AtomicBool>,
    disconnect_timer: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl WebDesktopSession {
    pub fn new(
        id: Uuid,
        user_id: Uuid,
        target_name: String,
        target_kind: TargetKind,
        server_handle: Arc<Mutex<WarpgateServerHandle>>,
        input_tx: Sender<DesktopInput>,
        abort_tx: UnboundedSender<()>,
        recorder: Option<Arc<DesktopRecorder>>,
    ) -> Self {
        Self {
            id,
            user_id,
            target_name,
            target_kind,
            _server_handle: server_handle,
            input_tx,
            abort_tx,
            recorder,
            output_buffer: Arc::new(Mutex::new(VecDeque::with_capacity(OUTPUT_BUFFER_CAPACITY))),
            output_notify: Arc::new(Notify::new()),
            is_dead: Arc::new(AtomicBool::new(false)),
            disconnect_timer: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn push_event(&self, msg: ServerMessage) {
        let mut buf = self.output_buffer.lock().await;
        if buf.len() >= OUTPUT_BUFFER_CAPACITY {
            // Prefer to drop "incremental" frames first
            let drop_idx = buf
                .iter()
                .position(ServerMessage::is_incremental)
                .unwrap_or(0);
            buf.remove(drop_idx);
        }
        buf.push_back(msg);
        self.output_notify.notify_waiters();
    }

    pub async fn drain_buffer(&self) -> Vec<ServerMessage> {
        self.output_buffer.lock().await.drain(..).collect()
    }

    pub fn is_dead(&self) -> bool {
        self.is_dead.load(Ordering::Relaxed)
    }

    pub fn abort(&self) {
        let _ = self.abort_tx.send(());
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn user_id(&self) -> Uuid {
        self.user_id
    }

    pub fn target_name(&self) -> &str {
        &self.target_name
    }

    pub fn target_kind(&self) -> &TargetKind {
        &self.target_kind
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

    pub async fn start_disconnect_timer(&self, manager: Arc<WebDesktopClientManager>) {
        let id = self.id();
        let timer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            manager.remove_session(id).await;
        });
        *self.disconnect_timer.lock().await = Some(timer);
    }

    pub async fn cancel_disconnect_timer(&self) {
        if let Some(handle) = self.disconnect_timer.lock().await.take() {
            handle.abort();
        }
    }

    pub fn wait_buffer(&self) -> Notified<'_> {
        self.output_notify.notified()
    }

    pub fn close(&self) {
        self.is_dead.store(true, Ordering::Relaxed);
        self.output_notify.notify_waiters();
    }
}
