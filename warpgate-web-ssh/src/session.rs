use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use russh::keys::PublicKey;
use tokio::sync::futures::Notified;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{Mutex, Notify, oneshot};
use tokio::task::JoinHandle;
use tracing::error;
use uuid::Uuid;
use warpgate_core::SessionHandle;
use warpgate_core::recordings::{SessionRecordings, TerminalRecorder};
use warpgate_db_entities::Target::TargetKind;
use warpgate_protocol_ssh::{
    ChannelOperation, PtyRequest, RCCommand, RCCommandReply, SshClientError, SshRecordingMetadata,
};

use crate::WebSshClientManager;
use crate::protocol::ServerMessage;

pub const OUTPUT_BUFFER_CAPACITY: usize = 2048;

pub struct PendingHostKey {
    pub reply: oneshot::Sender<bool>,
    pub key: PublicKey,
    pub host: String,
    pub port: u16,
}

pub struct WebSshSessionHandle {
    abort_tx: UnboundedSender<()>,
}

impl WebSshSessionHandle {
    pub fn new(abort_tx: UnboundedSender<()>) -> Self {
        Self { abort_tx }
    }
}

impl SessionHandle for WebSshSessionHandle {
    fn close(&mut self) {
        let _ = self.abort_tx.send(());
    }
}

pub struct WebSshSession {
    id: Uuid,
    user_id: Uuid,
    target_name: String,
    target_kind: TargetKind,

    command_tx: UnboundedSender<(RCCommand, Option<RCCommandReply>)>,
    abort_tx: UnboundedSender<()>,

    // events are buffer so that we can queue and replay them
    // if the WS stream reconnects
    output_buffer: Arc<Mutex<VecDeque<ServerMessage>>>,
    output_notify: Arc<Notify>,

    is_dead: Arc<AtomicBool>,
    disconnect_timer: Arc<Mutex<Option<JoinHandle<()>>>>,
    channel_counter: Arc<AtomicUsize>,
    recordings: Arc<Mutex<SessionRecordings>>,
    channel_recorders: Arc<Mutex<HashMap<Uuid, TerminalRecorder>>>,
    pending_host_key: Arc<Mutex<Option<PendingHostKey>>>,
}

impl WebSshSession {
    pub fn new(
        id: Uuid,
        user_id: Uuid,
        target_name: String,
        target_kind: TargetKind,
        command_tx: UnboundedSender<(RCCommand, Option<RCCommandReply>)>,
        abort_tx: UnboundedSender<()>,
        recordings: Arc<Mutex<SessionRecordings>>,
    ) -> Self {
        Self {
            id,
            user_id,
            target_name,
            target_kind,
            command_tx,
            abort_tx,
            output_buffer: Arc::new(Mutex::new(VecDeque::with_capacity(OUTPUT_BUFFER_CAPACITY))),
            output_notify: Arc::new(Notify::new()),
            is_dead: Arc::new(AtomicBool::new(false)),
            disconnect_timer: Arc::new(Mutex::new(None)),
            channel_counter: Arc::new(AtomicUsize::new(0)),
            recordings,
            channel_recorders: Arc::new(Mutex::new(HashMap::new())),
            pending_host_key: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn push_event(&self, msg: ServerMessage) {
        let mut buf = self.output_buffer.lock().await;
        if buf.len() >= OUTPUT_BUFFER_CAPACITY {
            buf.pop_front();
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

    pub async fn start_disconnect_timer(&self, manager: Arc<WebSshClientManager>) {
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

    pub async fn set_pending_host_key(&self, pending: PendingHostKey) {
        *self.pending_host_key.lock().await = Some(pending);
    }

    pub async fn take_pending_host_key(&self) -> Option<PendingHostKey> {
        self.pending_host_key.lock().await.take()
    }

    pub async fn with_recorder<F: AsyncFnOnce(&TerminalRecorder)>(&self, channel_id: Uuid, f: F) {
        let recorders = self.channel_recorders.lock().await;
        if let Some(r) = recorders.get(&channel_id) {
            f(r).await;
        }
    }

    pub async fn start_recording(&self, channel_id: Uuid) {
        let channel_number = self
            .channel_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        match self
            .recordings
            .lock()
            .await
            .start::<TerminalRecorder, _>(
                &self.id,
                Some(channel_id.to_string()),
                SshRecordingMetadata::Shell {
                    channel: channel_number,
                },
            )
            .await
        {
            Ok(recorder) => {
                self.channel_recorders
                    .lock()
                    .await
                    .insert(channel_id, recorder);
            }
            Err(warpgate_core::recordings::Error::Disabled) => {}
            Err(e) => {
                error!(%channel_id, ?e, "Failed to start terminal recording");
            }
        }
    }

    pub async fn stop_recording(&self, channel_id: Uuid) {
        self.channel_recorders.lock().await.remove(&channel_id);
    }

    pub fn close(&self) {
        self.is_dead
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.output_notify.notify_waiters();
    }

    async fn command(
        &self,
        cmd: RCCommand,
    ) -> Option<oneshot::Receiver<Result<(), SshClientError>>> {
        let (tx, rx) = oneshot::channel();

        if self.command_tx.send((cmd, Some(tx))).is_err() {
            return None;
        }

        Some(rx)
    }

    pub async fn open_shell_channel(&self, cols: u32, rows: u32) -> Uuid {
        let channel_id = Uuid::new_v4();

        self.command(RCCommand::Channel(channel_id, ChannelOperation::OpenShell))
            .await;
        self.command(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestPty(make_pty_request(cols, rows)),
        ))
        .await;
        self.command(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestShell,
        ))
        .await;
        self.start_recording(channel_id).await;
        self.with_recorder(channel_id, async move |r: &TerminalRecorder| {
            if let Err(e) = r.write_pty_resize(cols, rows).await {
                error!(%channel_id, ?e, "Failed to write initial PTY size to recording");
            }
        })
        .await;
        channel_id
    }

    pub async fn send_input(&self, channel_id: Uuid, data: Bytes) {
        self.command(RCCommand::Channel(channel_id, ChannelOperation::Data(data)))
            .await;
    }

    pub async fn resize_channel(&self, channel_id: Uuid, cols: u32, rows: u32) {
        self.command(RCCommand::Channel(
            channel_id,
            ChannelOperation::ResizePty(make_pty_request(cols, rows)),
        ))
        .await;
        self.with_recorder(channel_id, async move |r| {
            if let Err(e) = r.write_pty_resize(cols, rows).await {
                error!(%channel_id, ?e, "Failed to record PTY resize");
            }
        })
        .await;
    }

    pub async fn close_channel(&self, channel_id: Uuid) {
        self.command(RCCommand::Channel(channel_id, ChannelOperation::Close))
            .await;
    }
}

pub fn make_pty_request(cols: u32, rows: u32) -> PtyRequest {
    PtyRequest {
        term: "xterm-256color".to_owned(),
        col_width: cols,
        row_height: rows,
        pix_width: 0,
        pix_height: 0,
        modes: vec![],
    }
}
