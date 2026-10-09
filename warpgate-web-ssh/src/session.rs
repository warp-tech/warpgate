use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use bytes::Bytes;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{Mutex, oneshot};
use tracing::{error, info};
use uuid::Uuid;
use warpgate_common::{TargetSessionId, UserSessionId};
use warpgate_core::WarpgateServerHandle;
use warpgate_core::recordings::{SessionRecordings, TerminalRecorder};
use warpgate_db_entities::Target::TargetKind;
use warpgate_protocol_ssh::{
    ChannelAudit, ChannelOperation, PtyRequest, RCCommand, RCCommandReply, SshClientError,
    SshRecordingMetadata,
};
use warpgate_web_clients_common::{ManagedSession, Sheddable, WebSession};

use crate::protocol::ServerMessage;

/// Terminal output ring: the whole byte stream is droppable, so an idle/slow client's backlog
/// is capped at the most recent [`OUTPUT_BUFFER_CAPACITY`] messages.
const OUTPUT_BUFFER_CAPACITY: usize = 2048;

impl Sheddable for ServerMessage {
    fn is_droppable(&self) -> bool {
        true
    }
}

pub struct PendingHostKey {
    pub reply: oneshot::Sender<bool>,
}

pub struct WebSshSession {
    core: WebSession<ServerMessage>,

    command_tx: UnboundedSender<(RCCommand, Option<RCCommandReply>)>,

    channel_counter: Arc<AtomicUsize>,
    target_session_id: TargetSessionId,
    recordings: Arc<SessionRecordings>,
    channel_audits: Arc<Mutex<HashMap<Uuid, ChannelAudit>>>,
    pending_host_key: Arc<Mutex<Option<PendingHostKey>>>,
}

impl WebSshSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: UserSessionId,
        user_id: Uuid,
        target_name: String,
        target_kind: TargetKind,
        target_session_id: TargetSessionId,
        server_handle: Arc<Mutex<WarpgateServerHandle>>,
        command_tx: UnboundedSender<(RCCommand, Option<RCCommandReply>)>,
        abort_tx: UnboundedSender<()>,
        recordings: Arc<SessionRecordings>,
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
                OUTPUT_BUFFER_CAPACITY,
            ),
            command_tx,
            channel_counter: Arc::new(AtomicUsize::new(0)),
            target_session_id,
            recordings,
            channel_audits: Arc::new(Mutex::new(HashMap::new())),
            pending_host_key: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn set_pending_host_key(&self, pending: PendingHostKey) {
        *self.pending_host_key.lock().await = Some(pending);
    }

    pub async fn take_pending_host_key(&self) -> Option<PendingHostKey> {
        self.pending_host_key.lock().await.take()
    }

    async fn start_recording(&self, channel_id: Uuid) -> Option<TerminalRecorder> {
        let channel_number = self
            .channel_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        match self
            .recordings
            .start::<TerminalRecorder, _>(
                &self.target_session_id,
                None,
                SshRecordingMetadata::Shell {
                    channel: channel_number,
                },
            )
            .await
        {
            Ok(recorder) => Some(recorder),
            Err(warpgate_core::recordings::Error::Disabled) => None,
            Err(e) => {
                error!(%channel_id, ?e, "Failed to start terminal recording");
                None
            }
        }
    }

    pub async fn end_channel(&self, channel_id: Uuid) {
        self.channel_audits.lock().await.remove(&channel_id);
    }

    fn command(&self, cmd: RCCommand) -> Option<oneshot::Receiver<Result<(), SshClientError>>> {
        let (tx, rx) = oneshot::channel();

        if self.command_tx.send((cmd, Some(tx))).is_err() {
            return None;
        }

        Some(rx)
    }

    pub async fn open_shell_channel(&self, cols: u32, rows: u32) -> Uuid {
        let channel_id = Uuid::new_v4();

        info!(session=%self.id(), channel=%channel_id, "Opening session channel");

        let pty_request = make_pty_request(cols, rows);
        let mut audit = ChannelAudit::new(channel_id);
        let (cols, rows) = pty_request.screen_size();
        audit.start_command_detection(cols, rows);
        if let Some(recorder) = self.start_recording(channel_id).await {
            audit.set_recorder(recorder);
        }
        // seeds the recording with the initial screen size
        audit.on_resize(&pty_request).await;
        self.channel_audits.lock().await.insert(channel_id, audit);

        self.command(RCCommand::Channel(channel_id, ChannelOperation::OpenShell));
        self.command(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestPty(pty_request),
        ));
        self.command(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestShell,
        ));
        channel_id
    }

    pub async fn send_input(&self, channel_id: Uuid, data: Bytes) {
        if let Some(audit) = self.channel_audits.lock().await.get_mut(&channel_id) {
            audit.on_input(&data).await;
        }
        self.command(RCCommand::Channel(channel_id, ChannelOperation::Data(data)));
    }

    pub async fn on_output(&self, channel_id: Uuid, data: &[u8]) {
        if let Some(audit) = self.channel_audits.lock().await.get_mut(&channel_id) {
            audit.on_output(data).await;
        }
    }

    pub async fn resize_channel(&self, channel_id: Uuid, cols: u32, rows: u32) {
        let pty_request = make_pty_request(cols, rows);
        if let Some(audit) = self.channel_audits.lock().await.get_mut(&channel_id) {
            audit.on_resize(&pty_request).await;
        }
        self.command(RCCommand::Channel(
            channel_id,
            ChannelOperation::ResizePty(pty_request),
        ));
    }

    pub fn close_channel(&self, channel_id: Uuid) {
        self.command(RCCommand::Channel(channel_id, ChannelOperation::Close));
    }
}

impl std::ops::Deref for WebSshSession {
    type Target = WebSession<ServerMessage>;
    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl ManagedSession for WebSshSession {
    fn id(&self) -> UserSessionId {
        self.core.id()
    }

    fn user_id(&self) -> Uuid {
        self.core.user_id()
    }

    fn on_removed(&self) {
        self.core.abort();
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
