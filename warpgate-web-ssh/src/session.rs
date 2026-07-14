use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use bytes::Bytes;
use russh::keys::PublicKey;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{Mutex, oneshot};
use tracing::{error, info};
use uuid::Uuid;
use warpgate_core::WarpgateServerHandle;
use warpgate_core::recordings::{
    SessionRecordings, TerminalRecorder, TerminalRecordingStreamId,
};
use warpgate_db_entities::Target::TargetKind;
use warpgate_protocol_ssh::{
    ChannelOperation, PtyRequest, RCCommand, RCCommandReply, SshClientError, SshRecordingMetadata,
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
    pub key: PublicKey,
    pub host: String,
    pub port: u16,
}

pub struct WebSshSession {
    core: WebSession<ServerMessage>,

    command_tx: UnboundedSender<(RCCommand, Option<RCCommandReply>)>,

    channel_counter: Arc<AtomicUsize>,
    recordings: Arc<Mutex<SessionRecordings>>,
    channel_recorders: Arc<Mutex<HashMap<Uuid, TerminalRecorder>>>,
    pending_host_key: Arc<Mutex<Option<PendingHostKey>>>,
}

impl WebSshSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Uuid,
        user_id: Uuid,
        target_name: String,
        target_kind: TargetKind,
        server_handle: Arc<Mutex<WarpgateServerHandle>>,
        command_tx: UnboundedSender<(RCCommand, Option<RCCommandReply>)>,
        abort_tx: UnboundedSender<()>,
        recordings: Arc<Mutex<SessionRecordings>>,
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
            recordings,
            channel_recorders: Arc::new(Mutex::new(HashMap::new())),
            pending_host_key: Arc::new(Mutex::new(None)),
        }
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
                &self.id(),
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

        self.start_recording(channel_id).await;
        self.with_recorder(channel_id, async move |r: &TerminalRecorder| {
            if let Err(e) = r.write_pty_resize(cols, rows).await {
                error!(%channel_id, ?e, "Failed to write initial PTY size to recording");
            }
        })
        .await;

        self.command(RCCommand::Channel(channel_id, ChannelOperation::OpenShell));
        self.command(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestPty(make_pty_request(cols, rows)),
        ));
        self.command(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestShell,
        ));
        channel_id
    }

    pub async fn send_input(&self, channel_id: Uuid, data: Bytes) {
        self.with_recorder(channel_id, async |r| {
            if let Err(e) = r.write(TerminalRecordingStreamId::Input, &data).await {
                error!(%channel_id, ?e, "Failed to record terminal input");
            }
        })
        .await;
        self.command(RCCommand::Channel(channel_id, ChannelOperation::Data(data)));
    }

    pub async fn resize_channel(&self, channel_id: Uuid, cols: u32, rows: u32) {
        self.command(RCCommand::Channel(
            channel_id,
            ChannelOperation::ResizePty(make_pty_request(cols, rows)),
        ));
        self.with_recorder(channel_id, async move |r| {
            if let Err(e) = r.write_pty_resize(cols, rows).await {
                error!(%channel_id, ?e, "Failed to record PTY resize");
            }
        })
        .await;
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
    fn id(&self) -> Uuid {
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
