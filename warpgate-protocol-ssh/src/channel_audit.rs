use sea_orm::{ActiveModelTrait, DatabaseConnection, Set};
use time::OffsetDateTime;
use tracing::{error, info, warn};
use uuid::Uuid;
use warpgate_core::recordings::{TerminalRecorder, TerminalRecordingStreamId};
use warpgate_db_entities::Command;

use crate::command_detector::CommandDetector;
use crate::common::PtyRequest;

/// Context needed to persist a detected command.
#[derive(Clone)]
pub struct CommandRecordContext {
    pub db: DatabaseConnection,
    pub user_session_id: Uuid,
    pub target_session_id: Option<Uuid>,
    pub username: Option<String>,
}

/// Encapsulates channel recording and command detection
pub struct ChannelAudit {
    channel_id: Uuid,
    recorder: Option<TerminalRecorder>,
    detector: Option<CommandDetector>,
    command_context: Option<CommandRecordContext>,
}

impl ChannelAudit {
    pub const fn new(channel_id: Uuid) -> Self {
        Self {
            channel_id,
            recorder: None,
            detector: None,
            command_context: None,
        }
    }

    pub fn set_recorder(&mut self, recorder: TerminalRecorder) {
        self.recorder = Some(recorder);
    }

    pub fn start_command_detection(
        &mut self,
        cols: u16,
        rows: u16,
        command_context: Option<CommandRecordContext>,
    ) {
        self.detector = Some(CommandDetector::new(cols, rows));
        self.command_context = command_context;
    }

    pub async fn on_input(&mut self, data: &[u8]) {
        self.record(TerminalRecordingStreamId::Input, data).await;
        if let Some(detector) = self.detector.as_mut() {
            detector.on_input(data);
        }
    }

    pub async fn on_output(&mut self, data: &[u8]) {
        self.record(TerminalRecordingStreamId::Output, data).await;
        if let Some(detector) = self.detector.as_mut()
            && let Some(command) = detector.on_output(data)
        {
            info!(channel_id=%self.channel_id, %command, "Shell command");
            if let Some(context) = self.command_context.clone() {
                record_command(context, command);
            }
        }
    }

    pub async fn on_error_output(&mut self, data: &[u8]) {
        self.record(TerminalRecordingStreamId::Error, data).await;
    }

    pub async fn on_resize(&mut self, pty: &PtyRequest) {
        let channel_id = self.channel_id;
        if let Some(recorder) = self.recorder.as_mut()
            && let Err(error) = recorder
                .write_pty_resize(pty.col_width, pty.row_height)
                .await
        {
            error!(channel=%channel_id, ?error, "Failed to record PTY resize");
            self.recorder = None;
        }
        if let Some(detector) = self.detector.as_mut() {
            let (cols, rows) = pty.screen_size();
            detector.on_resize(cols, rows);
        }
    }

    async fn record(&mut self, stream: TerminalRecordingStreamId, data: &[u8]) {
        let channel_id = self.channel_id;
        if let Some(recorder) = self.recorder.as_mut()
            && let Err(error) = recorder.write(stream, data).await
        {
            error!(channel=%channel_id, ?error, "Failed to record terminal data");
            self.recorder = None;
        }
    }
}

/// Persists a detected command off the session's critical path. A failure is
/// logged and dropped: command auditing must never disturb the terminal stream.
fn record_command(context: CommandRecordContext, command: String) {
    tokio::spawn(async move {
        let row = Command::ActiveModel {
            id: Set(Uuid::new_v4()),
            timestamp: Set(OffsetDateTime::now_utc()),
            user_session_id: Set(context.user_session_id),
            target_session_id: Set(context.target_session_id),
            username: Set(context.username),
            command: Set(command),
        };
        if let Err(error) = row.insert(&context.db).await {
            warn!(?error, "failed to record shell command");
        }
    });
}
