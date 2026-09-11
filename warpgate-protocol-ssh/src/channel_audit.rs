use sea_orm::DatabaseConnection;
use tracing::{error, info, warn};
use uuid::Uuid;
use warpgate_common::{NodeId, TargetSessionId};
use warpgate_core::recordings::{TerminalRecorder, TerminalRecordingStreamId};
use warpgate_db_entities::SessionCommand;

use crate::command_detector::CommandDetector;
use crate::common::PtyRequest;

/// Where detected commands are persisted: the shared DB handle plus the
/// target session they belong to. Absent until a target session exists —
/// commands from the target-selection menu are logged, not stored.
struct CommandSink {
    db: DatabaseConnection,
    target_session_id: TargetSessionId,
    node_id: Option<NodeId>,
}

/// Encapsulates channel recording and command detection
pub struct ChannelAudit {
    channel_id: Uuid,
    recorder: Option<TerminalRecorder>,
    detector: Option<CommandDetector>,
    command_sink: Option<CommandSink>,
}

impl ChannelAudit {
    pub const fn new(channel_id: Uuid) -> Self {
        Self {
            channel_id,
            recorder: None,
            detector: None,
            command_sink: None,
        }
    }

    pub fn set_recorder(&mut self, recorder: TerminalRecorder) {
        self.recorder = Some(recorder);
    }

    /// Attach command persistence to the target session, mirroring how the
    /// recorder is attached once a target session exists.
    pub fn set_command_sink(
        &mut self,
        db: DatabaseConnection,
        target_session_id: TargetSessionId,
        node_id: Option<NodeId>,
    ) {
        self.command_sink = Some(CommandSink {
            db,
            target_session_id,
            node_id,
        });
    }

    pub fn start_command_detection(&mut self, cols: u16, rows: u16) {
        self.detector = Some(CommandDetector::new(cols, rows));
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
            match self.command_sink.as_ref() {
                Some(sink) => {
                    if let Err(error) = SessionCommand::Entity::insert_detected(
                        &sink.db,
                        sink.target_session_id,
                        &command,
                        sink.node_id,
                    )
                    .await
                    {
                        // Persistence must never break the session: fall back
                        // to log-only for the rest of it.
                        warn!(channel_id=%self.channel_id, %command, ?error, "Failed to persist shell command");
                        self.command_sink = None;
                        info!(channel_id=%self.channel_id, %command, "Shell command");
                    }
                }
                None => info!(channel_id=%self.channel_id, %command, "Shell command"),
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
