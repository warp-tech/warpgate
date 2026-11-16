use std::sync::{Arc, PoisonError, RwLock};

use sea_orm::{ActiveModelTrait, DatabaseConnection, Set};
use time::OffsetDateTime;
use tracing::{error, info, warn};
use uuid::Uuid;
use warpgate_core::recordings::{TerminalRecorder, TerminalRecordingStreamId};
use warpgate_db_entities::Command;

use crate::command_detector::CommandDetector;
use crate::common::PtyRequest;

/// The target a session is currently bound to, shared with the command
/// detector. Detection can start before the target is admitted (a channel held
/// at the approval gate), so the session re-stamps this whenever it resolves a
/// target and the insert reads it when a command is detected — a command
/// emitted after the target became known still carries its name.
pub type TargetNameHandle = Arc<RwLock<Option<String>>>;

pub fn new_target_name_handle() -> TargetNameHandle {
    Arc::new(RwLock::new(None))
}

/// Records the resolved target name. The lock is only ever held for the
/// assignment: no `.await` happens between acquiring it and releasing it, and
/// nothing else runs under [`std::sync::RwLock`] here.
pub fn stamp_target_name(handle: &TargetNameHandle, name: String) {
    *handle.write().unwrap_or_else(PoisonError::into_inner) = Some(name);
}

/// Context needed to persist a detected command.
#[derive(Clone)]
pub struct CommandRecordContext {
    pub db: DatabaseConnection,
    pub user_session_id: Uuid,
    pub username: Option<String>,
    pub target_name: TargetNameHandle,
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
        if let Some(detector) = self.detector.as_mut() {
            // A paste can complete several commands in one chunk; each is
            // recorded and logged on its own.
            for command in detector.on_output(data) {
                info!(channel_id=%self.channel_id, %command, "Shell command");
                if let Some(context) = self.command_context.clone() {
                    record_command(context, command);
                }
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
        let target_name = context
            .target_name
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let row = Command::ActiveModel {
            id: Set(Uuid::new_v4()),
            timestamp: Set(OffsetDateTime::now_utc()),
            user_session_id: Set(context.user_session_id),
            username: Set(context.username),
            target_name: Set(target_name),
            command: Set(command),
        };
        if let Err(error) = row.insert(&context.db).await {
            warn!(?error, "failed to record shell command");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The context carries a handle, not a snapshot: a target resolved after
    /// the detector started is what the insert reads.
    #[test]
    fn target_name_handle_sees_a_later_stamp() {
        let handle = new_target_name_handle();
        let in_context = handle.clone();

        assert_eq!(*in_context.read().unwrap(), None);
        stamp_target_name(&handle, "prod-db".into());
        assert_eq!(in_context.read().unwrap().as_deref(), Some("prod-db"));
        stamp_target_name(&handle, "prod-web".into());
        assert_eq!(in_context.read().unwrap().as_deref(), Some("prod-web"));
    }
}
