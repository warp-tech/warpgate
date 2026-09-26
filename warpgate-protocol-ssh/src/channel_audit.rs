use tracing::{error, info};
use uuid::Uuid;
use warpgate_core::recordings::{TerminalRecorder, TerminalRecordingStreamId};

use crate::command_detector::CommandDetector;
use crate::common::PtyRequest;

/// Encapsulates channel recording and command detection
pub struct ChannelAudit {
    channel_id: Uuid,
    recorder: Option<TerminalRecorder>,
    detector: Option<CommandDetector>,
}

impl ChannelAudit {
    pub const fn new(channel_id: Uuid) -> Self {
        Self {
            channel_id,
            recorder: None,
            detector: None,
        }
    }

    pub fn set_recorder(&mut self, recorder: TerminalRecorder) {
        self.recorder = Some(recorder);
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
            info!(channel_id=%self.channel_id, %command, "Shell command");
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
