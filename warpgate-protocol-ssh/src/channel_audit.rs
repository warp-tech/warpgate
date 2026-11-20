use tracing::info;
use uuid::Uuid;
use warpgate_core::recordings::{self, TerminalRecorder, TerminalRecordingStreamId};

use crate::command_detector::CommandDetector;
use crate::common::PtyRequest;

/// Encapsulates channel recording and command detection
pub struct ChannelAudit {
    channel_id: Uuid,
    recording: Recording,
    detector: Option<CommandDetector>,
}

enum Recording {
    Off,
    /// The recording starts later. Input received until then still reaches
    /// the target, so it is written to the recording when it starts
    Pending(Vec<u8>),
    On(TerminalRecorder),
}

impl ChannelAudit {
    pub const fn new(channel_id: Uuid) -> Self {
        Self {
            channel_id,
            recording: Recording::Off,
            detector: None,
        }
    }

    pub fn await_recorder(&mut self) {
        if matches!(self.recording, Recording::Off) {
            self.recording = Recording::Pending(vec![]);
        }
    }

    /// `None` when recording is disabled
    pub async fn set_recorder(
        &mut self,
        recorder: Option<TerminalRecorder>,
    ) -> recordings::Result<()> {
        let Some(recorder) = recorder else {
            self.recording = Recording::Off;
            return Ok(());
        };
        if let Recording::Pending(input) = &self.recording
            && !input.is_empty()
        {
            recorder
                .write(TerminalRecordingStreamId::Input, input)
                .await?;
        }
        self.recording = Recording::On(recorder);
        Ok(())
    }

    pub fn start_command_detection(&mut self, cols: u16, rows: u16) {
        self.detector = Some(CommandDetector::new(cols, rows));
    }

    pub async fn on_input(&mut self, data: &[u8]) -> recordings::Result<()> {
        self.record(TerminalRecordingStreamId::Input, data).await?;
        if let Some(detector) = self.detector.as_mut() {
            detector.on_input(data);
        }
        Ok(())
    }

    pub async fn on_output(&mut self, data: &[u8]) -> recordings::Result<()> {
        self.record(TerminalRecordingStreamId::Output, data).await?;
        if let Some(detector) = self.detector.as_mut()
            && let Some(command) = detector.on_output(data)
        {
            info!(channel_id=%self.channel_id, %command, "Shell command");
        }
        Ok(())
    }

    pub async fn on_error_output(&mut self, data: &[u8]) -> recordings::Result<()> {
        self.record(TerminalRecordingStreamId::Error, data).await
    }

    pub async fn on_resize(&mut self, pty: &PtyRequest) -> recordings::Result<()> {
        if let Recording::On(recorder) = &self.recording {
            recorder
                .write_pty_resize(pty.col_width, pty.row_height)
                .await?;
        }
        if let Some(detector) = self.detector.as_mut() {
            let (cols, rows) = pty.screen_size();
            detector.on_resize(cols, rows);
        }
        Ok(())
    }

    async fn record(
        &mut self,
        stream: TerminalRecordingStreamId,
        data: &[u8],
    ) -> recordings::Result<()> {
        match (&mut self.recording, stream) {
            (Recording::On(recorder), stream) => recorder.write(stream, data).await,
            (Recording::Pending(input), TerminalRecordingStreamId::Input) => {
                input.extend_from_slice(data);
                Ok(())
            }
            _ => Ok(()),
        }
    }
}
