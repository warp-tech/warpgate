use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use warpgate_common::TargetSessionId;
use warpgate_core::recordings::{
    NDJsonRecordingWriter, Recorder, RecordingWriterOpener, SessionRecordings, TerminalRecorder,
};
use warpgate_db_entities::Recording::RecordingKind;

/// One recorded Kubernetes API request/response as stored in a data NDJSON line
#[derive(Serialize, Deserialize, Debug)]
pub struct KubernetesRecordingItem {
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    pub request_method: String,
    pub request_path: String,
    pub request_headers: std::collections::HashMap<String, String>,
    #[serde(with = "warpgate_common::helpers::serde_base64")]
    pub request_body: Bytes,
    pub response_status: Option<u16>,
    pub response_body: Option<Vec<u8>>,
}

/// Recorder for Kubernetes API sessions
pub struct KubernetesRecorder {
    writer: NDJsonRecordingWriter,
}

impl KubernetesRecorder {
    pub async fn record_response(
        &self,
        method: &str,
        path: &str,
        headers: std::collections::HashMap<String, String>,
        request_body: &[u8],
        status: u16,
        response_body: &[u8],
    ) -> Result<(), warpgate_core::recordings::Error> {
        self.writer
            .write_json_line(&KubernetesRecordingItem {
                timestamp: OffsetDateTime::now_utc(),
                request_method: method.to_string(),
                request_path: path.to_string(),
                request_headers: headers,
                request_body: Bytes::from(request_body.to_vec()),
                response_status: Some(status),
                response_body: Some(response_body.to_vec()),
            })
            .await?;
        Ok(())
    }
}

impl Recorder for KubernetesRecorder {
    fn kind() -> RecordingKind {
        RecordingKind::Kubernetes
    }

    async fn new(opener: &RecordingWriterOpener) -> warpgate_core::recordings::Result<Self> {
        Ok(Self {
            writer: opener.open_ndjson_data().await?,
        })
    }
}

// ----------

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum SessionRecordingMetadata {
    #[serde(rename = "kubernetes-api")]
    Api,
    #[serde(rename = "kubernetes-exec")]
    Exec {
        namespace: String,
        pod: String,
        /// Absent when the client named no container (kubectl omits it for
        /// single-container pods and lets the API server choose).
        container: Option<String>,
        /// Full argv. `kubectl exec pod -- ls -la` sends one `command=` query
        /// parameter per element, and every one of them belongs here.
        command: Vec<String>,
    },
    #[serde(rename = "kubernetes-attach")]
    Attach {
        namespace: String,
        pod: String,
        container: Option<String>,
    },
}

/// Monotonic sequence giving every API request its own recording name.
///
/// `SessionRecordings::start` keys a recording by (session_id, name, kind) and
/// reuses the existing writer for a repeated name — so a fixed name would open
/// two `data.ndjson` writers on the same folder for concurrent requests and let
/// them clobber each other. A process-wide counter is monotonic (never random
/// or time-based) and is unique within any single session, which is all that is
/// required to keep each request's recording separate.
static API_RECORDING_SEQ: AtomicU64 = AtomicU64::new(0);

pub async fn start_recording_api(
    target_session_id: &TargetSessionId,
    recordings: &SessionRecordings,
) -> anyhow::Result<KubernetesRecorder> {
    let seq = API_RECORDING_SEQ.fetch_add(1, Ordering::Relaxed);
    recordings
        .start::<KubernetesRecorder, _>(
            target_session_id,
            Some(format!("api-{seq}")),
            SessionRecordingMetadata::Api,
        )
        .await
        .context("starting recording")
}

pub async fn start_recording_exec(
    target_session_id: &TargetSessionId,
    recordings: &SessionRecordings,
    metadata: SessionRecordingMetadata,
) -> anyhow::Result<TerminalRecorder> {
    recordings
        .start::<TerminalRecorder, _>(target_session_id, None, metadata)
        .await
        .context("starting recording")
}
