use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use regex::Regex;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use url::Url;
use warpgate_common::SessionId;
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
        container: String,
        command: String,
    },
    #[serde(rename = "kubernetes-attach")]
    Attach {
        namespace: String,
        pod: String,
        container: String,
    },
}

pub async fn start_recording_api(
    session_id: &SessionId,
    recordings: &Arc<Mutex<SessionRecordings>>,
) -> anyhow::Result<KubernetesRecorder> {
    let recordings = recordings.lock().await;
    recordings
        .start::<KubernetesRecorder, _>(
            session_id,
            Some("api".into()),
            SessionRecordingMetadata::Api,
        )
        .await
        .context("starting recording")
}

pub async fn start_recording_exec(
    session_id: &SessionId,
    recordings: &Arc<Mutex<SessionRecordings>>,
    metadata: SessionRecordingMetadata,
) -> anyhow::Result<TerminalRecorder> {
    let recordings = recordings.lock().await;
    recordings
        .start::<TerminalRecorder, _>(session_id, None, metadata)
        .await
        .context("starting recording")
}

pub fn deduce_exec_recording_metadata(target_url: &Url) -> Option<SessionRecordingMetadata> {
    let path = target_url.path();
    #[allow(clippy::unwrap_used, reason = "static regex")]
    let exec_url_regex =
        Regex::new(r"^/api/v1/namespaces/([^/]+)/pods/([^/]+)/(exec|attach)$").unwrap();
    if let Some(captures) = exec_url_regex.captures(path) {
        let namespace = captures.get(1).map_or("unknown", |m| m.as_str()).into();
        let pod = captures.get(2).map_or("unknown", |m| m.as_str()).into();
        let operation = captures.get(3).map_or("unknown", |m| m.as_str());
        let query = target_url.query().unwrap_or_default();
        let parsed_query: HashMap<_, _> = url::form_urlencoded::parse(query.as_bytes()).collect();
        let command = parsed_query
            .get("command")
            .cloned()
            .unwrap_or_else(|| "unknown".into())
            .into();
        let container = parsed_query
            .get("container")
            .cloned()
            .unwrap_or_else(|| "unknown".into())
            .into();
        return match operation {
            "exec" => Some(SessionRecordingMetadata::Exec {
                namespace,
                pod,
                container,
                command,
            }),
            "attach" => Some(SessionRecordingMetadata::Attach {
                namespace,
                pod,
                container,
            }),
            _ => None,
        };
    }
    None
}
