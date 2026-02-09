use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use poem_openapi::Object;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use url::Url;
use warpgate_common::SessionId;
use warpgate_core::recordings::{Recorder, RecordingWriter, SessionRecordings, TerminalRecorder};
use warpgate_db_entities::Recording::RecordingKind;

#[derive(Debug, Object)]
#[oai(rename = "KubernetesRecordingItem")]
pub struct KubernetesRecordingItemApiObject {
    pub timestamp: DateTime<Utc>,
    pub request_method: String,
    pub request_path: String,
    pub request_body: serde_json::Value,
    pub response_status: Option<u16>,
    pub response_body: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KubernetesRecordingItem {
    pub timestamp: DateTime<Utc>,
    pub request_method: String,
    pub request_path: String,
    pub request_headers: std::collections::HashMap<String, String>,
    #[serde(with = "warpgate_common::helpers::serde_base64")]
    pub request_body: Bytes,
    pub response_status: Option<u16>,
    pub response_body: Option<Vec<u8>>,
}

impl From<KubernetesRecordingItem> for KubernetesRecordingItemApiObject {
    fn from(item: KubernetesRecordingItem) -> Self {
        KubernetesRecordingItemApiObject {
            timestamp: item.timestamp,
            request_method: item.request_method,
            request_path: item.request_path,
            request_body: serde_json::from_slice(&item.request_body[..])
                .unwrap_or(serde_json::Value::Null),
            response_status: item.response_status,
            response_body: item
                .response_body
                .and_then(|body| serde_json::from_slice(&body[..]).ok())
                .unwrap_or(serde_json::Value::Null),
        }
    }
}

pub struct KubernetesRecorder {
    writer: RecordingWriter,
}

impl KubernetesRecorder {
    async fn write_item(
        &mut self,
        item: &KubernetesRecordingItem,
    ) -> Result<(), warpgate_core::recordings::Error> {
        let mut serialized_item =
            serde_json::to_vec(&item).map_err(warpgate_core::recordings::Error::Serialization)?;
        serialized_item.push(b'\n');
        self.writer.write(&serialized_item).await?;
        Ok(())
    }

    pub async fn record_response(
        &mut self,
        method: &str,
        path: &str,
        headers: std::collections::HashMap<String, String>,
        request_body: &[u8],
        status: u16,
        response_body: &[u8],
    ) -> Result<(), warpgate_core::recordings::Error> {
        self.write_item(&KubernetesRecordingItem {
            timestamp: Utc::now(),
            request_method: method.to_string(),
            request_path: path.to_string(),
            request_headers: headers,
            request_body: Bytes::from(request_body.to_vec()),
            response_status: Some(status),
            response_body: Some(response_body.to_vec()),
        })
        .await
    }
}

impl Recorder for KubernetesRecorder {
    fn kind() -> RecordingKind {
        RecordingKind::Kubernetes
    }

    fn new(writer: RecordingWriter) -> Self {
        KubernetesRecorder { writer }
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
    let mut recordings = recordings.lock().await;
    Ok(recordings
        .start::<KubernetesRecorder, _>(
            session_id,
            Some("api".into()),
            SessionRecordingMetadata::Api,
        )
        .await
        .context("starting recording")?)
}

pub async fn start_recording_exec(
    session_id: &SessionId,
    recordings: &Arc<Mutex<SessionRecordings>>,
    metadata: Option<SessionRecordingMetadata>,
) -> anyhow::Result<TerminalRecorder> {
    let mut recordings = recordings.lock().await;
    recordings
        .start::<TerminalRecorder, _>(session_id, None, metadata)
        .await
        .context("starting recording")
}

pub fn deduce_exec_recording_metadata(target_url: &Url) -> Option<SessionRecordingMetadata> {
    let path = target_url.path();
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
            .unwrap_or("unknown".into())
            .into();
        let container = parsed_query
            .get("container")
            .cloned()
            .unwrap_or("unknown".into())
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
