use bytes::Bytes;
use chrono::{DateTime, Utc};
use poem_openapi::Object;
use serde::{Deserialize, Serialize};
use warpgate_core::recordings::{Recorder, RecordingWriter};
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
