use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::time::Instant;
use warpgate_core::recordings::{Recorder, RecordingWriter};
use warpgate_db_entities::Recording::RecordingKind;

#[derive(Serialize, Deserialize, Debug)]
pub struct KubernetesRecordingItem {
    pub time: f32,
    pub request_method: String,
    pub request_path: String,
    pub request_headers: std::collections::HashMap<String, String>,
    #[serde(with = "warpgate_common::helpers::serde_base64")]
    pub request_body: Bytes,
    pub response_status: Option<u16>,
    pub response_body: Option<Vec<u8>>,
}

pub struct KubernetesRecorder {
    writer: RecordingWriter,
    started_at: Instant,
}

impl KubernetesRecorder {
    fn get_time(&self) -> f32 {
        self.started_at.elapsed().as_secs_f32()
    }

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

    pub async fn record_request(
        &mut self,
        method: &str,
        path: &str,
        headers: std::collections::HashMap<String, String>,
        body: &[u8],
    ) -> Result<(), warpgate_core::recordings::Error> {
        self.write_item(&KubernetesRecordingItem {
            time: self.get_time(),
            request_method: method.to_string(),
            request_path: path.to_string(),
            request_headers: headers,
            request_body: Bytes::from(body.to_vec()),
            response_status: None,
            response_body: None,
        })
        .await
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
            time: self.get_time(),
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
        KubernetesRecorder {
            writer,
            started_at: Instant::now(),
        }
    }
}
